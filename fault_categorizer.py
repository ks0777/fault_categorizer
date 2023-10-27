#!/bin/env python3

# Copyright (c) 2023 Kevin Schneider
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pypcode import Context, PcodePrettyPrinter
from pypcode.pypcode_native import OpCode as OpCode
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section
from elftools.elf.segments import Segment

from loop_integrity import check_li
from ite import check_ite
from cfi import check_cfi
from misc import check_branch, check_branch_intervention
from countermeasures import get_rules
from data_dependency_analysis import DataDependencyAnalysis

import util
import pandas
import h5py
import jsonpickle
import argparse


def log_results(fault_reports, elf, ddg, instruction_ops, instructions, args):
    rules = get_rules()
    instruction_addresses = sorted(instructions.keys())

    for report in fault_reports:
        source = util.decode_file_line(elf.get_dwarf_info(), report.fault_address)

        fault_detail = "Disassembly:\n"
        fault_insn_index = instruction_addresses.index(report.fault_address)
        fault_detail += util.disassembly_pp(
            instructions,
            instruction_addresses[fault_insn_index - 3],
            instruction_addresses[fault_insn_index + 6],
            report.fault_address,
        )

        if source != (None, None):
            source = {"filename": source[0].decode(), "line": source[1]}
            report.set_source(source)

        if report.affected_branches == None:
            report.set_detail(fault_detail)
            continue

        for i, address in enumerate(report.affected_branches):
            source = util.decode_file_line(elf.get_dwarf_info(), address)
            if source != (None, None):
                source = {"filename": source[0].decode(), "line": source[1]}
            else:
                source = {"filename": "-", "line": "-"}
            report.affected_branches[i] = {
                "address": report.affected_branches[i],
                "source": source,
            }

        if report.affected_branches:
            fault_detail += "Fault affected branch(es) at: \n"
            for branch in report.affected_branches:
                fault_detail += f"{hex(branch['address'])} ({branch['source']['filename']}:{branch['source']['line']})\n"

        if report.category == util.FaultCategory.UNKNOWN:
            dependents = ddg.find_dependents(report.fault_address)
            affects_store_op = False
            for dep in dependents:
                for op in instruction_ops[dep.insn_addr]:
                    if op.opcode == OpCode.STORE:
                        affects_store_op = True
                        break

            if affects_store_op:
                fault_detail += "\r\nThe skipped instruction affects a store instruction. If the target is inside device memory the analysis can not continue because of insufficient log data."
        report.set_detail(fault_detail)

    if args.output == "json":
        print(jsonpickle.encode(fault_reports, unpicklable=False))
        return

    if args.output == "sarif":
        sarif_report = dict()
        sarif_report[
            "$schema"
        ] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        sarif_report["version"] = "2.1.0"
        sarif_report["runs"] = [
            {
                "tool": {
                    "driver": {
                        "name": "Fault Analysis",
                        "informationUri": "https://github.com/ks0777/fault_categorizer",
                        "version": "1.0",
                        "rules": rules,
                    }
                },
                "results": [
                    {
                        "ruleId": report.category,
                        "message": {"text": report.detail},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": report.source["filename"]
                                    },
                                    "region": {"startLine": report.source["line"]},
                                }
                            }
                        ]
                        + (
                            [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": affected_branch["source"]["filename"]
                                        },
                                        "region": {
                                            "startLine": affected_branch["source"][
                                                "line"
                                            ]
                                        },
                                    }
                                }
                                for affected_branch in report.affected_branches
                                if affected_branch["source"]["filename"] != "-"
                            ]
                            if report.affected_branches != None
                            else []
                        ),
                    }
                    for report in fault_reports
                ],
            }
        ]

        print(jsonpickle.encode(sarif_report, unpicklable=False))
        return

    for report in fault_reports:
        if report.source != None:
            print(
                f"Skipped instruction at {hex(report.fault_address)} ({report.source['filename']}:{report.source['line']}) caused fault of type {report.category}"
            )
        else:
            print(
                f"Skipped instruction at {hex(report.fault_address)} caused fault of type {report.category}"
            )
        print(
            next(
                filter(
                    lambda rule: rule["id"] == str(report.category).split(".")[1], rules
                )
            )["help"]["markdown"]
        )
        if report.affected_branches:
            if len(report.affected_branches) == 1:
                branch = report.affected_branches[0]
                source = branch["source"]
                print(f"\tFault affected branch at {hex(branch['address'])}", end="")
                if branch["source"] != None:
                    print(f" ({source['filename']}:{source['line']})", end="")
                print("")
            else:
                print(
                    f"\tFault {'affects' if args.accurate else 'MIGHT have affected'} multiple branches at:"
                )
                for branch in report.affected_branches:
                    source = branch["source"]
                    if source != None:
                        print(
                            f"\t\t{hex(branch['address'])} ({source['filename']}:{source['line']})"
                        )
                    print("")

        if report.category == util.FaultCategory.UNKNOWN:
            print(
                f"\tUnable to detect how the skipped instruction influences the control flow. The instruction affects the following instructions: "
            )
            dependents = ddg.find_dependents(report.fault_address)
            affects_store_op = False
            for dep in dependents:
                print(f"\t\t{str(dep)}")
                for op in instruction_ops[dep.insn_addr]:
                    if op.opcode == OpCode.STORE:
                        affects_store_op = True
                        break

            if affects_store_op:
                print(
                    "\tThe skipped instruction affects a store instruction. If the target is inside device memory the analysis can not continue because of insufficient log data."
                )

        if report.detail:
            print("\n" + report.detail)

        print("")


def categorize_faults(args):
    fault_reports = []

    f_bin = open(args.filename, "rb")
    elf = ELFFile(f_bin)
    meminfo = pandas.read_hdf(args.hdf, "/Goldenrun/meminfo")
    tbexeclist = pandas.read_hdf(args.hdf, "/Goldenrun/tbexeclist")
    tbinfo = pandas.read_hdf(args.hdf, "/Goldenrun/tbinfo")
    hdf_file = h5py.File(args.hdf, "r")
    fault_dict = None

    if args.accurate:
        fault_dict = dict()
        for experiment_id in hdf_file["fault/"].keys():
            faults = hdf_file[f"fault/{experiment_id}/faults"]
            fault_address = faults["fault_address"][0]

            if args.success and faults.attrs["end_reason"].decode() not in [
                f"endpoint {int(success, 0)}/1" for success in args.success
            ]:
                continue  # filter out unsuccessful experiments
            if fault_address in fault_dict:
                fault_dict[fault_address].append(experiment_id)
            else:
                fault_dict[fault_address] = [experiment_id]
    hdf_file.close()

    instruction_ops, instructions = util.load_instruction_ops(elf)
    ddg = DataDependencyAnalysis(instruction_ops, tbexeclist, tbinfo, meminfo)

    basic_blocks = dict()
    postorders = dict()
    functions = list(util.get_functions(elf))
    for function in functions:
        _basic_blocks = util.find_basic_blocks(
            instruction_ops, function.start_address, function.end_address
        )
        if not _basic_blocks:
            continue
        basic_blocks |= _basic_blocks

        postorders[function.start_address] = []
        util.build_cfg(
            basic_blocks,
            basic_blocks[function.start_address],
            function,
            [],
            postorders[function.start_address],
        )

    for target_address in args.address:
        target_address = int(target_address, 0)

        function = next(
            filter(
                lambda f: f.start_address <= target_address
                and f.end_address >= target_address,
                functions,
            )
        )

        affected_branches = None
        if args.accurate:
            affected_branches = util.find_affected_branches(
                tbexeclist, basic_blocks, fault_dict, args.hdf, target_address
            )

        if (
            report := check_cfi(basic_blocks, instruction_ops, function, target_address)
        ) != None:
            fault_reports.append(report)
            continue
        if (
            report := check_li(
                basic_blocks, instruction_ops, ddg, affected_branches, target_address
            )
        ) != None:
            fault_reports.append(report)
            continue
        if (
            report := check_ite(
                basic_blocks,
                instruction_ops,
                function,
                ddg,
                postorders[function.start_address],
                affected_branches,
                target_address,
            )
        ) != None:
            if report.category == util.FaultCategory.UNKNOWN:
                report = check_branch_intervention(
                    report, ddg, instruction_ops, target_address
                )
            fault_reports.append(report)
            continue
        if (report := check_branch(instruction_ops, target_address)) != None:
            fault_reports.append(report)
            continue

        fault_reports.append(
            util.FaultReport(target_address, util.FaultCategory.UNKNOWN)
        )

    log_results(fault_reports, elf, ddg, instruction_ops, instructions, args)

    f_bin.close()

    return fault_reports


def main():
    parser = argparse.ArgumentParser(
        prog="Fault Categorizer",
        description="Categorizes discovered faults and suggests fixes",
    )

    parser.add_argument("filename", help="Path to the binary to be analyzed")
    parser.add_argument(
        "hdf",
        help="Path to the hdf5 file generated by ARCHIE (meminfo logging needs to be enabled)",
    )
    parser.add_argument(
        "-a",
        "--address",
        help="Address(es) of skipped instruction(s) that caused an exploitable fault",
        nargs="+",
        required=True,
    )
    parser.add_argument(
        "-s",
        "--success",
        help="Address(es) that define a successful fault attack once reached",
        nargs="+",
        required=False,
    )
    parser.add_argument(
        "--accurate",
        help="Accurate analysis of branch affecting faults. Needs the ring buffer in ARCHIE to be disabled since it uses the execution trace to identify the affected branch. If disabled this tool will generate reports for every branch that might be affected.",
        action="store_true",
    )
    parser.add_argument(
        "--output",
        help="Output analysis results in json format",
        choices=["h", "json", "sarif"],
        default="h",
        required=False,
    )

    args = parser.parse_args()

    faults = categorize_faults(args)


if __name__ == "__main__":
    main()
