#!/bin/env python3

from pypcode import Context, PcodePrettyPrinter
from pypcode.pypcode_native import OpCode as OpCode, Instruction, Address
import argparse
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section
from elftools.elf.segments import Segment

from loop_integrity import check_li
from ite import check_ite
from misc import check_branch, check_branch_intervention
import util

import pandas
import h5py
import jsonpickle

from data_dependency_analysis import DataDependencyAnalysis
from countermeasures import get_countermeasure, get_rules

def check_cfi(basic_blocks, instructions, elf, target_address):
    fault_category = None
    ops = instructions[target_address]
    if any(op.opcode == OpCode.CALL for op in ops):
        fault_category = util.FaultCategory.CFI_1

    bb = basic_blocks[max(basic_blocks)]
    if ops[-1].opcode == OpCode.RETURN:
        if max(bb.instructions) == target_address:
            fault_category = util.FaultCategory.CFI_2
        else:
            fault_category = util.FaultCategory.CFI_3

    if ops[-1].opcode == OpCode.BRANCH and max(bb.instructions) == target_address:
        fault_category = util.FaultCategory.CFI_4

    if fault_category:
        return util.FaultReport(target_address, fault_category)

def log_results(fault_reports, elf, ddg, instructions, args):
    for report in fault_reports:
        if args.countermeasures:
            report.set_countermeasure(get_countermeasure(report, not args.accurate))
        source = util.decode_file_line(elf.get_dwarf_info(), report.fault_address)
        if source != (None, None):
            source = { 'filename': source[0].decode(), 'line': source[1] }
            report.set_source(source)
        if report.affected_branches == None:
            continue
        for i, address in enumerate(report.affected_branches):
            source = util.decode_file_line(elf.get_dwarf_info(), address)
            if source != (None, None):
                source = { 'filename': source[0].decode(), 'line': source[1] }
                report.affected_branches[i] = { 'address': report.affected_branches[i], 'source': source }

    if args.output == 'json':
        print(jsonpickle.encode(fault_reports, unpicklable=False))
        return

    if args.output == 'sarif':
        sarif_report = dict()
        sarif_report['$schema'] = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json'
        sarif_report['version'] = '2.1.0'
        sarif_report['runs'] = [{
            'tool': {
                'driver': {
                    'name': 'Fault Analysis',
                    'informationUri': 'https://github.com/ks0777/fault_categorizer',
                    'version': '1.0',
                    'rules': get_rules()
                }
            },
            'results': [
                {
                    'ruleId': report.category,
                    'message': { 'text': (report.countermeasure if report.countermeasure else '') },
                    'locations': [
                        {
                            'physicalLocation': {
                                'artifactLocation': {
                                    'uri': report.source['filename']
                                },
                                'region': {
                                    'startLine': report.source['line']
                                }
                            }
                        } 
                    ] + ([
                        {
                            'physicalLocation': {
                                'artifactLocation': {
                                    'uri': affected_branch['source']['filename']
                                },
                                'region': {
                                    'startLine': affected_branch['source']['line']
                                }
                            }
                        }
                    for affected_branch in report.affected_branches] if report.affected_branches != None else [] )
                }
            for report in fault_reports]
        }]

        print(jsonpickle.encode(sarif_report, unpicklable=False))
        return


    for report in fault_reports:
        if report.source != None:
            print(f"Skipped instruction at {hex(report.fault_address)} ({report.source['filename']}:{report.source['line']}) caused fault of type {report.category}")
        else:
            print(f"Skipped instruction at {hex(report.fault_address)} caused fault of type {report.category}")
        if report.affected_branches:
            if len(report.affected_branches) == 1:
                branch = report.affected_branches[0]
                source = branch['source']
                print(f"\tFault affected branch at {hex(branch['address'])}", end='')
                if branch['source'] != None:
                    print(f" ({source['filename']}:{source['line']})", end='')
                print('')
            else:
                print(f"\tFault {'affects' if args.accurate else 'MIGHT have affected'} multiple branches at:")
                for branch in report.affected_branches:
                    source = branch['source']
                    if source != None:
                        print(f"\t\t{hex(branch['address'])} ({source['filename']}:{source['line']})")
                    print('')

        if report.category == util.FaultCategory.UNKNOWN:
            print(f"\tUnable to detect how the skipped instruction influences the control flow. The instruction affects the following instructions: ")
            dependents = ddg.find_dependents(report.fault_address)
            affects_store_op = False
            for dep in dependents:
                print(f"\t\t{str(dep)}")
                for op in instructions[dep.insn_addr]:
                    if op.opcode == OpCode.STORE:
                        affects_store_op = True
                        break

            if affects_store_op:
                print('\tThe skipped instruction affects a store instruction. If the target is inside device memory the analysis can not continue because of insufficient log data.')

        if report.countermeasure:
            print(report.countermeasure)

        print('')


def categorize_faults(args):
    fault_reports = []

    f_bin = open(args.filename, 'rb')
    elf = ELFFile(f_bin)
    meminfo = pandas.read_hdf(args.hdf, '/Goldenrun/meminfo')
    tbexeclist = pandas.read_hdf(args.hdf, '/Goldenrun/tbexeclist')
    tbinfo = pandas.read_hdf(args.hdf, '/Goldenrun/tbinfo')
    hdf_file = h5py.File(args.hdf, 'r')
    fault_dict = None

    if args.accurate:
        fault_dict = dict()
        for experiment_id in hdf_file['fault/'].keys():
            faults = hdf_file[f'fault/{experiment_id}/faults']
            fault_address = faults['fault_address'][0]
            if fault_address in fault_dict:
                fault_dict[fault_address].append(experiment_id)
            else:
                fault_dict[fault_address] = [experiment_id]
    hdf_file.close()


    instructions = util.load_instructions(elf)
    ddg = DataDependencyAnalysis(instructions, tbexeclist, tbinfo, meminfo)

    for target_address in args.address:
        target_address = int(target_address, 0)

        function = util.find_function_by_address(elf, target_address)
        basic_blocks = util.find_basic_blocks(instructions, function.start_address, function.end_address)

        postorder = []
        util.build_cfg(basic_blocks, basic_blocks[function.start_address], function, [], postorder) 

        if args.accurate:
            affected_branches = util.find_affected_branches(tbexeclist, basic_blocks, fault_dict, args.hdf, target_address)

        if (report := check_cfi(basic_blocks, instructions, elf, target_address)) != None:
            fault_reports.append(report)
            continue
        if (report := check_li(basic_blocks, instructions, ddg, affected_branches, target_address)) != None:
            fault_reports.append(report)
            continue
        if (report := check_ite(basic_blocks, instructions, function, ddg, postorder, affected_branches, target_address)) != None:
            if report.category == util.FaultCategory.ITE_3:
                report = check_branch_intervention(report, instructions, target_address)
            fault_reports.append(report)
            continue
        if (report:= check_branch(instructions, target_address)) != None:
            fault_reports.append(report)
            continue

        fault_reports.append(util.FaultReport(target_address, util.FaultCategory.UNKNOWN))

    log_results(fault_reports, elf, ddg, instructions, args)

    f_bin.close()

    return fault_reports

def main():
    parser = argparse.ArgumentParser(
        prog='Fault Categorizer',
        description='Categorizes discovered faults and suggests fixes'
    )

    parser.add_argument('filename',
        help='Path to the binary to be analyzed')
    parser.add_argument('hdf',
        help='Path to the hdf5 file generated by ARCHIE (meminfo logging needs to be enabled)')
    parser.add_argument('-a', '--address',
        help='Address of skipped instruction that caused an exploitable fault',
        nargs='+',
        required=True
    )
    parser.add_argument('-c', '--countermeasures',
        help='Suggest software-based countermeasures against discovered faults',
        action='store_true'
    )
    parser.add_argument('--accurate',
        help='Accurate analysis of branch affecting faults. Needs the ring buffer in ARCHIE to be disabled since it uses the execution trace to identify the affected branch. If disabled this tool will generate reports for every branch that might be affected.',
        action='store_true'
    )
    parser.add_argument('--output',
        help='Output analysis results in json format',
        choices=['h', 'json', 'sarif'],
        default='h',
        required=False
    )

    args = parser.parse_args()

    faults = categorize_faults(args)


if __name__ == '__main__':
    main()
