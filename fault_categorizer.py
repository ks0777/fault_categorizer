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

from data_dependency_analysis import DataDependencyAnalysis
from countermeasures import get_countermeasure

def check_cfi(instructions, elf, target_address):
    ops = instructions[target_address]
    if any(op.opcode == OpCode.CALL for op in ops):
        return True

    f = util.find_function_by_address(elf, target_address)

    return any(op.opcode == OpCode.RETURN for op in ops)

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

        if check_cfi(instructions, elf, target_address):
            fault_report = util.FaultReport(target_address, util.FaultCategory.CFI)
            fault_reports.append(fault_report)
            continue

        function = util.find_function_by_address(elf, target_address)
        basic_blocks = util.find_basic_blocks(instructions, function.start_address, function.end_address)

        postorder = []
        util.build_cfg(basic_blocks, basic_blocks[function.start_address], [], postorder) 

        idoms = util.find_dominators(basic_blocks, basic_blocks[function.start_address], postorder)

        if (report := check_li(basic_blocks, ddg, idoms, function.start_address, target_address)) != None:
            fault_reports.append(report)
            continue
        if (report := check_ite(basic_blocks, instructions, function, ddg, postorder, tbexeclist, fault_dict, args.hdf, target_address)) != None:
            if report.category == util.FaultCategory.ITE_3:
                report = check_branch_intervention(report, instructions, target_address)
            fault_reports.append(report)
            continue
        if (report:= check_branch(instructions, target_address)) != None:
            fault_reports.append(report)
            continue

        fault_reports.append(util.FaultReport(target_address, util.FaultCategory.UNKNOWN))

    for report in fault_reports:
        source_line = util.decode_file_line(elf.get_dwarf_info(), report.fault_address)
        if source_line[0] != None:
            print(f"Skipped instruction at {hex(report.fault_address)} ({source_line[0].decode()}:{source_line[1]}) caused fault of type {report.category}")
        else:
            print(f"Skipped instruction at {hex(report.fault_address)} caused fault of type {report.category}")
        if report.affected_branches:
            if len(report.affected_branches) == 1:
                source_line = util.decode_file_line(elf.get_dwarf_info(), report.affected_branches[0])
                print(f"\tFault affected branch at {hex(report.affected_branches[0])} ({source_line[0].decode()}:{source_line[1]})")
            else:
                print(f"\tFault {'affects' if args.accurate else 'MIGHT have affected'} multiple branches at:")
                for branch_address in report.affected_branches:
                    source_line = util.decode_file_line(elf.get_dwarf_info(), branch_address)
                    print(f"\t\t{hex(branch_address)} ({source_line[0].decode()}:{source_line[1]})")

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

        if args.countermeasures:
            print(get_countermeasure(report, not args.accurate))

        print('')

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

    args = parser.parse_args()

    faults = categorize_faults(args)


if __name__ == '__main__':
    main()
