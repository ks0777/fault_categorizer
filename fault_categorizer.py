#!/bin/env python3

from pypcode import Context, PcodePrettyPrinter
from pypcode.pypcode_native import OpCode as OpCode, Instruction, Address
import argparse
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section
from elftools.elf.segments import Segment
from enum import Enum

from loop_integrity import check_li

from util import extract_pcode_from_elf, find_function_by_address

class FaultCategory(Enum):
    UNKNOWN = 0
    CFI = 1
    LI = 2

def check_cfi(ops, elf, target_address):
    if any(op.opcode == OpCode.CALL for op in ops):
        return True

    f = find_function_by_address(elf, target_address)

    return any(op.opcode == OpCode.RETURN for op in ops) and f[2] == target_address

def categorize_faults(args):
    faults = []

    f = open(args.filename, 'rb')
    elf = ELFFile(f)

    for target_address in args.address:
        target_address = int(target_address, 16)
        ops = extract_pcode_from_elf(elf, target_address, max_instructions=1)

        fault_category = FaultCategory.UNKNOWN

        if check_cfi(ops, elf, target_address):
            fault_category = FaultCategory.CFI
        elif check_li(ops, elf, target_address):
            fault_category = FaultCategory.LI

        faults.append([target_address, fault_category])

    f.close()

    return faults

def main():
    parser = argparse.ArgumentParser(
            prog='Fault Categorizer',
            description='Categorizes discovered faults and suggests fixes'
            )

    parser.add_argument('filename',
                        help='Path to the binary to be analyzed')
    parser.add_argument('-a', '--address',
                        help='Address of skipped instruction that caused an exploitable fault',
                        nargs='+',
                        required=True)

    args = parser.parse_args()


    faults = categorize_faults(args)

    for [address, category] in faults:
        print(f"Fault at {hex(address)} is of type {category}")


if __name__ == '__main__':
    main()
