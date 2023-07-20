#!/bin/env python3

from pypcode import Context, PcodePrettyPrinter
from pypcode.pypcode_native import OpCode as OpCode, Instruction, Address
import argparse
from enum import Enum
import angr
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER, ObservationPointType
import pyvex
from angrutils import *
import archinfo

from util import extract_pcode_from_elf, find_function_by_address, addr_in_range, addr_in_node, get_pcode

class FaultCategory(Enum):
    UNKNOWN = 0
    CFI = 1
    LI = 2
    ITE = 3

def check_cfi(ops, cfg, target_address):
    if any(op.opcode == OpCode.CALL for op in ops):
        return True

    function_scope = find_function_by_address(cfg, target_address)

    return any(op.opcode == OpCode.RETURN for op in ops) and function_scope[1] == target_address

"""
# Searches for all instructions that the given instructions depends on. Will ignore paths that end in a GET of a register specified in ignore_regs (Needed for itstate, and dep registers)
def search_deps(project, dependencies, function_scope, depends_on, visited_locs=[], ignore_regs=[]):
    #print(dependencies)
    real_dep = len(dependencies) == 0
    for dep in dependencies:
        locs_str = str(dep._variable.location)
        if locs_str in visited_locs:
            continue
        visited_locs.append(locs_str)
        addr = dep._variable.location.ins_addr
        if addr_in_range(addr, function_scope[0], function_scope[1]):
            stmt = project.factory.block(dep._variable.location.block_addr).vex.statements[dep._variable.location.stmt_idx]
            if (stmt.tag != 'Ist_WrTmp' or stmt.data.tag != 'Iex_Get' or stmt.data.offset not in ignore_regs) and search_deps(project, dep.depends_on, function_scope, depends_on, visited_locs, ignore_regs):
                depends_on.add(addr)
                real_dep = True
            else:
                print('found ignored reg')
                continue
        else:
            print('!!! reached out of scope!')
            real_dep = True


    print('returning', real_dep)
    return real_dep
"""

def search_deps(project, cfg, target_address):
    function_scope = find_function_by_address(cfg, target_address)

    function = cfg.kb.functions[function_scope[0]]
    reaching_defs = project.analyses.ReachingDefinitions(function, observe_all=True, dep_graph=True, track_tmps=True, max_iterations=10)
    idk = reaching_defs.get_reaching_definitions_by_insn(target_address, OP_BEFORE)

    deps = set(())
    for tmp in idk.tmps.values():
        for _def in tmp:
            deps.add(_def.codeloc.ins_addr)

    return deps


def check_li(ops, project, cfg, target_address):
    function_scope = find_function_by_address(cfg, target_address)

    function = cfg.kb.functions[function_scope[0]]
    loop_finder = project.analyses.LoopFinder([function])

    for loop in loop_finder.loops:

        if (ops[-1].opcode == OpCode.CBRANCH or ops[-1].opcode == OpCode.BRANCH) and any([addr_in_node(target_address, edge[0]) for edge in loop.break_edges + loop.continue_edges]):
            return True

        loop_branch_addrs = set(())

        for edge in loop.break_edges + loop.continue_edges:
            head, tail = edge
            cfg_node = cfg._nodes_by_addr[head.addr][0]
            vex_block = project.factory.block(
                cfg_node.addr, size=cfg_node.size
            ).vex
            stmt = vex_block.statements[-1]
            if isinstance(stmt, pyvex.IRStmt.Exit):
                loop_branch_addrs.add(cfg_node.instruction_addrs[-1]) 
            else:
                print('Non exit statement found at end of break/continue node, should there be one?')

        for addr in loop_branch_addrs: 
            depends_on = search_deps(project, cfg, addr)

            if target_address in depends_on or (isinstance(project.arch, archinfo.ArchARM) and target_address + 1 in depends_on):
                return True

    return False

def check_cond(project, cfg, target_address):
    function_scope = find_function_by_address(cfg, target_address)
    function = cfg.kb.functions[function_scope[0]]

    for block in function.blocks:
        stmt = block.vex.statements[-1]
        if not isinstance(stmt, pyvex.IRStmt.Exit):
            continue

        branch_addr = block.instruction_addrs[-1]

        if branch_addr == target_address:
            return True

        depends_on = search_deps(project, cfg, branch_addr)

        if target_address in depends_on or (isinstance(project.arch, archinfo.ArchARM) and target_address + 1 in depends_on):
            return True

    return False


def categorize_faults(args):
    faults = []

    project = angr.Project(args.filename, load_options={'auto_load_libs': False})
    cfg = project.analyses.CFG()

    for target_address in args.address:
        target_address = int(target_address, 0)
        ops = get_pcode(project, target_address, max_instructions=1)

        fault_category = FaultCategory.UNKNOWN

        if check_cfi(ops, cfg, target_address):
            fault_category = FaultCategory.CFI
        elif check_li(ops, project, cfg, target_address):
            fault_category = FaultCategory.LI
        elif check_cond(project, cfg, target_address):
            fault_category = FaultCategory.ITE

        faults.append([target_address, fault_category])

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
