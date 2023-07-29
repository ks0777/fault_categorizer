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
import networkx as nx
import matplotlib.pyplot as plt

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

def search_deps2(project, view_item, function_scope, deps, visited_locs=[], ignore_regs=[]):
    stmt = project.factory.block(view_item._variable.location.block_addr).vex.statements[view_item._variable.location.stmt_idx]
    if (stmt.tag == 'Ist_WrTmp' and stmt.data.tag == 'Iex_Get' and stmt.data.offset in ignore_regs):
        print('ignored reg')
        return False

    locs_str = str(view_item._variable.location)
    if locs_str in visited_locs:
        return False

    visited_locs.append(locs_str)

    dependencies = view_item.depends_on

    if stmt.tag == 'Ist_WrTmp' and stmt.data.tag == 'Iex_ITE':
        cond = next(filter(lambda dep: dep._variable.variable.tmp_id == stmt.data.cond.tmp, dependencies))
        if not search_deps2(project, cond, function_scope, deps, visited_locs=visited_locs, ignore_regs=ignore_regs):
            stmt.pp()
            print('ignoring dep because condition depends on ignored')
            if isinstance(stmt.data.iftrue, pyvex.expr.Const):
                return True
            iftrue = next(filter(lambda dep: dep._variable.variable.tmp_id == stmt.data.iftrue.tmp, dependencies))
            return search_deps2(project, iftrue, function_scope, deps, visited_locs=visited_locs, ignore_regs=ignore_regs)

    if len(dependencies) == 0:
        deps.add(view_item._variable.location.ins_addr)
        return True

    real_dep = False

    for dep in dependencies:
        addr = dep._variable.location.ins_addr
        if not addr_in_range(addr, function_scope[0], function_scope[1]):
            print('out of scope')
            real_dep = True
            continue

        real_dep |= search_deps2(project, dep, function_scope, deps, visited_locs=visited_locs, ignore_regs=ignore_regs)

    if real_dep:
        stmt.pp()
        print('is real dependency')
        deps.add(view_item._variable.location.ins_addr)
        
    return real_dep

def build_graph(project, view_item, function_scope, G, parent_node=None):
    stmt = project.factory.block(view_item._variable.location.block_addr).vex.statements[view_item._variable.location.stmt_idx]
    locs_str = str(view_item._variable.location)
    if locs_str in G.nodes:
        G.add_edge(parent_node, locs_str)
        return False

    G.add_node(locs_str)
    if parent_node != None:
        G.add_edge(parent_node, locs_str)

    for dep in view_item.depends_on:
        addr = dep._variable.location.ins_addr
        if not addr_in_range(addr, function_scope[0], function_scope[1]):
            continue

        build_graph(project, dep, function_scope, G, locs_str)

def plot_graph(G):
    nx.draw_networkx(G)
    plt.show()


def search_deps3(project, cfg, target_address):
    function_scope = find_function_by_address(cfg, target_address)

    function = cfg.kb.functions[function_scope[0]]
    reaching_defs = project.analyses.ReachingDefinitions(function, observe_all=True, dep_graph=True, track_tmps=True, max_iterations=10)
    idk = reaching_defs.get_reaching_definitions_by_insn(target_address, OP_BEFORE)

    deps = set(())
    for tmp in idk.tmps.values():
        for _def in tmp:
            deps.add(_def.codeloc.ins_addr)
            #for __def in _def:

    for dep in deps:
        print(hex(dep))

    print(len(deps))
    return list(deps)

    """
    """

def check_li(ops, project, cfg, ddg, target_address, ignore_regs):
    function_scope = find_function_by_address(cfg, target_address)

    function = cfg.kb.functions[function_scope[0]]
    loop_finder = project.analyses.LoopFinder([function])

    for loop in loop_finder.loops:

        if (ops[-1].opcode == OpCode.CBRANCH or ops[-1].opcode == OpCode.BRANCH) and any([addr_in_node(target_address, edge[0]) for edge in loop.break_edges + loop.continue_edges]):
            return True

        loop_branch_addrs = set(())
        loop_branch_addrs.add(0x8000059)

        for edge in loop.break_edges + loop.continue_edges:
            head, tail = edge
            cfg_node = cfg._nodes_by_addr[head.addr][0]
            print(hex(cfg_node.addr))
            vex_block = project.factory.block(
                cfg_node.addr, size=cfg_node.size
            ).vex
            stmt = vex_block.statements[-1]
            if isinstance(stmt, pyvex.IRStmt.Exit):
                loop_branch_addrs.add(cfg_node.instruction_addrs[-1]) 
            else:
                print('Non exit statement found at end of break/continue node, should there be one?')

        for addr in loop_branch_addrs: 
            print('huh?', hex(addr))
            """
            depends_on = search_deps3(project, cfg, addr)
            """
            view_instr = ddg.view[addr]

            #depends_on = set(())
            #search_deps(project, view_instr.definitions, function_scope, depends_on, ignore_regs=ignore_regs)
            #depends_on = search_deps3(project, cfg, addr)
            #print(hex(addr), [f"{hex(x)}" for x in iter(depends_on)])
            deps = set(())

            for v in view_instr.definitions:
                search_deps2(project, v, function_scope, deps, visited_locs=[], ignore_regs=ignore_regs)

            for x in deps:
                print(hex(x))

            if target_address in deps or (isinstance(project.arch, archinfo.ArchARM) and target_address + 1 in deps):
                return True

    return False

def check_cond(project, cfg, ddg, target_address, ignore_regs):
    return False
    function_scope = find_function_by_address(cfg, target_address)
    function = cfg.kb.functions[function_scope[0]]

    for block in function.blocks:
        stmt = block.vex.statements[-1]
        if not isinstance(stmt, pyvex.IRStmt.Exit):
            continue

        if block.instruction_addrs[-1] == target_address:
            return True

        view_instr = ddg.view[block.instruction_addrs[-1]]

        depends_on = set(())
        search_deps(project, view_instr.definitions, function_scope, depends_on, [], ignore_regs=ignore_regs)
        print(hex(block.instruction_addrs[-1]), [f"{hex(x)}" for x in iter(depends_on)])

        if target_address in depends_on or (isinstance(project.arch, archinfo.ArchARM) and target_address - 1 in depends_on):
            continue
            return True

    return False


def categorize_faults(args):
    faults = []

    project = angr.Project(args.filename, load_options={'auto_load_libs': False})
    cfg_emulated = project.analyses.CFGEmulated(keep_state=True, state_add_options=angr.options.refs, iropt_level=0)
    #cfg = project.analyses.CFG()
    #plot_cfg(cfg_emulated, "aaaaah", asminst=True, remove_imports=True, remove_path_terminator=True)
    ddg = project.analyses.DDG(cfg_emulated)
    print(len(ddg.graph.edges), len(ddg.graph.nodes))
    #ddg = ddg.simplified_data_graph
    #plot_ddg_stmt(ddg.graph, "ahhhh_ddg_stmt", project=project)

    _regs = project.arch.registers
    ignore_regs = [_regs['itstate'][0]]

    project.factory.block(0x8000061).vex.pp()
    deps=set(())
    view_items = ddg.view[0x800007b].definitions
    print([v._variable.location.stmt_idx for v in view_items])
    for x in view_items:
        if x._variable.location.stmt_idx == 503:
            view_item = x
    function_scope = find_function_by_address(cfg_emulated, 0x8000059)
    search_deps2(project, view_item, function_scope, deps, ignore_regs=ignore_regs)
    import code
    import readline
    import rlcompleter
               
    vars = globals()
    vars.update(locals())
                                                  
    readline.set_completer(rlcompleter.Completer(vars).complete)
    readline.parse_and_bind("tab: complete")
    code.InteractiveConsole(vars).interact()


    for target_address in args.address:
        target_address = int(target_address, 0)
        ops = get_pcode(project, target_address, max_instructions=1)

        fault_category = FaultCategory.UNKNOWN

        if check_cfi(ops, cfg_emulated, target_address):
            fault_category = FaultCategory.CFI
        elif check_li(ops, project, cfg_emulated, ddg, target_address, ignore_regs):
            fault_category = FaultCategory.LI
        elif check_cond(project, cfg_emulated, ddg, target_address, ignore_regs):
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
