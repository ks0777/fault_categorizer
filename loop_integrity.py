import util
from pypcode.pypcode_native import OpCode as OpCode, Instruction, Address

from loop_analysis import LoopFinder 

def check_li(basic_blocks, instructions, ddg, affected_branches, target_address):
    loop_finder = LoopFinder(basic_blocks)
    if instructions[target_address][-1].opcode in [OpCode.CBRANCH, OpCode.BRANCH]:
        for loop in loop_finder.loops:
            if target_address in map(lambda edge: max(edge[0].instructions), loop.entry_edges):
                return util.FaultReport(target_address, util.FaultCategory.LI_1)
            if target_address in map(lambda edge: max(edge[0].instructions), loop.continue_edges):
                return util.FaultReport(target_address, util.FaultCategory.LI_2)
            if target_address in map(lambda edge: max(edge[0].instructions), loop.break_edges):
                return util.FaultReport(target_address, util.FaultCategory.LI_3)
        return None


    if affected_branches == None:
        dependents = ddg.find_dependents(target_address)
        dependent_branch_addresses = list(map(lambda node: node.insn_addr, filter(lambda node: instructions[node.insn_addr][-1].opcode == OpCode.CBRANCH, dependents)))

        if len(dependent_branch_addresses) > 1:
            return None

        affected_branches = dependent_branch_addresses

    for address in affected_branches:
        for loop in loop_finder.loops:
            if address in map(lambda edge: max(edge[0].instructions), loop.entry_edges):
                return util.FaultReport(target_address, util.FaultCategory.LI_4, affected_branches=affected_branches)
            if address in map(lambda edge: max(edge[0].instructions), loop.continue_edges):
                return util.FaultReport(target_address, util.FaultCategory.LI_5, affected_branches=affected_branches)
            if address in map(lambda edge: max(edge[0].instructions), loop.break_edges):
                return util.FaultReport(target_address, util.FaultCategory.LI_6, affected_branches=affected_branches)
        
