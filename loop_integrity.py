import util
from pypcode.pypcode_native import OpCode as OpCode, Instruction, Address

def find_loop_blocks(basic_blocks, current, head, discovered=set(())):
    if current in discovered:
        return set(())
    discovered.add(current)

    if head.start_address == current.start_address:
        return discovered

    for pred in current.predecessors:
        discovered = find_loop_blocks(basic_blocks, pred, head, discovered).union(discovered)
         
    return discovered

def is_in_loop(loop_blocks, address):
    for bb in loop_blocks:
        if address >= bb.start_address and address <= bb.end_address:
            return True

    return False

def check_li(basic_blocks, ddg, idoms, start_address, target_address):
    for bb in basic_blocks.values():
        back_edge_head = [successor for successor in bb.successors if bb.discovered_index >= successor.discovered_index]
        if len(back_edge_head) != 1:
            continue

        # print(f"Found back edge from {hex(bb.start_address)} to {hex(back_edge_head[0].start_address)}")

        if not util.dominates(back_edge_head[0].start_address, bb.start_address, start_address, idoms):
            continue

        loop_blocks = find_loop_blocks(basic_blocks, bb, back_edge_head[0], set(()))

        for loop_block in loop_blocks:
            address, ops = sorted(loop_block.instructions.items())[-1]
            last_op = ops[-1]

            if (last_op.opcode == OpCode.BRANCH or last_op.opcode == OpCode.CBRANCH) and (not is_in_loop(loop_blocks, last_op.inputs[0].offset) or not is_in_loop(loop_blocks, loop_block.end_address + 1)):
                if address == target_address:
                    return util.FaultReport(target_address, util.FaultCategory.LI_1)

                #print('Found unfaulted branch, checking if affected')

                if last_op.opcode == OpCode.CBRANCH:
                    dependencies = ddg.find_dependencies(address)
                    if target_address in map(lambda node: node.insn_addr, dependencies):
                        return util.FaultReport(target_address, util.FaultCategory.LI_2, affected_branches=[node.insn_addr])

    return None
