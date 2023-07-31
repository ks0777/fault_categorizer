import util
from pypcode.pypcode_native import OpCode as OpCode, Instruction, Address

def check_ite(basic_blocks, meminfo, idoms, start_address, target_address):

    for bb in basic_blocks.values():
        last_insn_address = max(bb.instructions)
        last_op = bb.instructions[last_insn_address][-1]
        if last_op.opcode == OpCode.BRANCH and last_insn_address == target_address:
            return util.FaultCategory.ITE_1 # We skipped a branch instruction in the ITE construction and wrongfully executed the else part.

        if last_op.opcode == OpCode.CBRANCH:
            if last_insn_address == target_address:
                return util.FaultCategory.ITE_2 # We skipped the conditional branch and executed secured code instead of the insecure default

            condition_nodes = [last_op.inputs[1].offset]
            if util.affects_condition(bb, target_address, condition_nodes, meminfo, []):
                return util.FaultCategory.ITE_3 # We skipped an instruction that affects the conditional branch of the ITE construction

    return None
