import util
from pypcode.pypcode_native import OpCode as OpCode, Instruction, Address

def check_ite(instructions, ddg, target_address):

    last_op = instructions[target_address][-1]
    if last_op.opcode == OpCode.BRANCH and last_insn_address == target_address:
        return util.FaultCategory.ITE_1 # We skipped a branch instruction in the ITE construction and wrongfully executed the else part.

    if last_op.opcode == OpCode.CBRANCH and last_insn_address == target_address:
        return util.FaultCategory.ITE_2 # We skipped the conditional branch and executed secured code instead of the insecure default

    dependents = ddg.find_dependents(target_address)
    for node in dependents:
        ops = instructions[node.insn_addr]
        if ops[-1].opcode == OpCode.CBRANCH:
            return util.FaultCategory.ITE_3 # We skipped an instruction that affects the conditional branch of the ITE construction

    return None
