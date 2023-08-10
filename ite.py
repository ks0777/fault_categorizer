import util
from pypcode.pypcode_native import OpCode as OpCode, Instruction, Address

class IfThen:
    def __init__(self, condition_blocks = [], then_blocks = []):
        self.condition_blocks = condition_blocks
        self.then_blocks = then_blocks

    def __repr__(self):
        return f"Condition(s): {[hex(bb.start_address) for bb in self.condition_blocks]}\nThen Block(s): {[hex(bb.start_address) for bb in self.then_blocks]}\n"

class IfThenElse:
    def __init__(self, condition_blocks = [], then_blocks = [], else_blocks = []):
        self.condition_blocks = condition_blocks
        self.then_blocks = then_blocks
        self.else_blocks = else_blocks

    def __repr__(self):
        return f"Condition(s): {[hex(bb.start_address) for bb in self.condition_blocks]}\nElse Block(s): {[hex(bb.start_address) for bb in self.else_blocks]}\nThen Block(s): {[hex(bb.start_address) for bb in self.then_blocks]}\n"


"""
Checks whether the branching instruction is part of an if-then or if-then-else construct
@param bb: Basic block containing the conditional branch of the construct
"""
def identify_constructs(basic_blocks, function, postorder):
    constructs = []
    all_condition_blocks = []

    for start_address in postorder:
        bb = basic_blocks[start_address]
        # Check if basic block is at the end of an IT(E) construct. It will have two predecessors in that case
        if len(bb.predecessors) >= 2:
            all_preds = sorted([util.get_predecessors(predecessor, function).union([predecessor]) for predecessor in bb.predecessors], key=lambda preds: len(preds))
            shortest_path = all_preds[0]
            longest_path = all_preds[-1]

            if set().union(*all_preds[1:]) != longest_path:
                continue

            # Intersection returns all blocks before the body. The last block is the condition
            pre_body_blocks = shortest_path & longest_path

            condition_blocks = [sorted(pre_body_blocks)[-1]]

            # If condition is already part of an IT(E) we identified it cant be part of another one with a smaller scope
            if condition_blocks[0] in all_condition_blocks:
                continue

            # If the shortest path is a subset of the longest path we do not have an else part
            if len(shortest_path - longest_path) == 0:
                then_blocks = longest_path - pre_body_blocks
                then_head = sorted(then_blocks)[0]

                # Follow up sequence of blocks that only have a single predecessor and have the body of the construct as a successor.
                # Needed to make sure conditions consisting of multiple parts that are connected through logical operations are also inluded.
                head = condition_blocks[0]
                while len(head.predecessors) == 1 and then_head in head.predecessors[0].successors:
                    head = head.predecessors[0]
                    condition_blocks.append(head)

                all_condition_blocks += condition_blocks

                constructs.append(IfThen(condition_blocks, then_blocks))
            else:
                # then and else might be mixed up but it does not matter for this purpose
                then_blocks = longest_path - pre_body_blocks
                else_blocks = shortest_path - pre_body_blocks
                then_head = sorted(then_blocks)[0]
                else_head = sorted(else_blocks)[0]

                # Follow up sequence of blocks that only have a single predecessor and have the body of the construct as a successor.
                # Needed to make sure conditions consisting of multiple parts that are connected through logical operations are also inluded.
                head = condition_blocks[0]
                while len(head.predecessors) == 1 and then_head in head.predecessors[0].successors and else_head in head.predecessors[0].successors:
                    head = head.predecessors[0]
                    condition_blocks.append(head)

                all_condition_blocks += condition_blocks

                constructs.append(IfThenElse(condition_blocks, then_blocks, else_blocks))
        elif bb.instructions[max(bb.instructions)][-1].opcode == OpCode.RETURN:
            for immediate_pred in sorted(bb.predecessors)[::-1]:
                pred_head = immediate_pred
                then_blocks = [bb]
                while len(pred_head.successors) == 1:
                    then_blocks.append(pred)

                condition_blocks = [pred_head]

                if condition_blocks == None:
                    continue

                # If condition is already part of an IT(E) we identified it cant be part of another one with a smaller scope
                if condition_blocks[0] in all_condition_blocks:
                    continue

                head = condition_blocks[0]
                while len(head.predecessors) == 1 and bb in head.predecessors[0].successors:
                    head = head.predecessors[0]
                    condition_blocks.append(head)

                all_condition_blocks += condition_blocks

                constructs.append(IfThen(condition_blocks, then_blocks))

    return constructs


def check_ite(basic_blocks, instructions, function, ddg, postorder, target_address):
    constructs = identify_constructs(basic_blocks, function, postorder)

    for construct in constructs:
        for condition_block in construct.condition_blocks:
            if target_address >= condition_block.start_address and target_address <= condition_block.end_address:
                print(hex(target_address), construct)
                break


    last_op = instructions[target_address][-1]
    if last_op.opcode == OpCode.BRANCH:
        return util.FaultReport(target_address, util.FaultCategory.ITE_1) # We skipped a branch instruction in the ITE construction and wrongfully executed the else part.

    if last_op.opcode == OpCode.CBRANCH:
        return util.FaultReport(target_address, util.FaultCategory.ITE_2) # We skipped the conditional branch and executed secured code instead of the insecure default

    dependents = ddg.find_dependents(target_address)
    for node in dependents:
        ops = instructions[node.insn_addr]
        if ops[-1].opcode == OpCode.CBRANCH:
            return util.FaultReport(target_address, util.FaultCategory.ITE_3, node.insn_addr) # We skipped an instruction that affects the conditional branch of the ITE construction

    return None
