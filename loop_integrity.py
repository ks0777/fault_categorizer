from pypcode.pypcode_native import OpCode as OpCode, Instruction, Address
from pypcode import PcodePrettyPrinter

from util import find_function_by_address, extract_disassembly_from_elf, extract_pcode_from_elf

class BasicBlock:
    def __init__(self, start_address, end_address, instructions):
        self.start_address = start_address
        self.end_address = end_address
        self.instructions = instructions
        self.successors = []
        self.predecessors = []
        self.dominators = []
        self.discovered_index = -1


def dfs(basic_blocks, current, discovered, postorder):
    if current.start_address in discovered:
        #print(f'already found instruction at {hex(current.start_address)}')
        return

    current.discovered_index = len(discovered)

    discovered.append(current.start_address)

    last_op = current.instructions[max(current.instructions)][-1]

    if OpCode.CBRANCH == last_op.opcode:
        successor = basic_blocks[current.end_address + 1]
        successor.predecessors.append(current)
        current.successors.append(successor)
        dfs(basic_blocks, successor, discovered, postorder)

        branch_op = last_op 
        successor = basic_blocks[branch_op.inputs[0].offset]
        successor.predecessors.append(current)
        current.successors.append(successor)
        dfs(basic_blocks, successor, discovered, postorder)
    elif OpCode.BRANCH == last_op.opcode:
        branch_op = last_op 
        successor = basic_blocks[branch_op.inputs[0].offset]
        successor.predecessors.append(current)
        current.successors.append(successor)
        dfs(basic_blocks, successor, discovered, postorder)
    elif OpCode.RETURN == last_op.opcode:
        pass
    else:
        successor = basic_blocks[current.end_address + 1]
        current.successors.append(successor)
        successor.predecessors.append(current)
        dfs(basic_blocks, basic_blocks[current.end_address + 1], discovered, postorder)

    postorder.append(current.start_address)

def intersect(b1, b2, idoms, postorder_map):
    while b1 != b2:
        if postorder_map[b1] < postorder_map[b2]:
            b1 = idoms[b1]
        else:
            b2 = idoms[b2]

    return b1
    

# https://www.cs.rice.edu/~keith/EMBED/dom.pdf
def find_dominators(basic_blocks, entry_bb, postorder):
    idoms = dict()
    idoms[entry_bb.start_address] = entry_bb.start_address
    changed = True

    postorder_map = dict()
    for i, addr in enumerate(postorder):
        postorder_map[addr] = i

    while changed:
        changed = False
        
        for bb_addr in postorder[:-1][::-1]:
            bb = basic_blocks[bb_addr]

            new_idom = bb.predecessors[0].start_address

            for pred in bb.predecessors[1:]:
                if pred.start_address in idoms:
                    new_idom = intersect(new_idom, pred.start_address, idoms, postorder_map)

            if idoms.get(bb.start_address, -1) != new_idom:
                idoms[bb.start_address] = new_idom
                changed = True

    return idoms
                
def dominates(a, b, entry, idoms):
    if a == entry:
        return True

    runner = idoms[b]
    while runner != entry:
        if runner == a:
            return True

        runner = idoms[runner]

    return False

def find_basic_blocks(instructions, elf):
    splits = set(())
    ops_dict = dict()
    basic_blocks = dict()
    
    for i, instruction in enumerate(instructions):
        ops = extract_pcode_from_elf(elf, instruction.addr.offset, max_instructions=1)
        ops_dict[instruction.addr.offset] = ops
        print(hex(instruction.addr.offset))
        for op in ops:
            print(PcodePrettyPrinter.fmt_op(op))

        if any(op.opcode == OpCode.CBRANCH or op.opcode == OpCode.BRANCH for op in ops):
            branch_op = [op for op in ops if op.opcode == OpCode.CBRANCH or op.opcode == OpCode.BRANCH][0]
            splits.add(list(filter(lambda instr: instr.addr.offset == branch_op.inputs[0].offset, instructions))[0])
            splits.add(instructions[i+1])

    head = instructions[0]
    for i in sorted(splits, key = lambda instr: instr.addr.offset):
        bb = BasicBlock(head.addr.offset, i.addr.offset-1, [])
        basic_blocks[bb.start_address] = bb
        head = i

    bb = BasicBlock(head.addr.offset, instructions[-1].addr.offset + instructions[-1].length - 1, [])
    basic_blocks[head.addr.offset] = bb

    for bb in basic_blocks.values():
        bb.instructions = dict()
        for i in range(bb.start_address, bb.end_address):
            if i in ops_dict:
                bb.instructions[i] = ops_dict[i]

        #print(hex(bb.start_address), hex(bb.end_address), bb.instructions)

    return basic_blocks

def affects_condition(bb, target_address, condition_nodes, discovered=[]):
    print('affects condition ', hex(bb.start_address), condition_nodes)
    if bb.start_address in discovered:
        return False
    discovered.append(bb.start_address)

    for address, ops in sorted(bb.instructions.items())[::-1]:
        for op in ops[::-1]:
            print(hex(address), op.opcode, op.output.offset if op.output else '', [node.offset for node in op.inputs])

            if op.opcode == OpCode.STORE and f"{op.inputs[0].offset} {op.inputs[1].offset}" in condition_nodes:
                if address == target_address:
                    return True
                condition_nodes += op.inputs[2].offset
                continue

            if op.output is None:
                continue

            if address == target_address and op.output.offset in condition_nodes:
                return True

            if op.opcode == OpCode.LOAD and op.output.offset in condition_nodes:
                condition_nodes.append(f"{op.inputs[0].offset} {op.inputs[1].offset}")

            elif op.output.offset in condition_nodes:
                condition_nodes = list(filter(lambda offset: offset != op.output.offset, condition_nodes))
                condition_nodes += [node.offset for node in op.inputs]
                print(condition_nodes)

            if address == target_address:
                return False

    for pred in bb.predecessors:
        print('target not found, searching in bb at ', hex(pred.start_address))
        if affects_condition(pred, target_address, condition_nodes, discovered):
            return True

    return False

def find_loop_blocks(basic_blocks, current, head, discovered=set(())):
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

def check_li(ops, elf, target_address):

    _, start_address, end_address = find_function_by_address(elf, target_address)
    #print('Function context', start_address, end_address)

    xd = extract_pcode_from_elf(elf, start_address, end_address)
    for op in xd:
        if op.opcode == OpCode.IMARK:
            print(hex(op.inputs[0].offset))
            continue
        print(PcodePrettyPrinter.fmt_op(op))

    instruction_list = extract_disassembly_from_elf(elf, start_address, end_address)
    instructions = dict()
    for instruction in instruction_list:
        instructions[instruction.addr.offset] = instruction

    basic_blocks = find_basic_blocks(instruction_list, elf)

    postorder = []
    dfs(basic_blocks, basic_blocks[start_address], [], postorder) 

    back_edges = []

    idoms = find_dominators(basic_blocks, basic_blocks[start_address], postorder)

    for bb in basic_blocks.values():
        back_edge_head = [successor for successor in bb.successors if bb.discovered_index >= successor.discovered_index]
        if len(back_edge_head) != 1:
            continue

        print(f"Found back edge from {hex(bb.start_address)} to {hex(back_edge_head[0].start_address)}")

        if not dominates(back_edge_head[0].start_address, bb.start_address, start_address, idoms):
            continue

        loop_blocks = find_loop_blocks(basic_blocks, bb, back_edge_head[0])

        for loop_block in loop_blocks:
            address, ops = sorted(loop_block.instructions.items())[-1]
            last_op = ops[-1]
            print(last_op.opcode, hex(last_op.inputs[0].offset))

            if (last_op.opcode == OpCode.BRANCH or last_op.opcode == OpCode.CBRANCH) and (not is_in_loop(loop_blocks, last_op.inputs[0].offset) or not is_in_loop(loop_blocks, loop_block.end_address + 1)):
                if address == target_address:
                    return True

                print('Found unfaulted branch, checking if affected')

                if last_op.opcode == OpCode.CBRANCH:
                    condition_nodes = [last_op.inputs[1].offset]

                    print(hex(loop_block.start_address), loop_block.predecessors)
                    if affects_condition(loop_block, target_address, condition_nodes):
                        return True


        #return affects_condition(branching_bb, target_address, condition_nodes)
    


    #for bb in basic_blocks.values():
    #    print(hex(bb.start_address), hex(bb.end_address), bb.discovered_index, list(map(lambda bb: hex(bb.start_address), bb.successors)),list(map(lambda bb: hex(bb.start_address), bb.predecessors)))

    #print(list(map(lambda addr: hex(addr), postorder)))

    #print(dominates(0x80000028, 0x80000038, instructions[0].addr.offset, idoms))

    return False
