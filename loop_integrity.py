from pypcode.pypcode_native import OpCode as OpCode, Instruction, Address

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
        current.successors.append(basic_blocks[current.end_address + 1])
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
                if pred.start_address not in idoms:
                    new_idom = intersect(new_idom, pred.start_address, idoms, postorder_map)

            if idoms.get(bb.start_address, -1) != new_idom:
                idoms[bb.start_address] = new_idom
                changed = True

    #print(idoms)
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

def affects_condition(bb, _ops, target_address):
    last_op = bb.instructions[max(bb.instructions)][-1]
    if last_op.opcode != OpCode.CBRANCH:
        return False

    condition_nodes = [last_op.inputs[1].offset]

    for address, ops in sorted(bb.instructions.items())[::-1]:
        for op in ops[::-1]:
            if op.output is None:
                continue

            if op.output.offset in condition_nodes:
                if address == target_address:
                    return True

                condition_nodes = list(filter(lambda offset: offset != op.output.offset, condition_nodes))
                condition_nodes += [node.offset for node in op.inputs]

    return False


def check_li(ops, elf, target_address):

    _, start_address, end_address = find_function_by_address(elf, target_address)
    #print('Function context', start_address, end_address)

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

        #print(f"Found back edge from {hex(bb.start_address)} to {hex(back_edge_head[0].start_address)}")

        if not dominates(back_edge_head[0].start_address, bb.start_address, start_address, idoms):
            continue

        if target_address >= bb.start_address and target_address <= bb.end_address or target_address >= back_edge_head[0].start_address and target_address <= back_edge_head[0].end_address:

            if OpCode.CBRANCH == ops[-1].opcode:
                return True

            return affects_condition(bb if target_address >= bb.start_address and target_address <= bb.end_address else back_edge_head[0], ops, target_address)
    


    #for bb in basic_blocks.values():
    #    print(hex(bb.start_address), hex(bb.end_address), bb.discovered_index, list(map(lambda bb: hex(bb.start_address), bb.successors)),list(map(lambda bb: hex(bb.start_address), bb.predecessors)))

    #print(list(map(lambda addr: hex(addr), postorder)))

    #print(dominates(0x80000028, 0x80000038, instructions[0].addr.offset, idoms))

    return False
