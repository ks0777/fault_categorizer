from pypcode.pypcode_native import OpCode as OpCode, Instruction, Address

from util import find_function_by_address, extract_disassembly_from_elf, extract_pcode_from_elf, debug_console

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

def find_basic_blocks(ops, start_address, end_address):
    basic_blocks = dict()
    splits = set(())

    current_insn_addr = 0
    split_next_insn = False
    insn_ops = dict()
    for op in ops:
        if op.opcode == OpCode.IMARK:
            current_insn_addr = op.inputs[0].offset
            insn_ops[current_insn_addr] = []
            if split_next_insn:
                split_next_insn = False
                splits.add(current_insn_addr)
            continue

        insn_ops[current_insn_addr].append(op)

        if op.opcode == OpCode.CBRANCH or op.opcode == OpCode.BRANCH:
            splits.add(op.inputs[0].offset)
            split_next_insn = True

    head = start_address
    for split_addr in sorted(splits):
        bb = BasicBlock(head, split_addr - 1, dict())
        basic_blocks[head] = bb
        head = split_addr

    bb = BasicBlock(head, end_address, dict())
    basic_blocks[head] = bb

    for bb in basic_blocks.values():
        for addr in range(bb.start_address, bb.end_address):
            if addr in insn_ops:
                bb.instructions[addr] = insn_ops[addr]

    return basic_blocks

def affects_condition(bb, target_address, condition_nodes, meminfo, discovered=[]):
    print('affects condition ', hex(bb.start_address), condition_nodes)
    if bb.start_address in discovered:
        return False
    discovered.append(bb.start_address)

    for insn_address, ops in sorted(bb.instructions.items())[::-1]:
        for op in ops[::-1]:
            #print(hex(insn_address), op.opcode, op.output.offset if op.output else '', [node.offset for node in op.inputs])

            writes = meminfo[(meminfo['insaddr'] == insn_address) & (meminfo['direction'] == 1)]['address']
            for mem_addr in writes:
                if op.opcode == OpCode.STORE and mem_addr in condition_nodes:
                    if insn_address == target_address:
                        return True
                    if op.inputs[2].space.name != 'const':
                        condition_nodes.append(op.inputs[2].offset)

            if op.output is None:
                continue

            if insn_address == target_address and op.output.offset in condition_nodes:
                return True

            if op.opcode == OpCode.LOAD and op.output.offset in condition_nodes:
                reads = meminfo[(meminfo['insaddr'] == insn_address) & (meminfo['direction'] == 0)]['address']
                for mem_addr in reads:
                    condition_nodes.append(mem_addr)

            elif op.output.offset in condition_nodes:
                # Todo: This step should only happen if the current instruction strongly dominates the instruction that previously wrote to the varnode
                condition_nodes = list(filter(lambda offset: offset != op.output.offset, condition_nodes))
                condition_nodes += [node.offset for node in filter(lambda node: node.space.name != 'const', op.inputs)]
                #print(condition_nodes)

            if insn_address == target_address:
                return False

    for pred in bb.predecessors:
        print('target not found, searching in bb at ', hex(pred.start_address))
        if affects_condition(pred, target_address, condition_nodes, meminfo, discovered):
            return True

    return False

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

def check_li(ops, elf, meminfo, target_address):
    _, start_address, end_address = find_function_by_address(elf, target_address)

    function_ops = extract_pcode_from_elf(elf, start_address, end_address=end_address)
    basic_blocks = find_basic_blocks(function_ops, start_address, end_address)

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

        loop_blocks = find_loop_blocks(basic_blocks, bb, back_edge_head[0])

        for loop_block in loop_blocks:
            address, ops = sorted(loop_block.instructions.items())[-1]
            last_op = ops[-1]
            #print(last_op.opcode, hex(last_op.inputs[0].offset))

            if (last_op.opcode == OpCode.BRANCH or last_op.opcode == OpCode.CBRANCH) and (not is_in_loop(loop_blocks, last_op.inputs[0].offset) or not is_in_loop(loop_blocks, loop_block.end_address + 1)):
                if address == target_address:
                    return True

                #print('Found unfaulted branch, checking if affected')

                if last_op.opcode == OpCode.CBRANCH:
                    condition_nodes = [last_op.inputs[1].offset]

                    print(hex(loop_block.start_address), loop_block.predecessors)
                    if affects_condition(loop_block, target_address, condition_nodes, meminfo):
                        return True

    return False
