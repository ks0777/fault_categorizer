from pypcode import Context
from pypcode.pypcode_native import OpCode as OpCode, Instruction, Address

from enum import Enum

class FaultCategory(Enum):
    UNKNOWN = 0
    CFI = 1
    LI = 2
    ITE_1 = 3
    ITE_2 = 4
    ITE_3 = 5

def extract_assembly_from_elf(elf, target_address, end_address=None, max_instructions=0):
    # Iterate over all program headers/segments
    for segment in elf.iter_segments():
        if segment.header.p_type != 'PT_LOAD':
            continue

        # Calculate the virtual address range for the segment
        segment_start_address = segment.header.p_vaddr
        segment_end_address = segment_start_address + segment.header.p_memsz

        # Check if the target address is within the current segment
        if segment_start_address <= target_address < segment_end_address:
            # Calculate the offset from the start of the segment
            offset = target_address - segment_start_address

            # Read the data at the specified offset (8 bytes should be enough for one instruction)
            if end_address is None:
                data = segment.data()[offset:offset+8*max_instructions]
            else:
                data = segment.data()[offset:offset+end_address-target_address]

            # Return the instructions
            return data 

    # If the target address is not found, return None
    return None

def extract_pcode_from_elf(elf, target_address, end_address=None, max_instructions=0):
    data = extract_assembly_from_elf(elf, target_address, end_address, max_instructions)
    if len(data) == 0:
        return None

    # Translate instructions to pcode
    ctx = Context('RISCV:LE:64:default')
    tx = ctx.translate(data, base_address=target_address, max_instructions=max_instructions)
    # Return the pcode
    return tx.ops

def load_instructions(elf):
    instructions = dict()
    data = None
    for segment in elf.iter_segments():
        if segment.header.p_type == 'PT_LOAD':
            data = segment.data()
            base_address = segment.header.p_vaddr
            break

    if data == None:
        print('[ERROR]: Unable to find loadable segment in binary')
        return

    # Translate instructions to pcode
    ctx = Context('RISCV:LE:64:default')
    tx = ctx.translate(data, base_address=base_address)

    current_insn_addr = None
    for op in tx.ops:
        if op.opcode == OpCode.IMARK:
            current_insn_addr = op.inputs[0].offset
            instructions[current_insn_addr] = []
            continue

        instructions[current_insn_addr].append(op)

    return instructions

class Function:
    def __init__(self, symbol, start_address, end_address):
        self.symbol = symbol
        self.start_address = start_address
        self.end_address = end_address

def find_function_by_address(elf, target_address):
    # Iterate over the sections in the ELF file
    for section in elf.iter_sections():
        # Check if the section is a symbol table
        if section.name == '.symtab':
            symbol_table = section
            break
    else:
        # If no symbol table is found, return None
        return None
    
    # Iterate over the symbols in the symbol table
    for symbol in symbol_table.iter_symbols():
        # Check if the symbol is a function
        if symbol['st_info']['type'] == 'STT_FUNC':
            start_address = symbol['st_value']
            end_address = start_address + symbol['st_size']
            
            # Check if the target address is within the function's scope
            if start_address <= target_address < end_address:
                return Function(symbol.name, start_address, end_address)
    
    # If no matching function is found, return None
    return None


class BasicBlock:
    def __init__(self, start_address, end_address, instructions):
        self.start_address = start_address
        self.end_address = end_address
        self.instructions = instructions
        self.successors = []
        self.predecessors = []
        self.dominators = []
        self.discovered_index = -1

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

def build_cfg(basic_blocks, current, discovered, postorder):
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
        build_cfg(basic_blocks, successor, discovered, postorder)

        branch_op = last_op 
        successor = basic_blocks[branch_op.inputs[0].offset]
        successor.predecessors.append(current)
        current.successors.append(successor)
        build_cfg(basic_blocks, successor, discovered, postorder)
    elif OpCode.BRANCH == last_op.opcode:
        branch_op = last_op 
        successor = basic_blocks[branch_op.inputs[0].offset]
        successor.predecessors.append(current)
        current.successors.append(successor)
        build_cfg(basic_blocks, successor, discovered, postorder)
    elif OpCode.RETURN == last_op.opcode:
        pass
    else:
        successor = basic_blocks[current.end_address + 1]
        current.successors.append(successor)
        successor.predecessors.append(current)
        build_cfg(basic_blocks, basic_blocks[current.end_address + 1], discovered, postorder)

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

def affects_condition(bb, target_address, condition_nodes, meminfo, discovered=[]):
    print('affects condition ', hex(bb.start_address), condition_nodes)
    if bb.start_address in discovered:
        return False
    discovered.append(bb.start_address)

    for insn_address, ops in sorted(bb.instructions.items())[::-1]:
        for op in ops[::-1]:
            print(hex(insn_address), op.opcode, op.output.offset if op.output else '', [node.offset for node in op.inputs])

            writes = meminfo[(meminfo['insaddr'] == insn_address) & (meminfo['direction'] == 1)]['address']
            for mem_addr in writes:
                if op.opcode == OpCode.STORE and mem_addr in condition_nodes:
                    if insn_address == target_address:
                        return True
                    for _input in op.inputs:
                        if _input.space.name != 'const':
                            condition_nodes.append(_input.offset)

            if op.output is None:
                continue

            if insn_address == target_address and op.output.offset in condition_nodes:
                return True

            if op.opcode == OpCode.LOAD and op.output.offset in condition_nodes:
                reads = meminfo[(meminfo['insaddr'] == insn_address) & (meminfo['direction'] == 0)]['address']
                condition_nodes = list(filter(lambda offset: offset != op.output.offset, condition_nodes))
                for mem_addr in reads:
                    condition_nodes.append(mem_addr)

            elif op.output.offset in condition_nodes:
                condition_nodes = list(filter(lambda offset: offset != op.output.offset, condition_nodes))
                condition_nodes += [node.offset for node in filter(lambda node: node.space.name != 'const', op.inputs)]

            if insn_address == target_address:
                return False

    for pred in bb.predecessors:
        print('target not found, searching in bb at ', hex(pred.start_address))
        if affects_condition(pred, target_address, condition_nodes if len(bb.predecessors) == 1 else condition_nodes.copy(), meminfo, discovered):
            return True

    return False




def debug_console(_locals):
    import code
    import readline
    import rlcompleter
               
    vars = globals()
    vars.update(_locals)
                                                  
    readline.set_completer(rlcompleter.Completer(vars).complete)
    readline.parse_and_bind("tab: complete")
    code.InteractiveConsole(vars).interact()
