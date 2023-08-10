from pypcode import Context
from pypcode.pypcode_native import OpCode, BadDataError

from enum import Enum

class FaultReport():
    def __init__(self, fault_address, category, affected_branch=None):
        self.fault_address = fault_address
        self.category = category
        self.affected_branch = affected_branch

    def __str__(self):
        return str(self.category) + (f' affected branch at {hex(self.affected_branch)}' if self.affected_branch else '')

class FaultCategory(Enum):
    UNKNOWN = 0
    CFI = 1
    LI_1 = 2
    LI_2 = 3
    ITE_1 = 4
    ITE_2 = 5
    ITE_3 = 6

def load_instructions(elf_file):
    instructions = dict()
    data = None

    ctx = Context('RISCV:LE:64:default')

    for section in elf_file.iter_sections():
        if section.name == '.text':  # Assuming text sections contain executable code
            # Get the address range for the section
            start_address = section['sh_addr']
            end_address = start_address + section['sh_size']
            
            # Iterate over symbols to find functions within the section
            for symbol in elf_file.get_section_by_name('.symtab').iter_symbols():
                if symbol['st_info']['type'] == 'STT_FUNC':
                    symbol_address = symbol['st_value']
                    if start_address <= symbol_address < end_address:
                        # Load the binary data of the function
                        function_data = section.data()[symbol_address - start_address : symbol_address - start_address + symbol['st_size']]

                        # Translate binary data into pcode operations
                        tx = ctx.translate(function_data, base_address=symbol_address)
                        current_insn_addr = None
                        for op in tx.ops:
                            # Keep track of instruction markers
                            if op.opcode == OpCode.IMARK:
                                current_insn_addr = op.inputs[0].offset
                                instructions[current_insn_addr] = []
                                continue

                            instructions[current_insn_addr].append(op)

    return instructions

def decode_file_line(dwarfinfo, address):
    # Go over all the line programs in the DWARF information, looking for
    # one that describes the given address.
    for CU in dwarfinfo.iter_CUs():
        # First, look at line programs to find the file/line for the address
        lineprog = dwarfinfo.line_program_for_CU(CU)
        prevstate = None
        for entry in lineprog.get_entries():
            # We're interested in those entries where a new state is assigned
            if entry.state is None:
                continue
            if entry.state.end_sequence:
                # if the line number sequence ends, clear prevstate.
                prevstate = None
                continue
            # Looking for a range of addresses in two consecutive states that
            # contain the required address.
            if prevstate and prevstate.address <= address < entry.state.address:
                filename = lineprog['file_entry'][prevstate.file - 1].name
                line = prevstate.line
                return filename, line
            prevstate = entry.state
    return None, None

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

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return f'BasicBlock<{self.discovered_index}> {hex(self.start_address)}-{hex(self.end_address)}'

    def __gt__(self, other):
        return self.discovered_index > other.discovered_index

def find_basic_blocks(instructions, start_address, end_address):
    basic_blocks = dict()
    splits = set(())

    insn_addresses = sorted(instructions.keys())
    split_next_insn = False
    for addr in insn_addresses[insn_addresses.index(start_address):]:
        if addr > end_address:
            break

        if split_next_insn:
            splits.add(addr)
            split_next_insn = False

        last_op = instructions[addr][-1]

        if last_op.opcode == OpCode.CBRANCH or last_op.opcode == OpCode.BRANCH:
            splits.add(last_op.inputs[0].offset)
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
            if addr in instructions:
                bb.instructions[addr] = instructions[addr]

    return basic_blocks

def build_cfg(basic_blocks, current, discovered, postorder):
    if current.start_address in discovered:
        #print(f'already found instruction at {hex(current.start_address)}')
        return

    current.discovered_index = len(discovered)

    discovered.append(current.start_address)

    if len(current.instructions) == 0:
        return

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

def _get_predecessors(bb, function, discovered):
    if bb.start_address in discovered:
        return set(())
    discovered.add(bb.start_address)

    if function != None and (bb.start_address < function.start_address or bb.end_address > function.end_address):
        return set(())

    predecessors = set(filter(lambda pred: pred.start_address not in discovered, bb.predecessors))

    for predecessor in predecessors:
        predecessors = predecessors.union(_get_predecessors(predecessor, function, discovered))

    return predecessors

def get_predecessors(bb, function=None):
    return _get_predecessors(bb, function, set(()))


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
