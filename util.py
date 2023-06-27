from pypcode import Context

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

def extract_disassembly_from_elf(elf, target_address, end_address=None, max_instructions=0):
    data = extract_assembly_from_elf(elf, target_address, end_address, max_instructions)
    if len(data) == 0:
        return None

    # Translate instructions to pcode
    ctx = Context('RISCV:LE:64:default')
    dx = ctx.disassemble(data, base_address=target_address, max_instructions=max_instructions)
    # Return the instructions
    return dx.instructions

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
                return [symbol.name, start_address, end_address]
    
    # If no matching function is found, return None
    return None
