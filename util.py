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

def get_pcode(project, target_address, max_instructions=1):
    mem = project.loader.memory

    # Save offset to restore it later
    offset = mem.tell()

    # Set internal pointer to memory to be read
    project.loader.memory.seek(target_address)
    # Read the data at the specified offset (8 bytes should be enough for one instruction)
    instruction_bytes = project.loader.memory.read(4*max_instructions)

    # Reset internal pointer to previous value
    mem.seek(offset)


    # Translate instructions to pcode
    ctx = Context('ARM:LE:32:Cortex')
    tx = ctx.translate(instruction_bytes, base_address=target_address, max_instructions=max_instructions)
    # Return the pcode
    return tx.ops

def addr_in_range(addr, start, end):
    return addr >= start and addr < end

def addr_in_node(addr, node):
    return addr >= node.addr and addr < (node.addr + node.size)

def find_function_by_address(cfg, target_address):
    for function in cfg.functions.values():
        if addr_in_range(target_address, function.addr, function.addr + function.size):
            return [function.addr, function.addr + function.size]
    raise Exception(f'Unable to find function bounds for address {target_address}')

