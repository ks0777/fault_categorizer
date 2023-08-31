
class BasicBlock:
    def __init__(self, start_address, end_address, instructions):
        self.start_address = start_address
        self.end_address = end_address
        self.instructions = instructions
        self.successors = []
        self.predecessors = []
        self.calls = None
        self.called_by = None
        self.discovered_index = -1


class CFG:
    def __init__(self, elf):
        self.basic_blocks = dict()
        self.postorder = []

        self._discovered = []
        self._callstack = []
        self._elf = elf

    def _find_basic_blocks(self, ops, start_address, end_address):
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
            self.basic_blocks[head] = bb
            head = split_addr

        bb = BasicBlock(head, end_address, dict())
        self.basic_blocks[head] = bb

        for bb in self.basic_blocks.values():
            for addr in range(bb.start_address, bb.end_address):
                if addr in insn_ops:
                    bb.instructions[addr] = insn_ops[addr]

    def _build_cfg(self, current, callee=None):
        if current.start_address in self.discovered:
            #print(f'already found instruction at {hex(current.start_address)}')
            return

        current.discovered_index = len(self.discovered)

        self.discovered.append(current.start_address)

        last_op = current.instructions[max(current.instructions)][-1]

        if OpCode.CBRANCH == last_op.opcode:
            successor = self.basic_blocks[current.end_address + 1]
            successor.predecessors.append(current)
            current.successors.append(successor)
            self.build_cfg(successor)

            successor = self.basic_blocks[last_op.inputs[0].offset]
            successor.predecessors.append(current)
            current.successors.append(successor)
            self.build_cfg(successor)
        elif OpCode.BRANCH == last_op.opcode:
            successor = self.basic_blocks[last_op.inputs[0].offset]
            successor.predecessors.append(current)
            current.successors.append(successor)
            self.build_cfg(successor)
        elif OpCode.RETURN == last_op.opcode:
            pass
        elif OpCode.CALL == last_op.opcode:
            function = util.find_function_by_address(self._elf, last_op.inputs[0].offset)
            ops = util.extract_pcode_from_elf(self._elf, function.target_address, function.end_address)
            self._find_basic_blocks(ops, function.start_address, function.end_address)
            successor = self.basic_blocks[last_op.inputs[0].offset]
            successor.called_by = current
            current.calls = successor
            self.build_cfg()
            pass
        else:
            successor = self.basic_blocks[current.end_address + 1]
            current.successors.append(successor)
            successor.predecessors.append(current)
            self.build_cfg(basic_blocks[current.end_address + 1])

        self.postorder.append(current.start_address)

