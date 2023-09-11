import util
from pypcode import Context, PcodePrettyPrinter
from pypcode.pypcode_native import OpCode as OpCode, Instruction, Address
import networkx as nx

class Node:
    def __init__(self, location, insn_addr, index):
        self.location = location
        self.insn_addr = insn_addr
        self.index = index

    def __hash__(self):
        #return hash((self.location << 80) + (self.insn_addr << 16) + self.index)
        return hash(self.location)

    def __eq__(self, other):
        return self.location == other.location and self.index == other.index 

    def __cmp__(self, other):
        return self.index > other.index

    def __str__(self):
        if self.insn_addr != None and self.index != None:
            return f"{hex(self.insn_addr)}[{self.index}] -> {self.location}"
        else:
            return f"Node@{self.location}"

class DataDependencyAnalysis:
    def __init__(self, instructions, tbexeclist, tbinfo, meminfo):
        self._tbexeclist = tbexeclist.sort_values(by=['pos'])
        self._tbinfo = tbinfo.set_index(['identity'])
        self._meminfo = meminfo
        self._instructions = instructions

        self.graph = nx.DiGraph()
        self._analyze_dependencies()

    def plot_graph(self):
        nx.draw(self.graph, with_labels=True)
        import matplotlib.pyplot as plt; plt.plot(); plt.show()

    def plot_ancestors(self, insn_addr):
        nodes = filter(lambda node: node.insn_addr == insn_addr, self.graph.nodes())

        ancestor_nodes = set(())
        for node in nodes:
            if node in self.graph:
                ancestor_nodes = ancestor_nodes.union(nx.ancestors(self.graph, node))

        subg = self.graph.subgraph(ancestor_nodes)
        nx.draw(subg, with_labels=True)
        import matplotlib.pyplot as plt; plt.plot(); plt.show()
        

    def find_dependencies(self, insn_addr):
        nodes = filter(lambda node: node.insn_addr == insn_addr, self.graph.nodes())
        dependencies = set(())
        for node in nodes:
            if node in self.graph:
                dependencies = dependencies.union(nx.ancestors(self.graph, node))

        return list(filter(lambda node: node in dependencies, self.graph.nodes))

    def find_dependents(self, insn_addr):
        nodes = filter(lambda node: node.insn_addr == insn_addr, self.graph.nodes())
        dependencies = set(())
        for node in nodes:
            if node in self.graph:
                dependencies = dependencies.union(nx.descendants(self.graph, node))

        return list(filter(lambda node: node in dependencies, self.graph.nodes))

    def _analyze_dependencies(self):
        insn_addresses = sorted(self._instructions.keys())
        visited_tbs = []

        index = 0
        for tb_addr in self._tbexeclist['tb']: 
            if tb_addr in visited_tbs or tb_addr not in insn_addresses:
                continue
            visited_tbs.append(tb_addr)
            tb = self._tbinfo.loc[tb_addr]
            insn_start_index = insn_addresses.index(tb_addr)

            for insn_addr in insn_addresses[insn_start_index:]:
                if insn_addr == tb_addr + tb['size']:
                    break
                ops = self._instructions[insn_addr]

                for op in ops:
                    outputs = [op.output.offset] if op.output != None else []
                    if op.opcode == OpCode.STORE:
                        writes = self._meminfo[(self._meminfo['insaddr'] == insn_addr) & (self._meminfo['direction'] == 1)]['address']
                        outputs += list(writes.values)
                        #print(f'writing to {hex(output)}')

                    nodes = []
                    for output in outputs:
                        node = Node(output, insn_addr, index)
                        if node not in self.graph:
                            nodes.append(node)
                            self.graph.add_node(node)

                    inputs = list(map(lambda varnode: varnode.offset, filter(lambda  _input: _input.space.name != 'const', op.inputs)))

                    if op.opcode == OpCode.LOAD:
                        reads = self._meminfo[(self._meminfo['insaddr'] == insn_addr) & (self._meminfo['direction'] == 0)]['address']
                        #print(f'reading from {hex(reads.values[0])}')
                        inputs.extend(reads.values)

                    for _input in inputs:
                        write_op_nodes = list(filter(lambda _node: _node.location == _input and _node not in nodes, self.graph.nodes()))
                        if len(write_op_nodes) > 0:
                            for node in nodes:
                                self.graph.add_edge(write_op_nodes[-1], next(filter(lambda _node: node == _node, self.graph.nodes())))

                    index +=1
                     
        #self.plot_graph()
