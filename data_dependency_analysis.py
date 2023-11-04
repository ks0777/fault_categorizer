# Copyright (c) 2023 Kevin Schneider
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import util
from pypcode import Context, PcodePrettyPrinter
from pypcode.pypcode_native import OpCode as OpCode, Instruction, Address
from functools import cache
import graph_tool.all as gt


class Node:
    def __init__(self, location, insn_addr, index):
        self.location = location
        self.insn_addr = insn_addr
        self.index = index

    def __hash__(self):
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
        self._tbexeclist = tbexeclist.sort_values(by=["pos"])
        self._tbinfo = tbinfo.set_index(["identity"])
        self._meminfo = meminfo
        self._instructions = instructions

        self.graph = gt.Graph(directed=True)
        self.graph_reverse = gt.Graph(
            directed=True
        )  # another graph which is built in reverse to quickly iterate over predecessors of a node
        self._analyze_dependencies()
        import pdb; pdb.set_trace()

    def __getstate__(self):
        state = dict()
        state["graph"] = self.graph
        state["graph_reverse"] = self.graph_reverse
        state["node_map"] = self.node_map
        state["node_map_rev"] = self.node_map_rev
        return state

    def __setstate(self, state):
        self.graph = state["graph"]
        self.graph_reverse = state["graph_reverse"]
        self.node_map = state["node_map"]
        self.node_map_rev = state["node_map_rev"]

    @cache
    def find_dependencies(self, insn_addr):
        if insn_addr not in self.node_map:
            return []
        dependencies = set()
        source_nodes = filter(
            lambda node: node == self.node_map[insn_addr], self.graph_reverse.vertices()
        )
        for source_node in source_nodes:
            for edge in gt.bfs_iterator(self.graph_reverse, source_node):
                dependencies.add(
                    self.node_map_rev[self.graph.vertex_index[edge.target()]]
                )

        return list(dependencies)

    @cache
    def find_dependents(self, insn_addr):
        if insn_addr not in self.node_map:
            return []
        dependents = set()
        source_nodes = filter(
            lambda node: node == self.node_map[insn_addr], self.graph.vertices()
        )
        for source_node in source_nodes:
            for edge in gt.bfs_iterator(self.graph, source_node):
                dependents.add(
                    self.node_map_rev[self.graph.vertex_index[edge.target()]]
                )

        return list(dependents)

    def _analyze_dependencies(self):
        insn_addresses = sorted(self._instructions.keys())

        # dicts that map vertex ids in graph to tb addresses
        self.node_map = dict()
        self.node_map_rev = []

        last_write_nodes = dict()

        writes_df = self._meminfo[self._meminfo["direction"] == 1].groupby(["insaddr"])
        writes = dict()
        for name, group in writes_df:
            writes[name[0]] = []
            for write in group["address"]:
                writes[name[0]].append(write)

        reads_df = self._meminfo[self._meminfo["direction"] == 0].groupby(["insaddr"])
        reads = dict()
        for name, group in reads_df:
            reads[name[0]] = []
            for read in group["address"]:
                reads[name[0]].append(read)

        index = 0
        graph_size = 0
        for tb_addr in self._tbexeclist["tb"]:
            tb = self._tbinfo.loc[tb_addr]

            if tb_addr not in insn_addresses:
                # For some reason the function associated with this instrcution was not disassembled
                continue
            insn_start_index = insn_addresses.index(tb_addr)

            for insn_addr in insn_addresses[insn_start_index:]:
                if insn_addr == tb_addr + tb["size"]:
                    break
                ops = self._instructions[insn_addr]

                for op in ops:
                    outputs = [op.output.offset] if op.output != None else []
                    if op.opcode == OpCode.STORE:
                        outputs += list(writes.get(insn_addr, []))

                    inputs = list(
                        map(
                            lambda varnode: varnode.offset,
                            filter(
                                lambda _input: _input.space.name != "const", op.inputs
                            ),
                        )
                    )

                    if op.opcode == OpCode.LOAD:
                        inputs.extend(reads.get(insn_addr, []))

                    if len(outputs) + len(inputs) == 0:
                        continue

                    for output in outputs:
                        if output not in last_write_nodes:
                            last_write_nodes[output] = []
                        last_write_nodes[output].append(insn_addr)

                    if insn_addr not in self.node_map:
                        self.node_map[insn_addr] = graph_size
                        self.node_map_rev.append(insn_addr)
                        graph_size += 1
                        self.graph.add_vertex()
                        self.graph_reverse.add_vertex()

                    #if insn_addr == 0x11844:
                        #import pdb; pdb.set_trace()

                    for _input in inputs:
                        if _input in last_write_nodes:
                            for write_node in last_write_nodes[_input]:
                                self.graph.add_edge(
                                    self.node_map[write_node],
                                    self.node_map[insn_addr],
                                )
                                self.graph_reverse.add_edge(
                                    self.node_map[insn_addr],
                                    self.node_map[write_node],
                                )
                    index += 1
