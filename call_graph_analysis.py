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


class Node:
    def __init__(self, function):
        self.function = function
        self.calls = []
        self.called_by = []


class CallGraphAnalysis:
    def __init__(self, elf, tbexeclist):
        self.elf = elf
        self.tbexeclist = tbexeclist.sort_values(by=["pos"])

        self.functions = dict()
        self.call_tree = None

        self._analyze_execution_trace()

    def _analyze_execution_trace(self):
        tb_associations = dict()

        head = None

        for tb_addr in self.tbexeclist["tb"]:
            if tb_addr not in tb_associations:
                function = util.find_function_by_address(self.elf, tb_addr)
                if function.start_address not in self.functions:
                    self.functions[function.start_address] = function
                function = self.functions[function.start_address]

                if head == None:
                    head = Node(function)
                    self.call_tree = head
                    continue

                if head.function.start_address == function.start_address:
                    continue

                if tb_addr == function.start_address:
                    callee_node = Node(function)
                    callee_node.called_by.append(head)
                    head.calls.append(callee_node)
                    head = callee_node
                    continue

                head = next(
                    filter(
                        lambda node: node.function.start_address
                        == function.start_address,
                        head.called_by,
                    )
                )
