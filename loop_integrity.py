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
from pypcode.pypcode_native import OpCode as OpCode, Instruction, Address

from loop_analysis import LoopFinder


def check_li(basic_blocks, instruction_ops, ddg, affected_branches, target_address):
    loop_finder = LoopFinder(basic_blocks)
    if instruction_ops[target_address][-1].opcode in [OpCode.CBRANCH, OpCode.BRANCH]:
        for loop in loop_finder.loops:
            if target_address in map(
                lambda edge: max(edge[0].instruction_ops), loop.entry_edges
            ):
                return util.FaultReport(target_address, util.FaultCategory.LI_1)
            if target_address in map(
                lambda edge: max(edge[0].instruction_ops),
                loop.continue_edges + loop.break_edges,
            ):
                return util.FaultReport(target_address, util.FaultCategory.LI_2)
        return None

    if affected_branches == None:
        dependents = ddg.find_dependents(target_address)
        dependent_branch_addresses = list(
            map(
                lambda node: node.insn_addr,
                filter(
                    lambda node: instruction_ops[node.insn_addr][-1].opcode
                    == OpCode.CBRANCH,
                    dependents,
                ),
            )
        )

        if len(dependent_branch_addresses) > 1:
            return None

        affected_branches = dependent_branch_addresses

    for address in affected_branches:
        for loop in loop_finder.loops:
            if address in map(
                lambda edge: max(edge[0].instruction_ops), loop.entry_edges
            ):
                return util.FaultReport(
                    target_address,
                    util.FaultCategory.LI_3,
                    affected_branches=affected_branches,
                )
            if address in map(
                lambda edge: max(edge[0].instruction_ops),
                loop.continue_edges + loop.break_edges,
            ):
                return util.FaultReport(
                    target_address,
                    util.FaultCategory.LI_4,
                    affected_branches=affected_branches,
                )
