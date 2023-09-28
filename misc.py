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
from pypcode.pypcode_native import OpCode as OpCode


def check_branch(instruction_ops, target_address):
    ops = instruction_ops[target_address]

    if ops[-1].opcode in [OpCode.BRANCH, OpCode.CBRANCH]:
        return util.FaultReport(target_address, util.FaultCategory.MISC_BRANCH)


def check_branch_intervention(report, ddg, instruction_ops, target_address):
    deps = ddg.find_dependents(target_address)

    if (
        len(set(report.affected_branches) & set(map(lambda node: node.insn_addr, deps)))
        > 0
    ):
        ops = instruction_ops[target_address]
        if any(op.opcode == OpCode.LOAD for op in ops):
            return util.FaultReport(
                target_address,
                util.FaultCategory.MISC_LOAD,
                affected_branches=report.affected_branches,
            )
        if any(op.opcode == OpCode.STORE for op in ops):
            return util.FaultReport(
                target_address,
                util.FaultCategory.MISC_STORE,
                affected_branches=report.affected_branches,
            )

        return util.FaultReport(
            target_address,
            util.FaultCategory.MISC,
            affected_branches=report.affected_branches,
        )

    return report
