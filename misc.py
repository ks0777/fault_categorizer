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


def check_branch(instructions, target_address):
    ops = instructions[target_address]

    if ops[-1].opcode == OpCode.BRANCH:
        return util.FaultReport(target_address, util.FaultCategory.MISC_BRANCH)


def check_branch_intervention(report, instructions, target_address):
    related_constructs = list(report.related_constructs.values())
    if len(related_constructs) == 1:
        return report

    # The related construct is None if none was identified or if the according branch instruction was outside of the function scope of the faulted instruction
    # If the faulted instruction only affects a single construct in the same function it likely means that the fault directly affects the validation of the condition and not the calculation of some value of the condition
    related_construct = related_constructs[0]
    for construct in related_constructs[1:]:
        if construct != related_construct:
            related_construct = None
            break

    if related_construct != None:
        return report

    ops = instructions[target_address]
    if any(op.opcode == OpCode.LOAD for op in ops):
        return util.FaultReport(target_address, util.FaultCategory.MISC_LOAD)
    if any(op.opcode == OpCode.STORE for op in ops):
        return util.FaultReport(target_address, util.FaultCategory.MISC_STORE)

    return util.FaultReport(
        target_address,
        util.FaultCategory.MISC,
        affected_branches=report.affected_branches,
    )
