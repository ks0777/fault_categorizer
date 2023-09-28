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

from pypcode.pypcode_native import OpCode as OpCode
import util


def check_cfi(basic_blocks, instruction_ops, function, target_address):
    fault_category = None
    ops = instruction_ops[target_address]
    if any(op.opcode == OpCode.CALL for op in ops):
        fault_category = util.FaultCategory.CFI_1

    last_bb = basic_blocks[
        max(filter(lambda bb_start: bb_start < function.end_address, basic_blocks))
    ]
    if ops[-1].opcode == OpCode.RETURN:
        if max(last_bb.instruction_ops) == target_address:
            fault_category = util.FaultCategory.CFI_2
        else:
            fault_category = util.FaultCategory.CFI_3

    if (
        ops[-1].opcode == OpCode.BRANCH
        and max(last_bb.instruction_ops) == target_address
    ):
        fault_category = util.FaultCategory.CFI_4

    if fault_category:
        return util.FaultReport(target_address, fault_category)
