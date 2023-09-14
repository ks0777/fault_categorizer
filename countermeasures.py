from util import FaultCategory
from ite import IfThen, IfThenElse

def get_countermeasure(report, ring_buffer_enabled):
    if report.category == FaultCategory.CFI_1:
        return "The faulted instruction is a function call. Harden this code by implementing a global counter that is increased before the function call and decreased before the respective return. This value needs to be validated after a function call and should contain the same value as before the call. If this check fails, trigger a panic.\n\nUse the `FIH_CALL(f, ret, ...)` macro from the hardening header file to call the function and use the `FIH_RET(ret)` macro inside that function to return from it."

    if report.category == FaultCategory.CFI_2:
        return "The faulted instruction is a CALL or RETURN. Harden this code by implementing a global counter that is increased/decreased on each function call/return respectively. This value needs to be validated after a function call and should contain the same value as before the call. If this check fails, trigger a panic."

    if report.category == FaultCategory.LI_1:
        return "The faulted instruction is a (conditional) branch that belongs to the logic of some loop. The fault can allow to break from the loop, or to continue the loop regardless of the exit condition. Harden this code by adding a check after the loop which validates that the loop exit condition is met. If this check fails, trigger a panic."

    if report.category == FaultCategory.LI_2:
        return "The faulted instruction affects the condition of a conditional branch that belongs to the logic of some loop. This can cause the loop body to be executed more or less often than expected, however the exit condition of the loop may still be fulfilled on exit. If this faulted instruction is part of the loop condition check, harden this code by performing an additional redundant check of the condition in the loop header. If the checks do not come to the same result, trigger a panic. If the faulted instruction directly affects the loop counter and not the check, add a ghost counter that goes through the same operations as the real counter. Add a check to the loop condition which compares this counter with the real counter and trigger a panic if they contain different values."

    if report.category == FaultCategory.ITE_1:
        return "The faulted instruction is an unconditional branch which is part of an if-then-else construct. By skipping this branch, the else part of the construct can wrongfully be executed. Harden this code by advising the compiler to swap the order of the if and else blocks."

    if report.category == FaultCategory.ITE_2:
        related_construct = report.related_constructs[report.fault_address]
        if related_construct == None or isinstance(related_construct, IfThen):
            return "The faulted instruction is a conditional branch which is part of an if-then construct. Insecure states should be the exception in the program. This means that skipping a state-changing instruction should leave the program in a secure state. Skipping a conditional branch which is part of an if-then construct will cause the then part to be executed in most cases. Because of that if-then constructs should always be designed to not be executed under normal conditions. Harden this code by applying aforementioned secure coding practices and by adding redundant checks of the condition."
        else:
            return "The faulted instruction is a conditional branch which is part of an if-then-else construct. Insecure states should be the exception in the program. This means that skipping a state-changing instruction should leave the program in a secure state. Skipping a conditional branch which is part of an if-then-else construct can cause the other part of the construct to be executed. Skipping an instruction in the header of an if-then-else construct should always result in a secure state. This can be achieved by changing the order of the then and else blocks and by adding redundant checks of the condition."

    if report.category == FaultCategory.ITE_3:
        if isinstance(report.related_constructs[report.affected_branches[0]], IfThen):
            return f"The faulted instruction {'MIGHT have affected' if ring_buffer_enabled else 'affects'} a conditional branch which is part of an if-then construct. It likely directly affects the condition check of a single construct. Harden this code by adding redundant checks of the condition."
        else:
            return f"The faulted instruction {'MIGHT have affected' if ring_buffer_enabled else 'affects'} a conditional branch which is part of an if-then-else construct. It likely directly affects the condition check of a single construct. Harden this code by changing the order of the then and else blocks and by adding redundant checks of the condition."
    
    if report.category == FaultCategory.MISC_BRANCH:
        return "The faulted instruction is an unconditional branch which probably does not belong to an if-then-else construct. Skipping this instruction alters the control flow of the program in a way which is unpredictable with the source code alone. Consequently, there is no straight-forward fix on the source code for this vulnerability. If this specific part of the firmware is written in Assembly, duplicating the branch instruction is sufficient as a mitigation. In any other case it might be sufficient to restructure the affected part of the firmware either through direct modifications of the source code or through compiler annotations."

    if report.category in [FaultCategory.MISC_LOAD, FaultCategory.MISC_STORE]:
        return f"The faulted instruction {'MIGHT have affected' if ring_buffer_enabled else 'affected'}  {'a conditional branch which is' if report.affected_branches == None or len(report.affected_branches) > 1 else 'some conditional branches which are'} part of one or multiple if-then-(else) constructs. The fault impacted the control flow by preventing a {'load' if report.category == FaultCategory.MISC_LOAD else 'store'} operation. This likely impacted a value which is later used in a condition of one or multiple if-then-(else) constructs. The fault does however not directly affect the condition check of a specific construct which means that the fault can only be prevented by securing the part of the program that calculates the faulted value which is used in the condition(s). Harden this code by performing the faulted {'load' if report.category == FaultCategory.MISC_LOAD else 'store'} operation redundantly{' and by comparing the results afterwards' if report.category == FaultCategory.MISC_STORE else ''}."

    if report.category == FaultCategory.MISC:
        return f"The faulted instruction {'MIGHT have affected' if ring_buffer_enabled else 'affected'} {'some conditional branches which are' if report.affected_branches and len(report.affected_branches) > 1 else 'a conditional branch which is'} part of one or multiple if-then-(else) constructs. The fault does likely not directly affect the condition check of a specific construct which means that the cause of the fault is unrelated to the identified constructs. Hardening this code against this fault in the source code is not straight-forward since its effects are complex and require understanding of the code. In general introducing redundancy to the code can fix this vulnerability, however this redundancy needs to be as fine-grained as possible in order to keep the perfomance impact small. If applicable however, the best solution is to design the program in a way that interventions during such computations will generate invalid results. This can for example be achieved by using complex constants for boolean values instead of the usual implementation where every value except 0 maps to True, or by using whitelists instead of blacklists etc."

    if report.category == FaultCategory.UNKNOWN:
        return "Unable to detect how the faulted instruction influences the control flow."

def get_rules():
    return [
        {
            'id': 'CFI_1',
            'name': 'Control Flow Integrity',
            'shortDescription': {
                'text': 'Violation of control-flow integrity possible'
            },
            'fullDescription': {
                'text': 'Lorem ipsum dolir sit amet consetutor'
            },
            'help': {
                'text': '',
                'markdown':
"""\
# Control Flow Integrity
## Fault Description
The faulted instruction is a function call. The fault causes the execution of the function to be fully skipped without causing any side effects.

## Mitigation
Harden this code by implementing a global counter that is saved locally and increased before each function call that should be protected. Every return instruction in that function needs to decrease that counter again before being executed. After the control flow has returned from the protected function the saved counter value is compared to the current value of the global counter and safely checked for equality. If this check fails, a panic needs to be triggered

## Implementation
Use the `FIH_CALL(f, ret, ...)` macro from the hardening header file to call the function and use the `FIH_RET(ret)` macro inside that function to return from it."
"""
            }
        }
    ]
