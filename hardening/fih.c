#include "fih.h"

int _fih_cfi_ctr = 0;

/* Increment the CFI counter by one, and return the value before the increment.
 */
int fih_cfi_get_and_increment(void)
{
    int saved = _fih_cfi_ctr;
    _fih_cfi_ctr = saved + 1;
    return saved;
}

/* Validate that the saved precall value is the same as the value of the global
 * counter. For this to be the case, a fih_ret must have been called between
 * these functions being executed. If the values aren't the same then panic.
 */
void fih_cfi_validate(int saved)
{
    if (saved != _fih_cfi_ctr) {
        FIH_PANIC;
    }
}

/* Decrement the global CFI counter by one, so that it has the same value as
 * before the cfi_precall
 */
void fih_cfi_decrement(void)
{
    _fih_cfi_ctr = _fih_cfi_ctr - 1;
}

/* Global failure loop for bootloader code. Uses attribute used to prevent
 * compiler removing due to non-standard calling procedure. Multiple loop jumps
 * used to make unlooping difficult.
 */
__attribute__((used))
__attribute__((noinline))
void fih_panic_loop(void)
{
    __asm volatile ("j fih_panic_loop");
    __asm volatile ("j fih_panic_loop");
    __asm volatile ("j fih_panic_loop");
    __asm volatile ("j fih_panic_loop");
    __asm volatile ("j fih_panic_loop");
    __asm volatile ("j fih_panic_loop");
    __asm volatile ("j fih_panic_loop");
    __asm volatile ("j fih_panic_loop");
    __asm volatile ("j fih_panic_loop");
}

