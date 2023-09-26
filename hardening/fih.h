
#define FIH_SUCCESS 0x1AAAAAAA
#define FIH_FAILURE 0x15555555

__attribute__((noinline)) __attribute__((used))
void fih_panic_loop(void);
#define FIH_PANIC fih_panic_loop()

#define FIH_EQ(x, y) ((x == y) && !(y != x))
#define FIH_NOT_EQ(x, y) ((x != y) || !(y == x))
#define FIH_LT(x, y) ((x < y) && !(y <= x))
#define FIH_GT(x, y) ((x > y) && !(y >= x))
#define FIH_LTE(x, y) ((x <= y) && !(y < x))
#define FIH_GTE(x, y) ((x >= y) && !(y > x))
#define FIH_SET(x, y) x = y; if(x != y) FIH_PANIC


extern int _fih_cfi_ctr;

int fih_cfi_get_and_increment(void);
void fih_cfi_validate(int saved);
void fih_cfi_decrement(void);

#define FIH_CALL(f, ret, ...) \
    do { \
        FIH_CFI_PRECALL_BLOCK; \
        ret = FIH_FAILURE; \
	ret = f(__VA_ARGS__); \
        FIH_CFI_POSTCALL_BLOCK; \
    } while (0)

#define FIH_RET(ret) \
    do { \
        FIH_CFI_PRERET; \
        return ret; \
    } while (0)

#define FIH_RET_2(ret) \
    volatile char ____decoy____ = 1; \
    if (__builtin_expect(____decoy____, 1)) { \
        FIH_CFI_PRERET; \
        return ret; \
    } \
    FIH_PANIC;

#define FIH_RET_3(ret) \
    volatile char ____decoy____ = 1; \
    if (__builtin_expect(____decoy____, 1)) { \
        return ret; \
    } \
    FIH_PANIC;

#define CONCAT_IMPL( x, y ) x##y
#define MACRO_CONCAT( x, y ) CONCAT_IMPL( x, y )

#define FIH_FUNCTION_BARRIER \
    __attribute__((used, noinline)) void MACRO_CONCAT(__function_barrier, __COUNTER__)() { \
	FIH_PANIC; \
    }

#define FIH_CFI_PRECALL_BLOCK \
    int _fih_cfi_saved_value = fih_cfi_get_and_increment()

#define FIH_CFI_POSTCALL_BLOCK \
    fih_cfi_validate(_fih_cfi_saved_value)

#define FIH_CFI_PRERET \
    fih_cfi_decrement()

