/* Source-owned position-independent analysis fixture. Never execute this target. */
volatile unsigned int rea_riscv_pie_global = 7;
volatile unsigned int *rea_riscv_pie_pointer = &rea_riscv_pie_global;

__attribute__((noinline)) unsigned int rea_riscv_pie_entry(unsigned int value)
{
    return value + *rea_riscv_pie_pointer;
}
