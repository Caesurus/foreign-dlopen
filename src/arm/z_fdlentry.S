    .syntax unified
    .text
    .align  2
    .global z_fdl_entry
    .type   z_fdl_entry,%function
    .arm                @ force ARM mode, supports the immediate
z_fdl_entry:
    mov   r12, sp
    bic   sp, sp, #7 
    mov   sp,  r12
    add   sp, #4
    b     fdl_entry_impl