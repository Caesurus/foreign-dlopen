    .text
    .globl  z_fdl_entry
    .type   z_fdl_entry,@function
z_fdl_entry:
    andq    $-16, %rsp        # align RSP to 16-byte boundary
    call    fdl_entry_impl    # tail-jump into C body