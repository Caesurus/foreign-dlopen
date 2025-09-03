    .text
    .globl  z_fdl_entry
    .type   z_fdl_entry,@function
z_fdl_entry:
    andl    $-16, %esp        # align RSP to 16-byte boundary
    call    fdl_entry_impl    # tail-jump into C body