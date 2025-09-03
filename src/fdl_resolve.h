#ifndef FDL_RESOLVE_H
#define FDL_RESOLVE_H

#include "z_elf.h"
#include <stdint.h>

extern void *fdl_dlopen;
extern void *fdl_dlsym;

int fdl_resolve_from_maps(unsigned long interp_base);
void *fdl_dlopen_sym(void *p);
void *fdl_dlsym_sym(void *p);

#endif /* FDL_RESOLVE_H */
