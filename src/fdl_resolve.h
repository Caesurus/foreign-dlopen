#ifndef FDL_RESOLVE_H
#define FDL_RESOLVE_H

#include "z_elf.h"
#include <stdint.h>

extern void *fdl_dlopen;
extern void *fdl_dlsym;

int fdl_resolve_from_maps(void);

#endif /* FDL_RESOLVE_H */
