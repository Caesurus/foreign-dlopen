#include "fdl_resolve.h"
#include "z_syscalls.h"
#include "z_utils.h"
#include "elf_loader.h"
#include <stddef.h>

#ifndef MAPS_PATH
#define MAPS_PATH "/proc/self/maps"
#endif

static unsigned long text_base;
static const char *soname;

void *fdl_dlopen_sym(void *p)
{
    static void *g_fdl_dlopen = NULL;
    if (p)
        g_fdl_dlopen = p;
    return g_fdl_dlopen;
}

void *fdl_dlsym_sym(void *p)
{
    static void *g_fdl_dlsym = NULL;
    if (p)
        g_fdl_dlsym = p;
    return g_fdl_dlsym;
}

/* helper: turn a DT_* pointer/offset into an absolute VA */
static inline void *dyn_ptr(unsigned long base,
                            unsigned long lo, unsigned long hi,
                            unsigned long p)
{
    unsigned long v = p;
    /* if it's not already inside this module's mapped range, treat as offset */
    if (v < lo || v >= hi)
        v += base;
    return (void *)v;
}

static inline uint32_t u32_mod(uint32_t a, uint32_t m)
{
    if (m == 0)
        return 0;
    // shift-subtract reduction, no hardware/software div required
    // used to avoid __aeabi_uidivmod on arm..
    while (a >= m)
    {
        uint32_t t = m;
        /* grow t to the largest power-of-two multiple ≤ a */
        while ((t << 1) > t && (t << 1) <= a)
            t <<= 1;
        a -= t;
    }
    return a;
}

/* Minimal readers */
static int read_all(int fd, char *buf, int sz)
{
    int off = 0, n;
    while (off < sz && (n = z_read(fd, buf + off, sz - off)) > 0)
        off += n;
    return off;
}

/* parse one /proc/self/maps line; returns 0 on success */
static int parse_maps_line(const char *line,
                           unsigned long *start,
                           char perms_out[5],
                           unsigned long *offset,
                           const char **path_out)
{
    const char *p = line;
    unsigned long v = 0;
    int i;

    /* start */
    v = 0;
    for (; (*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'); p++)
        v = (v << 4) | (unsigned long)((*p <= '9') ? *p - '0' : (*p >= 'a' ? 10 + *p - 'a' : 10 + *p - 'A'));
    if (*p != '-')
        return -1;
    *start = v;
    p++;

    /* end (skip) */
    for (; (*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'); p++)
        ;
    while (*p == ' ')
        p++;

    /* perms (4 chars) */
    for (i = 0; i < 4; i++)
    {
        if (!p[i])
            return -1;
        perms_out[i] = p[i];
    }
    perms_out[4] = 0;
    p += 4;
    while (*p == ' ')
        p++;

    /* offset */
    v = 0;
    for (; (*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'); p++)
        v = (v << 4) | (unsigned long)((*p <= '9') ? *p - '0' : (*p >= 'a' ? 10 + *p - 'a' : 10 + *p - 'A'));
    *offset = v;

    /* skip dev */
    while (*p && *p != ' ')
        p++;
    while (*p == ' ')
        p++;
    /* skip inode */
    while (*p && *p != ' ')
        p++;
    while (*p == ' ')
        p++;

    /* path (may be empty) */
    *path_out = (*p) ? p : NULL;
    return 0;
}

/* Parse /proc/self/maps to find libc mapping with offset 0 */
static int find_libc_base(void)
{
    static int cached = 0;
    static unsigned long cached_base = 0;
    static const char *cached_name = NULL;

    if (cached)
    {
        text_base = cached_base;
        soname = cached_name;
        return 0;
    }

    int fd = z_open(MAPS_PATH, O_RDONLY);
    if (fd < 0)
        return -1;

    char buf[65536];
    int n = read_all(fd, buf, sizeof(buf) - 1);
    z_close(fd);
    if (n <= 0)
        return -1;
    buf[n] = 0;
    char *p = buf;
    while (*p)
    {
        char *line = p;
        while (*p && *p != '\n')
            p++;
        char save = *p;
        *p = 0;

        unsigned long start = 0, off = 0;
        char perms[5];
        const char *path = NULL;
        // z_printf("Line to check %s\n", line);
        if (z_strstr(line, "libc"))
        {
            // z_printf("Line with libc: %s\n", line);
            if (parse_maps_line(line, &start, perms, &off, &path) == 0 &&
                path && off == 0)
            {
                text_base = start;
                soname = path;
                z_fdprintf(2, "libc base 0x%lx @ %s\n", text_base, soname);
                cached = 1;
                cached_base = text_base;
                cached_name = soname;
                *p = save;
                return 0;
            }
        }

        *p = save;
        if (*p)
            p++;
    }
    return -1;
}

/* In-memory ELF helpers */
typedef struct
{
    Elf_Ehdr *eh;
    Elf_Phdr *ph;
    Elf_Dyn *dyn;
    unsigned long base;
    unsigned long nbucket, nchain;
    uint32_t *buckets, *chains;
    uint32_t *gnu_buckets;
    uint32_t *gnu_chain;
    uint32_t gnu_maskwords;
    uint32_t gnu_shift2;
    unsigned long *gnu_bloom;
    uint32_t gnu_nbucket;
    uint32_t gnu_symoffset;
    Elf_Sym *dynsym;
    const char *dynstr;
    uint16_t *versym;
} mod_t;

static int mod_init(mod_t *m, unsigned long base)
{
    m->base = base;
    m->eh = (Elf_Ehdr *)base;
    if (m->eh->e_ident[0] != 0x7f || m->eh->e_ident[1] != 'E' ||
        m->eh->e_ident[2] != 'L' || m->eh->e_ident[3] != 'F')
        return -1;

    m->ph = (Elf_Phdr *)(base + m->eh->e_phoff);
    z_fdprintf(2, "mod_init: base=0x%lx phoff=0x%lx phnum=%u entsz=%u\n",
               base, (unsigned long)m->eh->e_phoff,
               (unsigned)m->eh->e_phnum, (unsigned)m->eh->e_phentsize);

    unsigned long lo = ~0UL, hi = 0;
    for (int i = 0; i < m->eh->e_phnum; i++)
    {
        Elf_Phdr *ph = &m->ph[i];
        if (ph->p_type == PT_LOAD)
        {
            unsigned long seg_lo = base + ph->p_vaddr;
            unsigned long seg_hi = seg_lo + ph->p_memsz;
            if (seg_lo < lo)
                lo = seg_lo;
            if (seg_hi > hi)
                hi = seg_hi;
        }
    }

    m->dyn = NULL;
    for (int i = 0; i < m->eh->e_phnum; i++)
    {
        if (m->ph[i].p_type == PT_DYNAMIC)
        {
            unsigned long dyn_addr = base + m->ph[i].p_vaddr;
            if (dyn_addr < lo || dyn_addr + sizeof(Elf_Dyn) > hi)
            {
                z_fdprintf(2, "mod_init: PT_DYNAMIC out of range: 0x%lx [0x%lx..0x%lx)\n",
                           dyn_addr, lo, hi);
                return -1;
            }
            m->dyn = (Elf_Dyn *)dyn_addr;
            z_fdprintf(2, "mod_init: PT_DYNAMIC @ 0x%lx\n", dyn_addr);
            break;
        }
    }
    if (!m->dyn)
    {
        z_fdprintf(2, "mod_init: no PT_DYNAMIC\n");
        return -1;
    }

    for (Elf_Dyn *d = m->dyn; d->d_tag != DT_NULL; d++)
    {
        switch (d->d_tag)
        {
        case DT_STRTAB:
            m->dynstr = (const char *)dyn_ptr(base, lo, hi, (unsigned long)d->d_un.d_ptr);
            break;
        case DT_SYMTAB:
            m->dynsym = (Elf_Sym *)dyn_ptr(base, lo, hi, (unsigned long)d->d_un.d_ptr);
            break;
        case DT_HASH:
        {
            uint32_t *h = (uint32_t *)dyn_ptr(base, lo, hi, (unsigned long)d->d_un.d_ptr);
            m->nbucket = h[0];
            m->nchain = h[1];
            m->buckets = &h[2];
            m->chains = &h[2 + m->nbucket];
            break;
        }
        case DT_GNU_HASH:
        {
            uint32_t *gh = (uint32_t *)dyn_ptr(base, lo, hi, (unsigned long)d->d_un.d_ptr);
            m->gnu_nbucket = gh[0];
            m->gnu_symoffset = gh[1];
            m->gnu_maskwords = gh[2];
            m->gnu_shift2 = gh[3];
            m->gnu_bloom = (unsigned long *)(gh + 4);
            m->gnu_buckets = (uint32_t *)(m->gnu_bloom + m->gnu_maskwords);
            m->gnu_chain = (uint32_t *)(m->gnu_buckets + m->gnu_nbucket);
            break;
        }
        case DT_VERSYM:
            m->versym = (uint16_t *)dyn_ptr(base, lo, hi, (unsigned long)d->d_un.d_ptr);
            break;
        default:
            break;
        }
    }
    z_fdprintf(2, "mod_init: dynsym=%p dynstr=%p gnu_hash=%p sysv_hash=%p\n", m->dynsym, m->dynstr, m->gnu_buckets, m->buckets);

    return (m->dynsym && m->dynstr) ? 0 : -1;
}

static uint32_t sysv_hash(const char *s)
{
    uint32_t h = 0, g;
    while (*s)
    {
        h = (h << 4) + (unsigned char)*s++;
        g = h & 0xF0000000U;
        if (g)
            h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

static uint32_t gnu_hash_str(const char *s)
{
    uint32_t h = 5381;
    for (unsigned char c; (c = *s++) != 0;)
        h = (h * 33) + c;
    return h;
}

/* GNU hash lookup */
static Elf_Sym *lookup_gnu(mod_t *m, const char *name)
{
    if (!m->gnu_buckets)
        return NULL;
    uint32_t h = gnu_hash_str(name);
    size_t bloom_idx = (h / (sizeof(unsigned long) * 8)) & (m->gnu_maskwords - 1);
    unsigned long bitmask = (1UL << (h % (sizeof(unsigned long) * 8))) |
                            (1UL << ((h >> m->gnu_shift2) % (sizeof(unsigned long) * 8)));
    if ((m->gnu_bloom[bloom_idx] & bitmask) != bitmask)
        return NULL;

    uint32_t idx = m->gnu_buckets[u32_mod(h, m->gnu_nbucket)];
    if (!idx)
        return NULL;
    for (;;)
    {
        uint32_t hv = m->gnu_chain[idx - m->gnu_symoffset];
        if ((hv | 1U) == (h | 1U))
        {
            Elf_Sym *sym = &m->dynsym[idx];
            if (sym->st_name && !z_strcmp(m->dynstr + sym->st_name, name))
                return sym;
        }
        if (hv & 1U)
            break;
        idx++;
    }
    return NULL;
}

/* SysV hash lookup */
static Elf_Sym *lookup_sysv(mod_t *m, const char *name)
{
    if (!m->buckets)
        return NULL;
    uint32_t h = sysv_hash(name);
    for (uint32_t i = m->buckets[u32_mod(h, m->nbucket)]; i != 0; i = m->chains[i])
    {
        Elf_Sym *sym = &m->dynsym[i];
        if (sym->st_name && !z_strcmp(m->dynstr + sym->st_name, name))
            return sym;
    }
    return NULL;
}

static void *resolve_sym(mod_t *m, const char *name)
{
    Elf_Sym *s = NULL;
    //z_printf("resolve_sym: %s\n", name);

    if (!s)
    {
        //z_printf("lookup_gnu\n");
        s = lookup_gnu(m, name);
    }
    if (!s)
    {
        //z_printf("lookup_sysv\n");
        s = lookup_sysv(m, name);
    }
    if (!s)
    {
        //z_printf("symbol not found\n");
        return NULL;
    }
    if (ELF_ST_TYPE(s->st_info) != STT_FUNC && ELF_ST_TYPE(s->st_info) != STT_GNU_IFUNC)
    {
        return NULL;
    }
    return (void *)(m->base + s->st_value);
}

int fdl_resolve_from_maps(unsigned long interp_base)
{
    if (find_libc_base() < 0)
    {
        if (interp_base)
        {
            z_printf("Falling back to the interpreter, for muslc the loader/libc are the same \n");
            text_base = interp_base;
        }
        else
        {
            return -1;
        }
    }

    mod_t M;
    z_memset(&M, 0, sizeof(M));
    if (mod_init(&M, text_base) < 0)
        return -1;
        
    /* glibc: prefer __libc_dlopen_mode; fallback to dlopen/dlsym */
    void *dlopen = resolve_sym(&M, "__libc_dlopen_mode");
    if (!dlopen)
        dlopen = resolve_sym(&M, "dlopen");

    void *dlsym = resolve_sym(&M, "dlsym");

    fdl_dlopen_sym(dlopen);
    fdl_dlsym_sym(dlsym);
    return (dlopen && dlsym) ? 0 : -1;
}
