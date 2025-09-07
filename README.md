# foreign-dlopen

Fork from [pfalcon/foreign-dlopen](https://github.com/pfalcon/foreign-dlopen).
Please see [Details](#details) for how this fork deviates from the original.

Some general notes:
- The original project has a #define for being able to use STDLIB. This has
been removed here. It's not needed, and therefore can be eliminated.
- This PoC was created and tested on a Linux 6.x Kernel with GLIBC 2.40-3.
The parsing of the maps "file" and the locating of the symbols will possibly
differ on different systems with different libc implementations, porting to
those systems is left as future work.
- Limited testing has been done, this is a weekend project and I don't have
time to pour into this, it's provided as-is. Contributions welcome.
- If you find something that's broken, feel free to fix and issue a pull request.

## Intro

Calling dlopen() function from statically-linked binaries is a well-known
(in narrow circles) problem [*](#references). A common approach is not
supporting it at all. A usual explanation goes along the lines of:

1. You usually link statically to exclude unneeded functions from the binary.
2. But if you want to dynamically load a shared library, it likely itself
is linked dynamically against libc (doing otherwise requires extra legwork,
and if you have a few such shared libraries, themselves statically linked,
you duplicate code in each).
3. But that means you would need to carry around (big) libc.so, which
undermines the original idea of static linking (you could link your app
against dynamic libc and save space).
4. Alternatively, you could link entire libc into your static executable,
and export dynamic symbols (`ld --export-dynamic`). That avoids carrying
around extra libc.so file, but again requires extra legwork. And it still
undermines the original benefit of static linking, as your app will be
the size of libc.so (+ your app's code).

The summary is that if you want to use dlopen() from static binary,
you would need to do extra legwork, and would lose benefits of static
linking. Ergo, don't use dlopen() with static linking, use dynamic linking
instead! And as no reasonable person would use dlopen() with static linking,
let's remove dlopen() (and that's entire dynamic loader, quite a bloaty
piece of code!) support from statically linked libc, to let people who really
need static linking, reap the maximum benefits of it.

Those are all very valid arguments, but they are all based on a "plugin"
model: you have a common system, sharing a common libc.

That's not the only usage model though. There's another model, which we'll
call "FFI (Foreign Function Interface) model". It goes along the lines of:

1. Suppose you have a perfect, closed world application. Statically linked
of course.
2. But you want to go out to ~~dirty~~ bustling outside world (in other
words, let your application, or users of your application, to dlopen()
outside shared libraries).
3. There are absolutely no expectations or stipulations about which libc
is used by those shared libraries. In particular, there's no expectations
that libc of your application and external shared lib are the same. Or
that you know which libc is used by external lib at all. For example,
your static binary may be linked against musl libc, but you may want
to load (allow to load) glibc bloat lying in abundance on a typical Linux
system.

Again, the only thing you want is to maintain your static perfect world,
independent from outside hustle. But, at user discretion, you want to
allow this hustling outside world into your address space, by means of
dlopen().

This cute project is a proof-of-concept solution for this usecase.

### References

* https://www.openwall.com/lists/musl/2012/12/08/4

## Details

Make ld.so load an executable which will jump back into our custom
loader. This way, both ld.so will be initialized, and we get back control.

This is where this fork deviates from the original project. The excellent
original project `pfalcon/foreign-dlopen` uses a custom helper, coupled with
`setjmp`/`longjmp`. The usage of having to pass the helper an address via argv
and having the `setjmp`/`longjmp` works but ideally we don't want to have to
create a helper per system that we're deploying to, since that requires
building and linking against the target libc's ld. Ideally we'd like to
use a "helper" already on the system, that we do not have control over.

So how do we achieve this?

Its structure is:

1. Custom ELF loader, built against any libc or lack thereof. This should be
simplified loader, without support for loading shared libs, etc. The only
thing it needs to load is a "helper" target executable and its INTERP.

2. The ELF loader loads the relevant sections into memory, but before it calls
into INTERP, we can hijack the ENTRY and overwrite it with our own. This allows
us to run INTERP, and then regain execution control in our code.

3. The "helper" binary should be linked against native libc of the target
environment whose shared libs we want to load (e.g., glibc). But this binary
can be any existing dynamically linked binary on the system, eg: /bin/sleep

4. Target binary is now also linked against target libc's libdl, but our entry
function is called and we regain execution control. Now the harder part... we
will need to locate the dlopen/dlsym locations ourselves.

5. Parse the `/proc/self/maps` file to determine what libc is used and its base
address.

6. With the base address, parse libc’s ELF headers in memory to locate the
`.dynsym`, `.dynstr`, and hash tables (`.gnu.hash` / `.hash`).
Using these, resolve symbol addresses for functions like `dlopen`, `dlsym`.

7. From there, we can directly call `dlopen()` on shared libraries on the system,
use `dlsym()` to resolve additional symbols (like `printf`), and interact with
them as if it were dynamically linked, all while keeping the main binary
statically self-contained. Note, the stack won't necessarily be 16 byte aligned
so we will need to ensure it is before calling the functions in libc.


## Building and running

1. `cd src`
2. Build static, stdlib-less sample application: `make`.
4. Run the sample: `./foreign_dlopen_demo`. While it is static, it will
dynamically load `libc.so.6` and call `printf()` from it.

### Armv7

1. `cd src`
2. Use crosscompile toolchain of your choice. Here is a simple one you can use.
```bash
docker run --rm dockcross/linux-armv7l-musl:latest > ./dockcross && chmod +x ./dockcross
sudo ./dockcross make clean all
```


## Credits

"Foreign dlopen" idea and implementation is by Paul Sokolovsky. The
implementation is based on the ELF loader by Mikhail Ilyin:
https://github.com/MikhailProg/elf.

The original project this was forked from:
https://github.com/pfalcon/foreign-dlopen
---
