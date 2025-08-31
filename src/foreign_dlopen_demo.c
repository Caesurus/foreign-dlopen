#include "z_utils.h"
#include "z_syscalls.h"
#include "elf_loader.h"

#define DL_APP_DEFAULT "/bin/sleep"

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	const char *app;
	if (argc > 1 && argv[1] && argv[1][0]) {
		app = argv[1];
	} else {
		app = DL_APP_DEFAULT;
	}

	char *targv[] = { (char *)app, (char *)"x" };
	exec_elf(app, 2, targv);

	z_exit(0);
}
