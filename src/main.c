#include "cli.h"
#include "error.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int main(int argc, const char **argv)
{
	struct seal_cli_config cfg;
	int ret;
	ret = seal_cli_config_parse(argc, argv, &cfg);
	if (ret != SEAL_OK) {
		printf("%s\n", seal_error_get_msg());
		return ret;
	}
	ret = seal_cli_run(&cfg);
	if (ret != SEAL_OK) {
		printf("%s\n", seal_error_get_msg());
		return ret;
	}
	return SEAL_OK;
}
