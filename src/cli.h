#ifndef SEAL_CLI_H_
#define SEAL_CLI_H_

#include "error.h"
#include <stdint.h>

#define SEAL_CLI_PWD_MAX 1024

enum seal_cli_mode {
	SEAL_CLI_MODE_ENCRYPT,
	SEAL_CLI_MODE_DECRYPT,
	SEAL_CLI_MODE_HELP,
};

struct seal_cli_config {
	enum seal_cli_mode mode;
	const char *ipath;
	const char *opath;
	bool override;
};

seal_error seal_cli_config_parse(int argc, const char **argv,
				 struct seal_cli_config *out);

seal_error seal_cli_run(struct seal_cli_config *cfg);

void seal_cli_print_help(void);

#endif
