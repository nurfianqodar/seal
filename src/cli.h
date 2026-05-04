#ifndef SEAL_CLI_H_
#define SEAL_CLI_H_

#include "error.h"
#include <linux/limits.h>
#include <stdint.h>

#define SEAL_CLI_PWD_MAX 1024

enum seal_cli_mode {
	SEAL_CLI_MODE_ENCRYPT,
	SEAL_CLI_MODE_DECRYPT,
	SEAL_CLI_MODE_HELP,
};

struct seal_cli_config {
	enum seal_cli_mode mode;
	char ipath[PATH_MAX];
	char opath[PATH_MAX];
	char key_path[PATH_MAX];
	bool override;
	bool use_key_file;
};

seal_error seal_cli_config_parse(int argc, const char **argv,
				 struct seal_cli_config *out);

seal_error seal_cli_run(struct seal_cli_config *cfg);

void seal_cli_print_help(void);

#endif
