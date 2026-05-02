#include "cli.h"
#include "error.h"
#include "seal.h"
#include <bits/getopt_core.h>
#include <getopt.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static seal_error seal_cli_mode_from_str(const char *str,
					 enum seal_cli_mode *mode)
{
	if (strcmp(str, "e") == 0 || strcmp(str, "encrypt") == 0) {
		*mode = SEAL_CLI_MODE_ENCRYPT;
		return SEAL_OK;
	}
	if (strcmp(str, "d") == 0 || strcmp(str, "decrypt") == 0) {
		*mode = SEAL_CLI_MODE_DECRYPT;
		return SEAL_OK;
	}
	seal_error_set_msg("invalid argument");
	return SEAL_E_INVAL;
}

static const struct option long_options[] = {
	{ "input", required_argument, 0, 'i' },
	{ "output", required_argument, 0, 'o' },
	{ "override", required_argument, 0, 'O' },
	{ 0, 0, 0, 0 },
};
static const char *short_options = "i:o:O";

seal_error seal_cli_config_parse(int argc, const char **argv,
				 struct seal_cli_config *out)
{
	if (argc < 2) {
		seal_error_set_msg("argument not enough");
		return SEAL_E_INVAL;
	}

	int ret;
	const char *mode_str = argv[1];

	ret = seal_cli_mode_from_str(mode_str, &out->mode);
	if (ret != SEAL_OK) {
		return ret;
	}

	optind = 2;

	int opt;
	int options_idx = 0;

	while ((opt = getopt_long(argc, (char **)argv, short_options,
				  long_options, &options_idx)) != -1) {
		switch (opt) {
		case 'i':
			out->ipath = optarg;
			break;
		case 'o':
			out->opath = optarg;
			break;
		case 'O':
			out->override = true;
			break;
		case '?':
		case ':':
		default:
			seal_error_set_msg("invalid argument");
			return SEAL_E_INVAL;
		}
	}

	if (!out->ipath) {
		seal_error_set_msg("input path required");
		return SEAL_E_INVAL;
	}

	return SEAL_OK;
}

seal_error seal_cli_run(struct seal_cli_config *cfg)
{
	char *pwd = getpass("password: ");
	size_t pwd_len = strlen(pwd);

	seal_error ret;

	switch (cfg->mode) {
	case SEAL_CLI_MODE_ENCRYPT: {
		char *pwd_rt;
		pwd_rt = getpass("confirm password: ");

		if (strcmp(pwd, pwd_rt) != 0) {
			seal_error_set_msg("password not match");
			return SEAL_E_INVAL;
		}
		ret = seal_encrypt(cfg->ipath, cfg->opath, (const uint8_t *)pwd,
				   pwd_len, cfg->override);
		if (ret != SEAL_OK) {
			return ret;
		}
		break;
	}
	case SEAL_CLI_MODE_DECRYPT: {
		ret = seal_decrypt(cfg->ipath, cfg->opath, (const uint8_t *)pwd,
				   pwd_len, cfg->override);
		if (ret != SEAL_OK) {
			return ret;
		}
		break;
	}
	}
	return SEAL_OK;
}
