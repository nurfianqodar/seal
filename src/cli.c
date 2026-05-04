#include "cli.h"
#include "error.h"
#include "seal.h"
#include "util.h"
#include <getopt.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *help_message = //
	"USAGE:\n"
	"\tseal <MODE> [OPTIONS]\n"
	"MODE:\n"
	"\tencrypt, e\tEncrypt file\n"
	"\tdecrypt, d\tDecrypt file\n"
	"\thelp, h\t\tShow this message\n"
	"OPTIONS:\n"
	"\t-i, --input PATH\tInput file path (required)\n"
	"\t-o, --output PATH\tOutput file path (required)\n"
	"\t-O, --override\t\tOverride output file if exists\n";

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
	if (strcmp(str, "h") == 0 || strcmp(str, "help") == 0) {
		*mode = SEAL_CLI_MODE_HELP;
		return SEAL_OK;
	}
	seal_error_set_msg("invalid argument");
	return SEAL_E_INVAL;
}

static seal_error seal_cli_promt_password(uint8_t *out, size_t *out_len,
					  bool confirm)
{
	char *pwd = getpass("password: ");
	snprintf((char *)out, SEAL_CLI_PWD_MAX, "%s", pwd);
	out[SEAL_CLI_PWD_MAX - 1] = '\0';
	*out_len = strnlen(pwd, SEAL_CLI_PWD_MAX);

	if (confirm) {
		seal_memzero(pwd, *out_len);
		char *pwd = getpass("confirm password: ");
		if (!seal_memequal(out, pwd, *out_len)) {
			seal_error_set_msg("password not match");
			return SEAL_E_INVAL;
		}
		seal_memzero(pwd, *out_len);
	}
	return SEAL_OK;
}

static const struct option long_options[] = {
	{ "input", required_argument, 0, 'i' },
	{ "output", required_argument, 0, 'o' },
	{ "override", no_argument, 0, 'O' },
	{ 0, 0, 0, 0 },
};
static const char *short_options = "i:o:O";

seal_error seal_cli_config_parse(int argc, const char **argv,
				 struct seal_cli_config *out)
{
	if (!out)
		return seal_error_set_msg("out cannot null"), SEAL_E_INVAL;

	if (argc < 2)
		return seal_error_set_msg("argument not enough"), SEAL_E_INVAL;

	seal_error ret;

	const char *mode_str = argv[1];
	if ((ret = seal_cli_mode_from_str(mode_str, &out->mode)) != SEAL_OK)
		return ret;

	if (out->mode == SEAL_CLI_MODE_HELP)
		return SEAL_OK;

	optind = 2;

	int opt;
	int options_idx = 0;

	out->override = false;
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

	if (!out->opath) {
		out->opath = out->ipath;
	}

	return SEAL_OK;
}

seal_error seal_cli_run(struct seal_cli_config *cfg)
{
	seal_error ret = SEAL_OK;
	switch (cfg->mode) {
	case SEAL_CLI_MODE_HELP: {
		seal_cli_print_help();
		ret = SEAL_OK;
		break;
	}
	case SEAL_CLI_MODE_ENCRYPT: {
		uint8_t pwd[SEAL_CLI_PWD_MAX];
		size_t pwd_len;
		ret = seal_cli_promt_password(pwd, &pwd_len, true);
		if (ret != SEAL_OK) {
			goto done_enc;
		}
		ret = seal_encrypt(cfg->ipath, cfg->opath, (const uint8_t *)pwd,
				   pwd_len, cfg->override);
		if (ret != SEAL_OK) {
			goto done_enc;
		}
done_enc:
		seal_memzero(pwd, SEAL_CLI_PWD_MAX);
		seal_memzero(&pwd_len, sizeof pwd_len);
		break;
	}
	case SEAL_CLI_MODE_DECRYPT: {
		uint8_t pwd[SEAL_CLI_PWD_MAX];
		size_t pwd_len;
		ret = seal_cli_promt_password(pwd, &pwd_len, false);
		if (ret != SEAL_OK) {
			goto done_dec;
		}
		ret = seal_decrypt(cfg->ipath, cfg->opath, (const uint8_t *)pwd,
				   pwd_len, cfg->override);
		if (ret != SEAL_OK) {
			goto done_dec;
		}
done_dec:
		seal_memzero(pwd, SEAL_CLI_PWD_MAX);
		seal_memzero(&pwd_len, sizeof pwd_len);
		break;
	}
	}
	return ret;
}

void seal_cli_print_help(void)
{
	printf("%s", help_message);
}
