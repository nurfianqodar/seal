#include "cli.h"
#include "error.h"
#include "file.h"
#include "seal.h"
#include "util.h"
#include <getopt.h>
#include <linux/limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
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
	"\t-O, --override\t\tOverride output file if exists\n"
	"\t-k, --key\t\tUse key file\n";

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
	{ "key", required_argument, 0, 'k' },
	{ "override", no_argument, 0, 'O' },
	{ 0, 0, 0, 0 },
};
static const char *short_options = "i:o:k:O";

seal_error seal_cli_config_parse(int argc, const char **argv,
				 struct seal_cli_config *out)
{
	if (!out)
		return seal_error_set_msg("out cannot null"), SEAL_E_INVAL;
	if (argc < 2)
		return seal_error_set_msg("argument not enough"), SEAL_E_INVAL;
	seal_memzero(out, sizeof *out);

	seal_error ret;

	const char *mode_str = argv[1];
	if ((ret = seal_cli_mode_from_str(mode_str, &out->mode)) != SEAL_OK)
		return ret;

	if (out->mode == SEAL_CLI_MODE_HELP)
		return SEAL_OK;

	optind = 2;

	int opt;
	int options_idx = 0;

	bool has_ipath, has_opath, has_key_path, has_override;
	has_ipath = has_opath = has_key_path = has_override = false;

	out->override = false;
	while ((opt = getopt_long(argc, (char **)argv, short_options,
				  long_options, &options_idx)) != -1) {
		switch (opt) {
		case 'i':
			if (snprintf(out->ipath, PATH_MAX, "%s", optarg) >=
			    PATH_MAX)
				return seal_error_set_msg("path too long"),
				       SEAL_E_INVAL;
			out->ipath[PATH_MAX - 1] = '\0';
			has_ipath = true;
			break;
		case 'o':
			if (snprintf(out->opath, PATH_MAX, "%s", optarg) >=
			    PATH_MAX)
				return seal_error_set_msg("path too long"),
				       SEAL_E_INVAL;
			out->opath[PATH_MAX - 1] = '\0';
			has_opath = true;
			break;
		case 'k':
			if (snprintf(out->key_path, PATH_MAX, "%s", optarg) >=
			    PATH_MAX)
				return seal_error_set_msg("path too long"),
				       SEAL_E_INVAL;
			out->key_path[PATH_MAX - 1] = '\0';
			has_key_path = true;
			break;
		case 'O':
			out->override = true;
			has_override = true;
			break;
		case '?':
		case ':':
		default:
			seal_error_set_msg("invalid argument");
			return SEAL_E_INVAL;
		}
	}

	if (!has_ipath)
		return seal_error_set_msg("input path required"), SEAL_E_INVAL;
	if (!has_opath)
		strncpy(out->opath, out->ipath, PATH_MAX);
	if (has_key_path)
		out->use_key_file = true;
	if (has_override)
		out->override = true;

	return SEAL_OK;
}

static seal_error seal_cli_read_password_file(const char *path, uint8_t *out,
					      size_t *out_len)
{
	struct stat st;
	if (stat(path, &st) != 0)
		return seal_error_set_msg("unable to open key file"),
		       SEAL_E_OPEN;

	size_t len = (size_t)st.st_size;

	if (len > SEAL_CLI_PWD_MAX)
		return seal_error_set_msg("key file too large"), SEAL_E_INVAL;

	FILE *file = fopen(path, "rb");
	if (!file)
		return seal_error_set_msg("unable to open key file"),
		       SEAL_E_OPEN;

	seal_error ret;

	if ((ret = seal_file_read_exact(file, out, len)) != SEAL_OK) {
		seal_error_set_msg("read key file error");
		fclose(file);
		return ret;
	}
	*out_len = len;

	fclose(file);
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
	} // end case SEAL_CLI_MODE_HELP
	case SEAL_CLI_MODE_ENCRYPT: {
		uint8_t pwd[SEAL_CLI_PWD_MAX];
		size_t pwd_len;
		if (cfg->use_key_file) {
			if ((ret = seal_cli_read_password_file(
				     cfg->key_path, pwd, &pwd_len)) != SEAL_OK)
				return ret;
		} else {
			if ((ret = seal_cli_promt_password(pwd, &pwd_len,
							   true)) != SEAL_OK)
				return ret;
		}
		if ((ret = seal_encrypt(cfg->ipath, cfg->opath,
					(const uint8_t *)pwd, pwd_len,
					cfg->override)) != SEAL_OK) {
			seal_memzero(pwd, SEAL_CLI_PWD_MAX);
			seal_memzero(&pwd_len, sizeof pwd_len);
		}
		seal_memzero(pwd, SEAL_CLI_PWD_MAX);
		seal_memzero(&pwd_len, sizeof pwd_len);
		break;
	} // end case SEAL_CLI_MODE_ENCRYPT
	case SEAL_CLI_MODE_DECRYPT: {
		uint8_t pwd[SEAL_CLI_PWD_MAX];
		size_t pwd_len;
		if (cfg->use_key_file) {
			if ((ret = seal_cli_read_password_file(
				     cfg->key_path, pwd, &pwd_len)) != SEAL_OK)
				return ret;
		} else {
			if ((ret = seal_cli_promt_password(pwd, &pwd_len,
							   false)) != SEAL_OK)
				return ret;
		}
		if ((ret = seal_decrypt(cfg->ipath, cfg->opath,
					(const uint8_t *)pwd, pwd_len,
					cfg->override)) != SEAL_OK) {
			seal_memzero(pwd, SEAL_CLI_PWD_MAX);
			seal_memzero(&pwd_len, sizeof pwd_len);
			return ret;
		}
		seal_memzero(pwd, SEAL_CLI_PWD_MAX);
		seal_memzero(&pwd_len, sizeof pwd_len);
		break;
	} // end case SEAL_CLI_MODE_DECRYPT
	default:
		return seal_error_set_msg("invalid cli mode"), SEAL_E_INVAL;
	}
	return ret;
}

void seal_cli_print_help(void)
{
	printf("%s", help_message);
}
