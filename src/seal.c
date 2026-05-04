#include "seal.h"
#include "chunk.h"
#include "cipher.h"
#include "define.h"
#include "error.h"
#include "file.h"
#include "header.h"
#include "util.h"
#include <assert.h>
#include <linux/limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static seal_error seal_do_encrypt(FILE *ifile, FILE *ofile, const uint8_t *pwd,
				  size_t pwd_len)
{
	assert(ifile != NULL);
	assert(ofile != NULL);
	assert(pwd != NULL);

	if (pwd_len == 0)
		return seal_error_set_msg("password cannot empty"),
		       SEAL_E_INVAL;

	seal_error ret = SEAL_OK;

	struct seal_cipher cipher;
	struct seal_header header;

	seal_header_init(&header);

	ret = seal_cipher_init(&cipher, &header, pwd, pwd_len);
	if (ret != SEAL_OK)
		goto cleanup;

	if ((ret = seal_file_write_exact(ofile, SEAL_MAGIC, SEAL_MAGIC_LEN)) !=
	    SEAL_OK)
		goto cleanup;

	if ((ret = seal_file_write_header(ofile, &header)) != SEAL_OK)
		goto cleanup;

	struct seal_chunk chunk;

	while (true) {
		if ((ret = seal_file_read_chunk(
			     ifile, &chunk, SEAL_CHUNK_MODE_PLAIN)) != SEAL_OK)
			goto cleanup;
		if (chunk.len == 0)
			break;
		if ((ret = seal_chunk_encrypt(&chunk, &cipher)) != SEAL_OK)
			goto cleanup;
		if ((ret = seal_file_write_chunk(ofile, &chunk)) != SEAL_OK)
			goto cleanup;
	}

	ret = seal_file_flush(ofile);

cleanup:
	seal_memzero(&chunk, sizeof chunk);
	seal_memzero(&cipher, sizeof cipher);
	seal_memzero(&header, sizeof header);
	return ret;
}

static seal_error seal_do_decrypt(FILE *ifile, FILE *ofile, const uint8_t *pwd,
				  size_t pwd_len)
{
	assert(ifile != NULL);
	assert(ofile != NULL);
	assert(pwd != NULL);

	if (pwd_len == 0)
		return seal_error_set_msg("password cannot empty"),
		       SEAL_E_INVAL;

	seal_error ret = SEAL_OK;

	struct seal_cipher cipher;
	struct seal_header header;

	if ((ret = seal_file_read_header(ifile, &header)) != SEAL_OK)
		goto cleanup;

	if ((ret = seal_cipher_init(&cipher, &header, pwd, pwd_len)) != SEAL_OK)
		goto cleanup;

	struct seal_chunk chunk;

	while (true) {
		if ((ret = seal_file_read_chunk(
			     ifile, &chunk, SEAL_CHUNK_MODE_CIPHER)) != SEAL_OK)
			goto cleanup;

		if (chunk.len == 0) {
			break;
		}

		if ((ret = seal_chunk_decrypt(&chunk, &cipher)) != SEAL_OK)
			goto cleanup;

		if ((ret = seal_file_write_chunk(ofile, &chunk)) != SEAL_OK)
			goto cleanup;
	}

	ret = seal_file_flush(ofile);

cleanup:
	seal_memzero(&chunk, sizeof chunk);
	seal_memzero(&cipher, sizeof cipher);
	seal_memzero(&header, sizeof header);
	return ret;
}

static void gen_tmp_path(const char *orig, char *tmp)
{
	assert(orig != NULL);
	assert(tmp != NULL);

	const char *last_slash = strrchr(orig, '/');
	size_t dir_len = 0;

	if (last_slash) {
		dir_len = last_slash - orig;
	} else {
		dir_len = 1;
	}

	char rand_str[32];
	snprintf(rand_str, sizeof(rand_str), "%ld_%d", time(NULL), getpid());
	if (last_slash) {
		snprintf(tmp, PATH_MAX, "%.*s/%s", (int)dir_len, orig,
			 rand_str);
	} else {
		snprintf(tmp, PATH_MAX, "./%s", rand_str);
	}
}

seal_error seal_encrypt(const char *_ipath, const char *_opath,
			const uint8_t *pwd, size_t pwd_len, bool override)
{
	char ipath[PATH_MAX], opath[PATH_MAX], tmp_opath[PATH_MAX];

	if (snprintf(ipath, PATH_MAX, "%s", _ipath) >= PATH_MAX)
		return seal_error_set_msg("input path too long"), SEAL_E_INVAL;

	if (snprintf(opath, PATH_MAX, "%s", _opath) >= PATH_MAX)
		return seal_error_set_msg("output path too long"), SEAL_E_INVAL;

	gen_tmp_path(opath, tmp_opath);

	seal_error ret;

	if (seal_file_path_is_exists(opath) && !override) {
		seal_error_set_msg("output file already exists");
		return SEAL_E_EXISTS;
	}

	FILE *ifile = NULL, *ofile = NULL;

	if ((ret = seal_file_open(&ifile, ipath, SEAL_FILE_MODE_PLAIN)) !=
	    SEAL_OK)
		return ret;

	if ((ret = seal_file_create(&ofile, tmp_opath, false)) != SEAL_OK)
		goto close_input;

	if ((ret = seal_do_encrypt(ifile, ofile, pwd, pwd_len)) != SEAL_OK)
		goto cleanup;

	if (0 != rename(tmp_opath, opath)) {
		ret = SEAL_E_MOVE;
		seal_error_set_msg("unable to move tmp to output");
		goto cleanup;
	}

cleanup:
	seal_file_close(&ofile);
	if (ret != SEAL_OK) {
		remove(tmp_opath);
	}
close_input:
	seal_file_close(&ifile);
	return ret;
}

seal_error seal_decrypt(const char *_ipath, const char *_opath,
			const uint8_t *pwd, size_t pwd_len, bool override)
{
	seal_error ret = SEAL_OK;
	char ipath[PATH_MAX], opath[PATH_MAX], tmp_opath[PATH_MAX];

	if (snprintf(ipath, PATH_MAX, "%s", _ipath) >= PATH_MAX)
		return seal_error_set_msg("input path too long"), SEAL_E_INVAL;

	if (snprintf(opath, PATH_MAX, "%s", _opath) >= PATH_MAX)
		return seal_error_set_msg("output path too long"), SEAL_E_INVAL;

	gen_tmp_path(opath, tmp_opath);

	if (seal_file_path_is_exists(opath) && !override) {
		seal_error_set_msg("output file already exists");
		return SEAL_E_EXISTS;
	}

	FILE *ifile = NULL, *ofile = NULL;

	if ((ret = seal_file_open(&ifile, ipath, SEAL_FILE_MODE_CIPHER)) !=
	    SEAL_OK)
		return ret;

	if ((ret = seal_file_create(&ofile, tmp_opath, false)) != SEAL_OK)
		goto close_input;

	if ((ret = seal_do_decrypt(ifile, ofile, pwd, pwd_len)) != SEAL_OK)
		goto cleanup;

	if (0 != rename(tmp_opath, opath)) {
		ret = SEAL_E_MOVE;
		seal_error_set_msg("unable to create output from tmp");
		goto cleanup;
	}

cleanup:
	seal_file_close(&ofile);
	if (ret != SEAL_OK) {
		remove(tmp_opath);
	}
close_input:
	seal_file_close(&ifile);
	return ret;
}
