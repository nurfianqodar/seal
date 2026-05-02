#include "seal.h"
#include "chunk.h"
#include "cipher.h"
#include "error.h"
#include "file.h"
#include "header.h"
#include "util.h"
#include <errno.h>
#include <linux/limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int seal_do_encrypt(FILE *ifile, FILE *ofile, const uint8_t *pwd,
			   size_t pwd_len)
{
	struct seal_chunk chunk;
	struct seal_cipher cipher;
	struct seal_header header;

	int ret;
	seal_header_init(&header);
	ret = seal_cipher_init(&cipher, &header, pwd, pwd_len);
	do {
		ret = seal_file_read_chunk(ifile, &chunk,
					   SEAL_CHUNK_MODE_PLAIN);
		if (ret != SEAL_OK) {
			seal_memzero(&chunk, sizeof chunk);
			seal_memzero(&cipher, sizeof cipher);
			seal_memzero(&header, sizeof header);
			return ret;
		}
		ret = seal_chunk_encrypt(&chunk, &cipher);
		if (ret != SEAL_OK) {
			seal_memzero(&chunk, sizeof chunk);
			seal_memzero(&cipher, sizeof cipher);
			seal_memzero(&header, sizeof header);
			return ret;
		}
		ret = seal_file_write_chunk(ofile, &chunk);
		if (ret != SEAL_OK) {
			seal_memzero(&chunk, sizeof chunk);
			seal_memzero(&cipher, sizeof cipher);
			seal_memzero(&header, sizeof header);
			return ret;
		}
	} while (chunk.len != 0);
	seal_memzero(&chunk, sizeof chunk);
	seal_memzero(&cipher, sizeof cipher);
	seal_memzero(&header, sizeof header);
	return SEAL_OK;
}

static int seal_do_decrypt(FILE *ifile, FILE *ofile, const uint8_t *pwd,
			   size_t pwd_len)
{
	struct seal_chunk chunk;
	struct seal_cipher cipher;
	struct seal_header header;

	int ret;
	seal_header_init(&header);
	ret = seal_cipher_init(&cipher, &header, pwd, pwd_len);
	do {
		ret = seal_file_read_chunk(ifile, &chunk,
					   SEAL_CHUNK_MODE_CIPHER);
		if (ret != SEAL_OK) {
			seal_memzero(&chunk, sizeof chunk);
			seal_memzero(&cipher, sizeof cipher);
			seal_memzero(&header, sizeof header);
			return ret;
		}
		ret = seal_chunk_decrypt(&chunk, &cipher);
		if (ret != SEAL_OK) {
			seal_memzero(&chunk, sizeof chunk);
			seal_memzero(&cipher, sizeof cipher);
			seal_memzero(&header, sizeof header);
			return ret;
		}
		ret = seal_file_write_chunk(ofile, &chunk);
		if (ret != SEAL_OK) {
			seal_memzero(&chunk, sizeof chunk);
			seal_memzero(&cipher, sizeof cipher);
			seal_memzero(&header, sizeof header);
			return ret;
		}
	} while (chunk.len != 0);
	seal_memzero(&chunk, sizeof chunk);
	seal_memzero(&cipher, sizeof cipher);
	seal_memzero(&header, sizeof header);
	return SEAL_OK;
}

static void gen_tmp_path(const char *orig, char *tmp)
{
	if (!orig || !tmp)
		return;
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

int seal_encrypt(const char *_ipath, const char *_opath, const uint8_t *pwd,
		 size_t pwd_len, bool override)
{
	char ipath[PATH_MAX], opath[PATH_MAX], tmp_opath[PATH_MAX];
	strncpy(ipath, _ipath, PATH_MAX);
	strncpy(opath, _opath, PATH_MAX);

	if (!seal_file_path_is_exists(ipath)) {
		seal_error_set_msg("input file not found");
		return SEAL_E_NOENT;
	}

	if (seal_file_path_is_exists(opath)) {
		if (!override) {
			seal_error_set_msg("output file already exists");
			return SEAL_E_EXISTS;
		}
	}

	size_t attempt = 0;
	gen_tmp_path(opath, tmp_opath);
	while (seal_file_path_is_exists(tmp_opath)) {
		gen_tmp_path(opath, tmp_opath);
		attempt += 1;
		if (attempt >= 10) {
			seal_error_set_msg("unable to create temporary file");
			return SEAL_E_EXISTS;
		}
	}

	FILE *ifile, *ofile;

	int ret;

	ret = seal_file_open(&ifile, ipath, SEAL_FILE_MODE_PLAIN);
	if (ret != SEAL_OK) {
		return ret;
	}

	ret = seal_file_create(&ofile, tmp_opath, false);
	if (ret != SEAL_OK) {
		fclose(ifile);
		return ret;
	}

	ret = seal_do_encrypt(ifile, ofile, pwd, pwd_len);
	if (ret != SEAL_OK) {
		fclose(ifile);
		fclose(ofile);
		remove(tmp_opath);
		return ret;
	}

	if (0 != rename(tmp_opath, opath)) {
		seal_error_set_msg(strerror(errno));
		remove(tmp_opath);
		return SEAL_E_MOVE;
	}

	return SEAL_OK;
}

int seal_decrypt(const char *_ipath, const char *_opath, const uint8_t *pwd,
		 size_t pwd_len, bool override)
{
	char ipath[PATH_MAX], opath[PATH_MAX], tmp_opath[PATH_MAX];
	strncpy(ipath, _ipath, PATH_MAX);
	strncpy(opath, _opath, PATH_MAX);

	if (!seal_file_path_is_exists(ipath)) {
		seal_error_set_msg("input file not found");
		return SEAL_E_NOENT;
	}

	if (seal_file_path_is_exists(opath)) {
		if (!override) {
			seal_error_set_msg("output file already exists");
			return SEAL_E_EXISTS;
		}
	}

	size_t attempt = 0;
	gen_tmp_path(opath, tmp_opath);
	while (seal_file_path_is_exists(tmp_opath)) {
		gen_tmp_path(opath, tmp_opath);
		attempt += 1;
		if (attempt >= 10) {
			seal_error_set_msg("unable to create temporary file");
			return SEAL_E_EXISTS;
		}
	}

	FILE *ifile, *ofile;

	int ret;

	ret = seal_file_open(&ifile, ipath, SEAL_FILE_MODE_CIPHER);
	if (ret != SEAL_OK) {
		return ret;
	}

	ret = seal_file_create(&ofile, tmp_opath, false);
	if (ret != SEAL_OK) {
		fclose(ifile);
		return ret;
	}

	ret = seal_do_decrypt(ifile, ofile, pwd, pwd_len);
	if (ret != SEAL_OK) {
		fclose(ifile);
		fclose(ofile);
		remove(tmp_opath);
		return ret;
	}

	if (0 != rename(tmp_opath, opath)) {
		seal_error_set_msg(strerror(errno));
		remove(tmp_opath);
		return SEAL_E_MOVE;
	}

	return SEAL_OK;
}
