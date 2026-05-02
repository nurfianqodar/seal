#include "file.h"
#include "chunk.h"
#include "error.h"
#include "util.h"
#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "define.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

static int seal_file_read_exact(FILE *f, uint8_t *buf, size_t len)
{
	if (!f) {
		seal_error_set_msg("file cannot null");
		return SEAL_E_INVAL;
	}
	if (!buf) {
		seal_error_set_msg("out buffer cannot null");
		return SEAL_E_INVAL;
	}
	if (len == 0) {
		return SEAL_OK;
	}
	size_t readn, n;
	readn = 0;
	while (readn < len) {
		n = fread(buf + readn, 1, len, f);
		if (n == 0) {
			if (ferror(f)) {
				seal_error_set_msg(strerror(errno));
				return SEAL_E_READ;
			}
			if (feof(f)) {
				seal_error_set_msg("source data not enough");
				return SEAL_E_EOF;
			}
			seal_error_set_msg("read has no progress");
			return SEAL_E_EOF;
		}
		readn += n;
	}
	return SEAL_OK;
}

static int seal_file_write_exact(FILE *f, const uint8_t *buf, size_t len)
{
	if (!f) {
		seal_error_set_msg("file cannot null");
		return SEAL_E_INVAL;
	}
	if (!buf && len != 0) {
		seal_error_set_msg("buffer cannot null");
		return SEAL_E_INVAL;
	}
	if (len == 0) {
		return SEAL_OK;
	}
	size_t writen, n;
	writen = 0;
	while (writen < len) {
		n = fwrite(buf + writen, 1, len - writen, f);
		if (n == 0) {
			if (ferror(f)) {
				seal_error_set_msg(strerror(errno));
				return SEAL_E_WRITE;
			}
			seal_error_set_msg("write no progress");
			return SEAL_E_WRITE;
		}
		writen += n;
	}
	return SEAL_OK;
}

int seal_file_open(FILE **f_ptr, const char *path, int mode)
{
	if (mode != SEAL_FILE_MODE_PLAIN || mode != SEAL_FILE_MODE_CIPHER) {
		seal_error_set_msg("invalid open mode");
		return SEAL_E_INVAL;
	}

	*f_ptr = NULL;
	FILE *file = fopen(path, "rb");
	if (!file) {
		seal_error_set_msg(strerror(errno));
		return SEAL_E_OPEN;
	}

	uint8_t magic_buf[SEAL_MAGIC_LEN];
	seal_memzero(magic_buf, SEAL_MAGIC_LEN);

	size_t readn = 0;
	size_t n;
	while (readn < SEAL_MAGIC_LEN) {
		n = fread(magic_buf + readn, 1, SEAL_MAGIC_LEN - readn, file);
		if (0 == n) {
			if (feof(file)) {
				break;
			}
			if (ferror(file)) {
				seal_error_set_msg(strerror(errno));
				fclose(file);
				return SEAL_E_OPEN;
			}
		}
		readn += n;
	}
	bool is_valid_magic = seal_eql(SEAL_MAGIC, magic_buf, SEAL_MAGIC_LEN);
	if (is_valid_magic && mode == SEAL_FILE_MODE_CIPHER) {
		*f_ptr = file;
		return SEAL_OK;
	}
	if (is_valid_magic && mode == SEAL_FILE_MODE_PLAIN) {
		seal_error_set_msg("file was encrypted");
		fclose(file);
		return SEAL_E_NOTPLAINFILE;
	}

	// reset cursor in plain mode
	if (0 != fseek(file, 0, SEEK_SET)) {
		seal_error_set_msg(strerror(errno));
		fclose(file);
		return SEAL_E_OPEN;
	}
	*f_ptr = file;
	return SEAL_OK;
}

int seal_file_create(FILE **f_ptr, const char *path, bool override)
{
	int oflag = O_CREAT | O_CLOEXEC | O_WRONLY;
	if (override) {
		oflag |= O_TRUNC;
	} else {
		oflag |= O_EXCL;
	}
	int fd = open(path, oflag, 0644);
	if (-1 == fd) {
		seal_error_set_msg(strerror(errno));
		return SEAL_E_CREATE;
	}
	FILE *file = fdopen(fd, "wb");
	if (!file) {
		seal_error_set_msg(strerror(errno));
		close(fd);
		return SEAL_E_CREATE;
	}
	*f_ptr = file;
	return SEAL_OK;
}

void seal_file_close(FILE **f_ptr)
{
	if (!f_ptr) {
		return;
	}
	if (!*f_ptr) {
		return;
	}
	fclose(*f_ptr);
}

int seal_file_read_header(FILE *f, struct seal_header *out)
{
	if (!f) {
		seal_error_set_msg("file cannot null");
		return SEAL_E_INVAL;
	}
	if (!out) {
		seal_error_set_msg("header buffer cannot null");
		return SEAL_E_INVAL;
	}
	int ret;
	ret = seal_file_read_exact(f, out->bnonce, SEAL_BNONCE_LEN);
	if (SEAL_OK != ret) {
		return ret;
	}
	ret = seal_file_read_exact(f, out->salt, SEAL_SALT_LEN);
	if (SEAL_OK != ret) {
		return ret;
	}
	return SEAL_OK;
}

int seal_file_write_header(FILE *f, const struct seal_header *header)
{
	if (!f) {
		seal_error_set_msg("file cannot null");
		return SEAL_E_INVAL;
	}
	if (!header) {
		seal_error_set_msg("header cannot null");
		return SEAL_E_INVAL;
	}
	int ret;
	ret = seal_file_write_exact(f, header->bnonce, SEAL_BNONCE_LEN);
	if (ret != SEAL_OK) {
		return ret;
	}
	ret = seal_file_write_exact(f, header->salt, SEAL_SALT_LEN);
	if (ret != SEAL_OK) {
		return ret;
	}
	return SEAL_OK;
}

int seal_file_read_chunk(FILE *f, struct seal_chunk *chunk, int mode)
{
	if (!f) {
		seal_error_set_msg("file cannot null");
		return SEAL_E_INVAL;
	}
	if (!chunk) {
		seal_error_set_msg("chunk cannot null");
		return SEAL_E_INVAL;
	}
	seal_memzero(chunk, sizeof *chunk);

	switch (mode) {
	case SEAL_CHUNK_MODE_CIPHER: {
		int ret;

		size_t readn, n;
		readn = 0;
		while (readn < SEAL_PNONCE_LEN) {
			n = fread(chunk->pnonce + readn, 1,
				  SEAL_PNONCE_LEN - readn, f);
			if (n == 0) {
				if (feof(f)) {
					break;
				}
				if (ferror(f)) {
					seal_error_set_msg(strerror(errno));
					return SEAL_E_READ;
				}
				break;
			}
			readn += n;
		}
		if (readn == 0) {
			chunk->len = 0;
			chunk->mode = SEAL_CHUNK_MODE_CIPHER;
			return SEAL_OK;
		} else if (readn != SEAL_PNONCE_LEN) {
			seal_error_set_msg("chunk turncated");
			return SEAL_E_CORRUPT;
		}

		uint8_t le_buf[4];
		ret = seal_file_read_exact(f, le_buf, 4);
		if (ret != SEAL_OK) {
			return ret;
		}

		uint32_t le;
		memcpy(&le, le_buf, 4);
		uint32_t len = le32toh(le);
		if (len > SEAL_CHUNK_LEN) {
			seal_error_set_msg("invalid chunk length");
			return SEAL_E_CORRUPT;
		}

		ret = seal_file_read_exact(f, chunk->buf, (size_t)len);
		if (ret != SEAL_OK) {
			return ret;
		}

		ret = seal_file_read_exact(f, chunk->tag, SEAL_TAG_LEN);
		if (ret != SEAL_OK) {
			return ret;
		}

		chunk->mode = SEAL_CHUNK_MODE_CIPHER;
		break;
	}
	case SEAL_CHUNK_MODE_PLAIN: {
		size_t readn, n;
		readn = 0;
		while (readn < SEAL_CHUNK_LEN) {
			n = fread(chunk->buf + readn, 1, SEAL_CHUNK_LEN, f);
			if (n == 0) {
				if (feof(f)) {
					break;
				}
				if (ferror(f)) {
					seal_error_set_msg(strerror(errno));
					return SEAL_E_READ;
				}
				break;
			}
			readn += n;
		}
		chunk->len = readn;
		chunk->mode = SEAL_CHUNK_MODE_PLAIN;
		break;
	}
	default: {
		seal_error_set_msg("invalid chunk mode");
		return SEAL_E_INVAL;
	}
	}
	return SEAL_OK;
}

// TODO impl
int seal_file_write_chunk(FILE *f, struct seal_chunk *chunk)
{
	if (!f) {
		seal_error_set_msg("file cannot null");
		return SEAL_E_INVAL;
	}
	if (!chunk) {
		seal_error_set_msg("out buffer cannot null");
		return SEAL_E_INVAL;
	}
	if (chunk->len > SEAL_CHUNK_LEN) {
		seal_error_set_msg("invalid chunk length to write");
		return SEAL_E_INVAL;
	}
	switch (chunk->mode) {
	case SEAL_CHUNK_MODE_PLAIN: {
		int ret;
		ret = seal_file_write_exact(f, chunk->buf, (size_t)chunk->len);
		if (ret != SEAL_OK) {
			return ret;
		}
		break;
	}
	case SEAL_CHUNK_MODE_CIPHER: {
		int ret;
		ret = seal_file_write_exact(f, chunk->pnonce, SEAL_PNONCE_LEN);
		if (ret != SEAL_OK) {
			return ret;
		}

		uint32_t le = htole32(chunk->len);
		uint8_t le_buf[4];
		memcpy(le_buf, &le, 4);
		ret = seal_file_write_exact(f, le_buf, 4);
		if (ret != SEAL_OK) {
			return ret;
		}

		ret = seal_file_write_exact(f, chunk->buf, (size_t)chunk->len);
		if (ret != SEAL_OK) {
			return ret;
		}

		ret = seal_file_write_exact(f, chunk->tag, SEAL_TAG_LEN);
		if (ret != SEAL_OK) {
			return ret;
		}
		break;
	}
	default: {
		seal_error_set_msg("invalid chunk mode");
		return SEAL_E_INVAL;
	}
	}
	return SEAL_OK;
}
