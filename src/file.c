#include "file.h"
#include "chunk.h"
#include "define.h"
#include "error.h"
#include "util.h"
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

seal_error seal_file_read_exact(FILE *f, uint8_t *buf, size_t len)
{
	if (!f)
		return seal_error_set_msg("file cannot null"), SEAL_E_INVAL;
	if (!buf)
		return seal_error_set_msg("out buffer cannot null"),
		       SEAL_E_INVAL;
	if (len == 0)
		return SEAL_OK;

	size_t readn = 0;

	while (readn < len) {
		size_t n = fread(buf + readn, 1, len - readn, f);
		if (n == 0) {
			if (feof(f))
				return seal_error_set_msg(
					       "unexpected end of file"),
				       SEAL_E_EOF;
			if (ferror(f))
				return seal_error_set_msg("read error"),
				       SEAL_E_READ;
			seal_error_set_msg("read no progress");
			return SEAL_E_READ;
		}
		readn += n;
	}
	return SEAL_OK;
}

static seal_error seal_file_has_magic(FILE *f, bool *has_magic)
{
	uint8_t magic_buf[SEAL_MAGIC_LEN];
	seal_memzero(magic_buf, SEAL_MAGIC_LEN);

	size_t readn = 0;
	while (readn < SEAL_MAGIC_LEN) {
		size_t n =
			fread(magic_buf + readn, 1, SEAL_MAGIC_LEN - readn, f);
		if (n == 0) {
			if (ferror(f))
				return seal_error_set_msg("read error"),
				       SEAL_E_READ;
			break;
		}
		readn += n;
	}
	*has_magic = seal_memequal(SEAL_MAGIC, magic_buf, SEAL_MAGIC_LEN);
	return SEAL_OK;
}

seal_error seal_file_write_exact(FILE *f, const uint8_t *buf, size_t len)
{
	if (!f)
		return seal_error_set_msg("file cannot null"), SEAL_E_INVAL;

	if (!buf && len != 0)
		return seal_error_set_msg("buffer cannot null"), SEAL_E_INVAL;

	if (len == 0)
		return SEAL_OK;

	size_t writen = 0;
	while (writen < len) {
		size_t n = fwrite(buf + writen, 1, len - writen, f);
		if (n == 0) {
			if (ferror(f))
				return seal_error_set_msg(strerror(errno)),
				       SEAL_E_WRITE;

			seal_error_set_msg("write no progress");
			return SEAL_E_WRITE;
		}
		writen += n;
	}
	return SEAL_OK;
}

seal_error seal_file_open(FILE **f_ptr, const char *path, int mode)
{
	if (!f_ptr)
		return seal_error_set_msg("f_ptr cannot null"), SEAL_E_INVAL;
	if (!path)
		return seal_error_set_msg("path cannot null"), SEAL_E_INVAL;

	if (mode != SEAL_FILE_MODE_PLAIN && mode != SEAL_FILE_MODE_CIPHER)
		return seal_error_set_msg("invalid open mode"), SEAL_E_INVAL;
	if (!seal_file_path_is_exists(path))
		return seal_error_set_msg("file not found"), SEAL_E_NOENT;

	*f_ptr = NULL;

	FILE *file = fopen(path, "rb");
	if (!file)
		return seal_error_set_msg("open file failed"), SEAL_E_OPEN;

	seal_error ret = SEAL_OK;

	bool has_magic = false;
	if ((ret = seal_file_has_magic(file, &has_magic)) != SEAL_OK)
		return ret;

	switch (mode) {
	case SEAL_FILE_MODE_PLAIN: {
		if (has_magic) {
			seal_file_close(&file);
			seal_error_set_msg("file already encrypted");
			return SEAL_E_NOTPLAINFILE;
		}
		if (fseek(file, 0, SEEK_SET) != 0) {
			seal_file_close(&file);
			seal_error_set_msg("fseek error");
			return SEAL_E_OPEN;
		}
		break;
	}
	case SEAL_FILE_MODE_CIPHER: {
		if (!has_magic) {
			seal_file_close(&file);
			seal_error_set_msg("file not encrypted");
			return SEAL_E_NOTCIPHERFILE;
		}
		break;
	}
	}
	*f_ptr = file;
	return SEAL_OK;
}

seal_error seal_file_create(FILE **f_ptr, const char *path)
{
	if (!f_ptr)
		return seal_error_set_msg("f_ptr cannot null"), SEAL_E_INVAL;
	if (!path)
		return seal_error_set_msg("path cannot null"), SEAL_E_INVAL;

	int fd = open(path, O_CREAT | O_CLOEXEC | O_WRONLY | O_TRUNC, 0600);
	if (-1 == fd)
		return seal_error_set_msg("open error"), SEAL_E_CREATE;

	FILE *file = fdopen(fd, "wb");
	if (!file) {
		close(fd);
		seal_error_set_msg("fdopen error");
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

seal_error seal_file_read_header(FILE *f, struct seal_header *out)
{
	if (!f)
		return seal_error_set_msg("file cannot null"), SEAL_E_INVAL;
	if (!out)
		return seal_error_set_msg("header buffer cannot null"),
		       SEAL_E_INVAL;

	seal_error ret = SEAL_OK;

	if ((ret = seal_file_read_exact(f, out->bnonce, SEAL_BNONCE_LEN)) !=
	    SEAL_OK)
		return ret;

	if ((ret = seal_file_read_exact(f, out->salt, SEAL_SALT_LEN)) !=
	    SEAL_OK)
		return ret;

	return ret;
}

seal_error seal_file_write_header(FILE *f, const struct seal_header *header)
{
	if (!f)
		return seal_error_set_msg("file cannot null"), SEAL_E_INVAL;

	if (!header)
		return seal_error_set_msg("header cannot null"), SEAL_E_INVAL;

	seal_error ret;
	if ((ret = seal_file_write_exact(f, header->bnonce, SEAL_BNONCE_LEN)) !=
	    SEAL_OK)
		return ret;

	if ((ret = seal_file_write_exact(f, header->salt, SEAL_SALT_LEN)) !=
	    SEAL_OK)
		return ret;

	return ret;
}

seal_error seal_file_read_chunk(FILE *f, struct seal_chunk *chunk, int mode)
{
	if (!f)
		return seal_error_set_msg("file cannot null"), SEAL_E_INVAL;
	if (!chunk)
		return seal_error_set_msg("chunk cannot null"), SEAL_E_INVAL;

	seal_error ret = SEAL_OK;

	switch (mode) {
	case SEAL_CHUNK_MODE_CIPHER: {
		size_t readn = 0;
		while (readn < SEAL_PNONCE_LEN) {
			size_t n = fread(chunk->pnonce + readn, 1,
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
		if ((ret = seal_file_read_exact(f, le_buf, 4)) != SEAL_OK)
			return ret;

		uint32_t le;
		memcpy(&le, le_buf, 4);

		uint32_t len = le32toh(le);
		if (len > SEAL_CHUNK_LEN)
			return seal_error_set_msg("invalid chunk length"),
			       SEAL_E_CORRUPT;

		if ((ret = seal_file_read_exact(f, chunk->buf, (size_t)len)) !=
		    SEAL_OK)
			return ret;

		if ((ret = seal_file_read_exact(f, chunk->tag, SEAL_TAG_LEN)) !=
		    SEAL_OK)
			return ret;

		chunk->mode = SEAL_CHUNK_MODE_CIPHER;
		chunk->len = len;
		break;
	}
	case SEAL_CHUNK_MODE_PLAIN: {
		size_t readn = 0;
		while (readn < SEAL_CHUNK_LEN) {
			size_t n = fread(chunk->buf + readn, 1,
					 SEAL_CHUNK_LEN - readn, f);
			if (n == 0) {
				if (feof(f))
					break;

				if (ferror(f))
					return seal_error_set_msg(
						       strerror(errno)),
					       SEAL_E_READ;
				break;
			}
			readn += n;
		}
		chunk->len = readn;
		chunk->mode = SEAL_CHUNK_MODE_PLAIN;
		break;
	}
	default:
		return seal_error_set_msg("invalid chunk mode"), SEAL_E_INVAL;
	}
	return SEAL_OK;
}

seal_error seal_file_write_chunk(FILE *f, struct seal_chunk *chunk)
{
	if (!f)
		return seal_error_set_msg("file cannot null"), SEAL_E_INVAL;
	if (!chunk)
		return seal_error_set_msg("out buffer cannot null"),
		       SEAL_E_INVAL;

	if (chunk->len > SEAL_CHUNK_LEN) {
		seal_error_set_msg("invalid chunk length");
		return SEAL_E_INVAL;
	}

	seal_error ret = SEAL_OK;

	switch (chunk->mode) {
	case SEAL_CHUNK_MODE_PLAIN: {
		if ((ret = seal_file_write_exact(
			     f, chunk->buf, (size_t)chunk->len)) != SEAL_OK)
			return ret;
		break;
	}
	case SEAL_CHUNK_MODE_CIPHER: {
		if ((ret = seal_file_write_exact(f, chunk->pnonce,
						 SEAL_PNONCE_LEN)) != SEAL_OK)
			return ret;

		uint32_t le = htole32(chunk->len);
		uint8_t le_buf[4];
		memcpy(le_buf, &le, 4);

		if ((ret = seal_file_write_exact(f, le_buf, 4)) != SEAL_OK)
			return ret;

		if ((ret = seal_file_write_exact(
			     f, chunk->buf, (size_t)chunk->len)) != SEAL_OK)
			return ret;

		if ((ret = seal_file_write_exact(f, chunk->tag,
						 SEAL_TAG_LEN)) != SEAL_OK)
			return ret;
		break;
	}
	default:
		return seal_error_set_msg("invalid chunk mode"), SEAL_E_INVAL;
	}
	return ret;
}

bool seal_file_path_is_exists(const char *path)
{
	struct stat st;
	if (stat(path, &st) != 0)
		return false;
	return true;
}

seal_error seal_file_flush(FILE *f)
{
	if (0 != fflush(f))
		return seal_error_set_msg("flush file error"), SEAL_E_WRITE;

	int fd = fileno(f);
	if (fd == -1)
		return seal_error_set_msg("fileno failed"), SEAL_E_WRITE;

	while (fsync(fd) == -1) {
		if (errno != EINTR)
			return seal_error_set_msg("fsync failed"), SEAL_E_WRITE;
	}
	return SEAL_OK;
}
