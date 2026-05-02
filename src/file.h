#ifndef SEAL_FILE_H_
#define SEAL_FILE_H_

#include "chunk.h"
#include "header.h"
#include <stdio.h>
#define SEAL_FILE_MODE_PLAIN 1
#define SEAL_FILE_MODE_CIPHER 2

int seal_file_read_exact(FILE *f, uint8_t *buf, size_t len);
int seal_file_write_exact(FILE *f, const uint8_t *buf, size_t len);

int seal_file_open(FILE **f_ptr, const char *path, int mode);
int seal_file_create(FILE **f_ptr, const char *path, bool override);
void seal_file_close(FILE **f_ptr);

int seal_file_read_header(FILE *f, struct seal_header *out);
int seal_file_write_header(FILE *f, const struct seal_header *header);

int seal_file_read_chunk(FILE *f, struct seal_chunk *chunk, int mode);
int seal_file_write_chunk(FILE *f, struct seal_chunk *chunk);

bool seal_file_path_is_exists(const char *path);

int seal_file_flush(FILE *f);

#endif
