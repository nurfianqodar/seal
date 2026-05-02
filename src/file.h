#ifndef SEAL_FILE_H_
#define SEAL_FILE_H_

#include <stdio.h>
#define SEAL_FILE_MODE_PLAIN 1
#define SEAL_FILE_MODE_CIPHER 2

int seal_file_open(FILE **f_ptr, const char *path, int mode);
int seal_file_create(FILE **f_ptr, const char *path, bool override);
void seal_file_close(FILE **f_ptr);

#endif
