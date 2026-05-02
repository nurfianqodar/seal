#include "define.h"
#include <stddef.h>
#include <stdint.h>

static const uint8_t seal_magic_storage_arr[] = { 's', 'e', 'a', 'l',
						  '/', 'v', '1' };

static const uint8_t *seal_magic_storage_ptr =
	(const uint8_t *)seal_magic_storage_arr;

static const size_t seal_magic_len_stroage = sizeof seal_magic_storage_arr;

const uint8_t **__seal_magic_location(void)
{
	return &seal_magic_storage_ptr;
}

const size_t *__seal_magic_len_location(void)
{
	return &seal_magic_len_stroage;
}
