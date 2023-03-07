/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2023 EPAM Systems
 */

#ifndef XENLIB_XRUN_STORAGE_H
#define XENLIB_XRUN_STORAGE_H

#include <sys/types.h>
#include <zephyr/types.h>

#ifdef DEBUG
int lsdir(const char *path);
int write_file(const char *path, const char *name, char *buf,
					 size_t size);
#endif

ssize_t read_file(const char *path, const char *name,
				  char *buf, size_t size, int skip);
ssize_t get_file_size(const char *path, const char *name);

#endif /* XENLIB_XRUN_STORAGE_H */
