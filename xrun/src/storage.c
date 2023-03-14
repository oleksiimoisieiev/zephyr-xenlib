// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 EPAM Systems
 */
#include <stdio.h>

#include <zephyr/device.h>
#include <zephyr/fs/fs.h>
#include <zephyr/fs/littlefs.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>

#include <storage.h>
#define DEBUG
#define MAX_PATH_LEN 255

LOG_MODULE_REGISTER(storage);

#define PARTITION_NODE DT_NODELABEL(storage)

static volatile bool mounted = false;

static int littlefs_flash_erase(unsigned int id)
{
	const struct flash_area *pfa;
	int rc;

	rc = flash_area_open(id, &pfa);
	if (rc < 0) {
		LOG_ERR("FAIL: unable to find flash area %u: %d\n",
			id, rc);
		return rc;
	}

	LOG_DBG("Area %u at 0x%x on %s for %u bytes\n",
		   id, (unsigned int)pfa->fa_off, pfa->fa_dev->name,
		   (unsigned int)pfa->fa_size);

	flash_area_close(pfa);
	return rc;
}

#if DT_NODE_EXISTS(PARTITION_NODE)
FS_FSTAB_DECLARE_ENTRY(PARTITION_NODE);
#else /* PARTITION_NODE */
FS_LITTLEFS_DECLARE_DEFAULT_CONFIG(storage);
static struct fs_mount_t lfs_storage_mnt = {
	.type = FS_LITTLEFS,
	.fs_data = &storage,
	.storage_dev = (void *)FIXED_PARTITION_ID(storage_partition),
	.mnt_point = "/lfs",
};
#endif /* PARTITION_NODE */

	struct fs_mount_t *mp =
#if DT_NODE_EXISTS(PARTITION_NODE)
		&FS_FSTAB_ENTRY(PARTITION_NODE)
#else
		&lfs_storage_mnt
#endif
		;

static int littlefs_mount(struct fs_mount_t *mp)
{
	int rc;

	rc = littlefs_flash_erase((uintptr_t)mp->storage_dev);
	if (rc < 0) {
		return rc;
	}

	/* Do not mount if auto-mount has been enabled */
#if !DT_NODE_EXISTS(PARTITION_NODE) ||						\
	!(FSTAB_ENTRY_DT_MOUNT_FLAGS(PARTITION_NODE) & FS_MOUNT_FLAG_AUTOMOUNT)
	rc = fs_mount(mp);
	if (rc < 0) {
		LOG_PRINTK("FAIL: mount id %" PRIuPTR " at %s: %d\n",
		       (uintptr_t)mp->storage_dev, mp->mnt_point, rc);
		return rc;
	}
	LOG_DBG("%s mount: %d\n", mp->mnt_point, rc);
#else
	LOG_DBG("%s automounted\n", mp->mnt_point);
#endif

	mounted = true;
	return 0;
}

ssize_t read_file(const char *path, const char *name,
				  char *buf, size_t size, int skip)
{
	struct fs_file_t file;
	ssize_t rc;
	int ret;
	char fname[MAX_PATH_LEN];

	if (!mounted) {
		rc = littlefs_mount(mp);
		if (rc) {
			return rc;
		}
	}

	snprintf(fname, MAX_PATH_LEN, "%s/%s", path, name);

	fs_file_t_init(&file);
	ret = fs_open(&file, fname, FS_O_READ);
	if (ret < 0) {
		LOG_ERR("FAIL: open %s: %d", fname, ret);
		return ret;
	}

	if (skip) {
		rc = fs_seek(&file, skip, FS_SEEK_SET);
		if (rc < 0) {
			LOG_ERR("FAIL: seek %s: %ld", fname, rc);
			goto out;
		}
	}

	rc = fs_read(&file, buf, size);
	if (rc < 0) {
		LOG_ERR("FAIL: read %s: [rd:%ld]", fname, rc);
		goto out;
	}

out:
	ret = fs_close(&file);
	if (ret < 0) {
		LOG_ERR("FAIL: close %s: %d", fname, ret);
		return ret;
	}

	return rc;
}

ssize_t get_file_size(const char *path, const char *name)
{
	int rc;
	struct fs_dirent dirent;
	char fname[MAX_PATH_LEN];

	if (!mounted) {
		rc = littlefs_mount(mp);
		if (rc) {
            return rc;
		}
	}

	snprintf(fname, MAX_PATH_LEN, "%s/%s", path, name);

	rc = fs_stat(fname, &dirent);
	if (rc < 0) {
		LOG_ERR("FAIL: stat %s: %d", fname, rc);
		return rc;
	}

	/* Check if the file exists - if not just write the pattern */
	if (rc == 0 && dirent.type == FS_DIR_ENTRY_FILE && dirent.size == 0) {
          LOG_ERR("File: %s not found", fname);
		  return -ENOENT;
	}

	return dirent.size;
}

#ifdef DEBUG
int lsdir(const char *path)
{
	int res;
	struct fs_dir_t dirp;
	static struct fs_dirent entry;

	fs_dir_t_init(&dirp);

	/* Verify fs_opendir() */
	res = fs_opendir(&dirp, path);
	if (res) {
		LOG_ERR("Error opening dir %s [%d]\n", path, res);
		return res;
	}

	LOG_PRINTK("\nListing dir %s ...\n", path);
	for (;;) {
		/* Verify fs_readdir() */
		res = fs_readdir(&dirp, &entry);

		/* entry.name[0] == 0 means end-of-dir */
		if (res || entry.name[0] == 0) {
			if (res < 0) {
				LOG_ERR("Error reading dir [%d]\n", res);
			}
			break;
		}

		if (entry.type == FS_DIR_ENTRY_DIR) {
			LOG_DBG("[DIR ] %s\n", entry.name);
		} else {
			LOG_DBG("[FILE] %s (size = %zu)\n", entry.name, entry.size);
		}
	}

	/* Verify fs_closedir() */
	fs_closedir(&dirp);

	return res;
}

int write_file(const char *path, const char *name,
					 char *buf, size_t size)
{
	struct fs_file_t file;
	int rc, ret;
	char fname[MAX_PATH_LEN];

	if (!mounted) {
		rc = littlefs_mount(mp);
		if (rc) {
            return rc;
		}
	}

	snprintf(fname, MAX_PATH_LEN, "%s/%s", path, name);

	fs_file_t_init(&file);
	rc = fs_open(&file, fname, FS_O_CREATE | FS_O_RDWR);
	if (rc < 0) {
		LOG_ERR("FAIL: open %s: %d", fname, rc);
		return rc;
	}

	rc = fs_write(&file, buf, size);
	if (rc < 0) {
		LOG_ERR("FAIL: write %s: %d", fname, rc);
		goto out;
	}

	LOG_PRINTK("%s write file size %lu: [wr:%d]\n", fname, size, rc);

 out:
	ret = fs_close(&file);
	if (ret < 0) {
		LOG_ERR("FAIL: close %s: %d", fname, ret);
		return ret;
	}

	return (rc < 0 ? rc : 0);
}
#endif /* DEBUG */
