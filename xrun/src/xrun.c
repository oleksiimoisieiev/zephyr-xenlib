// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 EPAM Systems
 */
#include <domain.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/data/json.h>
#include <zephyr/logging/log.h>
#include <zephyr/spinlock.h>
#include <zephyr/sys/slist.h>
#include <zephyr/xen/public/domctl.h>

#include <storage.h>
#include <xen_dom_mgmt.h>

#define MAX_STR_SIZE 64

#ifndef XRUN_JSON_SIZE_MAX
#define XRUN_JSON_SIZE_MAX KB(512)
#endif

LOG_MODULE_REGISTER(xrun);

#define CONTAINER_NAME_SIZE 64
#define UNIKERNEL_ID_START 12

enum domain_status {
	RUNNING = 0,
	PAUSED,
	DESTROYED,
};

static struct k_spinlock container_lock;
static sys_slist_t container_list = SYS_SLIST_STATIC_INIT(&container_list);
static uint32_t next_domid = UNIKERNEL_ID_START;

#define XRUN_JSON_PARAMETERS_MAX 24

struct hypervisor_spec {
	const char *path;
	const char *parameters[XRUN_JSON_PARAMETERS_MAX];
	size_t params_len;
};

struct kernel_spec {
	const char *path;
	const char *parameters[XRUN_JSON_PARAMETERS_MAX];
	size_t params_len;
};

struct hwconfig_spec {
	const char *devicetree;
};

struct vm_spec {
	struct hypervisor_spec hypervisor;
	struct kernel_spec kernel;
	struct hwconfig_spec hwconfig;
};

struct domain_spec {
	const char *ociVersion;
	struct vm_spec vm;
};

struct container {
	sys_snode_t node;

	char container_id[CONTAINER_NAME_SIZE];
	const char *bundle;

	uint8_t devicetree[CONFIG_PARTIAL_DEVICE_TREE_SIZE];

	uint64_t domid;
	struct domain_spec spec;
	struct xen_domain_cfg domcfg;
	enum domain_status status;
};

static const struct json_obj_descr hypervisor_spec_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hypervisor_spec, path, JSON_TOK_STRING),
	JSON_OBJ_DESCR_ARRAY(struct hypervisor_spec, parameters,
						 XRUN_JSON_PARAMETERS_MAX, params_len,
						 JSON_TOK_STRING),
};

static const struct json_obj_descr kernel_spec_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct kernel_spec, path, JSON_TOK_STRING),
	JSON_OBJ_DESCR_ARRAY(struct hypervisor_spec, parameters,
					   XRUN_JSON_PARAMETERS_MAX, params_len,
					   JSON_TOK_STRING),
};

static const struct json_obj_descr hwconfig_spec_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hwconfig_spec, devicetree, JSON_TOK_STRING),
};

static const struct json_obj_descr vm_spec_descr[] = {
	JSON_OBJ_DESCR_OBJECT(struct vm_spec, hypervisor, hypervisor_spec_descr),
	JSON_OBJ_DESCR_OBJECT(struct vm_spec, kernel, kernel_spec_descr),
	JSON_OBJ_DESCR_OBJECT(struct vm_spec, hwconfig, hwconfig_spec_descr),

};

static const struct json_obj_descr domain_spec_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct domain_spec, ociVersion, JSON_TOK_STRING),
	JSON_OBJ_DESCR_OBJECT(struct domain_spec, vm, vm_spec_descr),
};

int parse_config_json(char *json, size_t json_size, struct domain_spec *domain)
{
	int expected_return_code = (1 << ARRAY_SIZE(domain_spec_descr)) - 1;
	int ret = json_obj_parse(json, json_size, domain_spec_descr,
							 ARRAY_SIZE(domain_spec_descr), domain);

	if (ret < 0) {
		LOG_ERR("JSON Parse Error: %d\n", ret);
		return ret;
	} else if (ret != expected_return_code) {
		LOG_ERR("Not all values decoded; Expected return code %d but got %d\n",
			   expected_return_code, ret);
		return ret;
	}

	return ret;
}

static struct container *get_container(const char *container_id)
{
	struct container *container = NULL;
	k_spinlock_key_t key = k_spin_lock(&container_lock);

	SYS_SLIST_FOR_EACH_CONTAINER(&container_list, container, node) {
		if (strncmp(container->container_id, container_id,
				CONTAINER_NAME_SIZE) == 0)
			break;
	}

	k_spin_unlock(&container_lock, key);
	return container;
}

static struct container *register_container_id(const char *container_id)
{
	struct container *container;
	k_spinlock_key_t key;

	container = get_container(container_id);
	if (container) {
		LOG_ERR("Container %s already exists\n", container_id);
		return NULL;
	}

	key = k_spin_lock(&container_lock);
	container = (struct container *)k_malloc(sizeof(*container));
	if (!container)
		goto err;

	strncpy(container->container_id, container_id, CONTAINER_NAME_SIZE);
	container->domid = next_domid++;

	sys_slist_append(&container_list, &container->node);
err:
	k_spin_unlock(&container_lock, key);

	return container;
}

static int unregister_container_id(const char *container_id)
{
	struct container *container = get_container(container_id);
	k_spinlock_key_t key;

	if (!container)
		return -ENOENT;

	key = k_spin_lock(&container_lock);
	sys_slist_find_and_remove(&container_list, &container->node);
	k_spin_unlock(&container_lock, key);
	k_free(container);
	return 0;
}

const char *test_cmdline = "test=1";

static int load_image_bytes(uint8_t *buf, size_t bufsize,
			uint64_t image_load_offset, void *image_info)
{
	ssize_t res;
	struct container *container;

	if (!image_info)
		return -EINVAL;

	container = (struct container *)image_info;

	res = read_file(container->bundle, container->spec.vm.kernel.path,
					 buf, bufsize, image_load_offset);

	return (res > 0) ? 0: res;
}

static ssize_t get_image_size(void *image_info, uint64_t *size)
{
	struct container *containter;
	ssize_t image_size;
	if (!image_info)
		return -EINVAL;

	containter = (struct container *)image_info;

	image_size = get_file_size(containter->bundle,
					containter->spec.vm.kernel.path);
	if (image_size > 0)
		*size = image_size;

	return (size == 0) ? -EINVAL : 0;
}

static int fill_domcfg(struct container *container)
{
	ssize_t res;
	struct xen_domain_cfg *domcfg = &container->domcfg;

	domcfg->mem_kb = 4096;
	domcfg->flags = (XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap);
	domcfg->max_evtchns = 10;
	domcfg->max_vcpus = 1;
	domcfg->gnt_frames = 32;
	domcfg->max_maptrack_frames = 1;

	domcfg->nr_iomems = 0;

	/* irqs = domd_irqs, */
	domcfg->nr_irqs = 0;

	domcfg->gic_version = XEN_DOMCTL_CONFIG_GIC_V2;
	domcfg->tee_type = XEN_DOMCTL_CONFIG_TEE_NONE;

	/* domcfg->dtdevs = domd_dtdevs, */
	domcfg->nr_dtdevs = 0;

	domcfg->cmdline = test_cmdline;

	domcfg->get_image_size = get_image_size;
	domcfg->load_image_bytes = load_image_bytes;
	domcfg->image_info = container;

	res = read_file(container->bundle, container->spec.vm.hwconfig.devicetree,
					container->devicetree, CONFIG_PARTIAL_DEVICE_TREE_SIZE, 0);
	if (res < 0) {
		printk("Unable to read dtb rc: %ld\n", res);
		return res;
	}

	domcfg->dtb_start = container->devicetree;
	domcfg->dtb_end = container->devicetree + res;

	return 0;
}

int xrun_run(const char *bundle, int console_socket, const char *container_id)
{
	int ret = 0;
	ssize_t bytes_read;
	char config[XRUN_JSON_SIZE_MAX] = {0};
	struct container *container = register_container_id(container_id);

	if (!container)
		return -EINVAL;

	bytes_read = read_file(bundle, "config.json", config,
					XRUN_JSON_SIZE_MAX, 0);
	if (bytes_read < 0) {
		LOG_ERR("Can't read config.json ret = %ld\n", bytes_read);
		return bytes_read;
	}

	parse_config_json(config, bytes_read, &container->spec);
	container->bundle = bundle;
	container->status = RUNNING;
	LOG_DBG("xrun_run domid = %lld\n", container->domid);

	ret = fill_domcfg(container);
	if (ret) {
		return ret;
	}

	ret = domain_create(&container->domcfg, container->domid);
	if (ret)
		goto err;

	ret = domain_unpause(container->domid);
	return ret;
err:
	unregister_container_id(container_id);
	return ret;
}

int xrun_pause(const char *container_id)
{
	int ret = 0;
	struct container *container = get_container(container_id);
	if (!container)
		return -EINVAL;

	ret = domain_pause(container->domid);
	if (ret)
		return ret;

	container->status = PAUSED;
	return 0;
}

int xrun_resume(const char *container_id)
{
	int ret = 0;
	struct container *container = get_container(container_id);
	if (!container)
		return -EINVAL;

	ret = domain_unpause(container->domid);
	if (ret)
		return ret;

	container->status = RUNNING;
	return 0;
}

int xrun_kill(const char *container_id)
{
	int ret = 0;
	struct container *container = get_container(container_id);

	if (!container)
		return -EINVAL;

	ret = domain_destroy(container->domid);
	if (ret)
		return ret;

	return unregister_container_id(container_id);
}

int xrun_state(const char *container_id)
{
	struct container *container = get_container(container_id);

	if (!container)
		return -EINVAL;

	return container->status;
}
