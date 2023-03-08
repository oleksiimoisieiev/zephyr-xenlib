/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XENLIB_XEN_DOMAIN_H
#define XENLIB_XEN_DOMAIN_H

#include <sys/types.h>
#include <zephyr/xen/events.h>
#include <zephyr/xen/generic.h>

struct xen_domain_iomem {
	/* where to map, if 0 - map to same place as mfn */
	uint64_t first_gfn;
	/* what to map */
	uint64_t first_mfn;
	/* how much frames to map */
	uint64_t nr_mfns;
};

typedef int (*load_image_bytes_t)(uint8_t *buf, size_t bufsize,
                uint64_t image_load_offset, void *image_info);
typedef ssize_t (*get_image_size_t)(void *image_info, uint64_t *size);

struct xen_domain_cfg {
	uint64_t mem_kb;

	uint32_t flags;
	uint32_t max_vcpus;
	uint32_t max_evtchns;
	int32_t gnt_frames;
	int32_t max_maptrack_frames;

	/* ARM arch related */
	uint8_t gic_version;
	uint16_t tee_type;

	/* For peripheral sharing*/
	struct xen_domain_iomem *iomems;
	uint32_t nr_iomems;

	uint32_t *irqs;
	uint32_t nr_irqs;

	char **dtdevs;
	uint32_t nr_dtdevs;

	char *cmdline;

	const char *dtb_start, *dtb_end;

	load_image_bytes_t load_image_bytes;
	get_image_size_t get_image_size;

	void *image_info;
};

struct xen_domain {
	uint32_t domid;
	struct xencons_interface *intf;
	struct xenstore_domain_interface *domint;
	int num_vcpus;
	int address_size;
	uint64_t max_mem_kb;
	sys_dnode_t node;
	size_t stack_slot;

	struct k_sem console_sem;
	struct k_thread console_thrd;
	k_tid_t console_tid;
	bool console_thrd_stop;
	evtchn_port_t console_evtchn;
	evtchn_port_t local_console_evtchn;

	struct k_sem xb_sem;
	struct k_thread xenstore_thrd;
	bool xenstore_thrd_stop;
	k_tid_t xenstore_tid;
	evtchn_port_t xenstore_evtchn;
	evtchn_port_t local_xenstore_evtchn;

	int transaction;
	int running_transaction;
	int stop_transaction_id;
	bool pending_stop_transaction;
};

#endif /* XENLIB_XEN_DOMAIN_H */
