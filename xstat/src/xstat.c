#include <string.h>
#include <stdio.h>
#include <zephyr/shell/shell.h>
#include <zephyr/arch/arm64/hypercall.h>
#include <zephyr/xen/public/version.h>
#include <zephyr/xen/public/sysctl.h>
#include <zephyr/xen/public/sched.h>
#include <xstat.h>
#include <xss.h>

static int xenstat_get_domain_name(unsigned int domain_id, char *name, int len)
{
	char path[80];

	snprintf(path, sizeof(path),"/local/domain/%i/name", domain_id);
	return xss_read(path, name, len);
}

/* Get domain states */
unsigned int xenstat_domain_dying(xenstat_domain * domain)
{
	return (domain->state & XEN_DOMINF_dying) == XEN_DOMINF_dying;
}

unsigned int xenstat_domain_crashed(xenstat_domain * domain)
{
	return ((domain->state & XEN_DOMINF_shutdown) == XEN_DOMINF_shutdown)
	    && (((domain->state >> XEN_DOMINF_shutdownshift)
		 & XEN_DOMINF_shutdownmask) == SHUTDOWN_crash);
}

unsigned int xenstat_domain_shutdown(xenstat_domain * domain)
{
	return ((domain->state & XEN_DOMINF_shutdown) == XEN_DOMINF_shutdown)
	    && (((domain->state >> XEN_DOMINF_shutdownshift)
		 & XEN_DOMINF_shutdownmask) != SHUTDOWN_crash);
}

unsigned int xenstat_domain_paused(xenstat_domain * domain)
{
	return (domain->state & XEN_DOMINF_paused) == XEN_DOMINF_paused;
}

unsigned int xenstat_domain_blocked(xenstat_domain * domain)
{
	return (domain->state & XEN_DOMINF_blocked) == XEN_DOMINF_blocked;
}

unsigned int xenstat_domain_running(xenstat_domain * domain)
{
	return (domain->state & XEN_DOMINF_running) == XEN_DOMINF_running;
}

int xstat_getvcpu(xenstat_vcpu *info, int dom, int vcpu)
{
	struct xen_domctl domctl;
	int ret;

	memset(&info, 0, sizeof(info));
	domctl.cmd = XEN_DOMCTL_getvcpuinfo;
	domctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
	domctl.domain = dom;
	domctl.u.getvcpuinfo.vcpu  = vcpu;
	ret = HYPERVISOR_domctl(&domctl);
	if (ret < 0)
		return ret;
	info->online = domctl.u.getvcpuinfo.online;
	info->ns = domctl.u.getvcpuinfo.cpu_time;
	return 0;
}

int xstat_getdominfo(xenstat_domain *domains, int first, int num)
{
	struct xen_sysctl sysctl;
	struct xen_domctl_getdomaininfo *domaininfo;
	struct xen_domctl_getdomaininfo infos[MAX_DOMAINS]; 
	int i, ret;

	if (num > MAX_DOMAINS)
		num = MAX_DOMAINS;
	memset(&sysctl, 0, sizeof(sysctl));
	sysctl.cmd = XEN_SYSCTL_getdomaininfolist;
	sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
	sysctl.u.getdomaininfolist.first_domain = first;
	sysctl.u.getdomaininfolist.max_domains  = num;
	sysctl.u.getdomaininfolist.buffer.p  = infos;
	ret = HYPERVISOR_sysctl(&sysctl);
	if (ret < 0)
		return ret;
	domaininfo = sysctl.u.getdomaininfolist.buffer.p;
	for (i = 0; i < sysctl.u.getdomaininfolist.num_domains; i++)
	{
		domains[i].id = domaininfo[i].domain;
		memset(domains->name, 0, MAX_DOMAIN_NAME);
		xenstat_get_domain_name(domaininfo->domain, domains[i].name, MAX_DOMAIN_NAME);
		printk("Domain: %d name %s\n", domains[i].id, domains[i].name);
		domains[i].state = domaininfo[i].flags;
		domains[i].cpu_ns = domaininfo[i].cpu_time;
		domains[i].num_vcpus = (domaininfo[i].max_vcpu_id+1);
		domains[i].cur_mem = ((unsigned long long)domaininfo[i].tot_pages) * CONFIG_MMU_PAGE_SIZE;
		domains[i].max_mem = domaininfo->max_pages == UINT_MAX
			? (unsigned long long)-1
			: (unsigned long long)(domaininfo[i].max_pages * CONFIG_MMU_PAGE_SIZE);
		domains[i].ssid = domaininfo[i].ssidref;
	}
	return sysctl.u.getdomaininfolist.num_domains;
}

int xstat_getstat(xenstat *stat)
{
	struct xen_sysctl sysctl;
	int ret;
	char extra[XEN_EXTRAVERSION_LEN];
	int major, minor;

	ret = HYPERVISOR_xen_version(XENVER_version, NULL);
	if (ret < 0)
		return ret;
	major = ret >> 16;
	minor = ret & 0xffff;
	memset(extra, 0, sizeof(extra));
	ret = HYPERVISOR_xen_version(XENVER_extraversion, extra);
	if (ret < 0)
		return ret;
	sprintf(stat->xen_version, "%d.%d%s", major, minor, extra);

	memset(&sysctl, 0, sizeof(sysctl));
	sysctl.cmd = XEN_SYSCTL_physinfo;
	sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
	ret = HYPERVISOR_sysctl(&sysctl);
	if (ret < 0)
		return ret;
	stat->cpu_hz = ((unsigned long long)sysctl.u.physinfo.cpu_khz) * 1000ULL;
	stat->num_cpus = sysctl.u.physinfo.nr_cpus;
	stat->tot_mem = ((unsigned long long)sysctl.u.physinfo.total_pages) * CONFIG_MMU_PAGE_SIZE;
	stat->free_mem = ((unsigned long long)sysctl.u.physinfo.free_pages) * CONFIG_MMU_PAGE_SIZE;

	return ret;
}

int xstat_version(const struct shell *shell)
{
	int ret;
	char extra[XEN_EXTRAVERSION_LEN];
	int major, minor;
	/*
#define XENVER_version      0

#define XENVER_extraversion 1
typedef char xen_extraversion_t[16];
#define XEN_EXTRAVERSION_LEN (sizeof(xen_extraversion_t))
	 */
	ret = HYPERVISOR_xen_version(XENVER_version, NULL);
	if (ret < 0)
		return ret;
	major = ret >> 16;
	minor = ret & 0xffff;
	memset(extra, 0, sizeof(extra));
	ret = HYPERVISOR_xen_version(XENVER_extraversion, extra);
	if (ret < 0) {
		shell_error(shell, "extravesion error %d", ret);
	}

	shell_print(shell, "Version: %d.%d%s", major, minor, extra);
	return ret;
}
