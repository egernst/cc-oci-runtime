/*
 * This file is part of cc-oci-runtime.
 *
 * Copyright (C) 2016 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <glib.h>
#include <uuid/uuid.h>

#include "oci.h"
#include "util.h"
#include "networking.h"
#include "hypervisor.h"
#include "common.h"

/** Length of an ASCII-formatted UUID */
#define UUID_MAX 37

/* Values passed in from automake.
 *
 * XXX: They are assigned to variables to allow the tests
 * to modify the values.
 */
private gchar *sysconfdir = SYSCONFDIR;
private gchar *defaultsdir = DEFAULTSDIR;

static gboolean
config_net_check_vf(struct cc_oci_config *config, guint index) {
        struct cc_oci_net_if_cfg *if_cfg = NULL;

        if_cfg = (struct cc_oci_net_if_cfg *)
                g_slist_nth_data(config->net.interfaces, index);

        if (!if_cfg) {
                goto out;
        }

        return if_cfg->vf_based;
out:
        return false;
}

/*!
 * Switch VF interface to container
 *
 * \param d_info \ref cc_oci_device.
 * \param pid \ ref GPid
 */
gboolean
cc_oci_switch_iface_to_container (struct cc_oci_device* d_info, GPid pid)
{

	DIR *d;
	struct dirent *dir;
	gboolean retval = false;
        guint Pid;
	int fork_pid, status;
	gchar *netns_path = NULL, *iface_name = NULL, *iface_dir_path = NULL, *pid_str = NULL;

	Pid = (unsigned) pid;

        netns_path = g_strdup_printf("/proc/%d/ns/net", Pid);

        g_debug ("cor child netns path %s", netns_path);

        iface_dir_path = g_strdup_printf("/sys/bus/pci/devices/%s/net", d_info->bdf);

	d = opendir(iface_dir_path);
        if (!d) {
                g_debug ("opening net dir on bdf %s failed", d_info->bdf);
		goto out;
        }

        while ((dir = readdir(d)) != NULL) {
                if (g_strcmp0 (dir->d_name, ".") &&
                        g_strcmp0 (dir->d_name, "..")) {
                        break;
                }
        }

        iface_name = g_strdup(dir->d_name);
	g_debug ("iface name for bdf %s - %s", d_info->bdf, iface_name);

	fork_pid = fork();
	if (!fork_pid) {
		/* child process */
		char * arg[4];
		pid_str = g_strdup_printf("%d", Pid);

                arg[0] = "/usr/bin/cc-sriovdownscript.sh";
                arg[1] = pid_str;
                arg[2] = iface_name;
                arg[3] = NULL;
                if (execvp (arg[0], &arg[0]) < 0) {
                        g_debug (" failed to execute the down script");
                }
                _exit(1);

        } else if (fork_pid > 0) {
		/* parent process - wait for exec to finish */
                while (waitpid(fork_pid, &status, 0) != fork_pid);

                if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                   g_debug("sriovdownscript existed with success");
                }
        }

        retval = true;
out:
	g_free(iface_dir_path);
	g_free(iface_name);
	g_free(netns_path);
	g_free(pid_str);
	return retval;
}
/*!
 * Bind given device to host.
 *
 * \param d_info \ref cc_oci_device.
 */
gboolean
cc_oci_bind_host (struct cc_oci_device* d_info)
{
        FILE* f;
        gchar *bind_driver_path = NULL, *unbind_driver_path = NULL;
	gboolean retval = false;

	bind_driver_path = g_strdup_printf("/sys/bus/pci/drivers/%s/bind",
				d_info->driver);
	unbind_driver_path = g_strdup_printf("/sys/bus/pci/devices/%s/driver/unbind",
				d_info->bdf);
        g_debug ("driver path for binding %s %s", d_info->bdf, bind_driver_path);

        f = fopen(unbind_driver_path, "w");
        if (!f) {
		g_debug ("cor: opening %s failed", unbind_driver_path);
		g_debug ("cor: file open error %d", errno);
		goto out;
        }
        fprintf(f, "%s", d_info->bdf);
        fclose(f);

        f = fopen (bind_driver_path, "w");
        if (!f) {
		g_debug ("cor: opening %s failed", bind_driver_path);
		g_debug ("cor: file open error %d", errno);
		goto out;
        }
        fprintf(f, "%s", d_info->bdf);
        fclose(f);

	retval = true;
out:
	g_free(bind_driver_path);
	g_free(unbind_driver_path);
        return retval;
}

/*!
 * Unbind a given interface from the host and add it as
 * a vfio pci device for the guest.
 *
 * \param config \ref cc_oci_config*
 * \param index \ref guint
 *
 */
gboolean
cc_oci_unbind_host(struct cc_oci_config *config, guint index)
{
        struct cc_oci_net_if_cfg *if_cfg = NULL;
        FILE* f;
	gchar *device_path = NULL;
	gboolean retval = false;

        if_cfg = (struct cc_oci_net_if_cfg *)
                g_slist_nth_data(config->net.interfaces, index);

        if (!if_cfg)
                goto out;

        if (!if_cfg->vf_based)
                goto out;
 
        f = fopen("/sys/bus/pci/drivers/vfio-pci/new_id", "w");
        if (!f) {
		g_debug ("cor: opening vfio-pci/new_id failed");
		g_debug ("cor: file open error %d", errno);
		goto out;
        }
        fprintf(f, "8086 1515");
        fclose(f);

	device_path = g_strdup_printf("/sys/bus/pci/devices/%s/driver/unbind", if_cfg->bdf);
        g_debug ("device_path %s", device_path);

        f = fopen(device_path, "w");
        if (!f) {
		g_debug ("cor: opening %s failed", device_path);
		g_debug ("cor: file open error %d", errno);
		goto out;
        }
        fprintf(f, "%s", if_cfg->bdf);
        fclose(f);

        f = fopen("/sys/bus/pci/drivers/vfio-pci/bind", "w");
        if (!f) {
           g_debug ("cor: opening pci-stub/bind failed");
           g_debug ("cor: file open error %d", errno);
           return false;
        }
        fprintf(f, "%s", if_cfg->bdf);
        fclose(f);

	retval = true;
out:
	g_free(device_path);
	return retval;
}

static gchar*
cc_oci_expand_device_passthru(struct cc_oci_config *config, guint index)
{
        struct cc_oci_net_if_cfg *if_cfg = NULL;
	gchar *expanded_device = NULL;
	gchar **fields = NULL;

        if_cfg = (struct cc_oci_net_if_cfg *)
                g_slist_nth_data(config->net.interfaces, index);

        if (!if_cfg) {
                goto out;
        }

        if (!if_cfg->vf_based) {
                goto out;
        }

        fields = g_strsplit (if_cfg->bdf, ":", 2);
	expanded_device = g_strdup_printf("vfio-pci,host=%s",fields[1]);
	g_strfreev(fields);

	return expanded_device;
out:
	return g_strdup("");
}

static gchar *
cc_oci_expand_net_cmdline(struct cc_oci_config *config) {
	/* www.kernel.org/doc/Documentation/filesystems/nfs/nfsroot.txt
        * ip=<client-ip>:<server-ip>:<gw-ip>:<netmask>:<hostname>:
         * <device>:<autoconf>:<dns0-ip>:<dns1-ip>
	 */

	if (! config) {
		return NULL;
	}

	if (! config->net.hostname) {
		return NULL;
	}

	return ( g_strdup_printf("ip=::::::%s::off::",
		config->net.hostname));
}

#define QEMU_FMT_NETDEV "tap,ifname=%s,script=no,downscript=no,id=%s,vhost=on"

static gchar *
cc_oci_expand_netdev_cmdline(struct cc_oci_config *config, guint index) {
	struct cc_oci_net_if_cfg *if_cfg = NULL;

	if_cfg = (struct cc_oci_net_if_cfg *)
		g_slist_nth_data(config->net.interfaces, index);

	if (if_cfg == NULL) {
		goto out;
	}


	return g_strdup_printf(QEMU_FMT_NETDEV,
		if_cfg->tap_device,
		if_cfg->tap_device);

out:
	return g_strdup("");
}

#define QEMU_FMT_DEVICE_MAC "driver=virtio-net-pci,netdev=%s,mac=%s"

static gchar *
cc_oci_expand_net_device_cmdline(struct cc_oci_config *config, guint index) {
	struct cc_oci_net_if_cfg *if_cfg = NULL;

	if_cfg = (struct cc_oci_net_if_cfg *)
		g_slist_nth_data(config->net.interfaces, index);

	if (if_cfg == NULL) {
		goto out;
	}

	return g_strdup_printf(QEMU_FMT_DEVICE_MAC,
		if_cfg->tap_device,
		if_cfg->mac_address);

out:
	return g_strdup("");
}

/*
 *
 *
 */
#define DPDK_CMDLINE_OBJ "memory-backend-file,id=dpdkmem,size=2048M,mem-path=/dev/hugepages,share=on,prealloc=on"
#define DPDK_CMDLINE_NUMA "node,memdev=dpdkmem"
#define DPDK_CMDLINE_CHAR "socket,id=char%d,path=" VHOSTUSER_PORT_PATH
#define DPDK_CMDLINE_NETD "type=vhost-user,id=mynet%d,chardev=char%d,vhostforce"
#define DPDK_CMDLINE_DEV  "virtio-net-pci,netdev=mynet%d,mac=%s"

/*!
 * Expand vhostuser qemu option for character device
 *
 * \param if_cfg \ref cc_oci_net_if_cfg.
 */
static gchar *
cc_oci_expand_vhostuser_chardev_params(struct cc_oci_net_if_cfg *if_cfg, guint index) {
	struct cc_oci_net_ipv4_cfg *ipv4_cfg = NULL;
	gchar *vhostuser_port_path = NULL;
	guint i;

	if (if_cfg == NULL) {
		goto out;
	}

	/*
	 * Need to append the interface's IP in order to identify the full
	 * vhostuser port path.  It isn't expected that there'd be multiple IPs
	 * associated with the interface, but to be safe, walk through the
	 * list and double checking that the file exists on the system.
	 */
	for (i=0; i < g_slist_length(if_cfg->ipv4_addrs); i++) {
		ipv4_cfg = (struct cc_oci_net_ipv4_cfg *)
			g_slist_nth_data(if_cfg->ipv4_addrs, i);

		vhostuser_port_path = g_strdup_printf(VHOSTUSER_PORT_PATH, ipv4_cfg->ip_address);

		if (g_file_test (vhostuser_port_path, G_FILE_TEST_EXISTS)) {
			// this is the match
			g_free(vhostuser_port_path);
			return g_strdup_printf(DPDK_CMDLINE_CHAR, index, ipv4_cfg->ip_address);
		}
		g_free(vhostuser_port_path);
	}
out:
	return g_strdup("");
}

/*!
 * Append qemu options for networking
 *
 * \param config \ref cc_oci_config.
 * \param additional_args Array that will be appended
 */
static void
cc_oci_append_network_args(struct cc_oci_config *config, 
			GPtrArray *additional_args)
{
	gchar *netdev_params = NULL;
	gchar *net_device_params = NULL;
	gchar *vhostuser_params = NULL;
	struct cc_oci_net_if_cfg *if_cfg = NULL;
	guint vhostuser_flag = 0;

	if (! (config && additional_args)) {
		return;
	}

	if ( config->net.interfaces == NULL ) {
		g_ptr_array_add(additional_args, g_strdup("-net\nnone\n"));
	} else {
		for (guint index = 0; index < g_slist_length(config->net.interfaces); index++) {

			if_cfg = (struct cc_oci_net_if_cfg *)
				g_slist_nth_data(config->net.interfaces, index);

			if (if_cfg == NULL)
				continue;

			/*
			 * vhostuser based networking interfaces are a special case which
			 * requires additional parameters
			 */
			if (if_cfg->vhostuser_socket_path != NULL ) {
				vhostuser_flag = 1;

				g_ptr_array_add(additional_args, g_strdup("-chardev"));
				vhostuser_params = cc_oci_expand_vhostuser_chardev_params(if_cfg, index);
				g_ptr_array_add(additional_args, vhostuser_params);

				g_ptr_array_add(additional_args, g_strdup("-netdev"));
				g_ptr_array_add(additional_args, g_strdup_printf(DPDK_CMDLINE_NETD,index,index));

				g_ptr_array_add(additional_args, g_strdup("-device"));
				g_ptr_array_add(additional_args, g_strdup_printf(DPDK_CMDLINE_DEV,index,if_cfg->mac_address));
			/*
			 * Check for SRIOV-VF special case: if this is a VF interface,
			 * unbind it from the host and then add command line arguments
			 */
			} else if (config_net_check_vf(config, index)) {
				if (cc_oci_unbind_host(config, index)) {
					g_ptr_array_add(additional_args, g_strdup("-device"));
					g_ptr_array_add(additional_args, cc_oci_expand_device_passthru(config, 0));
				}
			} else {
				netdev_params = cc_oci_expand_netdev_cmdline(config, index);
				net_device_params = cc_oci_expand_net_device_cmdline(config, index);
				g_ptr_array_add(additional_args, g_strdup("-netdev"));
				g_ptr_array_add(additional_args, netdev_params);
				g_ptr_array_add(additional_args, g_strdup("-device"));
				g_ptr_array_add(additional_args, net_device_params);
			}

		}

		/*
		 * If any of the interfaces detected are vhost-user based, the VM
		 * needs to be setup as a NUMA device.  The parameter needs to
		 * be set only once, so doing outside the loop in case there
		 * are multiple vhost-user interfaces attached
		 */
		if (vhostuser_flag) {
			g_ptr_array_add(additional_args, g_strdup("-object"));
			g_ptr_array_add(additional_args, g_strdup(DPDK_CMDLINE_OBJ));
			g_ptr_array_add(additional_args, g_strdup("-numa"));
			g_ptr_array_add(additional_args, g_strdup(DPDK_CMDLINE_NUMA));
		}
        }
}

/*!
 * Replace any special tokens found in \p args with their expanded
 * values.
 *
 * \param config \ref cc_oci_config.
 * \param[in, out] args Command-line to expand.
 *
 * \warning this is not very efficient.
 *
 * \return \c true on success, else \c false.
 */
gboolean
cc_oci_expand_cmdline (struct cc_oci_config *config,
		gchar **args)
{
	struct stat       st;
	gchar           **arg;
	gchar            *bytes = NULL;
	gchar            *console_device = NULL;
	gchar            *workload_dir;
	gchar		 *hypervisor_console = NULL;
	g_autofree gchar *procsock_device = NULL;

	gboolean          ret = false;
	gint              count;
	uuid_t            uuid;
	/* uuid pattern */
	const char        uuid_pattern[UUID_MAX] = "00000000-0000-0000-0000-000000000000";
	char              uuid_str[UUID_MAX] = { 0 };
	gint              uuid_index = 0;

	gchar            *kernel_net_params = NULL;
	struct cc_proxy  *proxy;

	if (! (config && args)) {
		return false;
	}

	if (! config->vm) {
		g_critical ("No vm configuration");
		goto out;
	}

	if (! config->bundle_path) {
		g_critical ("No bundle path");
		goto out;
	}

	if (! config->proxy) {
		g_critical ("No proxy");
		goto out;
	}

	/* We're about to launch the hypervisor so validate paths.*/

	workload_dir = cc_oci_get_workload_dir(config);
	if (! workload_dir) {
		g_critical ("No workload");
		goto out;
	}

	if ((!config->vm->image_path[0])
		|| stat (config->vm->image_path, &st) < 0) {
		g_critical ("image file: %s does not exist",
			    config->vm->image_path);
		return false;
	}

	if (!(config->vm->kernel_path[0]
		&& g_file_test (config->vm->kernel_path, G_FILE_TEST_EXISTS))) {
		g_critical ("kernel image: %s does not exist",
			    config->vm->kernel_path);
		return false;
	}

	if (!(workload_dir[0]
		&& g_file_test (workload_dir, G_FILE_TEST_IS_DIR))) {
		g_critical ("workload directory: %s does not exist",
			    workload_dir);
		return false;
	}

	uuid_generate_random(uuid);
	for(size_t i=0; i<sizeof(uuid_t) && uuid_index < sizeof(uuid_pattern); ++i) {
		/* hex to char */
		uuid_index += g_snprintf(uuid_str+uuid_index,
		                  sizeof(uuid_pattern)-(gulong)uuid_index,
		                  "%02x", uuid[i]);

		/* copy separator '-' */
		if (uuid_pattern[uuid_index] == '-') {
			uuid_index += g_snprintf(uuid_str+uuid_index,
			                  sizeof(uuid_pattern)-(gulong)uuid_index, "-");
		}
	}

	bytes = g_strdup_printf ("%lu", (unsigned long int)st.st_size);

	hypervisor_console = g_build_path ("/", config->state.runtime_path,
			CC_OCI_CONSOLE_SOCKET, NULL);

	console_device = g_strdup_printf (
			"socket,path=%s,server,nowait,id=charconsole0,signal=off",
			hypervisor_console);

	procsock_device = g_strdup_printf ("socket,id=procsock,path=%s,server,nowait", config->state.procsock_path);

	proxy = config->proxy;

	proxy->vm_console_socket = hypervisor_console;

	proxy->agent_ctl_socket = g_build_path ("/", config->state.runtime_path,
			CC_OCI_AGENT_CTL_SOCKET, NULL);

	g_debug("guest agent ctl socket: %s", proxy->agent_ctl_socket);

	proxy->agent_tty_socket = g_build_path("/", config->state.runtime_path,
			CC_OCI_AGENT_TTY_SOCKET, NULL);

	g_debug("guest agent tty socket: %s", proxy->agent_tty_socket);

	kernel_net_params = cc_oci_expand_net_cmdline(config);

	struct special_tag {
		const gchar* name;
		const gchar* value;
	} special_tags[] = {
		{ "@WORKLOAD_DIR@"      , workload_dir               },
		{ "@KERNEL@"            , config->vm->kernel_path    },
		{ "@KERNEL_PARAMS@"     , config->vm->kernel_params  },
		{ "@KERNEL_NET_PARAMS@" , kernel_net_params          },
		{ "@IMAGE@"             , config->vm->image_path     },
		{ "@SIZE@"              , bytes                      },
		{ "@COMMS_SOCKET@"      , config->state.comms_path   },
		{ "@PROCESS_SOCKET@"    , procsock_device            },
		{ "@CONSOLE_DEVICE@"    , console_device             },
		{ "@NAME@"              , g_strrstr(uuid_str, "-")+1 },
		{ "@UUID@"              , uuid_str                   },
		{ "@AGENT_CTL_SOCKET@"  , proxy->agent_ctl_socket    },
		{ "@AGENT_TTY_SOCKET@"  , proxy->agent_tty_socket    },
		{ NULL }
	};

	for (arg = args, count = 0; arg && *arg; arg++, count++) {
		if (! count) {
			/* command must be the first entry */
			if (! g_path_is_absolute (*arg)) {
				gchar *cmd = g_find_program_in_path (*arg);

				if (cmd) {
					g_free (*arg);
					*arg = cmd;
				}
			}
		}

		/* when first character is '#' line is a comment and must be ignored */
		if (**arg == '#') {
			g_strlcpy(*arg, "\0", LINE_MAX);
			continue;
		}

		/* looking for '#' */
		gchar* ptr = g_strstr_len(*arg, LINE_MAX, "#");
		while (ptr) {
			/* if '[:space:]#' then replace '#' with '\0' (EOL) */
			if (g_ascii_isspace(*(ptr-1))) {
				g_strlcpy(ptr, "\0", LINE_MAX);
				break;
			}
			ptr = g_strstr_len(ptr+1, LINE_MAX, "#");
		}

		for (struct special_tag* tag=special_tags; tag && tag->name; tag++) {
			if (! cc_oci_replace_string(arg, tag->name, tag->value)) {
				goto out;
			}
		}
	}

	ret = true;

out:
	g_free_if_set (bytes);
	g_free_if_set (console_device);
	g_free_if_set (kernel_net_params);

	return ret;
}

/*!
 * Determine the full path to the \ref CC_OCI_HYPERVISOR_CMDLINE_FILE
 * file.
 * Priority order to get file path : bundle dir, sysconfdir , defaultsdir
 *
 * \param config \ref cc_oci_config.
 *
 * \return Newly-allocated string on success, else \c NULL.
 */
private gchar *
cc_oci_vm_args_file_path (const struct cc_oci_config *config)
{
	gchar *args_file = NULL;

	if (! config) {
		return NULL;
	}

	if (! config->bundle_path) {
		return NULL;
	}

	args_file = cc_oci_get_bundlepath_file (config->bundle_path,
			CC_OCI_HYPERVISOR_CMDLINE_FILE);
	if (! args_file) {
		return NULL;
	}

	if (g_file_test (args_file, G_FILE_TEST_EXISTS)) {
		goto out;
	}

	g_free_if_set (args_file);

	/* Try sysconfdir if bundle file does not exist */
	args_file = g_build_path ("/", sysconfdir,
			CC_OCI_HYPERVISOR_CMDLINE_FILE, NULL);

	if (g_file_test (args_file, G_FILE_TEST_EXISTS)) {
		goto out;
	}

	g_free_if_set (args_file);

	/* Finally, try stateless dir */
	args_file = g_build_path ("/", defaultsdir,
			CC_OCI_HYPERVISOR_CMDLINE_FILE, NULL);

	if (g_file_test (args_file, G_FILE_TEST_EXISTS)) {
		goto out;
	}

	g_free_if_set (args_file);

	/* no file found, so give up */
	args_file = NULL;

out:
	g_debug ("using %s", args_file);
	return args_file;
}

/*!
 * Generate the unexpanded list of hypervisor arguments to use.
 *
 * \param config \ref cc_oci_config.
 * \param[out] args Command-line to expand.
 * \param hypervisor_extra_args Additional args to be appended
 *
 * \return \c true on success, else \c false.
 */
gboolean
cc_oci_vm_args_get (struct cc_oci_config *config,
		gchar ***args,
		GPtrArray *hypervisor_extra_args)
{
	gboolean  ret;
	gchar    *args_file = NULL;
	guint     line_count = 0;
	gchar   **arg;
	gchar   **new_args;
	guint       extra_args_len = 0;

	if (! (config && args)) {
		return false;
	}

	args_file = cc_oci_vm_args_file_path (config);
	if (! args_file) {
		g_critical("File %s not found",
				CC_OCI_HYPERVISOR_CMDLINE_FILE);
	}

	ret = cc_oci_file_to_strv (args_file, args);
	if (! ret) {
		goto out;
	}

	ret = cc_oci_expand_cmdline (config, *args);
	if (! ret) {
		goto out;
	}

	/* count non-empty lines */
	for (arg = *args; arg && *arg; arg++) {
		if (**arg != '\0') {
			line_count++;
		}
	}

	if (hypervisor_extra_args) {
		extra_args_len = hypervisor_extra_args->len;
	}

	new_args = g_malloc0(sizeof(gchar*) * (line_count + extra_args_len + 1));

	/* copy non-empty lines */
	for (arg = *args, line_count = 0; arg && *arg; arg++) {
		/* *do not* add empty lines */
		if (**arg != '\0') {
			/* container fails if arg contains spaces */
			g_strstrip(*arg);
			new_args[line_count] = *arg;
			line_count++;
		} else {
			/* free empty lines */
			g_free(*arg);
		}
	}

	/*  append additional args array */
	for (int i = 0; i < extra_args_len; i++) {
		const gchar* arg = g_ptr_array_index(hypervisor_extra_args, i);
		if (arg != '\0') {
			new_args[line_count++] = g_strstrip(g_strdup(arg));
		}
	}

	/* only free pointer to gchar* */
	g_free(*args);

	/* copy new args */
	*args = new_args;

	ret = true;
out:
	g_free_if_set (args_file);
	return ret;
}

/*!
 * Populate array that will be appended to hypervisor command line.
 *
 * \param config \ref cc_oci_config.
 * \param additional_args Array to append
 */
void
cc_oci_populate_extra_args(struct cc_oci_config *config ,
		GPtrArray *additional_args)
{
	if (! (config && additional_args)) {
		return;
	}

	/* Add args to be appended here.*/
	//g_ptr_array_add(additional_args, g_strdup("-device testdevice"));

	cc_oci_append_network_args(config, additional_args);

	return;
}
