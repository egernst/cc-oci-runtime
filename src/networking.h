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

#ifndef _CC_OCI_NETWORKING_H
#define _CC_OCI_NETWORKING_H

#include "netlink.h"

/* Both openvswitch and VPP will place the vhost-user socket in a particular location,
 * and we chose to name the interface v_<ip address> during endpoint creation
 * in the respective Docker plugins.  VHOSTUSER_PORT_PATH is used to identify this file.
 */
#define VHOSTUSER_PORT_PATH "/tmp/v_%s"


#define SRIOV_TEARDOWN_SCRIPT	"/usr/bin/cc-sriovdownscript.sh"
#define PCI_DRIVER_UNBIND_PATH	"/sys/bus/pci/devices/%s/driver/unbind"
#define PCI_DRIVER_BIND_PATH	"/sys/bus/pci/drivers/%s/bind"
#define VFIO_RMID_PATH		"/sys/bus/pci/drivers/vfio-pci/remove_id"
#define VFIO_NEWID_PATH		"/sys/bus/pci/drivers/vfio-pci/new_id"


void cc_oci_net_interface_free (struct cc_oci_net_if_cfg *if_cfg);

void cc_oci_net_ipv4_route_free(struct cc_oci_net_ipv4_route *route);

gboolean cc_oci_network_create(const struct cc_oci_config *const config,
		      struct netlink_handle *hndl);

gchar * cc_net_get_ip_address(const gint family, const void *const sin_addr);


gboolean cc_oci_network_discover(struct cc_oci_config *const config,
			struct netlink_handle *hndl);

gboolean is_interface_ovs(struct cc_oci_net_if_cfg* if_cfg);

JsonObject * cc_oci_network_devices_to_json (const struct cc_oci_config *config);
#endif /* _CC_OCI_NETWORKING_H */
