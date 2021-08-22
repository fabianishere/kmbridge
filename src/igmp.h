/*
 * kmbridge: In-kernel IGMP Proxy support
 *
 * Copyright (C) 2021 Fabian Mastenbroek.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef KMBRIDGE_IGMP_H
#define KMBRIDGE_IGMP_H

#include <linux/netdevice.h>

/**
 * Join the given multicast group on the upstream network.
 *
 * @param dev The net device that should join the group.
 * @param group The group to join.
 */
void igmp_join(struct net_device *dev, __be32 group);

/**
 * Leave the given multicast group on the upstream network.
 *
 * @param dev The net device that should leave the group.
 * @param group The group to leave.
 */
void igmp_leave(struct net_device *dev, __be32 group);

/**
 * Probe all devices in the downstream network for a specific group membership.
 *
 * @param dev The net device that should send the probe.
 * @param group The group to probe.
 */
void igmp_probe(struct net_device *dev, __be32 group);

/**
 * Probe all devices in the downstream network for group membership.
 *
 * @param dev The net device that should send the probe.
 */
void igmp_probe_all(struct net_device *dev);

#endif /* KMBRIDGE_IGMP_H */
