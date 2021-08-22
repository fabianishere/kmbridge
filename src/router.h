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

#ifndef KMBRIDGE_ROUTER_H
#define KMBRIDGE_ROUTER_H

#include <linux/rhashtable.h>

/**
 * A route for a specific multicast group address.
 */
struct route {
    /**
     * The multicast group to which this route belongs.
     */
    u32 group;

    struct rhash_head linkage;
    refcount_t ref;
    struct rcu_head rcu_read;

    /* The age of the route */
    int age_value;
    /* Activity counter */
    int age_activity;
};

/**
 * Initialize the multicast router for the downstream networks.
 */
int router_init(void);

/**
 * Release all resources associated with the multicast router.
 */
void router_exit(void);

/**
 * Add a route to the routing table for the specified group.
 *
 * @param group The group to add to the routing table.
 * @param src The source device requesting the route.
 */
void router_add_route(u32 group);

/**
 * Delete a route to the routing table for the specified group.
 *
 * @param group The group to remove from the routing table.
 */
void router_delete_route(u32 group);

/**
 * Lookup the route for a certain group.
 *
 * @param group The group to lookup the route for.
 * @return The found route or <code>null</code> if no route exists.
 */
struct route * router_lookup(u32 group);

#endif /* KMBRIDGE_ROUTER_H */
