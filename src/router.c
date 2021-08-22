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

#define MODULE_NAME "kmbridge"
#define pr_fmt(fmt) MODULE_NAME ": " fmt

#include <linux/kernel.h>

#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>

#include "router.h"

const static struct rhashtable_params route_table_params = {
    .key_len     = sizeof(u32),
    .key_offset  = offsetof(struct route, group),
    .head_offset = offsetof(struct route, linkage),
    .automatic_shrinking = true,
};
static struct rhashtable route_table;

int router_init(void)
{
    int err;
    if ((err = rhashtable_init(&route_table, &route_table_params)) < 0) {
        return err;
    }

    return 0;
}

void router_exit(void)
{
    rhashtable_destroy(&route_table);
}

void router_add_route(u32 group)
{
    struct route *route = rhashtable_lookup_fast(&route_table, &group, route_table_params);
    if (!route) {
        struct route *new_route = kzalloc(sizeof(*route), GFP_KERNEL);
        new_route->group = group;

        route = rhashtable_lookup_get_insert_fast(&route_table, &(new_route->linkage), route_table_params);
        if (!route) {
            route = new_route;
        } else {
            kfree(new_route);
        }

        if (IS_ERR(route)) {
            pr_err("Failed to insert into route table: %ld\n", PTR_ERR(route));
            return;
        }
    }
}

void router_delete_route(u32 group)
{
    struct route *route;

    rcu_read_lock();
    route = rhashtable_lookup_fast(&route_table, &group, route_table_params);
    if (route && rhashtable_remove_fast(&route_table, &route->linkage, route_table_params) == 0) {
        kfree(route);
    }
    rcu_read_unlock();
}

struct route * router_lookup(u32 group)
{
    return (struct route *) rhashtable_lookup_fast(&route_table, &group, route_table_params);
}
