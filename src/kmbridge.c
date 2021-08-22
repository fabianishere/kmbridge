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
#include <linux/module.h>
#include <linux/err.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/igmp.h>

#include <net/protocol.h>
#include <net/ip.h>

#include "igmp.h"
#include "router.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Fabian Mastenbroek <mail.fabianm@gmail.com>");
MODULE_DESCRIPTION("In-kernel IGMP Proxy");
MODULE_VERSION("1.0");

static int dev_param_get(char *buffer, const struct kernel_param *kp)
{
    struct net_device* dev = *((struct net_device **) kp->arg);

    if (!dev) {
        return scnprintf(buffer, PAGE_SIZE, "%s\n", "");
    }

    return scnprintf(buffer, PAGE_SIZE, "%s\n", dev->name);
}

static int dev_param_set(const char *val, const struct kernel_param *kp)
{
    struct net_device *dev = dev_get_by_name(&init_net, val);

    if (!dev) {
        return -EINVAL;
    }

    *((struct net_device **)kp->arg) = dev;
    return 0;
}

static void dev_param_free(void *arg) {
    struct net_device *dev = *((struct net_device **) arg);
    if (dev) {
        dev_put(dev);
    }
}

static const struct kernel_param_ops dev_param_ops = {
    .set = dev_param_set,
    .get = dev_param_get,
    .free = dev_param_free
};

static struct net_device *upstream = NULL;
module_param_cb(upstream, &dev_param_ops, &upstream, 0);
MODULE_PARM_DESC(upstream, "Upstream device");

static struct net_device *downstream = NULL;
module_param_cb(downstream, &dev_param_ops, &downstream, 0);
MODULE_PARM_DESC(downstream, "Downstream device");

static struct nf_hook_ops nf_upstream, nf_downstream;

/**
 * The netfilter receive hook attached to the upstream device.
 */
static unsigned int nf_upstream_rcv(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct route *route;
    struct sk_buff *copy;

    if (!skb) {
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);
    if (!ipv4_is_multicast(iph->daddr)) {
        return NF_ACCEPT;
    }

    pr_info("Received multicast packet from %pI4\n", &iph->saddr);

    /* Lookup the route for the multicast packet */
    route = router_lookup(iph->daddr);
    if (!route) {
        return NF_ACCEPT;
    }

    pr_info("Routing multicast packet from %pI4 to downstream\n", &iph->saddr);

    /* Clone packet and forward it to the downstream interface */
    copy = skb_clone(skb, GFP_ATOMIC);
    copy->dev = downstream;
    dev_queue_xmit(copy);

    return NF_ACCEPT;
}

/**
 * Handle incoming membership reports and update the routing table accordingly.
 *
 * @param src The source from which the report originates.
 * @param group The group to join.
 */
static void nf_downstream_report(__be32 src, __be32 group)
{
    /* Validate the group address */
    if (!ipv4_is_multicast(group)) {
        pr_debug("Dropping report with invalid multicast group %pI4\n", &group);
        return;
    }

    pr_info("Insert group %pI4 (from: %pI4) to route table\n", &group, &src);
    router_add_route(ntohl(group));
}

/**
 * Handle incoming group leave message and update the routing table accordingly.
 *
 * @param src The source from which the message originates.
 * @param group The group to leave.
 */
static void nf_downstream_leave(__be32 src, __be32 group)
{
    /* Validate the group address */
    if (!ipv4_is_multicast(group)) {
        pr_debug("Dropping leave message with invalid multicast group: %pI4\n", &group);
        return;
    }

    igmp_probe(downstream, group);
}

/**
 * The netfilter receive hook attached to the downstream device.
 */
static unsigned int nf_downstream_rcv(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct igmphdr *ih;

    if (!skb) {
        return NF_ACCEPT;
    }

    /* Verify whether we have received an IGMP pakcet */
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_IGMP) {
        return NF_ACCEPT;
    }

    /* Verify whether the packet is a valid IGMP packet */
    if (ip_mc_check_igmp(skb, NULL) < 0) {
        return NF_DROP;
    }

    ih = igmp_hdr(skb);
    switch (ih->type) {
        case IGMP_HOST_MEMBERSHIP_REPORT:
        case IGMPV2_HOST_MEMBERSHIP_REPORT:
            pr_info("Received membership report for group %pI4\n", &ih->group);
            nf_downstream_report(iph->saddr, ih->group);
            break;
        case IGMP_HOST_LEAVE_MESSAGE:
            pr_info("Host wants to leave group %pI4", &ih->group);
            nf_downstream_leave(iph->saddr, ih->group);
            break;
        default:
            pr_debug("Ignoring unknown IGMP message type %x\n", ih->type);
            break;
    }

    return NF_ACCEPT;
}

static int __init
kmbridge_init(void)
{
    int err = 0;

    /* Make sure the user has specified an upstream/downstream device */
    if (!upstream) {
        pr_err("Invalid upstream device\n");
        return -EINVAL;
    } else if (!downstream) {
        pr_err("Invalid downstream device\n");
        return -EINVAL;
    } else if (upstream == downstream) {
        pr_err("Upstream and downstream cannot be the same device\n");
        return -EINVAL;
    }

    if ((err = router_init()) < 0) {
        pr_err("Failed to initialize multicast router: %d\n", err);
        return err;
    }

    pr_debug("Attaching to upstream %s\n", upstream->name);

    nf_upstream.hook = nf_upstream_rcv;
    nf_upstream.hooknum = NF_INET_PRE_ROUTING; /* Intercept packets before routing since they will be dropped afterwards */
    nf_upstream.pf = PF_INET;
    nf_upstream.priority = NF_IP_PRI_FIRST;
    if ((err = nf_register_net_hook(&init_net, &nf_upstream)) != 0) {
        goto err_upstream_hook;
    }

    pr_debug("Attaching to downstream %s\n", downstream->name);

    nf_downstream.hook = nf_downstream_rcv;
    nf_downstream.hooknum = NF_INET_PRE_ROUTING; /* Intercept packets before routing since they will be dropped afterwards */
    nf_downstream.pf = PF_INET;
    nf_downstream.priority = NF_IP_PRI_FIRST;
    if ((err = nf_register_net_hook(&init_net, &nf_downstream)) != 0) {
        goto err_downstream_hook;
    }

    igmp_probe_all(downstream);

    pr_debug("Joining all-routers group\n");
    igmp_join(downstream, htonl(INADDR_ALLRTRS_GROUP));

    pr_info("In-kernel IGMP Proxy is running...\n");

    return 0;
err_downstream_hook:
    nf_unregister_net_hook(&init_net, &nf_upstream);
err_upstream_hook:
    router_exit();
    return err;
}

module_init(kmbridge_init)

static void __exit
kmbridge_exit(void)
{
    pr_info("Stopping...\n");

    igmp_leave(downstream, htonl(INADDR_ALLRTRS_GROUP));

    /* Unregister netfilter hooks */
    nf_unregister_net_hook(&init_net, &nf_upstream);
    nf_unregister_net_hook(&init_net, &nf_downstream);

    router_exit();
}

module_exit(kmbridge_exit);
