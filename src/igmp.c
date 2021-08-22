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
#include <linux/skbuff.h>
#include <linux/igmp.h>

#include <net/protocol.h>
#include <net/ip.h>

#define INTERVAL_QUERY          125
#define INTERVAL_QUERY_RESPONSE  10

void igmp_join(struct net_device *dev, __be32 group)
{
    int err;
    struct sock *sk = init_net.ipv4.mc_autojoin_sk;
    struct ip_mreqn mreq;
    struct in_addr saddr = { .s_addr = group };
    mreq.imr_multiaddr = saddr;
    mreq.imr_ifindex = dev->ifindex;

    lock_sock(sk);
    rtnl_lock();
    if ((err = ip_mc_join_group(sk, &mreq)) < 0) {
        pr_err("Failed to join upstream group %pI4: %d\n", &group, err);
    }
    rtnl_unlock();
    release_sock(sk);
}

void igmp_leave(struct net_device *dev, __be32 group)
{
    int err;
    struct sock *sk = init_net.ipv4.mc_autojoin_sk;
    struct ip_mreqn mreq;
    struct in_addr saddr = { .s_addr = group };
    mreq.imr_multiaddr = saddr;
    mreq.imr_ifindex = dev->ifindex;

    lock_sock(sk);
    rtnl_lock();
    if ((err = ip_mc_leave_group(sk, &mreq)) < 0) {
        pr_err("Failed to leave upstream group %pI4: %d\n", &group, err);
    }
    rtnl_unlock();
    release_sock(sk);
}

/**
 * Allocate a buffer for an IGMP packet.
 */
static struct sk_buff * igmp_query_alloc(struct net_device *dev, __be32 dst, __be32 code, u32 group)
{
    size_t pkt_size, igmp_hdr_size;
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct igmphdr *ih;
    void *csum_start = NULL;
    __sum16 *csum = NULL;

    igmp_hdr_size = sizeof(*ih);
    pkt_size = sizeof(*eth) + sizeof(*iph) + 4 + igmp_hdr_size;
    skb = netdev_alloc_skb_ip_align(dev, pkt_size);
    if (!skb) {
        return NULL;
    }

    skb->protocol = htons(ETH_P_IP);

    skb_reset_mac_header(skb);
    eth = eth_hdr(skb);

    ether_addr_copy(eth->h_source, dev->dev_addr);
    ip_eth_mc_map(dst, eth->h_dest);
    eth->h_proto = htons(ETH_P_IP);
    skb_put(skb, sizeof(*eth));

    skb_set_network_header(skb, skb->len);
    iph = ip_hdr(skb);
    iph->tot_len = htons(pkt_size - sizeof(*eth));

    iph->version = 4;
    iph->ihl = 6;
    iph->tos = 0xc0;
    iph->id = 0;
    iph->frag_off = htons(IP_DF);
    iph->ttl = 1;
    iph->protocol = IPPROTO_IGMP;
    iph->saddr = inet_select_addr(dev, 0, RT_SCOPE_LINK);
    iph->daddr = dst;
    ((u8 *)&iph[1])[0] = IPOPT_RA;
    ((u8 *)&iph[1])[1] = 4;
    ((u8 *)&iph[1])[2] = 0;
    ((u8 *)&iph[1])[3] = 0;
    ip_send_check(iph);
    skb_put(skb, 24);

    skb_set_transport_header(skb, skb->len);

    ih = igmp_hdr(skb);
    ih->type = IGMP_HOST_MEMBERSHIP_QUERY;
    ih->code = code;
    ih->group = group;
    ih->csum = 0;
    csum = &ih->csum;
    csum_start = (void *)ih;

    *csum = ip_compute_csum(csum_start, igmp_hdr_size);
    skb_put(skb, igmp_hdr_size);
    __skb_pull(skb, sizeof(*eth));

    return skb;
}

/**
 * Send an IGMP query to the downstream network.
 */
static void igmp_query_send(struct net_device *dev, __be32 dst, __be32 code, __be32 group)
{
    struct sk_buff *skb = igmp_query_alloc(dev, dst, code, group);

    if (!skb) {
        pr_err("Failed to allocate packet buffer for IGMP packet\n");
        return;
    }

    dev_queue_xmit(skb);
}

void igmp_probe(struct net_device *dev, __be32 group)
{
    __be32 code = htonl(INTERVAL_QUERY_RESPONSE * IGMP_TIMER_SCALE);

    pr_info("Sent membership query for group %pI4\n", &group);

    igmp_query_send(dev, group, code, group);
}

void igmp_probe_all(struct net_device *dev)
{
    __be32 dst = htonl(INADDR_ALLHOSTS_GROUP);
    __be32 code = htonl(INTERVAL_QUERY_RESPONSE * IGMP_TIMER_SCALE);

    pr_info("Sent membership query to %pI4\n", &dst);

    igmp_query_send(dev, dst, code, 0);
}
