#include "packet.h"
#include "checksum.h"

#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <string.h>

int sl_parse_ipv4_tcp(const uint8_t *packet, size_t packet_len,
                      sl_packet_view *view)
{
    const struct iphdr *ip;
    const struct tcphdr *tcp;
    size_t ihl, thl, total;
    uint16_t frag;

    if (!packet || !view || packet_len < sizeof(struct iphdr))
        return 0;

    ip = (const struct iphdr *)packet;
    if (ip->version != 4 || ip->ihl < 5 || ip->protocol != IPPROTO_TCP)
        return 0;

    ihl = (size_t)ip->ihl * 4;
    total = ntohs(ip->tot_len);
    if (total > packet_len || total < ihl + sizeof(struct tcphdr))
        return 0;

    /* This first-stage parser deliberately rejects fragmented IPv4 packets. */
    frag = ntohs(ip->frag_off);
    if (frag & (0x2000U | 0x1fffU))
        return 0;

    tcp = (const struct tcphdr *)(packet + ihl);
    thl = (size_t)tcp->doff * 4;
    if (tcp->doff < 5 || ihl + thl > total)
        return 0;

    view->ip_header_len = ihl;
    view->tcp_header_len = thl;
    view->tcp_offset = ihl;
    view->payload_offset = ihl + thl;
    view->payload_len = total - ihl - thl;
    view->packet_len = total;
    return 1;
}

int sl_recalculate_checksums(uint8_t *packet, size_t packet_len)
{
    struct iphdr *ip;
    struct tcphdr *tcp;
    size_t ihl, total, tcp_len;

    if (!packet || packet_len < sizeof(struct iphdr))
        return 0;

    ip = (struct iphdr *)packet;
    ihl = (size_t)ip->ihl * 4;
    total = ntohs(ip->tot_len);

    if (ip->version != 4 || ihl < 20 || total > packet_len ||
        total < ihl + sizeof(struct tcphdr) || ip->protocol != IPPROTO_TCP)
        return 0;

    tcp = (struct tcphdr *)(packet + ihl);
    tcp_len = total - ihl;

    ip->check = 0;
    ip->check = sl_checksum(packet, ihl);

    tcp->check = 0;
    tcp->check = sl_tcp4_checksum(packet, ihl, tcp_len);
    return 1;
}
