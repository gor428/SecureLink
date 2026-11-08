#include "checksum.h"

#include <arpa/inet.h>
#include <string.h>

uint16_t sl_checksum(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += ((uint16_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len)
        sum += (uint16_t)p[0] << 8;

    while (sum >> 16)
        sum = (sum & 0xffffU) + (sum >> 16);

    return htons((uint16_t)~sum);
}

/* ipv4_packet points to the start of the IPv4 header. */
uint16_t sl_tcp4_checksum(const uint8_t *ipv4_packet,
                          size_t ip_header_len,
                          size_t tcp_len)
{
    uint32_t sum = 0;
    const uint8_t *tcp = ipv4_packet + ip_header_len;
    size_t i;

    /* IPv4 pseudo-header: source, destination, zero, protocol, TCP length. */
    for (i = 12; i < 20; i += 2)
        sum += ((uint16_t)ipv4_packet[i] << 8) | ipv4_packet[i + 1];

    sum += 6; /* IPPROTO_TCP */
    sum += (uint16_t)tcp_len;

    for (i = 0; i + 1 < tcp_len; i += 2)
        sum += ((uint16_t)tcp[i] << 8) | tcp[i + 1];

    if (tcp_len & 1U)
        sum += (uint16_t)tcp[tcp_len - 1] << 8;

    while (sum >> 16)
        sum = (sum & 0xffffU) + (sum >> 16);

    return htons((uint16_t)~sum);
}
