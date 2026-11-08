#ifndef SECURELINK_PACKET_H
#define SECURELINK_PACKET_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t ip_header_len;
    size_t tcp_header_len;
    size_t tcp_offset;
    size_t payload_offset;
    size_t payload_len;
    size_t packet_len;
} sl_packet_view;

/* Parse a complete, unfragmented IPv4/TCP packet. Returns 1 on success. */
int sl_parse_ipv4_tcp(const uint8_t *packet, size_t packet_len,
                      sl_packet_view *view);

/* Recalculate IPv4 and TCP checksums after packet bytes/length are changed. */
int sl_recalculate_checksums(uint8_t *packet, size_t packet_len);

#endif
