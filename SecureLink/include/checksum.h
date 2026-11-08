#ifndef SECURELINK_CHECKSUM_H
#define SECURELINK_CHECKSUM_H

#include <stddef.h>
#include <stdint.h>

uint16_t sl_checksum(const void *data, size_t len);
uint16_t sl_tcp4_checksum(const uint8_t *ipv4_packet,
                          size_t ip_header_len,
                          size_t tcp_len);

#endif
