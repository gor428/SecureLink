# SecureLink architecture notes

## Data path

1. Linux routes a selected packet through the gateway.
2. An NFQUEUE rule sends it to the userspace process.
3. The process validates IPv4/TCP lengths and fragmentation state.
4. The process selects a session and directional traffic key.
5. The TCP payload is encrypted/decrypted.
6. The IPv4 total length and checksums are updated.
7. The modified packet is accepted back into the kernel forwarding path.

## Control path

The gateways use a separate TCP control connection for the authenticated ephemeral key exchange. The control channel is not used to encapsulate protected data packets.

## Important engineering constraints

- The first parser rejects fragmented IPv4 packets. Reassembly or a documented MTU/DF policy is required before broad deployment.
- TCP segmentation offload and receive coalescing can cause userspace queue packets to differ from on-wire packets. Disable offloads on lab interfaces during initial testing.
- NFQUEUE queue overflow and userspace process failure need an explicit policy.
- The first working prototype should protect a single configured TCP flow before generalizing to multiple flows.
- The exact nonce/retransmission design must be finalized before data-plane integration. The nonce must be reproducible by the receiver without transmitting extra metadata.
