# Configuration

Runtime configuration is intentionally not committed yet. Device-specific secrets must not be stored in Git.

The final configuration will include:
- local role (device1/device2)
- peer control address and port
- selected protected TCP flow(s)
- pre-shared handshake authentication secret (loaded from a root-readable file)
- NFQUEUE number
- interface names

Use a random secret of at least 32 bytes. Keep the secret outside the repository and restrict permissions to root.
