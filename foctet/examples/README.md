# Core examples

Recommended first examples:

- `secure_channel_tokio.rs`: authenticated native handshake with pinned peer identities.
- `secure_channel_sync.rs`: blocking equivalent of the authenticated secure-channel flow.
- `file_archive_roundtrip.rs`: single-file and split archive roundtrip for file data.

Useful commands:

```bash
cargo run -p foctet --example secure_channel_tokio
cargo run -p foctet --example secure_channel_sync
cargo run -p foctet --example file_archive_roundtrip -- <input_file> <output_dir>
```

Notes:

- Loopback channel examples generate fresh identities and exchange pins in process. Provision peer pins independently when the endpoints run on different hosts.
- New production integrations should usually start with the authenticated `secure_channel_*` examples.
- For a full cross-crate map of examples, see the [example guide](../../docs/examples.md).
