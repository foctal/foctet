# Native database storage

Native SQLx storage and atomic replay adapters for SQLite, PostgreSQL, MySQL and
MariaDB; enable `turso` for the remote HTTPS Hrana adapter. Requires Rust 1.94.
This crate is not a Worker driver. Use `foctet-storage-wire` for portable Worker
SQL plans. Initialize schemas explicitly and supply trusted writer pins and
expected revisions independently of the untrusted database.

See the [storage documentation](https://github.com/foctal/foctet/blob/main/docs/storage-integration.md)
and [security policy](https://github.com/foctal/foctet/blob/main/SECURITY.md).
