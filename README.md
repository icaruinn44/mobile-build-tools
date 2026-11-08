# Mobile build tools

Generic mobile CI workflows. Application sources and binary artifacts remain private.

The archive workflow is manual and restricted to the repository owner on `main`.
Its input is an AES-256-GCM authenticated encrypted archive; the key is supplied
only through an Actions secret. Application build output, logs and diagnostics
are encrypted before being stored as artifacts. No plaintext application source,
signing key, package or detailed application log is published by these workflows.
