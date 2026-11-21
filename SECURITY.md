# Security policy

The first supported configuration is one Linux Docker host, a pinned
Vaultwarden image, and private Tailscale HTTPS. Keep the image and clients
updated, and verify a restore before promoting an update.

Never include vault exports, database files, passwords, keys, tokens, or
private hostnames in a bug report. Use disposable data to reproduce issues.

If this repository is published, use its GitHub private vulnerability
reporting channel when enabled. Share the smallest possible reproduction,
affected version, and expected behavior. The public issue tracker is
appropriate for setup questions without confidential information.

The tool reports exactly what it checked. An isolated server boot and
SQLite integrity check do not establish successful client decryption,
attachment download, or recovery of a lost authentication factor.
