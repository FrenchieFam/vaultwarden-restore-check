# Adoption research

GitHub API snapshot, November 21, 2026 UTC. Stars provide rough interest
signals, not install counts or evidence that any one feature caused adoption.

| Project | Approx. GitHub stars | What to learn |
|---|---:|---|
| [Vaultwarden](https://github.com/dani-garcia/vaultwarden) | 71,089 | Existing mobile and browser clients remove a major switching cost. Reuse them. |
| [Uptime Kuma](https://github.com/louislam/uptime-kuma) | 94,724 | Show the observable outcome quickly. A useful result should be apparent in the first session. |
| [Dockge](https://github.com/louislam/dockge) | 24,869 | Make one existing workflow easier, and keep the underlying Compose files ordinary and editable. |
| [ttionya/vaultwarden-backup](https://github.com/ttionya/vaultwarden-backup) | 1,915 | Vaultwarden backup and rclone integration already have users and documented alternatives. Compare its restore workflow before building another backup scheduler. |
| [backup-vaultwarden](https://github.com/dayflower/backup-vaultwarden) | — | Encryption and optional cloud destinations already exist. They are baseline capabilities. |

## What this project should prove

A newcomer can go from an empty Compose directory to a private vault, use a
test login from iPhone and Brave, and produce a restore receipt from an
independently downloaded backup. Differentiate on completing that entire
journey and explaining the difference between **backup exists**,
**restored server booted**, and **a client decrypted the test entry**.
Avoid promising uniqueness before testing competing workflows.

## Release priorities

1. Lead with a short Debian/Docker quickstart and a screenshot or GIF of
   the checks, using fake hostnames and accounts. A useful demo beats a
   large feature list.
2. Make defaults visible. Loopback binding, private HTTPS, closed
   registration, no telemetry, and clear version pins should be easy to
   inspect and reproduce.
3. Publish only the supported path at first. List prerequisites and
   limitations, test clean installs and wrong-key/corrupt archive cases,
   and document rollback. Maintain a security-reporting path and choose a
   license before publishing.
4. Validate with five fresh installs on supported systems before claiming
   ease of use. Record time to first AutoFill, where people get stuck,
   and whether they can restore and decrypt the test entry independently.
   Add compatibility profiles only after the first flow is repeatable.
5. Use precise repository topics such as `vaultwarden`, `self-hosted`,
   `backup`, and `disaster-recovery`. Invite feedback on the setup and
   restore workflow once the repository and message are approved.
   [GitHub topic guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics)
