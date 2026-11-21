# Private Vaultwarden setup and recovery

A small Python CLI for planning a private Vaultwarden installation, checking
its Tailscale HTTPS route, creating encrypted backups, and proving a
restored copy can start. It uses the existing Bitwarden apps for passwords, passkeys,
biometrics, and AutoFill.

## Prepare a private deployment

Requirements are Python 3.11+, Docker Compose, Tailscale with HTTPS on
your tailnet, and age for restore tests. Use a new deployment directory
and reserve loopback port 8223 and tailnet HTTPS port 8447.

Generate a Compose plan, substituting your own Tailscale node name:

```sh
python3 vault_setup.py plan --host node.exampletail.ts.net > compose.yaml
```

Review the file, start the service with `docker compose up -d`, and use
`tailscale serve --bg --https=8447 http://127.0.0.1:8223`. Tailscale Serve
keeps the route in the tailnet. Verify the route and certificate:

```sh
python3 vault_setup.py check --host node.exampletail.ts.net
```

This check confirms the route on this host and reaches the HTTPS health
endpoint. Test from your iPhone on the tailnet, then confirm the address
is unavailable from a device outside it.

## Connect your devices

Registration starts closed. Follow Vaultwarden's [admin setup](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-admin-page) and
[invite-only registration guidance](https://github.com/dani-garcia/vaultwarden/wiki/Disable-registration-of-new-users)
to provision the initial account. Keep the temporary admin endpoint private
and disable it after setup. Keep the master passphrase, two-step login
recovery, and tailnet recovery available independently of the vault.

1. In the official Bitwarden app and browser extension, select **Self-hosted**
   and enter the full HTTPS server URL, including the port.
2. On iPhone, enable Face ID in Bitwarden and select Bitwarden in
   **Settings → General → AutoFill & Passwords**.
3. Add a disposable login. Verify it syncs to both devices and that
   AutoFill works before importing real credentials.

[Bitwarden client setup](https://bitwarden.com/help/change-client-environment/) ·
[iPhone AutoFill](https://bitwarden.com/help/auto-fill-ios/)

## Create an encrypted backup

Use the data directory from the Compose deployment and an age public key.
Keep its corresponding private recovery key off-host. Stop Vaultwarden
briefly for the backup so attachments and SQLite describe the same point
in time. Restart it afterward, including if the backup fails. The CLI
creates an SQLite snapshot and captures the server key, configuration,
and any regular attachment and Send files. It accepts a new archive path
on a local filesystem with hard links.

```sh
python3 vault_setup.py backup --data ./data \
  --recipient "$AGE_PUBLIC_KEY" --output ./vault-backup.tar.gz.age
```

Save the printed SHA-256 with your backup receipt. Copy only the resulting
ciphertext to independent storage. Use a fresh output filename each time.

## Check a restore

This command accepts an age-encrypted gzip tar archived from one
Vaultwarden server. Use an SQLite online backup and include
`db.sqlite3` and `rsa_key.pem` together in one directory within the tar.
Get the expected SHA-256 at creation time and test a separately
downloaded copy. See [Vaultwarden backup guidance](https://github.com/dani-garcia/vaultwarden/wiki/Backing-up-your-vault)
for the complete data set, including attachments and server configuration.

```sh
mkdir -p receipts
python3 vault_setup.py restore-check downloaded.tar.gz.age \
  --sha256 "$EXPECTED_SHA256" --identity /path/to/recovery-key \
  --receipt receipts/drill.json
```

Add `--sudo-docker` if your Docker setup already permits noninteractive
sudo. The command requires the pinned image locally, authenticates
and extracts only the two required files, checks SQLite, and boots a
temporary container without networking. A receipt records the archive
hash, account and encrypted item counts, and successful isolated boot.
Backup assets at the archive root are copied into the drill; saved server
configuration is excluded from the drill so production settings cannot
change its security controls. The receipt does not establish successful
attachment downloads, client login, or decryption. Rehearse those
separately using a disposable account.

Check receipt freshness for a recurring local check:

```sh
python3 vault_setup.py status --receipt receipts/drill.json --max-age-days 30
```
The tool never requests the vault master passphrase or prints vault items.

Run unit checks with `python3 -m unittest -q`. With the pinned image
already available, run `bash tests/smoke.sh` to test the disposable backup
and restore. No live vault is touched. See [adoption research](ADOPTION.md)
and [security reporting](SECURITY.md). The helper is independent of
Vaultwarden and Bitwarden.
