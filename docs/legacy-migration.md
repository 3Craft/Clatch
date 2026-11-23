# Adopting a Legacy Python Gateway on Debian

This guide applies only if you are migrating an existing Debian 13 gateway that
uses the legacy `/etc/jdn-gateway/` layout and `jdn-gateway-guard.service`.
For fresh installations, follow the Debian quickstart in [README.md](../README.md).

## Before migrating

- Run the migration on a disposable clone first.
- Keep the migration backup on a persistent local filesystem using a new canonical absolute path.
- `clatch migrate plan` checks the running legacy guard, installed interception mode, and approved policy.
- Adoption preserves the existing boot wiring and configuration in `/etc/jdn-gateway/`.
  For that layout, pass `--config /etc/jdn-gateway/config.json` to `clatch status`,
  `clatch guard verify`, `clatch config check`, `clatch health`, `clatch explain`, or `clatch stats`.
  Use `systemctl status jdn-gateway-guard.service` to check the legacy unit.

## Migration procedure

```sh
./clatch-linux-amd64 migrate plan
./clatch-linux-amd64 migrate apply /root/clatch-migration
clatch guard verify --config /etc/jdn-gateway/config.json
clatch migrate confirm
```

`clatch migrate apply` arms a 10-minute systemd rollback timer before replacing
the entry points. Confirm after verifying the guard, DNS, and expected routes.
`clatch migrate confirm` and `clatch migrate rollback` automatically resolve the
recorded backup path from the migration state file when omitted, or you can pass
the backup directory explicitly.

To roll back manually (including after confirmation):

```sh
/root/clatch-migration/clatch-recover migrate rollback /root/clatch-migration
```

## Resolving v2rayA executable or GeoIP drift

If a v2rayA package update replaced the running executables, resolve the drift
before migrating. When the GeoIP file has changed too:

1. Restore the copy that matches `geoip_sha256` in the approved policy before restarting v2rayA.
2. Verify the legacy guard and DNS, then rerun `clatch migrate plan`.
3. After migration, keep that approved copy available while using
   `clatch whitelist refresh --config /etc/jdn-gateway/config.json --apply`
   (or `gateway-whitelist refresh --apply`) to approve the new GeoIP data.
