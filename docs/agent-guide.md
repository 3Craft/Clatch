# Operating Clatch with AI Agents

Clatch is designed for both human operators and autonomous coding/ops agents.
This guide summarizes the machine-readable CLI contract, discovery commands,
and safety boundaries.

## Machine Contract

- **Structured JSON everywhere**: Pass `--json` (or `--format json`), or export
  `CLATCH_FORMAT=json` in the agent environment.
- **Deterministic failure output**: In JSON mode, failures and invalid arguments
  also emit a single valid JSON object on stdout containing `error`, `passed: false`,
  and `error_detail` (`code`, `message`, `hint`, `retryable`, `next_steps`).
- **Exit codes**:
  - `0`: Success (`clatch status` without `--strict` returns `0` even when `degraded` or `pending`; pass `--strict` to fail non-healthy states).
  - `1`: Operation or verification check failed.
  - `2`: Invalid CLI arguments or unknown command.

## Zero-Hallucination Discovery

Do not guess flags or JSON schema fields. Query the binary directly:

```sh
# Full CLI catalog (commands, flags, defaults, mutating/root metadata, exit codes)
clatch help --json

# Single command metadata
clatch help whitelist --json

# Build version and embedded BPF capability
clatch version --json

# Strict JSON Schemas (Draft 2020-12) for every Clatch config file
clatch schema --list --json
clatch schema install-profile
clatch schema policy-source
clatch schema health
clatch schema openwrt
```

## Read-Only Triage Playbook

Start with non-destructive inspection commands before proposing any change:

```sh
CLATCH_FORMAT=json clatch doctor
CLATCH_FORMAT=json clatch status
CLATCH_FORMAT=json clatch config check
CLATCH_FORMAT=json clatch guard verify
CLATCH_FORMAT=json clatch explain 1.1.1.1 --live
CLATCH_FORMAT=json clatch stats
CLATCH_FORMAT=json clatch health
```

For OpenWrt gateways:

```sh
CLATCH_FORMAT=json clatch openwrt status
CLATCH_FORMAT=json clatch explain 198.18.0.1 --openwrt /etc/clatch/openwrt.json
CLATCH_FORMAT=json clatch stats --openwrt /etc/clatch/openwrt.json
```

## Safe Mutation Playbooks

### 1. Fresh Debian 13 installation

1. Generate starter files (or validate user-provided ones):
   ```sh
   clatch init profile --backend xray-core --output /root/gateway-profile.json --json
   clatch init policy --output /root/gateway-policy.json --json
   ```
2. Run full non-destructive preflight checks:
   ```sh
   clatch doctor --profile /root/gateway-profile.json --json
   clatch install plan /root/gateway-profile.json --json
   ```
3. Apply with a persistent local backup directory (arms automatic rollback timer):
   ```sh
   clatch install apply /root/gateway-profile.json /root/clatch-install --json
   ```
   The JSON output includes `confirm_command`, `rollback_command`, and `rollback_timer`.
4. Verify before confirming:
   ```sh
   clatch guard verify --json
   clatch health --json
   clatch install confirm --json
   ```

### 2. Native v2rayA whitelist updates

Always preview first (dry run is the default), review `add`, `remove`, and `needs_restart`,
then commit explicitly with `--apply`:

```sh
clatch whitelist add 198.51.100.10/32 --json
clatch whitelist add 198.51.100.10/32 --apply --json
```

### 3. Standalone policy updates

Use the two-phase intersection transaction:

```sh
clatch policy stage /etc/clatch/config.json /root/policy-tx /root/new-policy.json --json
# Update proxy routing to match, verify DNS/health, then commit or roll back:
clatch policy commit /etc/clatch/config.json /root/policy-tx --json
```

## Hard Safety Boundaries

- Never edit v2rayA's SQLite database directly; always use `clatch whitelist`.
- Never flush nftables or detach pinned TCX links to "work around" a blocked IP;
  use `clatch explain <IP> --live` to diagnose and update the approved policy cleanly.
- Never delete an unconfirmed install/migration backup directory before `confirm` succeeds.
