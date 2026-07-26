# terraform-aws-eth-validator

A single-region AWS reference deployment for one Ethereum validator, built
around one rule: **there is never a second instance signing with your keys.**

Two things live here.

1. **The Terraform module** — one execution + consensus host, one validator
   host, keys on the validator host only, no autoscaling group, no automatic
   failover, and a security boundary between the two that a reviewer can read
   in one sitting. Its safety properties are asserted in `terraform test`
   against a mocked provider, so CI proves them without an AWS account.

2. **`slashguard`** — a dependency-free Go binary that reads an
   [EIP-3076](https://eips.ethereum.org/EIPS/eip-3076) slashing-protection
   export and the keystore directory a host is about to load, and exits
   non-zero when the combination could produce a double signature. It runs as
   `ExecStartPre` on the validator unit, so a failed check means systemd never
   starts the client.

Everything here is testable offline. No AWS credentials are needed to run the
module's test suite, and `slashguard` never opens a socket.

## Why there is no failover

Automatic failover of a validator client is a mechanism whose failure mode is
two instances signing with the same keys. Being offline for an hour costs a
validator a small fraction of a percent of its balance. A correlated slashing
costs a meaningful fraction of the stake and ejects the validator. The trade is
not close, and a module that ships failover by default is selling you the
expensive failure to avoid the cheap one.

So: one validator instance, `create_before_destroy = false` written down
explicitly, termination protection on, doppelganger protection on, and a
preflight that refuses to start the client when the evidence is incomplete.

## slashguard

### Install

```
go install github.com/moveeeax/terraform-aws-eth-validator/cmd/slashguard@latest
```

Or from a checkout:

```
make build     # produces ./slashguard
```

### Usage example (this one runs)

The repository ships fixtures. Clone it and run the check against a host whose
keystore directory holds three keys while the export only covers two:

```
git clone https://github.com/moveeeax/terraform-aws-eth-validator
cd terraform-aws-eth-validator
make build

./slashguard \
  --interchange testdata/interchange/clean.json \
  --keystores   testdata/keystores/extra \
  --genesis-validators-root 0x415f7d28a5d66b012547d7991089127689f11afa0b6792a080a000a15bbd0352 \
  --current-epoch 120004
```

```
slashguard — EIP-3076 slashing-protection preflight

  interchange   testdata/interchange/clean.json
  keystores     testdata/keystores/extra (3 key(s))
  coverage      2 of 3 local key(s) have a protection record
  keys exported 2

2 finding(s)

  [SP004] critical keystore on this host has no slashing-protection record
    subject     0xdfbd85c4e86a4c99b58f44b2aad009e1af35888082e270dc6b5c0834e5445d3d11b7df5474c58c4997a5df323c9024eb
    detail      keystore-m_12381_3600_2_0_0.json is present in testdata/keystores/extra but absent from the export.
    failure     how this becomes a slashing:
                1. The validator client loads the keystore at start-up.
                2. No protection record exists for the key, so the client treats it as never having signed.
                3. The key signs an attestation for the current epoch as soon as it is scheduled.
                4. If the key signed at that epoch on the host being replaced, the two messages are a slashable double vote.
    remediation Do not start the validator client. Either export the missing key's history from the instance that has it, or remove the keystore from this host until you can.
...

RESULT: DO NOT START THE VALIDATOR — 1 finding(s) at or above high
```

Exit code is `1`. Swap `testdata/keystores/extra` for `testdata/keystores/clean`
and the same command exits `0` with no findings.

The genesis validators root above is a **fixture value**, not a real network
root. On a real host, read it from the beacon node that will serve the
validator:

```
curl -s "$BEACON/eth/v1/beacon/genesis" | jq -r .data.genesis_validators_root
```

This tool deliberately ships no table of network roots. A hardcoded constant
that goes stale fails in the direction of "looks fine", which is the wrong
direction for this check.

### Flags

| Flag | Meaning |
|---|---|
| `--interchange FILE` | the EIP-3076 export (required) |
| `--keystores DIR` | keystore directory this host will load |
| `--genesis-validators-root R` | expected root, from your own beacon node |
| `--current-epoch N` | head epoch, used for the staleness check |
| `--max-epoch-lag N` | staleness tolerance in epochs (default 4) |
| `--format` | `text`, `json` or `markdown` |
| `--fail-on` | `info`, `medium`, `high` (default), `critical` |

Exit codes: `0` clean, `1` blocked, `2` the check could not run.

Checks that could not run because an input was missing are printed as skipped.
A pass with skipped checks is not a clean bill of health, and the output says
so rather than quietly implying otherwise.

### Rules

Every finding carries a numbered failure sequence: the steps by which the
condition turns into a slashed validator. A finding without one is a lint
warning, and nobody gets out of bed for a lint warning.

| Rule | Severity | Condition |
|---|---|---|
| SP001 | critical | `interchange_format_version` is not `5` |
| SP002 | critical | the export's genesis root is not the target network's |
| SP003 | high | `genesis_validators_root` missing or malformed |
| SP004 | critical | a keystore on this host has no record in the export |
| SP005 | critical | a public key appears twice with different histories |
| SP006 | high | a key's history is empty |
| SP007 | critical | an attestation record has `source_epoch > target_epoch` |
| SP008 | high | the export is more than `--max-epoch-lag` epochs behind head |
| SP009 | medium | the export covers a key this host does not hold |
| SP010 | critical | a slot or epoch is not a uint64 |
| SP011 | high | a public key is not 48 bytes of hex |
| SP012 | high | the export contains epochs later than head |
| SP013 | info | slots and epochs encoded as JSON numbers, not strings |
| SP014 | medium | a file in the keystore directory is not readable as a keystore |

## The Terraform module

### What it creates

- One beacon host: execution client plus consensus client, its own EBS volume
  for chaindata, peer ports open to the internet.
- One validator host: the validator client and the keystores. No inbound rules
  except an optional metrics scrape from CIDRs you name. It reaches the beacon
  API through a security-group reference, never a CIDR.
- IMDSv2 required, encrypted volumes, no SSH key on either host — access is
  Session Manager.
- An IAM role for the validator host that grants nothing beyond SSM. There is
  no cloud path to the keys, so an attacker holding the instance role cannot
  reconstruct the key set on a second machine.
- A systemd unit whose `ExecStartPre` is `slashguard`.

It does **not** download client binaries. Fetching an execution client at first
boot, unverified, onto a host that will hold consensus state, is a supply-chain
problem dressed up as convenience. The versions the deployment expects are
written to `/etc/eth-validator/versions.env`; installing pinned,
checksum-verified binaries is your configuration management's job.

### Usage

```hcl
module "validator" {
  source = "github.com/moveeeax/terraform-aws-eth-validator"

  name    = "holesky-01"
  network = "holesky"

  vpc_id              = "vpc-0123456789abcdef0"
  beacon_subnet_id    = "subnet-0123456789abcdef0" # public
  validator_subnet_id = "subnet-0abcdef1234567890" # private

  beacon_ami_id    = "ami-0123456789abcdef0"
  validator_ami_id = "ami-0abcdef1234567890"

  fee_recipient = "0x000000000000000000000000000000000000dEaD"

  # curl -s "$BEACON/eth/v1/beacon/genesis" | jq -r .data.genesis_validators_root
  genesis_validators_root = "0x<64 hex characters from your own beacon node>"

  monitoring_cidr_blocks = ["10.20.0.0/16"]
}
```

A complete example is in [`examples/holesky`](examples/holesky).

### The safety output

`module.validator.slashing_safety` is derived entirely from configuration, so
it is known at plan time:

```
{
  validator_instance_count            = 1
  automatic_failover                  = false
  replacement_strategy                = "destroy-then-create"
  doppelganger_protection             = true
  keys_on_separate_host_from_beacon   = true
  validator_role_can_read_key_backups = false
  beacon_api_reachable_from_cidrs     = []
  validator_ingress_cidrs             = ["10.20.0.0/16"]
  slashguard_preflight                = true
  termination_protection              = true
  imdsv2_required                     = true
  volumes_encrypted                   = true
  ssh_key_configured                  = false
}
```

Diff it in a pull request and the safety posture of a change is visible before
anyone applies it. `terraform test` asserts against these same values.

### Guard rails in the variables

Some configurations are refused rather than warned about:

- `monitoring_cidr_blocks` may not contain `0.0.0.0/0`.
- `doppelganger_protection = false` also requires
  `i_accept_the_risk_of_disabling_doppelganger_protection = true`. If you
  cannot write that line down, do not disable it.
- `enable_slashguard_preflight = true` requires `genesis_validators_root`. A
  preflight that cannot tell which chain an export came from is not a
  preflight.
- `fee_recipient` must be a real 20-byte address; `graffiti` must fit in 32
  bytes; `chaindata_volume_size_gb` has a floor.

## Monitoring

`monitoring/prometheus/` ships four alerts and nothing else: missed
attestations, peer count collapse, disk fill rate, and clock skew. Those are
the conditions that reliably precede an incident on a single pair. Everything
else is a dashboard.

Fill the scrape targets from the module's `prometheus_scrape_targets` output.

## Restoring a host

[`docs/restore-procedure.md`](docs/restore-procedure.md) is the written
procedure, with `slashguard` as the gate between "the keys are on the box" and
"the client is running". Rehearse it on a testnet, including a deliberately
incomplete export, so you have seen the block happen.

## Testing

```
make test        # Go unit tests + terraform test
make test-go     # Go only
make test-tf     # terraform validate + terraform test, mocked provider
make lint        # gofmt, go vet, terraform fmt, tflint
```

`terraform test` uses `mock_provider "aws"`. It needs the AWS provider from the
registry, but no credentials and no account, and it creates nothing.

## Status and scope

This is a v1 reference deployment. It is deliberately narrow:

- Ethereum only. No other chain.
- AWS only. No other cloud.
- No DVT (Obol, SSV) topology automation.
- No remote signer (Web3Signer + HA database).
- No automatic failover, ever.

Not yet done: an end-to-end `terraform apply` against a real AWS account and a
live testnet validator. Everything in this repository is verified by offline
tests; the apply path is not yet exercised in CI.
