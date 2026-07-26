# Restoring a validator host without creating a second signer

The only outcome this procedure refuses to allow is two instances signing with
the same keys. Downtime during the procedure is expected and acceptable.

Read the whole thing before starting. Do not improvise the order.

## What you need before you touch anything

- Console or Session Manager access to the host being replaced, or firm
  evidence that it is powered off.
- The keystore backup and its password.
- A slashing-protection export (EIP-3076) taken from the instance that was
  signing. The newer, the better.
- The genesis validators root of the network, from the beacon node that will
  serve the new host:

  ```
  curl -s "$BEACON/eth/v1/beacon/genesis" | jq -r .data.genesis_validators_root
  ```

- The current head epoch, from the same node:

  ```
  curl -s "$BEACON/eth/v1/beacon/headers/head" \
    | jq -r '.data[0].header.message.slot | tonumber / 32 | floor'
  ```

- `slashguard` on the new host at `/usr/local/bin/slashguard`.

## 1. Stop the old signer, and prove it

Not "restart it later". Stop it, and make it unable to come back on its own.

```
systemctl stop eth-validator
systemctl disable eth-validator
mv /var/lib/eth/validator/keys /var/lib/eth/validator/keys.retired
```

If the old host is unreachable, do not proceed on the assumption that it is
down. Terminate it through the cloud API and confirm the state transition
before continuing. A host you cannot see is a host that may be signing.

## 2. Take a fresh export, if you still can

```
lighthouse account validator slashing-protection export /tmp/slashing-protection.json
```

An export taken now is worth more than any backup. If the old host is gone,
use the most recent backup and expect step 4 to flag it as stale — that
finding is the procedure working, not a nuisance.

## 3. Put the keys and the export on the new host

Copy the keystores into `/var/lib/eth/validator/keys` and the export to
`/var/lib/eth/validator/slashing-protection.json`. Fix ownership:

```
chown -R ethvalidator:ethvalidator /var/lib/eth/validator
chmod 0700 /var/lib/eth/validator/keys
```

Do not start anything yet.

## 4. Run the preflight

```
slashguard \
  --interchange /var/lib/eth/validator/slashing-protection.json \
  --keystores   /var/lib/eth/validator/keys \
  --genesis-validators-root 0x<from step 0> \
  --current-epoch <from step 0> \
  --format markdown | tee /var/log/eth/restore-$(date -u +%Y%m%dT%H%M%SZ).md
```

Exit code 0 and you may continue. Exit code 1 and you may not: read the failure
sequence attached to the finding, fix the cause, and run it again. The most
common blocking findings during a restore are:

| Rule  | Means |
|-------|-------|
| SP004 | a keystore on this host is not covered by the export |
| SP002 | the export came from a different chain |
| SP008 | the export is older than the tolerance you set |
| SP005 | the export has two histories for one key |

Keep the Markdown output. It is the record that the restore was checked, and
it is the first thing anyone will ask for if something goes wrong later.

## 5. Import the protection database, then the keys

```
lighthouse account validator slashing-protection import \
  /var/lib/eth/validator/slashing-protection.json
```

Protection first, keys second. Every time. A client that finds keys without a
protection database will happily sign from zero.

## 6. Start with doppelganger protection on

```
systemctl start eth-validator
journalctl -u eth-validator -f
```

The client will sit out two to three epochs while it listens for its own
attestations on the network. Missing those attestations is the price of
finding out that the old host is still signing before you join it.

If doppelganger protection triggers, stop. You have two signers. Go back to
step 1 and find the other one.

## 7. Confirm and record

- Attestations appearing on a block explorer for the expected keys.
- `validator_monitor_prev_epoch_attestation_hits_total` climbing.
- The preflight report from step 4 filed with the change record.
- The old host's keystores deleted, not just moved.

## Rehearsing this

Run the whole procedure on Holesky or Hoodi, end to end, including step 4 with
a deliberately incomplete export so you see the block happen. A restore
procedure that has only ever been read is not a tested restore procedure.
