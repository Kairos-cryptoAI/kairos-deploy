# Restic preparation without a remote destination

This slice is the owner's explicitly selected offline preparation. The actual
operational state is `BLOCKED_DESTINATION_UNCONFIGURED`. It does not select an
SFTP host, S3 account, paid backend, retention/RPO/RTO, or managed key custodian.
It cannot upload, initialize a remote repository, dump/migrate primary, start
consumers, forget/prune/unlock, or update readiness. Local crypto success is not
off-host disaster recovery, a production key-custody proof or a DB restore.

## Interfaces and source binding

`python -m scripts.restic_preparation --policy operations/offhost-backup.example.json`
prints fixed missing prerequisites and exits 2. Unknown fields, URLs, credentials,
enablement, other profiles and non-null remote choices fail closed.

Add `--manifest`, `--accepted-history-receipt` and
`--accepted-history-signature` together to prepare a canonical four-file inventory:
the contained `Backup-Kairos.ps1` custom dump and exact manifest, plus the accepted
signed PAPER read-only receipt/signature. The proof must bind the same archive and
manifest bytes, reviewed controller/worker/catalog identities, unchanged primary,
all full-history table digests, public sequences and checkpoint counts. Only
reviewed pure validators run; there is no DB, Redis, Docker, provider or secret
connection. The dump limit is 256MiB and metadata limit 1MiB; hashing is streamed.
The output remains unsigned/signing-required and blocked for remote transfer.

Historical backup preparation does not claim that the current runtime is fresh or
recovered. Future source drift requires a newly accepted proof, not silent reuse.

## Native tool supply chain

The committed lock records official HTTPS release metadata for
[Restic 0.19.1](https://github.com/restic/restic/releases/tag/v0.19.1), Windows AMD64.
It explicitly says native signature verification and installation have not been
performed. There is no implicit download, PATH lookup, update or installer.

After source/resource review, the operator may provide the exact locked archive,
`SHA256SUMS`, `SHA256SUMS.asc` and `maintainer.asc` inside the private operational
workspace. The maintainer key is documented in the
[official installation guide](https://restic.readthedocs.io/en/stable/020_installation.html).
The verifier checks the actual copied input bytes, isolates public-key import in a
new keyring, requires primary fingerprint
`CF8F18F2844575973F79D4E191A6868BD3F7A907`, verifies the signed checksum binding,
and allows exactly one named executable ZIP entry of at most 32MiB. A caller dict
claiming `maintainer_signature_verified=true` cannot authorize execution. Every
fixture independently re-verifies the signed bundle; it cannot accept an arbitrary
executable/hash or arbitrary commands. No private GPG/API keys are read.

## Optional fixed local synthetic fixture

The optional CLI requires all three flags `--native-fixture-bundle`,
`--new-fixture-directory`, and `--authorize-local-synthetic-fixture`, with the
offline policy and no real backup inputs. Bundle and exclusively new work directory
must remain under the private operational workspace, without reparse/UNC paths.
Provision the workspace with explicit protected operator/Admin/SYSTEM read access
before use. Passwords are random ephemeral fixture values, never operator keys;
their protected files are not printed. Preserve failed fixtures for review.

The only native flow is local init, cat config, fixed synthetic stdin backup,
complete literal snapshot lookup, `check --read-data`, wrong-password decryption
rejection, and restore to an absent target with `--overwrite never --verify`.
The restored file count/name/bytes and SHA256 must match the fixed synthetic input.
Full data authentication is documented by
[repository check](https://restic.readthedocs.io/en/stable/045_working_with_repos.html),
and the exact restore flags were checked against
[the pinned 0.19.1 source](https://github.com/restic/restic/blob/v0.19.1/cmd/restic/cmd_restore.go).

The fixed input is about 2KiB; each child has a 120-second timeout and output limit
1MiB. Ambient RESTIC/SSH/provider/proxy environment is stripped. `GOMAXPROCS=1`
and `GOMEMLIMIT=256MiB` are runtime tuning, not hard OS quotas; native execution
requires explicit parent host/resource review. This script is not a network
sandbox. Its exact local command inputs provide no remote backend or credentials.
No actual binary/crypto test is claimed by mocked contract tests.

## Remaining external acceptance

An independently owned destination/failure domain, managed password/credential
custody and disaster recovery, retention/deletion isolation, RPO/RTO/cost limits,
signed exact snapshot readback and a bounded full database restore must still be
selected and proved. These are independent gates. `PAPER_QUALIFIED`, `ALPHA_READY`
and `LIVE_READY` remain false and strategy policy remains `REJECT_ALL`.
