# The vault: the disk's salt from a vault

The vault is remote attestation over TLS: before it releases its part of
the disk's key, kira-vault verifies a quote of this TPM against the
slot's approved boot state. The code (at the console or over SSH) and the
phone (at the machine) are the other two ways the boot is checked.

> Arch and Debian. Experimental. The vault releases its part when its
> checks pass, or once an operator approves the boot - on the vault's
> command line, or over its operator REST interface, where the approval
> can carry an operator's **pepper** that goes into the key (§12).
>
> Two programs: **kira** on the machine, and **kira-vault**, a
> separate service with a TPM of its own, in its own repository beside this
> one (`../kira-vault`). Their contract is the Go package
> `vaultproto` in this repository. What is planned beyond it is
> [PLAN-VAULT.md](PLAN-VAULT.md); how the recipes of the disk's key
> compare, [DISK-KEY.md](DISK-KEY.md).

The vault keeps a keyslot's **salt**: a part only this machine's TPM opens,
and only in a boot state the slot's signing key approved, before the boot
is closed (PCR 15). The vault releases it only to a fresh TPM quote of such a
state, and stops releasing it for a machine an operator revokes. The
keyslot's **password** is the TPM's own part - nothing is typed, the
machine unlocks unattended (`0x2400`, with a pepper `0x2401`) - or typed by
the person at the machine after the code screen (`0x1400`, `0x1401`).
Without the vault, the recovery recipe and the recovery passphrase stay
the way in.

```bash
vault#    kira-vault token create --name db-03     # prints the line below
machine#  kira luks enrol /dev/sda2 --password tpm --salt vault \
              --url https://vault:8443 --pin sha256:… --token …
```

Contents: [1 The idea](#1-the-idea) ·
[2 What protects the key](#2-what-protects-the-key) ·
[3 Setting it up](#3-setting-it-up) · [4 Enrolment](#4-enrolment) ·
[5 At boot](#5-at-boot) · [6 The vault](#6-the-vault) ·
[7 The machine's side](#7-the-machines-side) ·
[8 The protocol](#8-the-protocol) · [9 Threats](#9-threats) ·
[10 The code](#10-the-code) · [11 Tests](#11-tests) ·
[12 Operator approval and the pepper](#12-operator-approval-and-the-pepper) · [12a The one-time keyboard](#12a-the-one-time-keyboard) · [13 Known limits](#13-known-limits)

## 1. The idea

```
salt     = hex( HKDF-SHA256(ikm = R, salt = P or none,
                            info = "kira/vault/salt/v1" ‖ lp(label), len = 32) )
password = typed at the machine                                   (0x1400, 0x1401)
         | hex( HKDF-SHA256(ikm = L, info = "kira/vault/password/v1" ‖ lp(label)) )
                                                                  (0x2400, 0x2401)
key      = the combiner's: Argon2id(password, salt), base64 and a newline
```

The keyslot's passphrase is the combiner's, as for every recipe
([DISK-KEY.md](DISK-KEY.md)): a guessed pepper costs a whole Argon2id. The
derivation strings and the label are the contract with every enrolled
keyslot.

| Part | Where it is kept | Who can open it |
|---|---|---|
| **L**, local, 32 bytes (unattended recipes only) | in the slot's blob in the machine's TPM NV (attestation method 2), wrapped with `TPM2_MakeCredential` for the TPM's EK and the slot's release key | this TPM, in a boot state the slot's signing key approved, before the close (PCR 15) |
| **R**, remote, 32 bytes | only in the vault, wrapped the same way, encrypted there under a key sealed in the **vault's** TPM | the vault releases it (§5); then only this machine's TPM opens it, under the same policy as L |
| **P**, pepper (optional, per keyslot) | with an operator; typed once on the machine at enrolment, never sent then, never stored by the vault | given with each approval (the vault's CLI or its operator interface); the vault passes it on once, wrapped for the machine's TPM like R (§12) |

R is drawn on the machine at enrolment; the vault never sees it in the
clear. With a pepper and an unattended recipe, the slot's blob keeps an
HMAC of the key (the pepper check) to tell a mistyped pepper from the
right one at boot. Neither part is ever stored in the clear anywhere; the
key exists only in the moment it is derived and handed to cryptsetup.

## 2. What protects the key

Three layers, each depending on PCR state:

1. **The machine's TPM.** L and R open only through the release key's
   policy (`core/attest/releasekey.go`): the slot's approval - PolicyPCR over
   the sealed selection, PolicyNV over the generation, the signing key's
   signature, PolicyAuthorize, PolicyPCR(15 == zero) (SECURITY-BACKGROUND.md §4) - then
   PolicyCommandCode(ActivateCredential). After the close (PCR 15
   extended at the end of the code screen) the release key's own policy
   fails, so in the running system, root included, neither part opens,
   whatever the signing key approves. A copied or relayed answer of the vault is useless on any other
   TPM.
2. **The vault's check** (`vaultproto.VerifyRelease`). The machine quotes
   the slot's sealed selection with its attestation key over a fresh
   challenge of the vault, and sends the slot's approval signature and
   generation. The vault rebuilds the approved policy from the quoted
   values and verifies the signature with the signing key it pinned at
   enrolment. So it releases R exactly for the boot states the machine's
   own signing key approved - a slot's PCR 11 signed by the PCR key it
   pinned at enrolment by that key's signature, which the machine sends too -
   no list of PCR values on the vault, and a
   approve after a kernel update needs nothing there - and refuses a
   generation lower than the highest it has seen (an approval an approval
   revoked). It also refuses a revoked device, rate-limits, locks a device
   after repeated failures, and logs every request. And it establishes Secure
   Boot's state from the quoted PCR 7 and PCR 7's events from the event log,
   replayed against it (`attest.EstablishSecureBoot`): `on`, `off`, `setup_mode` or
   `not_established`, never what the machine says. Every state but `on` is red in the
   device's view and in the audit, for a request refused too. **It refuses every state but `on`**, on top of the check above, also what
   the signing key approved and a slot whose selection has no PCR 7, which is
   `not_established`; no per-device exception (docs/SECURITY-BACKGROUND.md §13.5). A refused
   state is no failure of the device, and asks no operator.
3. **The vault's TPM.** Each device record is encrypted with a key sealed
   in the vault's TPM to the vault's own PCRs (default PCR 7). A copy of
   the vault's disk or a backup opens nothing; a vault booted in another
   state releases nothing.

What the vault adds over a local-only key: a machine can be **revoked** -
reported stolen, it no longer unlocks, even in a good boot state - and it
does not unlock away from the network that reaches the vault. What the
vault cannot do: open a disk.

## 3. Setting it up

**On the vault host** (a machine with a TPM 2.0, Secure Boot on, its state
directory on an encrypted volume measured into PCR 15), as root:

```bash
make -C kira-vault build && sudo make -C kira-vault install   # /usr/bin and the unit
sudo kira-vault control                                       # the guided way, or by hand:
kira-vault init --url https://vault.example:8443              # --pcrs 7,15 by default
systemctl enable --now kira-vault
# open TCP 8443 in the firewall for the machines
```

`kira-vault control` is the vault's control panel, like `kira control`: every
step the command it equals, the vault judged line by line (§6.7). In a container
instead of the unit: `make container` builds the image (the release binary
alone), `make install-container` the Quadlet for podman (the host's tss group
mapped into the container's user namespace); `init` then runs in the same image
(control shows the line), and `approve` in serve's container.

`init` asks the **approval PIN** twice and checks the vault host's logs (Secure
Boot from PCR 7's events, the state directory's volume measured into PCR 15:
§6.2) before anything is made. It draws the **master key**, shows it once as the
**backup** (11 groups of five; the vault's only recovery secret: write it down and
keep it offline, §6.5), and makes in the TPM the approval key behind the PIN, the
counter and the master; it approves the vault's boot state as it is. It creates
`/var/lib/kira-vault` (0700): the vault's TLS root (ECDSA P-256, valid 20
years; its key in the TPM, §6.2) and the configuration. `serve` makes a leaf for
the vault's host or address at every start (valid 90 days, made again with fewer
than 30 days left while serving). It prints the **pin** (`sha256:` over the root's
SubjectPublicKeyInfo). `kira-vault tls root` prints the root, for the machines
and the operators: each verifies the vault's chain against it. `init` takes the
TPM at `/dev/tpmrm0` (or `/dev/tpm0`) and an admin socket in `/run/kira-vault/`
alone: what the unit and the container reach.

**For each machine:**

1. The machine's boot image needs its network: `kira control`,
   the section "Network & SSH" (SSH.md §1); the network is enough,
   SSH is not needed. `vault enrol` warns when it is off.
2. On the vault: `kira-vault token create --name NAME [--mode
   approve] [--ttl 1h]`. It prints the token, the URL, the pin and the
   exact command for the machine. A token works once. For a machine the
   vault knows already (a new TPM, a new slot): `--replace DEVICE`.
3. The root to the machine: `kira-vault tls root > vault-ca.pem`,
   copied over (it is no secret). On the machine it goes into
   `/etc/kira/vault-ca.pem` - by hand, or with `--ca vault-ca.pem`
   at the enrolment below, which takes it only when its key is the pin:
   the pin, which comes with the token, authenticates the root. The boot
   image carries the bundle; without it the image has no vault part, and
   `control` says so.
4. On the machine, with a recovery passphrase in another keyslot - in
   `kira control`, "Disk unlock", "Salt from a vault": it
   sets up the network when there is none, asks the URL, the pin and the
   token, whether the password is held by the TPM (unattended) or typed,
   and the pepper, and the root's file; asks the vault whether it answers,
   verified against the root and the pin,
   before anything is enrolled, and shows afterwards, at every look,
   whether the vault still knows this device. Or by hand:
   `kira luks enrol <device> [--password tpm] --salt vault [--pepper]
   --url … --pin … --token … [--ca FILE] [--nvram N] [--label L] [--name NAME]`. It
   enrols with the vault, asks the password (typed recipes) and the
   pepper, adds the keyslot (authorised by the recovery passphrase,
   asked) and marks it. Or in steps (unattended): `kira vault enrol …
   --out /run/kira/luks.key`, `cryptsetup luksAddKey`, `kira
   luks mark <device> --keyslot N --password tpm --salt vault`.
5. The image is rebuilt (the root bundle goes in): the vault's address
   and pin are in the slot's blob. The next boot unlocks unattended (`0x2400`), or asks the
   password after the code screen (`0x1400`).

**With operator approval and a pepper** (§12):

```bash
vault#    kira-vault config set operator-listen :8444    # serve stopped; or init --operator-listen :8444
vault#    kira-vault operator add alice                  # the bearer token, once, and a curl line
machine#  kira luks enrol /dev/sda2 --password tpm --salt vault --pepper --url … --pin … --token …
                                                              # asks the pepper twice
vault#    kira-vault requests answer                     # approve, deny or skip; asks the pepper
vault#    kira-vault tls root > vault-ca.pem             # the operators' copy, no secret
anywhere$ curl --cacert vault-ca.pem -H "Authorization: Bearer $TOKEN" \
              https://vault:8444/v1/requests
anywhere$ curl --cacert vault-ca.pem -H "Authorization: Bearer $TOKEN" \
              -d '{"pepper":"…"}' https://vault:8444/v1/requests/<id>/approve
```

## 4. Enrolment

`vaultEnrolKey` (`internal/vaultkey/vault.go`), on the booted machine, with the signing
key (as slot approve):

1. Refuse unless the recovery keyslot is confirmed (`luks enrol` checks
   the device has a keyslot that is not kira's).
2. Give the slot what it lacks: the attestation part (device ID,
   attestation key, the EK algorithm with a certificate if the TPM has
   one) and the release key under the slot's policy. A slot already
   enrolled with a vault is refused.
3. Draw L and R; wrap both for this TPM's EK and the release key's name.
   Check the slot's record still fits (8 KiB) with the vault method in it.
4. `POST /v1/enrol` with the token, the device's public data (EK, EK
   certificate, AK), the slot's approval data (signing key, policyRef,
   the generation index's Name, the generation, the sealed PCR selection)
   and the wrapped R. The vault answers with a credential for (EK, name of
   AK); the machine opens it with the AK and returns the secret (`POST
   /v1/enrol/confirm`): proof that the AK lives in that TPM.
5. Write the vault's URL and pin, the label and the wrapped L into the
   slot's blob (signed, in NV). Nothing of R is kept.
6. Derive the key from L and R once, for `luksAddKey`; wipe L and R.

That the TPM opens both parts under the slot's policy is proven by the
next boot, in the initrd. `slot add` and `slot approve` keep the vault method (seal
keeps the slot's policyRef, so the release key stays valid); a phone can
be enrolled next to it and removed again without touching it.

## 5. At boot

```mermaid
sequenceDiagram
    participant M as run (initrd)
    participant V as vault
    participant T as machine's TPM
    M->>T: ActivateCredential: L (release key under the slot's policy)
    M->>V: POST /v1/challenge {device_id}
    V->>M: {request_id, nonce, expires_in}
    M->>T: Quote(AK, QualifyingData(device, request, nonce), slot's selection)
    M->>V: POST /v1/release {quote, values, generation, approval}
    V->>V: VerifyRelease, revocation, lock, rate, mode
    alt auto, checks pass
        V->>M: released {remote}
    else approve mode
        V->>M: pending {retry_after}; M sends the same request again
    else
        V->>M: denied {reason}
    end
    M->>T: ActivateCredential: R (and the pepper's key)
    M->>M: salt from R; unattended: key = combiner(L's password, salt), the hold ends;<br/>typed: the salt is kept, the password asked after the hold
```

- **While the code screen holds.** On a UKI system the separator extends
  the PCRs right after the hold, and the parts open only before it. So
  `run` starts the attempt for every slot with the vault method as soon as
  it starts, and the attempt lasts exactly as long as the hold (90 s by
  default; until confirmed with the SSH server's hold 0). An unattended
  recipe's key made ends the hold on its own; the key provider then
  answers the volume (Arch: systemd-cryptsetup on the key socket; Debian:
  the keyscript) with it. With a typed password, the salt is kept and
  the password asked at kira's prompt after the hold.
- **L first** (unattended recipes). When the TPM does not open the local
  part, this boot state is not one the signing key approved, and the
  vault is not asked.
- **With a pepper.** The keyslot's salt needs the pepper the approval
  carries. The release brings it wrapped like R: a fresh key K made for
  the TPM's EK and the slot's release key, and the pepper under K
  (AES-256-GCM, the device ID bound in); the TPM opens K with a second
  ActivateCredential through the slot's approval, so the pepper opens only
  where R opens, and does not rely on the connection to the vault. For an
  unattended recipe, a pepper that does not fit the slot's pepper check is
  never handed to cryptsetup: `run` says so and asks the vault again, for
  a new approval, while the code screen holds; with a typed password a
  wrong pepper and a wrong password cannot be told apart, and the key
  simply opens nothing. A release without a pepper for such a keyslot, or
  with one for a keyslot without, is refused.
- **The network coming up.** A vault not reachable yet is tried again each
  second; an answer - a refusal, a vault whose key is not the pinned one -
  is final.
- **The vault's TLS.** TLS 1.3; the chain must end at a root of
  `/etc/kira/vault-ca.pem` (in the image), be for the vault's host
  or address and within its dates against the machine's clock (the RTC:
  a wrong clock refuses the vault, and says so); then a key of the
  verified chain must be the pin (`vaultproto.ClientConfig`). The bundle
  lies unsigned in the image; the pin is in the slot's signed blob, so a
  root put there by somebody else gets no other vault accepted. A vault
  that does not verify is not tried again.
- **Without a key** (no network, refused, revoked, pending too long, the
  TPM refused): the code screen holds as without a vault, Enter or the
  SSH session continues, and cryptsetup's own prompt follows - also in
  the SSH session (SSH.md §6) - where the recovery passphrase works.
- **What it says.** On the console and in the log (Arch: the journal;
  Debian: `/run/initramfs/kira.log`):

```
vault: slot 0: asking the vault at https://172.17.2.198:8443 for the disk's remote part ...
vault: slot 0: the vault at … is not reachable yet (… network is unreachable); trying until it is
vault: slot 0: the vault waits for an operator's approval of this boot
vault: slot 0: the pepper given with the approval does not fit this keyslot; asking the vault for a new approval
vault: slot 0: the vault waits for an operator's approval of this boot
vault: slot 0: released; the key is made
unlock: making the key for vda3_crypt, as its header says
unlock: answered for vda3_crypt (87 bytes)
```

or `vault: slot 0: no key: the vault refused: "the device is revoked"`.
With a typed password the line is `vault: slot 0: released; the salt is
opened`, and the password is asked after the code screen. Without
anything from the vault, the volume's next recipe is the fallback -
another device-held salt, then the recovery recipe at kira's prompt
(at the console, or in the SSH session), saying "no key from the vault
(…)"; a volume without one gets `unlock: no key for vda3_crypt: …;
cryptsetup's own prompt follows`, where a plain passphrase works.

When a volume has several of kira's keyslots, they are tried in the
recipes' order ([DISK-KEY.md](DISK-KEY.md#the-recipes)): the unattended
recipes (they need nobody), then the device-held salts with a typed
password, the recovery recipe last.

## 6. The vault

`kira-vault`, one binary, no cgo, run by a hardened systemd unit
(root without capabilities beyond binding the port, only `/dev/tpmrm0`,
`ProtectSystem=strict`, its state and runtime directories, a system call
filter, no core dumps). Without `CAP_DAC_OVERRIDE`, root reaches the TPM
through its group: the unit has `SupplementaryGroups=tss`, because
`/dev/tpmrm0` is `root:tss` on Arch but `tss:tss` on Debian (found when
the vault first ran on Debian: "permission denied" at the first
enrolment).

### 6.1 Release rules

| Rule | Value |
|---|---|
| challenge | 32 random bytes, valid 120 s, for one request; a terminal answer (released, denied) consumes it |
| pending | a request in approve mode stays pending 15 min, then is denied; the machine re-sends the same request every 5 s and is answered by its ID; an approved request is verified again when answered, and answered for 120 s after the approval |
| pepper | a device enrolled with a pepper is always in approve mode (`device mode … auto` is refused); its approval must carry a pepper (1-256 bytes), a plain device's must not; the pepper is held in memory with the approved request, sent once with the release, then wiped - also when the approval expires or the device is revoked; never written, never logged ("approved by alice, with a pepper") |
| failures | 5 verified quotes in a row that the release refuses (a revoked generation, no approval of the quoted state) lock the device until `device unlock`; a success resets the count. A request whose quote the device's attestation key did not sign is denied and changes nothing of the device: a device ID is no secret, and a lock for what is sent under it would be anyone's to set |
| rate | at most 3 challenges per address per minute (`challenge_rate` in the configuration: `config set challenge-rate N`, `init --challenge-rate N`) and 10 per device; what an address asks beyond its own limit counts against no device. A boot asks for one challenge per keyslot of the vault's, and machines behind one address share its limit: raise it where several boot together. The machine takes a 429 as "not yet" and asks again |
| names | a machine's name and a keyslot's label: 1 to 64 letters, digits, `.`, `_`, `-`, the first a letter or a digit; anything else is refused at enrolment (`--name`, `--label` on the machine) |
| audit before authentication | what is refused before anyone is authenticated (an unknown device, an unknown token, a name not taken, a rate limit) is written at most 20 times per minute, each kind once per address; the rest is counted and written as one line. Whoever can reach the vault cannot fill its log - a release needs its line written. The log is never cut or rotated by the vault: its past is not a flood's to erase |
| generation | the highest verified generation is kept; a lower one is refused |
| revoked | denied, "the device is revoked" |
| the vault's own boot state is not approved | denied, "the vault's own boot state is not approved: an operator approves it (kira-vault approve)"; not counted against the device; no enrolment either |
| audit | every enrolment, challenge, verification, release, denial and admin action, append-only, synced after each line; a request with a verified quote names Secure Boot's state (`secure_boot`, `secure_boot_red`) |

Pending requests live in memory only: after a restart, the machine starts
with a new challenge. Request bodies are limited to 1 MiB.

### 6.2 Keys at rest

One **master key** (32 bytes, HMAC-SHA256), drawn at `init` in locked memory,
shown once as the backup, and imported into the vault's TPM under the storage
primary - wrapped for the primary's public key (an outer wrapper: not on the bus
in the clear), not fixed to the TPM (it existed once, at init, and then only in the
backup). Each machine's **K_dev** is the master's HMAC of its device ID and a
32-byte **r_dev** of its own, computed in the TPM and returned encrypted (a salted
session); its record's wrapped R is encrypted with AES-256-GCM under K_dev, the
device ID as AAD. K_dev lives in locked memory for one enrolment or release, then
is wiped. A **revoke** deletes r_dev: the device's key cannot be made again by
anyone, with or without the backup.

The **TLS root key** (ECDSA P-256), whose public key is the machines' pin, follows
from the master (HKDF, a label of its own) and is imported into the TPM beside it,
wrapped the same way: no TLS private key is a file. `serve` has the TPM sign a
**leaf** at its start and again 30 days before the leaf ends (90 days); the leaf's
key (Ed25519) is made in memory each time and never written. A restore of the
master's backup makes the same root key again, so the pin holds. It is ECDSA because
it has to follow from the master: no RSA key is made from a seed with the standard
library. It is used by its empty authValue, not under the approval: serve signs a
leaf with nobody there, and takes an approval's requests before anything is approved.

The master is used only under an **approval** of the vault's own boot state:

    master's policy = PolicyAuthorize(approval key, ref) ; PolicyCommandCode(TPM2_HMAC)
    approved        = PolicyPCR(the vault's PCRs, their values) ; PolicyNV(counter == N)

- **The approval key** is an RSA signing key in the vault's TPM (as long as the
  TPM takes: `TPM2_TestParms`), its authValue the approval PIN,
  dictionary-attack protected; the PIN goes through salted HMAC sessions.
- **The counter** is an NV counter at 0x01804000 (outside kira's range and aSSH's),
  raised only with the approval key (PolicySigned): each approval raises it and
  names its new value, so every older approval fails in the TPM, whatever the PCRs.
- **An approval** (`approve`, the first at `init`) is the policy over the live
  values signed with the approval key: `approvals/<time>.json`. serve takes the one
  whose values and counter are the live ones.
- **The approval refuses PCR 7** whose firmware log does not establish Secure Boot
  on (core's `attest.EstablishSecureBoot`), and **PCR 15** without the state
  directory on dm-crypt, without systemd's measurement log replaying to it, or -
  where systemd-cryptsetup measures volumes (`tpm2-measure-pcr=yes` in crypttab) -
  without the volume's `cryptsetup:` event. Where nothing measures volumes
  (Debian's initramfs-tools), that is a note, and serve refuses to start off
  dm-crypt. With kira installed on the vault host, its close extends PCR 15 and
  logs it there too.
- **The selection** is 7 and 15 by default: an approval is due on a db/dbx update
  or another volume, not on a kernel update; 11 and 4 are optional.

### 6.3 Admin interface and operator interface

**Admin:** HTTP over a root-only Unix socket
(`/run/kira-vault/admin.sock`, 0600); the CLI is its client: `GET
/v1/devices[/{id}]`, `POST /v1/devices/{id}/revoke|unlock|mode`,
`GET /v1/requests`, `POST /v1/requests/{id}/approve|deny`, `GET|POST
/v1/tokens`, `DELETE /v1/tokens/{id}`, `GET /v1/status`, `GET
/v1/audit[?follow=1]`, `GET|POST /v1/operators`, `DELETE
/v1/operators/{name}`. The audit names the actor "admin". A
device's release mode is a number there (`"mode": 1` at once, `2` after an
approval: `vaultproto.ReleaseMode`); the CLI takes and shows the words
auto and approve.

**Operator:** the REST interface over the network, §12.

### 6.4 State directory

```
/var/lib/kira-vault/
  config.json           listen address, URL, the vault's PCRs, TPM path, admin socket
  master.json           the master and the TLS root key as the TPM holds them, the approval keys
  approvals/<time>.json the approvals of the vault's boot state
  tls/ca.pem            the root's certificate (20 years): the vault's identity; its key, the pin's, is in the TPM (master.json)
  tls/cert.pem          the certificate of the leaf it serves (90 days); its key is in serve's memory alone
  devices/<id>.json     pinned device data, release state, r_dev, the encrypted wrapped R
  tokens/<sha256>.json  unused tokens, stored only as their hash
  operators/<name>.json operators' bearer tokens, stored only as their hash
  audit.log
```

Files are 0600, written atomically (temp file, fsync, rename, fsync of
the directory). `init` and `config` work on the directory directly and
refuse while `serve` holds its lock; `approve` writes `approvals/` beside a
running serve.

### 6.5 Recovery

- **The vault's boot state changed** (a firmware or Secure Boot update, another
  volume): nothing is released until `kira-vault approve` - beside the running
  serve, with the approval PIN - approves the new state; it shows what moved and
  what the logs say of it first.
- **The TPM is lost** (a new mainboard, a new host): restore the state directory
  from its backup, then `kira-vault init --restore` with the master's backup: a
  new PIN, approval key and counter in the new TPM, and every machine is released
  to as before - under the pin it has: the TLS root key follows from the master. `kira-vault backup check` checks a written-down backup.
- **The backup is lost and the TPM too:** the records cannot be opened. Each
  machine unlocks with its recovery passphrase and is enrolled again with a
  `--replace` token.
- **A machine was reported stolen:** `kira-vault device revoke DEVICE` - for good;
  it comes back only by a new enrolment.

### 6.6 Commands

| Command | |
|---|---|
| `control [--dir] [--socket] [--lines] [--debug]` | the control panel (§6.7) |
| `init [--dir] [--listen :8443] [--url] [--pcrs 7,15] [--tpm /dev/tpmrm0] [--admin-socket] [--operator-listen] [--challenge-rate 3]` | create the vault: its keys in this TPM, the backup shown once |
| `init --restore [--dir]` | the master from its backup into this TPM, in a restored state directory |
| `approve [--dir]` | approve the vault's boot state as it is (the PIN) |
| `approvals [--dir]` | the approvals, and which is in use |
| `backup check [--dir]` | check a written-down backup |
| `serve [--dir]` | run the vault (the unit, or the container, does this) |
| `status` | the vault as it runs: the approval, the TPM, the certificates, the counts |
| `token create --name NAME [--mode auto\|approve] [--ttl 1h] [--replace DEVICE]` | a one-time enrolment token, with the machine's command line |
| `token list`, `token withdraw ID` | the unused tokens (never their value); withdraw one |
| `devices` | the enrolled machines: mode, state, generation, last release |
| `device show\|revoke\|unlock DEVICE` | one machine; a revoke is final |
| `device mode DEVICE auto\|approve` | release at once, or after an operator's approval |
| `requests` | releases waiting for approval |
| `requests answer` | go through them one by one: approve, deny or skip; the pepper asked where needed |
| `request approve\|deny ID` | decide one; a pepper device's approval asks the pepper |
| `audit [--follow]` | the audit log |
| `config set operator-listen ADDR\|"" [--dir]` | turn the operator interface on (an address, e.g. `:8444`) or off; serve stopped |
| `config set challenge-rate N [--dir]` | the challenges one address gets per minute (0: the default, 3); serve stopped |
| `operator add NAME` | an operator: prints the bearer token once, the URL and a curl line (`--cacert`) |
| `tls root [--dir]` | the vault's root certificate (PEM), for machines and operators; also while serve runs |
| `operators`, `operator remove NAME` | list, remove |

DEVICE is a hex device ID or a unique name. The admin commands take
`--socket`, or `--dir` for the socket of that directory's configuration.
`devices` and `requests` show whether a device needs a pepper. For such a
device, `request approve` and `requests answer` ask the pepper on the
terminal (without echo; one line from a pipe) and send it with the
approval; the operator interface carries it as `{"pepper":"…"}`.

### 6.7 The control panel

`kira-vault control`, as root: the sections Overview, Setup (create, restore,
check the backup, run it under the unit or in the container, the firewall's
advice), Machines (enrol, the unused tokens, each device), Requests, Operators,
Approvals, Tools and Reference - a full screen on a terminal (go-tui-slim's
panel, as `kira control`), line menus with `--lines`, everything printed without a
terminal. Its overview judges line by line: how serve runs (the unit, a container,
neither: by the admin socket's peer), the state directory and its volume, the vault
host's Secure Boot (its EFI variables), the selection, whether an approval is due
and what moved, the TPM's dictionary-attack state, the certificate's name and
ends, the URL's host, a TLS handshake to each listen address verified against the
root, the admin socket, the devices, tokens and requests. It never opens the TPM
(serve has it) and never writes the state directory: it runs the CLI. The backup,
tokens and PINs are shown or asked in a step's run below the screen, never in a
frame.

## 7. The machine's side

- **Configuration.** None in control.conf: the vault's URL and pin are in
  the slot's blob, signed with it, so an enrolment needs no rebuild. The
  network is the image's (`KIRA_NET_*`, SSH.md). The image may have no
  resolver: an IP address in the URL needs none.
- **The blob.** Attestation method 2 (SECURITY-BACKGROUND.md §10): URL,
  pin, label, the wrapped L (unattended recipes), whether a pepper goes
  into the salt, and for an unattended recipe with a pepper the pepper
  check. The attestation part carries the device ID,
  the attestation key and the release key, shared with the phone method.
- **The LUKS token.** Type `kira-2400` (`-2401`, `-1400`, `-1401`),
  the recipe's number, bound to the slot (`"slot"`) and carrying the
  label. `luks status` and `status`
  describe it; deleting the slot makes the keyslot dirty.
- **Commands:**

```
kira luks enrol <device> [--password tpm] --salt vault --url URL --pin PIN --token T [--ca FILE]
                     [--pepper] [--nvram N] [--label L] [--name NAME] [--existing-key-file F]
kira luks mark  <device> --keyslot N [--password tpm] --salt vault [--pepper] [--nvram N]
kira vault enrol   --url URL --pin PIN --token T [--ca FILE] --out PATH [--pepper] [--nvram N] [--label L] [--name NAME] [--yes]
kira vault status  [--nvram N]     the slot's vault, and whether it answers for this machine
kira vault unenrol [--nvram N]     the vault method and L out of the blob; revoke on the vault,
                                        remove the keyslot by hand
kira status                        "enrolled with the vault at …"; notes a vault keyslot
                                        whose slot has no vault, and a vault without a keyslot
```

## 8. The protocol

JSON over HTTPS, `[]byte` as base64 (`core/vaultproto/proto.go`):

| Path | Request | Answer |
|---|---|---|
| `POST /v1/enrol` | `EnrolRequest`: token, device ID, name, EK, EK certificate, AK, signing key, policyRef, generation index Name, generation, selection, wrapped R, label, whether the key needs a pepper (never the pepper), the slot's release key (TPMT_PUBLIC; the vault checks it is made under the slot's policy and fixedTPM, and keeps its Name) | `EnrolChallenge`: enrol ID, a credential for (EK, AK Name) |
| `POST /v1/enrol/confirm` | `EnrolConfirm`: enrol ID, the opened secret | `EnrolResult`: device ID, mode |
| `POST /v1/challenge` | `ChallengeRequest`: device ID | `ChallengeResponse`: request ID, 32-byte nonce, seconds valid |
| `POST /v1/release` | `ReleaseRequest`: request ID, device ID, the quote (TPMS_ATTEST and its signature), the PCR values, generation, approval signature, the PCR key's signature for a slot with PCR 11 signed, the digests of PCR 7's events in the event log | `ReleaseResponse`: `released` with the wrapped R (and, for a pepper device, the operator's pepper wrapped for the TPM: K by MakeCredential for (EK, release key Name), the pepper under K), `pending` with `retry_after`, or `denied` with the reason |

Errors are 4xx with `{"error": …}`. The quote's qualifying data is
`SHA-256("kira/vault/release/v1" ‖ lp(device ID) ‖ lp(request ID) ‖
lp(nonce))`. `VerifyRelease` checks, against the device pinned at
enrolment: the quote is signed by its AK, is a TPM quote
(`TPM_GENERATED_VALUE`, `TPM_ST_ATTEST_QUOTE`) with that qualifying data,
covers exactly the pinned selection, and the values reproduce its digest;
the generation is not below the minimum; the signing key's approval
verifies over `H(ApprovedPolicy(PolicyPCR(values), genIndexName, gen) ‖
policyRef)`. The policy digests are computed in software and are the very
functions kira seals with (`internal/nvslot/policy.go` calls them).

## 9. Threats

| Attacker has | Result |
|---|---|
| the machine | L in its TPM; R withheld once the device is revoked, or unreachable away from the vault's network |
| the machine, the vault reachable, not revoked | unlocks only in an approved boot state, as the owner's boot would; a tampered boot gets neither part. Approve mode - an operator's approval, with a pepper if enrolled so - closes the rest |
| a tampered boot chain | the TPM refuses L; the vault refuses the quote on its own |
| the vault's disk or a backup | records encrypted under keys sealed in the vault's TPM; no TLS private key, so the vault cannot be impersonated with it (the root's key is in the TPM, the leaf's in memory) |
| root on the running vault | the wrapped R of every device: useless without each machine's TPM in an approved state; can deny service; can have the TPM sign a leaf of their own while there, valid for as long as they date it - what an operator then sends a false vault (a token, a pepper) is theirs |
| a relay or a recorded answer | opens only on the machine's TPM, under its policy |
| a vault impersonated on the network | its chain does not end at the vault's root, or its key is not the pin; it could only withhold R, which the real one may too |
| a root of their own in the boot image's bundle | still not the pin: the pin is in the slot's signed blob |
| the machine's clock set back or ahead | a certificate outside its dates refuses the vault; the fallbacks stay |
| the machine and root on the vault, a keyslot with a pepper | still no key: the pepper is with the operators, the vault never keeps it (a pepper given to a compromised running vault is seen, though) |
| an operator's token | can approve releases and read requests and devices, nothing else; cannot revoke, lock, enrol or read the audit |
| a device's ID and the vault's address, nothing else | can ask for that device's challenges up to the limits and so delay its release (the machine asks again); cannot lock the device, and cannot fill the audit log |
| root on the running machine | the disk is open already; after the close no part opens again |

Availability is the dominant risk: no vault, no unattended boot. The
recovery keyslot is mandatory, and the console prompt is always there.

## 10. The code

| Where | What |
|---|---|
| `core/vaultproto/` | messages, `QualifyingData`, `PinOf`, `VerifyRelease`, the policy digests |
| `internal/vaultkey/vault.go` | the key's derivation, the pinned client, the boot's release (`startVaultKeys`, `openVaultKey`, `fetchRemote`), `vault enrol\|status\|unenrol` |
| `internal/phonegate/factor.go`, `core/attest/releasekey.go` | the release key and the wrap/unwrap shared with the phone salt |
| `internal/nvslot/attestation.go` | attestation method 2 |
| `internal/admin/luks.go`, `internal/diskkey/recipe.go`, `internal/diskkey/header.go`, `internal/diskkey/unlock.go` | the recipe, the token, the key provider |
| `internal/bootrun/run.go` | the attempt started with `run`, ended with the hold; a key made ends it |
| `../kira-vault/internal/server` | the machine-facing protocol and the rules (§6.1), the admin interface |
| `../kira-vault/internal/keys` | the master, the approval key, the counter, the backup, AES-GCM |
| `../kira-vault/internal/approval`, `bootstate`, `control` | the approval of the live state; the logs' evidence; the control panel |
| `../kira-vault/internal/state` | the state directory, tokens, the lock, the audit log |
| `../kira-vault/packaging/` | the systemd unit |

## 11. Tests

- **vaultproto** (`go test ./vaultproto`): an approved boot is released;
  refused are another nonce, request or device, a moved PCR, values that
  are not the quoted ones, a rolled-back generation, a generation the
  approval is not for, another selection, a quote by another key,
  something that is not a quote; an approval of the slot is accepted without a change on
  the vault; the JSON field names. The vault's `TestSecureBootStates`,
  `TestChangedPCR7IsRefusedAndShown`, `TestRequestShowsSecureBoot`.
- **kira, unit** (`internal/admin/vault_test.go`): the key's derivation
  (labels, order, pepper), the vault method in the blob, the pinned client
  (the right key, another key, a vault not reached, its error words
  without escape sequences), the key provider and the recipe's order, the
  token.
- **kira, swtpm** (`TestVaultPepper`): the pepper asked at
  enrolment and never sent; a mistyped pepper caught and the vault asked
  again; a release without a pepper refused.
- **kira, swtpm** (`TestVaultKeyRoundTrip`): enrolment against a
  vault that speaks the protocol (a wrong token refused, the AK proven, a
  second enrolment refused); the boot's key equals the enrolment's; the
  vault's PolicyPCR digest equals the TPM's trial session; after a PCR
  moved the TPM refuses L and the vault is not asked, and asked directly
  the vault refuses the quote; unenrolment.
- **kira-vault, unit**: enrolment and release with a simulated
  machine, tokens (wrong, expired, reused, replace), a wrong AK proof,
  challenge expiry and reuse, rollback, the lock and unlock, revoke, the
  rate limit, approve mode (approve, deny, expiry, an approved request of
  a device revoked meanwhile), the vault's boot state changed, the audit
  log without secrets, the pin, the CLI end to end; the pepper (forced
  approve mode, refused approvals, released once, never in the state
  directory, wiped on expiry and revocation); the operator interface
  (401s, the endpoints allowed and refused, the body limit, the failed-
  authentication limit, a removed operator); all on an injected clock.
- **kira-vault, swtpm**: the master imported, the TPM's HMAC the master's; a wrong
  PIN, a moved PCR, an older and a forged approval refused; two approval keys under
  PolicyOR; the vault end to end with a moved PCR, `approve` beside serve, a pepper
  device approved over the operator interface, and the master restored from its
  backup into a second TPM; `control`'s printout of it. The policies' digests are
  pinned by known answers; the firmware's logs of the test VMs give PCR 7's chains
  kira's parser gives.
- **On the test VMs** (2026-10-11): the vault on the Arch VM (PCR 7,
  Secure Boot on), the Debian VM as the machine (slot 0 sealed to PCR
  0,2,7,8,9; `luks enrol`, then the recipe tpm+vault, added keyslot 2). Three boots:
  - **auto:** back in 45 s with nothing typed; the vault released at
    generation 3, the hold ended a second later, `run` answered with the
    64-byte key;
  - **revoked:** denied ("the device is revoked"), the code screen held,
    confirmed over the initrd's SSH, cryptsetup's own prompt answered there
    with the recovery passphrase;
  - **approve mode:** pending until `request approve`, then on its own;
    the image had been rebuilt and approved in between (generation 4), and
    the vault accepted it without a change.

  Then the other way round (the same day): a second vault on the Debian
  VM (PCR 7, Secure Boot off), the **Arch VM as the machine** - UKI with
  Secure Boot, slot 0 sealed to PCR 0,2,7,11, systemd in the initrd, the
  key over the key socket:
  - **auto:** back in 32 s with nothing typed. The vault released 2.5 s
    after the first try, the key was made at 08:05:10.685, the code screen
    ended (READY) at .811, systemd-cryptsetup had the key at 08:05:11.4,
    and the separator ran at 08:05:19 - the parts were opened well before
    it. The vault accepted generation 23 (enrolled at 15, approved by
    every image build since);
  - **revoked:** denied; the code screen held, confirmed over SSH, and
    systemd-cryptsetup's own question came into the session through
    ask-password; the session that left it was asked again in the next,
    and the recovery passphrase opened the disk.

  The operator interface and the pepper, the same day: the Arch vault
  with `operator-listen :8444` and operator `alice`, the Debian VM
  enrolled again with `--pepper` (the vault forced approve mode). From
  this workstation with curl: no token → 401, an admin path → 404, a wrong
  pin → curl refused. One boot: the request appeared, `{}` was refused
  (400), a mistyped pepper was released and caught by the machine's check
  ("does not fit … asking the vault for a new approval"), the new request
  approved with the right pepper opened the disk; the pepper was in
  neither the vault's state directory nor its journal nor the machine's
  log.

  In each boot the first try came before the network was up, and the
  retry worked.

## 12. Operator approval and the pepper

**The operator interface** is a second HTTPS listener of `serve`, apart
from the machines' so the two can be firewalled apart, off until
`operator_listen` is set (`init --operator-listen :8444`, or `config set
operator-listen :8444` with serve stopped). Same certificate, TLS 1.3:
operators verify it against the vault's root (curl: `--cacert
vault-ca.pem`, from `kira-vault tls root`, as `operator add`
prints).

| Endpoint | |
|---|---|
| `GET /v1/requests` | the pending and approved requests: device, pepper yes/no, generation, the quoted PCR values, where from, until when, what the quote establishes of Secure Boot (`secure_boot`, `secure_boot_red`) |
| `POST /v1/requests/{id}/approve` | `{}` to release, `{"pepper":"…"}` for a device enrolled with one |
| `POST /v1/requests/{id}/deny` | deny |
| `GET /v1/devices`, `GET /v1/devices/{id}` | the devices (by ID or unique name), with what the last verified quote established of Secure Boot (`secure_boot`, `secure_boot_red`, `secure_boot_at`); not established before the first |

Nothing else is served there (404). Authentication is a bearer token per
operator (`Authorization: Bearer …`), 32 random bytes from `operator add
NAME`, shown once and stored only as its SHA-256, compared in constant
time; a missing or wrong one gets 401 and is audited, and after 10
failures in a minute an address is refused without its token being
checked. Bodies are at most 4 KiB. The audit names the operator.

**The pepper** (§1) makes an operator part of the key: a device enrolled
with `--pepper` is released only on an approval that carries the pepper,
and its key cannot be made without it - not by the machine, not by
whoever holds the vault. What the machine and the vault do with it is in
§5 and §6.1.

## 12a The one-time keyboard

A device enrolled with `--keyboard-pepper` (recipe `0x1402`; [DISK-KEY.md](DISK-KEY.md#a-pepper-typed-through-a-one-time-keyboard-0x1302-0x1402))
is enrolled as any other, R and all, with `keyboard` in its enrolment. Every release of R then
carries `keyboard` beside it: a seed drawn for this boot, `TPM2_MakeCredential` for the EK and the
slot's release key, so it opens where R opens. The layout it stands for, which the person types a
pepper of their own through at the machine, is in `kira-vault requests` (drawn on a US keyboard:
each key above the character it types) and in `keyboard_keys` and `layout` of `GET /v1/requests`, as
a request in state `released`, for 15 minutes (`LayoutTTL`). It is kept in memory alone, never in the
audit, which says only "with a one-time keyboard". The pepper never reaches the vault, and the vault
cannot tell a right one from a wrong one. Approve mode works as for any device; an operator's pepper
(`--pepper`) is not taken together with it.

## 13. Known limits

- The pepper passes through the vault's memory at every approval: a
  compromised running vault sees it then. Wiping it is best effort (Go
  decodes JSON through strings).
- The operator interface has no roles: every operator may approve every
  device.
- On Debian the code screen does not know a volume's recipe before it
  asks (no routing on the kernel command line), so after a refusal it
  says "continue to cryptsetup's prompt" without naming the vault.
- The attempt lasts as long as the hold: approve mode needs a hold long
  enough for the operator (the SSH server's hold 0, or a longer `--hold`).
- The vault's port must be open to the machines; the test VM's rule was a
  runtime one.
