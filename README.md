# luksury

TPM2-backed automatic unlocking for **classic systemd-boot
(`vmlinuz` + `initrd`) LUKS2 root volumes**.

This is a rewrite of the original C++ `luksury`.  It no longer implements TPM
sealing, PCR prediction or LUKS handling itself.  Instead it wires up the
systemd components that do:

- `systemd-cryptenroll` enrolls a TPM2 token in the LUKS2 header
- `systemd-pcrlock` creates a TPM NV policy from the measured boot
- `systemd-cryptsetup` unseals the key at boot

The result survives kernel, initrd and boot-loader updates without re-enrolling
the LUKS token: the update hooks re-lock the new initrd/cmdline or boot loader
and refresh the pcrlock policy, while the LUKS token stays unchanged.

## Requirements

- LUKS2 root volume
- systemd >= 256 (for `systemd-pcrlock`, `systemd-cryptenroll --tpm2-pcrlock`, and the pcrlock boot credential)
- TPM 2.0 revision 1.38 or newer (`PolicyAuthorizeNV`)
- systemd-boot with classic `linux` + `initrd` entries
- dracut (required: the boot-time pcrlock hook is a dracut module)
- Secure Boot recommended (see security notes)

UKIs are intentionally **not** supported by this tool.  Use a signed PCR policy
with `systemd-measure` for UKIs instead.

## Usage

```sh
# Configure auto-unlock and install the update hook.
sudo ./luksury setup

# After a manual kernel/initrd rebuild, refresh the pcrlock policy.
sudo luksury update

# Show the current state.
sudo luksury status

# Remove the TPM2 token, policy and hooks.  Passphrase/recovery key remain.
sudo luksury remove
```

`setup` supports:

```text
--mode auto|pcrlock|literal   pcrlock is the update-safe default
--pcrs 4,7,9                  PCRs for pcrlock (default 4,7,9)
--pcrlock-location 740        systemd-pcrlock make-policy --location
--lock-gpt                    also bind PCR 5 (re-run setup after GPT changes)
--bootloader-pe PATH          additional boot loader PE to lock to PCR 4
```

`update` supports `--initrd PATH`, `--cmdline PATH`, and `--kernel VERSION`.
The kernel-install hook normally supplies these automatically.

Use `--dry-run` to see the commands without changing anything, and `--yes` for
non-interactive confirmation.

## What setup does

1. Finds the LUKS2 container behind `/` (including LVM on LUKS).
2. Backs up the LUKS header to `/root/luks-header-*.img`.
3. Enrolls a recovery key if none exists.  Store it offline.
4. Installs the dracut module and rebuilds the initramfs **before** locking it.
   It snapshots the running initrd/cmdline, then locks both the running and the
   newly built image as pcrlock variants:

   ```sh
   systemd-pcrlock lock-kernel-initrd --pcrlock=/var/lib/pcrlock.d/720-kernel-initrd.pcrlock.d/<running>.pcrlock /path/to/running-initrd
   systemd-pcrlock lock-kernel-cmdline --pcrlock=/var/lib/pcrlock.d/710-kernel-cmdline.pcrlock.d/<running>.pcrlock /proc/cmdline
   systemd-pcrlock lock-kernel-initrd --pcrlock=/var/lib/pcrlock.d/720-kernel-initrd.pcrlock.d/<target>.pcrlock /boot/.../initrd.img-...
   systemd-pcrlock lock-kernel-cmdline --pcrlock=/var/lib/pcrlock.d/710-kernel-cmdline.pcrlock.d/<target>.pcrlock /etc/kernel/cmdline
   systemd-pcrlock lock-pe --pcr=4 --pcrlock=/var/lib/pcrlock.d/630-bootloader.pcrlock.d/pe-<hash>.pcrlock /boot/efi/EFI/systemd/systemd-bootx64.efi
   # PCR 4 is rebuilt from the validated event log; see "PCR 4 prediction" below.
   systemd-pcrlock predict --pcr=4 --pcr=7 --pcr=9 --location=740 \
       --components=/var/lib/luksury/pcrlock.d   # must include PCR 4 and PCR 9
   systemd-pcrlock make-policy --pcr=4 --pcr=7 --pcr=9 --location=740 \
       --components=/var/lib/luksury/pcrlock.d
   ```

5. Enrolls the TPM2 token:

   ```sh
   systemd-cryptenroll --tpm2-device=auto \
       --tpm2-pcrlock=/var/lib/systemd/pcrlock.json /dev/...
   ```

6. `systemd-pcrlock make-policy` writes its own credential to
   `$BOOT/loader/credentials/pcrlock.<entry-token>.cred` (systemd >= 256).
   luksury does **not** write a separate `pcrlock.json` to the boot partition.
7. A drop-in for `systemd-cryptsetup@.service` runs a small initrd script via
   `ExecStartPre=` immediately before the TPM unseal.  It waits for the
   credential partition if necessary, mounts it read-only, and copies the
   `pcrlock.*.cred` files to `/run/credentials/@encrypted/`.  `systemd-cryptsetup`
   picks the matching credential via the SRK/NV data stored in the LUKS token.
8. Rewrites the root `/etc/crypttab` entry to `none,tpm2-device=auto`
   (backup kept).
9. Installs update hooks:
   - `/etc/kernel/install.d/99-luksury.install` (systemd-boot/dracut)
   - `/etc/initramfs/post-update.d/zzz-luksury` (initramfs-tools)
   - `/etc/pacman.d/hooks/99-luksury.hook` (Arch)
   - `/etc/systemd/system/systemd-boot-update.service.d/99-luksury.conf`
     (re-lock a newly installed systemd-boot for PCR 4)
10. Performs a self-test with `systemd-cryptsetup attach`.  This validates the
    current boot only; the real test is the next reboot.

The LUKS passphrase is **not** removed and no key is stored on the root
filesystem.  The original keyslot remains as a fallback.

## Updates

On a kernel/initrd update, the hook runs:

```sh
luksury update --initrd ... --cmdline ...
```

which does:

```sh
systemd-pcrlock lock-kernel-initrd --pcrlock=.../720-kernel-initrd.pcrlock.d/<new>.pcrlock "$NEW_INITRD"
systemd-pcrlock lock-kernel-cmdline --pcrlock=.../710-kernel-cmdline.pcrlock.d/<new>.pcrlock "$NEW_CMDLINE"
systemd-pcrlock lock-pe --pcr=4 --pcrlock=.../630-bootloader.pcrlock.d/pe-<hash>.pcrlock "$BOOT_LOADER"
systemd-pcrlock make-policy --pcr=4 --pcr=7 --pcr=9 --location=740 \
    --components=/var/lib/luksury/pcrlock.d
# systemd-pcrlock refreshes $BOOT/loader/credentials/pcrlock.<entry-token>.cred
```

No initramfs rebuild is needed: the initrd script reads the pcrlock credential
from the boot partition at boot.  No LUKS re-enrollment is needed either: the
token is bound to the TPM NV index, not to literal PCR values.

The `systemd-boot-update.service` drop-in runs `luksury refresh-bootloader`
after `bootctl update`, so a new boot loader is locked into PCR 4 before the
next boot.  That command only regenerates the PCR 4 component; it does not
re-read or rebuild the initrd component.  Old boot loader variants are retained
for a few updates so the running (pre-update) boot stays covered.

## PCR 4 prediction

`systemd-pcrlock lock-pe` describes what systemd expects a PE binary to be
measured as.  Some firmware measures additional records into PCR 4 (drivers,
boot-option actions, or a non-standard PE hash), which makes `lock-pe` alone
unpredictable; pcrlock then drops PCR 4 from the policy.

luksury therefore builds a private component set in
`/var/lib/luksury/pcrlock.d/`:

1. It reads the combined event log with `systemd-pcrlock cel --json=short`.
2. It replays every PCR 4 record with SHA-256 and checks the result against
   `/sys/class/tpm/tpm0/pcr-sha256/4`.  If the log does not match the TPM, the
   command fails before the NV policy or LUKS token is touched.
3. It writes `400-pcr4.pcrlock.d/running.pcrlock` with the exact record
   sequence from the running boot.
4. For every known `630-bootloader` PE variant it writes an additional
   `400-pcr4.pcrlock.d/pe-<hash>.pcrlock` in which only the
   `EV_EFI_BOOT_SERVICES_APPLICATION` record is replaced by the `lock-pe`
   prediction.  This covers the next boot loader before it is booted.
5. All other pcrlock components are copied into the private tree.  Components
   that also touch PCR 4 (for example `350-action-efi-application` and
   `500-separator`) are copied with their PCR 4 records removed, so the event
   log derived component is the only source of the PCR 4 prediction.

`predict` and `make-policy` are then run with
`--components=/var/lib/luksury/pcrlock.d`.  PCR 4 is mandatory: if the event
log cannot be read, does not match the TPM, or still cannot be predicted, the
command exits non-zero and leaves the existing policy in place.

`luksury refresh-bootloader` always rebuilds these components, even when the
boot loader PE itself did not change, so an existing policy that was created
without PCR 4 is repaired on the next run.

The updater keeps pcrlock **variants** for both the initrd/cmdline used by the
running boot and the newly installed one.  This is essential: the current
boot's event log still contains the old measurements, so replacing the single
`generated.pcrlock` with the new image would make `systemd-pcrlock` drop PCR 9.
Keeping both variants lets `make-policy` predict the old and new PCR 9 values,
so the policy works before and after the reboot.  Old variants are pruned only
after a successful policy update.

`--location=740` is deliberate for classic systemd-boot.  It includes
`710-kernel-cmdline` and `720-kernel-initrd` but excludes `750-*` and later.
Components such as `750-os-separator` are measured by services that have
`ConditionSecurity=measured-os`; those services do not run on classic
systemd-boot, so including them would make pcrlock drop PCR 9.

`setup` rebuilds the initramfs **before** generating the policy, and preserves
the previously running initrd as a variant.  If the running initrd has already
been overwritten (for example by an earlier `remove` that rebuilt the
initramfs), `setup` refuses before touching the TPM NV policy; reboot with the
recovery key/passphrase and run it again.

## Security notes

- **PCR 9 must be in the policy.**  The tool runs `systemd-pcrlock predict`
  before `make-policy` and refuses to touch the TPM NV policy or enroll if PCR 9
  (initrd and kernel command line) cannot be covered.  It also verifies the
  finished `pcrlock.json`.  PCR 12 cannot be used with pcrlock because the
  pcrlock policy itself is measured there.
- **PCR 4 is mandatory when configured.**  The tool runs
  `systemd-pcrlock lock-pe` on the current boot loader, the fallback loader,
  `EFI/BOOT/BOOT*.EFI`, shim when present, and any `--bootloader-pe` paths.  It
  also derives the running boot's PCR 4 records from the validated event log
  (see "PCR 4 prediction").  If PCR 4 cannot be predicted, `setup`, `update`
  and `refresh-bootloader` fail before changing the TPM NV policy or the LUKS
  token.  Chains that measure more than one PE into PCR 4 (for example some
  shim setups) can still only be predicted for the running boot; boot loader
  updates on such systems may fail closed until the new chain has booted once.
- **PCR 7 needs Secure Boot.**  With Secure Boot disabled there is no stable
  PCR 7 policy to lock; the tool warns and binds the other covered PCRs
  (normally 4 and 9).  Enable Secure Boot if you want the boot loader and
  secure-boot state in the policy.
- **Secure Boot is still important.**  Measured boot only records what the
  boot chain measures; an attacker who controls the bootloader could forge
  measurements.  Enable Secure Boot and sign the bootloader/kernel with keys
  you trust.
- **Keep the recovery key offline.**  TPM clear, firmware changes or a broken
  policy can invalidate the TPM token; the recovery key/passphrase must remain
  usable.
- `systemd-pcrlock` is marked experimental in current systemd.  Test updates
  before relying on them, and keep the recovery key available when rebooting.
- **A pre-root policy copy is unavoidable with pcrlock on classic boot.**
  `systemd-cryptsetup` needs the policy before the root file system is
  unlocked, and classic systemd-boot does not pass credentials to the initrd
  the way `systemd-stub` does for UKIs.  systemd-pcrlock therefore writes a
  null-key credential to `$BOOT/loader/credentials/pcrlock.<token>.cred`;
  luksury 2.1 consumes that credential instead of adding its own copy.  The
  credential is not secret, and the TPM NV index remains the trust anchor.
  A modified credential or policy file can cause a denial of unlock, not a
  policy bypass.  If you need to avoid boot-media storage entirely, use
  `--mode=literal` and accept re-enrollment after updates.

## Migration from the old luksury

The old implementation is preserved in `old/`.  It stored a keyfile at
`/var/lib/luksury/root_keyfile.bin` and a sealed object at a TPM persistent
handle.  The new tool does not use either.

Upgrading from luksury 2.0 migrates the default PCR set from `7,9` to `4,7,9`.
`update` keeps the old `/boot/.../luksury/pcrlock.json` copy fresh while a 2.0
initrd is still in use.  Run `setup` to rebuild the initrd with the credential
hook; setup then removes the old copy.  `luksury remove` also deletes it.

Upgrading from 2.1 to 2.2 adds the event-log-based PCR 4 prediction.  No LUKS
re-enrollment is needed.  The next `update`, `setup`, or boot-time
`refresh-bootloader` run rebuilds the private component tree and refuses to
write a policy that does not cover PCR 4.

After verifying that the new auto-unlock works:

1. Remove the old key from the LUKS header:
   `cryptsetup luksRemoveKey /dev/... /var/lib/luksury/root_keyfile.bin --key-file ...`
2. Evict the old TPM object (the old `luksury remove` can do this).
3. Remove `/var/lib/luksury/root_keyfile.bin` and
   `/var/lib/luksury/persistent_handle.bin`.
4. Keep the LUKS passphrase and the new recovery key.

## Files

| Path | Purpose |
| --- | --- |
| `/etc/luksury/config.json` | luksury state |
| `/usr/local/sbin/luksury` | installed copy of this script |
| `/usr/lib/dracut/modules.d/89luksury/` | initramfs policy hook |
| `/etc/dracut.conf.d/99-luksury.conf` | dracut module enablement |
| `/etc/kernel/install.d/99-luksury.install` | kernel-install update hook |
| `/etc/initramfs/post-update.d/zzz-luksury` | initramfs-tools update hook |
| `/etc/pacman.d/hooks/99-luksury.hook` | Arch update hook |
| `/etc/systemd/system/systemd-boot-update.service.d/99-luksury.conf` | re-lock a new boot loader for PCR 4 |
| `/var/lib/luksury/pcrlock.d/` | private pcrlock component tree used to predict PCR 4 |
| `/var/log/luksury.log` | log |
| `$BOOT/loader/credentials/pcrlock.<token>.cred` | systemd-pcrlock's credential, consumed by the initramfs |

## Manual test after setup

Reboot with the recovery key available, then confirm auto-unlock works.  To
verify the cmdline is actually bound, temporarily add `rd.break=pre-mount` to a
copy of the boot entry (or edit the entry, keeping a backup).  The TPM must
refuse to unseal and `systemd-cryptsetup` must ask for the passphrase.  Restore
the entry afterwards and run `sudo luksury update` if needed.
