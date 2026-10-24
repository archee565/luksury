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
--lock-gpt                    also bind PCR 5 (fails if pcrlock drops PCR 5)
--bootloader-pe PATH          additional boot loader PE to lock to PCR 4
```

Re-running `setup` keeps the existing mode, PCR list, pcrlock location,
`--lock-gpt` setting and `--bootloader-pe` paths unless you override them.
The first run defaults to auto mode, PCRs 4,7,9 and location 740.

`update` supports `--initrd PATH`, `--cmdline PATH`, and `--kernel VERSION`.
The kernel-install hook normally supplies these automatically.

Use `--dry-run` to see the commands without changing anything, and `--yes` for
non-interactive confirmation.

## What setup does

1. Finds the LUKS2 container behind `/` (including LVM on LUKS).
2. Backs up the LUKS header to `/root/luks-header-*.img`.
3. Enrolls a recovery key if none exists.  The recovery key output is written
   to `/root/luksury-recovery-key-*.txt` (mode 0600); move it offline.
4. Installs the dracut module and rebuilds the initramfs **before** locking it.
   The newly generated initrd is hashed once, then installed to `/boot` and the
   boot-entry path.  The kernel is verified against the dpkg MD5 sums, hashed
   with `lock-pe`, and the boot loader PEs are hashed from the root filesystem
   package copies.  Only the resulting digest records are kept:

   ```text
   /var/lib/luksury/hashes.json
   ```

   The running command line is passed through the same dangerous-option filter
   as the target and must match the last verified cmdline (or the new trusted
   target).  The actual default boot entry is resolved (including
   `@saved`/`@current` via the systemd-boot EFI variables), every entry for the
   target kernel is checked, and the kernel named by each entry must be in the
   hash store.  The running boot loader must match exactly one trusted
   root-filesystem PE.

   Prediction never hashes or reads the ESP or `/boot`:
   `710-kernel-cmdline`, `720-kernel-initrd` and `400-pcr4` are written directly
   from the hash store and the current TPM event log, then:

   ```sh
   systemd-pcrlock lock-secureboot-policy   # when PCR 7 is requested
   systemd-pcrlock lock-secureboot-authority
   systemd-pcrlock lock-gpt                 # when --lock-gpt is used
   systemd-pcrlock predict --pcr=4 --pcr=7 --pcr=9 --location=740 \
       --components=/var/lib/luksury/pcrlock.d
   systemd-pcrlock make-policy --pcr=4 --pcr=7 --pcr=9 --location=740 \
       --components=/var/lib/luksury/pcrlock.d
   ```

   Every requested PCR is checked.  PCR 4, 9 and 5 are mandatory when
   requested; PCR 7 may only be dropped when Secure Boot is disabled.  If
   `make-policy` or the post-write verification fails, setup restores the
   previous policy, component tree, initrd and boot credential.

5. Enrolls the TPM2 token:

   ```sh
   systemd-cryptenroll --tpm2-device=auto \
       --tpm2-pcrlock=/var/lib/systemd/pcrlock.json /dev/...
   ```

6. `systemd-pcrlock make-policy` writes its own credential to
   `$BOOT/loader/credentials/pcrlock.<entry-token>.cred` (systemd >= 256).
   luksury does **not** write a separate `pcrlock.json` to the boot partition.
   The credential, `/var/lib/systemd/pcrlock.json` and
   `/run/systemd/pcrlock.json` are made root-only; the sealed `pinPrivate` is
   replaced with a dummy in the boot credential (it is only needed for
   `make-policy` on the encrypted root).
7. A drop-in for `systemd-cryptsetup@.service` runs a small initrd script via
   `ExecStartPre=` immediately before the TPM unseal.  It waits for the
   credential partition if necessary, verifies the mounted partition against
   the recorded PARTUUID/device and filesystem UUID, mounts it
   `ro,nosuid,nodev,noexec`, and copies the `pcrlock.*.cred` files to
   `/run/credentials/@encrypted/`.  `systemd-cryptsetup` picks the matching
   credential via the SRK/NV data stored in the LUKS token.
8. Rewrites the root `/etc/crypttab` entry to `none,tpm2-device=auto`
   (backup kept).
9. Installs update hooks:
    - `/etc/kernel/install.d/99-luksury.install` (systemd-boot/dracut)
    - `/etc/initramfs/post-update.d/zzz-luksury` (initramfs-tools)
    - `/etc/pacman.d/hooks/99-luksury.hook` (Arch)
    - `/etc/systemd/system/systemd-boot-update.service.d/99-luksury.conf`
      (re-lock a newly installed systemd-boot for PCR 4)
10. Performs a self-test with `systemd-cryptsetup attach`.  This validates the
    current boot only; the real test is the next reboot.  In literal mode the
    self-test no longer passes a stale pcrlock path, and a busy/already-active
    test device is reported as inconclusive rather than success.

The LUKS passphrase is **not** removed and no key is stored on the root
filesystem.  The original keyslot remains as a fallback.

## Updates

On a kernel/initrd update, the hook runs:

```sh
luksury update --kernel <version> [--cmdline PATH] [--kernel-image PATH]
```

which does:

1. Verify the kernel image against `/var/lib/dpkg/info/linux-image-*.md5sums`
   and store its `lock-pe` PCR 4 record.
2. Generate a fresh initrd on the encrypted root, store its PCR 9 record, and
   install it to `/boot` and the boot-entry path.
3. Build the trusted command line from `/etc/kernel/cmdline` or `/proc/cmdline`,
   filter the running command line, require it to match the last verified
   cmdline or the new target, and verify the actual default boot entry and all
   entries for the target kernel.
4. Verify the installed boot loader PE against the root-filesystem package
   copies with `installed_bootloader_record`; the running boot loader must
   already be in the hash store.
5. Build `400-pcr4` from the current event log with the target kernel and
   installed boot loader records substituted, then run
   `systemd-pcrlock make-policy`.  The new policy, component tree, initrd,
   boot credential, runtime policy and legacy copy are rolled back if
   verification fails.

No initramfs rebuild is needed after this: the initrd script reads the pcrlock
credential from the boot partition at boot.  No LUKS re-enrollment is needed
either: the token is bound to the TPM NV index, not to literal PCR values.

The `systemd-boot-update.service` drop-in runs `luksury refresh-bootloader`
after `bootctl update`, so a new boot loader is locked into PCR 4 before the
next boot.  That command only regenerates the PCR 4 component; it does not
re-read or rebuild the initrd component.  The running boot loader must still
match a trusted root-filesystem PE, which normally requires `bootctl update`
to have installed the current package copy.

If `update` fails because the default boot entry still points at the old
kernel (common during a kernel package install), boot the previous,
policy-covered kernel, set the new entry as the default, and add the new kernel
to the policy:

```sh
sudo bootctl set-default <new-entry.conf>
sudo luksury update --kernel <new-version>
```

The new initrd is installed even when the policy update fails, so the new entry
remains bootable with the passphrase.

## PCR 4 prediction

`systemd-pcrlock lock-pe` describes what systemd expects a PE binary to be
measured as.  On classic systemd-boot, firmware also measures the kernel image
into PCR 4 as an `EV_EFI_BOOT_SERVICES_APPLICATION` record.  luksury therefore
requires the kernel measurement: if the running kernel's stored `lock-pe` digest
does not match a PCR 4 boot-services record, `setup`, `update` and
`refresh-bootloader` fail.

luksury builds a private component set in `/var/lib/luksury/pcrlock.d/`:

1. It reads the combined event log with `systemd-pcrlock cel --json=short`.
2. It replays every PCR 4 record with SHA-256 and checks the result against
   `/sys/class/tpm/tpm0/pcr-sha256/4`.  If the log does not match the TPM, the
   command fails before the NV policy or LUKS token is touched.
3. It identifies the kernel record by matching its digest against the trusted
   hash store, and requires the running boot loader record to match exactly one
   trusted root-filesystem PE.  Zero or multiple boot loader matches fail
   closed (shim+systemd-boot chains are refused rather than guessed).
4. It writes `400-pcr4.pcrlock.d/running.pcrlock` with the exact record
   sequence from the running boot, plus a target variant in which the kernel
   record is replaced by the target kernel's stored `lock-pe` digest and the
   boot loader record is replaced by the installed trusted PE.  The target PE
   comes from `installed_bootloader_record`, not from an arbitrary ESP file.
5. All other pcrlock components are copied into the private tree.  Components
   that also touch PCR 4 (for example `350-action-efi-application` and
   `500-separator`) are copied with their PCR 4 records removed, so the event
   log derived component is the only source of the PCR 4 prediction.

`predict` and `make-policy` are then run with
`--components=/var/lib/luksury/pcrlock.d`.  PCR 4 and the kernel measurement are
mandatory: if the event log cannot be read, does not match the TPM, or does not
contain a measurable kernel record, the command exits non-zero and leaves the
existing policy in place.

`luksury refresh-bootloader` always rebuilds these components, even when the
boot loader PE itself did not change, so an existing policy that was created
without PCR 4 is repaired on the next run.

The updater keeps pcrlock **variants** for both the initrd/cmdline used by the
running boot and the newly installed one.  This is essential: the current
boot's event log still contains the old measurements, so replacing the single
`generated.pcrlock` with the new image would make `systemd-pcrlock` drop PCR 9.
Keeping both variants lets `make-policy` predict the old and new PCR 9 values,
so the policy works before and after the reboot.  `setup` and `update` rewrite
the 710/720 components with the running and target records; `refresh-bootloader`
preserves the last verified set rather than re-locking the running cmdline/initrd.

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

- **The ESP is not used for target kernel, initrd or boot loader hashes.**  A
  modified ESP initrd, kernel or boot loader must not be lockable by a later
  `update`.  Target kernel/initrd/boot loader digests are built from
  `/var/lib/luksury/hashes.json` (on the encrypted root) and the current TPM
  event log.  `/boot` and the ESP are only installation and verification
  targets; a file found there is used only if its digest is already in the
  store.  The target command line comes from `/etc/kernel/cmdline` when it
  exists; otherwise `/proc/cmdline` is used after filtering the dangerous
  options listed below.  The currently running initrd is still recorded as a
  running variant on `setup` (so the current boot remains unlockable); run
  setup from a known-good boot.  The running command line is filtered and must
  match the last verified cmdline or the new trusted target, and the running
  boot loader must match a trusted root-filesystem PE.
- **The kernel must be measured.**  luksury identifies the kernel's PCR 4
  boot-services record through the trusted hash store.  If the kernel is not
  measured, or its digest cannot be reproduced with `lock-pe`, setup and update
  fail closed.
- **`/boot` is unencrypted on many systems.**  luksury does not rely on
  `/boot` content for target prediction: kernels are verified against dpkg's
  MD5 sums, initrds are generated by luksury itself, and boot loader PEs come
  from the root-filesystem package directories.  The installed boot loader PE
  is additionally matched with `installed_bootloader_record`.
- **PCR 9 must be in the policy.**  The tool runs `systemd-pcrlock predict`
  before `make-policy` and refuses to touch the TPM NV policy or enroll if PCR 9
  (initrd and kernel command line) cannot be covered.  It also verifies the
  finished `pcrlock.json`.  PCR 12 cannot be used with pcrlock because the
  pcrlock policy itself is measured there.
- **Dangerous cmdline options are refused.**  `setup` and `update` filter both
  the target and the running command line.  They refuse `init=` (except
  `/sbin/init` or the systemd binary), `rd.break`, `rd.shell`, `rd.emergency`,
  `systemd.debug-shell`/`systemd.debug_shell`, `systemd.unit=emergency/rescue/
  debug-shell`, `systemd.wants=`, `systemd.mask=`, `systemd.setenv=`,
  `systemd.sulogin=`, `systemd.crash_shell`, `systemd.crash_reboot`,
  `systemd.default_standard_shell`, `lockdown=none`,
  `module.sig_enforce=0/no`, `selinux=0`, `apparmor=0`, `iommu=off` and
  `nokaslr`.  The `rd.`-prefixed forms are checked too (for example
  `rd.systemd.debug_shell`), and quoted options are parsed before checking.
- **PCR 4 is mandatory.**  The tool runs `systemd-pcrlock lock-pe` on the
  root-filesystem systemd-boot/shim package PEs and any `--bootloader-pe` paths
  outside the ESP.  It derives the running boot's PCR 4 records from the
  validated event log, requires exactly one trusted kernel record and exactly
  one trusted running boot loader record, and substitutes the target kernel and
  installed boot loader records.  If PCR 4 cannot be predicted, `setup`,
  `update` and `refresh-bootloader` fail before changing the TPM NV policy or
  the LUKS token.  Chains that measure more than one trusted PE into PCR 4 (for
  example shim plus systemd-boot) fail closed rather than guessing which record
  to replace.
- **The default boot entry must be the target.**  `verify_installed_entry`
  resolves the actual default entry (including `@saved`/`@current` through the
  systemd-boot EFI variables), checks every entry for the target kernel, and
  verifies the kernel named by each entry against the hash store.  A decoy
  entry cannot hide the real default.  If `loader.conf` uses `@saved`/`@current`
  and the systemd-boot EFI variable is unreadable, setup fails rather than
  guessing.  If a kernel update leaves the default on the old kernel, boot the
  previous policy-covered kernel, run `bootctl set-default <new-entry>`, then
  add the new kernel with `luksury update --kernel <new-version>`.
- **PCR 7 needs Secure Boot.**  When Secure Boot is enabled, `setup` generates
  the secure-boot policy/authority components and fails if PCR 7 is dropped.
  With Secure Boot disabled there is no stable PCR 7 policy to lock; the tool
  warns and binds the other covered PCRs (normally 4 and 9).  `--lock-gpt`
  generates the GPT component and fails if PCR 5 is dropped.
- **Policy and credential files are root-only.**  `setup`, `update` and
  `refresh-bootloader` chmod `/var/lib/systemd/pcrlock.json`,
  `/run/systemd/pcrlock.json` and the boot credential 0600.  The sealed
  `pinPrivate` is replaced with a dummy in the ESP credential, because the
  initrd only needs the policy fields.  The tool warns if `/dev/tpmrm0` is
  accessible to a non-root group (for example `tss`): a local user with TPM
  access can unseal the host policy's sealed recovery PIN and rewrite the NV
  policy.  Restrict the TPM device to root or only trusted users.
- **Policy updates are transactional.**  If `make-policy` succeeds but
  post-write verification or credential verification fails, luksury restores
  the previous pcrlock policy, component tree, initrd files, boot credential,
  runtime policy and legacy copy.  A new kernel's initrd is installed before
  the policy checks, so the kernel entry remains bootable with the passphrase
  if the policy update is rolled back.
- **Secure Boot is still important.**  Measured boot only records what the
  boot chain measures; an attacker who controls the bootloader could forge
  measurements.  Enable Secure Boot and sign the bootloader/kernel with keys
  you trust.  `setup` warns when Secure Boot is disabled or the platform is in
  Setup Mode, but it does not refuse to run.
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
  luksury consumes that credential instead of adding its own copy.  The
  credential is not secret, the TPM NV index remains the trust anchor, and the
  sealed `pinPrivate` is replaced with a dummy in the boot copy.  A modified
  credential or policy file can cause a denial of unlock, not a policy bypass.
  If you need to avoid boot-media storage entirely, use
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

Upgrading from 2.3 to 2.4 tightens the running-boot checks (cmdline filter and
target match, running boot loader must be in the hash store, actual default
entry verified), generates and verifies PCR 7/5 components, makes the policy
and credential files root-only, strips the sealed PIN from the boot credential,
verifies the credential partition PARTUUID/device in the initrd, and rolls back
failed policy updates.  Re-run `setup` to rebuild the initrd with the newer
hook.

After verifying that the new auto-unlock works, remove any old unlock material
manually.  Do not remove the old keyfile/TPM object until you have verified the
new auto-unlock:

1. Remove the old key from the LUKS header:
   `cryptsetup --batch-mode luksRemoveKey /dev/... /var/lib/luksury/root_keyfile.bin`
2. Evict the old TPM object (the old `luksury remove` can do this, or
   `tpm2_evictcontrol -C o -c 0x<handle>`).
3. Remove `/var/lib/luksury/root_keyfile.bin` and
   `/var/lib/luksury/persistent_handle.bin`.
4. Keep the LUKS passphrase and the new recovery key.

## Files

| Path | Purpose |
| --- | --- |
| `/etc/luksury/config.json` | luksury state, including credential PARTUUID/device |
| `/usr/local/sbin/luksury` | installed copy of this script |
| `/usr/lib/dracut/modules.d/89luksury/` | initramfs policy hook |
| `/etc/dracut.conf.d/99-luksury.conf` | dracut module enablement |
| `/etc/kernel/install.d/99-luksury.install` | kernel-install update hook |
| `/etc/initramfs/post-update.d/zzz-luksury` | initramfs-tools update hook |
| `/etc/pacman.d/hooks/99-luksury.hook` | Arch update hook |
| `/etc/systemd/system/systemd-boot-update.service.d/99-luksury.conf` | re-lock a new boot loader for PCR 4 |
| `/var/lib/luksury/hashes.json` | trusted kernel/initrd/cmdline/bootloader digest records (0600) |
| `/var/lib/luksury/pcrlock.d/` | private pcrlock component tree used for prediction |
| `/var/log/luksury.log` | log |
| `/root/luksury-recovery-key-*.txt` | recovery key output (0600); move offline |
| `/var/lib/systemd/pcrlock.json` | pcrlock policy and sealed PIN (0600) |
| `$BOOT/loader/credentials/pcrlock.<token>.cred` | systemd-pcrlock's credential (0600, sealed PIN stripped), consumed by the initramfs |

## Manual test after setup

Reboot with the recovery key available, then confirm auto-unlock works.  To
verify the cmdline is actually bound, temporarily add `rd.break=pre-mount` to a
copy of the boot entry (or edit the entry, keeping a backup).  The TPM must
refuse to unseal and `systemd-cryptsetup` must ask for the passphrase.  Restore
the entry afterwards and run `sudo luksury update` if needed.  Do not run
`setup` from the `rd.break` boot: the running-cmdline filter refuses it, and a
dangerous option must never be promoted into the policy.
