# luksury

TPM2-backed automatic unlocking for **classic systemd-boot
(`vmlinuz` + `initrd`) LUKS2 root volumes**.

This is a rewrite of the original C++ `luksury`.  It no longer implements TPM
sealing, PCR prediction or LUKS handling itself.  Instead it wires up the
systemd components that do:

- `systemd-cryptenroll` enrolls a TPM2 token in the LUKS2 header
- `systemd-pcrlock` creates a TPM NV policy from the measured boot
- `systemd-cryptsetup` unseals the key at boot

The result survives kernel and initrd updates without re-enrolling the LUKS
token: the update hook re-locks the new initrd/cmdline and refreshes the
pcrlock policy, while the LUKS token stays unchanged.

## Requirements

- LUKS2 root volume
- systemd >= 255 (for `systemd-pcrlock` and `systemd-cryptenroll --tpm2-pcrlock`)
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
--pcrs 7,9                    PCRs for pcrlock (default 7,9)
--pcrlock-location 740        systemd-pcrlock make-policy --location
--lock-gpt                    also bind PCR 5 (re-run setup after GPT changes)
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
   systemd-pcrlock predict --pcr=7 --pcr=9 --location=740   # must include PCR 9
   systemd-pcrlock make-policy --pcr=7 --pcr=9 --location=740
   ```

5. Enrolls the TPM2 token:

   ```sh
   systemd-cryptenroll --tpm2-device=auto \
       --tpm2-pcrlock=/var/lib/systemd/pcrlock.json /dev/...
   ```

6. Copies `pcrlock.json` to the unencrypted boot partition at
   `luksury/pcrlock.json`.
7. A drop-in for `systemd-cryptsetup@.service` runs a small initrd script via
   `ExecStartPre=` immediately before the TPM unseal.  It waits for the boot
   partition if necessary, mounts it read-only, and installs the policy at
   `/run/systemd/pcrlock.json`.  Running inside the cryptsetup unit guarantees
   the policy is present before `systemd-cryptsetup` looks for it.
8. Rewrites the root `/etc/crypttab` entry to `none,tpm2-device=auto`
   (backup kept).
9. Installs update hooks:
   - `/etc/kernel/install.d/99-luksury.install` (systemd-boot/dracut)
   - `/etc/initramfs/post-update.d/zzz-luksury` (initramfs-tools)
   - `/etc/pacman.d/hooks/99-luksury.hook` (Arch)
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
systemd-pcrlock make-policy --pcr=7 --pcr=9 --location=740
# atomically copy /var/lib/systemd/pcrlock.json to the boot partition
```

No initramfs rebuild is needed: the initrd script reads the policy from the
boot partition at boot.  No LUKS re-enrollment is needed either: the token is
bound to the TPM NV index, not to literal PCR values.

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
- **PCR 7 needs Secure Boot.**  With Secure Boot disabled there is no stable
  PCR 7 policy to lock; the tool warns and binds PCR 9 only.  Enable Secure
  Boot if you want the boot loader/secure-boot state in the policy.
- **Secure Boot is still important.**  Measured boot only records what the
  boot chain measures; an attacker who controls the bootloader could forge
  measurements.  Enable Secure Boot and sign the bootloader/kernel with keys
  you trust.
- **Keep the recovery key offline.**  TPM clear, firmware changes or a broken
  policy can invalidate the TPM token; the recovery key/passphrase must remain
  usable.
- `systemd-pcrlock` is marked experimental in current systemd.  Test updates
  before relying on them, and keep the recovery key available when rebooting.
- The pcrlock policy JSON is stored unencrypted on the boot partition.  This
  is intentional (the policy is not secret and the NV index is the trust
  anchor), but the boot partition is writable by anyone with physical access.
  A modified file can cause a denial of unlock, not a policy bypass.

## Migration from the old luksury

The old implementation is preserved in `old/`.  It stored a keyfile at
`/var/lib/luksury/root_keyfile.bin` and a sealed object at a TPM persistent
handle.  The new tool does not use either.

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
| `/var/log/luksury.log` | log |
| `/boot/.../luksury/pcrlock.json` | policy copy for the initramfs |

## Manual test after setup

Reboot with the recovery key available, then confirm auto-unlock works.  To
verify the cmdline is actually bound, temporarily add `rd.break=pre-mount` to a
copy of the boot entry (or edit the entry, keeping a backup).  The TPM must
refuse to unseal and `systemd-cryptsetup` must ask for the passphrase.  Restore
the entry afterwards and run `sudo luksury update` if needed.
