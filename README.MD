# luksury

Builds, signs and installs a Unified Kernel Image (UKI) for the default boot
entry of an Ubuntu system with a LUKS2-encrypted root, and binds the volume
unlock to the TPM2 (Secure Boot optional, GRUB or systemd-boot).
Automatically updates the PCR to predicted values on system updates.

# Alpha phase

Bugs,vulnerabilities reports are welcome.

## Requirements

* Ubuntu **25.04 or newer** (x86-64), UEFI boot, TPM 2.0, LUKS2 root activated
  via `/etc/crypttab`, dpkg-managed Ubuntu kernel, `python3` ≥ 3.9.
* A **dracut-based initrd**

## Installation:

## Step 1 — Switch to Dracut, if you are using initramfs-tools (Hello Kubuntu)

On modern Ubuntu system, mkinitramfs invokes dracut.

```console
$ update-initramfs --version        # mentions "dracut" already? Then skip ahead
$ dpkg-query -W | grep -Ew '(clevis-initramfs|zfs-initramfs)'   # if found, install clevis-dracut / zfs-dracut instead
$ sudo apt install dracut           # removes initramfs-tools, regenerates all initrds
$ update-initramfs --version        # must now mention "dracut"
```

Reboot once and confirm the system still boots.

## Step 2 — Install the dependencies

```console
$ sudo apt install dracut binutils sbsigntool openssl efibootmgr mokutil shim-signed systemd-boot-efi tpm2-tools cryptsetup python3
```
If `apt` cannot find `systemd-boot-efi`, enable universe first:
`sudo add-apt-repository universe && sudo apt update`.

## Step 3 — Install

```console
$ sudo ./luksury.py --dry-run       # inspect first
$ sudo ./luksury.py                 # bootstrap (same as: sudo ./luksury.py install)
```

This installs the update hook, creates the EFI boot entry, prepares the
recovery key, updates the crypttab TPM2 options and regenerates the initrd;
the hook then builds and signs the UKI. On the next boot, confirm the queued
MOK enrollment in MokManager with the fixed password **`luksury`** (only
needed while Secure Boot is enforcing). luksury never reboots automatically.

## PCRs used

The TPM2 token is bound to these PCRs (PCR 7 only while Secure Boot is
enforcing):

| PCR | Measured content | Binding in luksury |
| --- | --- | --- |
| 0 | Core system firmware (UEFI code) | firmware value, plus the systemd os-separator extension on systemd ≥ 261 |
| 2 | Option ROMs | firmware value, plus the os-separator extension on systemd ≥ 261 |
| 4 | Boot loader, kernel and initrd | predicted for the shim-chained boot: firmware prefix + private shim + complete UKI, including the embedded kernel and initrd |
| 7 | Secure Boot policy and certificates | predicted Secure Boot policy plus shim's authority measurement of the luksury signing certificate; not bound when Secure Boot is off |
| 12 | OS/kernel/data events | systemd-stub's measurement of the ESP global credentials (`loader/credentials`), including the systemd NvPCR anchor on systemd ≥ 259 |
| 13 | Other boot components (Fat binaries) | the systemd os-separator value; zero only when the separator does not run (sysext/confext unsupported) |
| 15 | OS vendor specific | zero: systemd-cryptsetup measures the LUKS volume key into PCR 15 only after the token has been unsealed, so it can't be unsealed a second time |

Falls back to password prompt on PCR mismatch. Change in hardware, BIOS, or secure boot DBX update may cause it.

## Uninstall

```console
$ sudo ./luksury.py remove
```

removes everything except the MOK key.
