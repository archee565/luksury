#!/usr/bin/python3 -I
"""Bootstrap and update a UKI for the default boot entry.

When the system uses systemd-boot, the default entry is resolved from the
Boot Loader Specification entries on the ESP and XBOOTLDR partitions.  When
the current boot does not identify systemd-boot or GRUB through LoaderInfo
(the firmware booted a unified kernel image directly, or the loader does not
publish the interface, as GRUB does not), GRUB is used if it is installed,
and systemd-boot otherwise.  The default GRUB entry is used for GRUB.

This deliberately does not use systemd-ukify.  The image is assembled with
binutils objcopy from systemd's linuxx64.efi.stub, using PE section VMAs
calculated from the stub itself (Ubuntu's stub has a non-zero ImageBase, so
the commonly copied hard-coded 0x20000/0x2000000 offsets are not portable).

The kernel that is embedded must match the MD5 checksum recorded in the
dpkg database.  A kernel that differs from a matching reference is rejected,
and a kernel without any dpkg checksum is never embedded.

Run as root:

    sudo ./luksury.py --dry-run
    sudo ./luksury.py

The first real run is a bootstrap: it requires UEFI.  Secure Boot is
optional.  It creates or reuses a UKI code-signing key.  When Secure Boot is
enforcing, the certificate is queued with mokutil for MOK enrollment; without
Secure Boot the UKI is still signed, but no MOK enrollment is needed because
shim does not verify it.  The bootstrap installs the initramfs post-update
hook, creates the EFI boot entry, updates the root crypttab TPM2 options,
prepares the recovery key and regenerates only the default entry's initrd
with update-initramfs.  The boot entry loads a private copy of shim-signed's
shim.
The signed UKI is installed next to that copy under shim's fixed second-stage
name, grubx64.efi, so the chain does not depend on firmware passing the UKI
path as optional load data.  The post-update hook builds and signs the UKI.
Later initrd updates use the same hook; only that hook creates a UKI.  The
script does not modify GRUB or systemd-boot configuration.  A queued MOK
enrollment must be confirmed in MokManager on the next boot with the fixed
password "luksury"; luksury never reboots the machine automatically.

A dracut-based system is required.  Dracut produces a single initrd with the
early microcode archive already included, so the default entry must have
exactly one initrd; entries with multiple initrds are rejected.

The hook also computes the UKI's PCR4 measurements directly from the PE
images and predicts PCR4 for the shim-chained boot.  The pre-shim prefix is
read from the firmware event log when available, stopping at shim, GRUB,
systemd-boot or the UKI, whichever loads the image; earlier firmware
measurements remain in the prefix.  The built-in action/separator prefix is
used if the log is unavailable.  The new shim and UKI are added after that
prefix, plus the embedded kernel only when the current boot's event log (or,
without one, the systemd-stub version gate) shows that the kernel is measured
into PCR4.  --pcr4-kernel and --pcr4-no-kernel override that decision when the
event log cannot be used.  This does not require systemd-pcrlock.

The kernel command line embedded in the UKI is read from the trusted settings
on the encrypted root: /etc/kernel/cmdline for systemd-boot and
/etc/default/grub for GRUB.  If /etc/kernel/cmdline is missing, the GRUB
command line is used when GRUB is installed.  The boot entry's own command
line is not used.  The active root device is substituted for root=.
The embedded command line always ends with rd.shell=0 and
rd.emergency=reboot, and options that can open a shell, run an arbitrary
init, pause the boot for a shell or select a rescue/emergency/debug target
(rd.break, rd.debug, systemd.debug_shell, systemd.unit=, init=, ...) are
removed.  A boot that fails after the root has been unlocked therefore
cannot leave a shell with the volume key available.  The
UKI and its initrd live on the ESP, which must be treated as public: do not
put a root keyfile or other secret in the initrd.

The hook updates the root LUKS device's TPM2 enrollment
so that it is bound to PCR 0, 2, 4, 12, 13 and 15, plus PCR 7 while Secure
Boot is enforcing.  PCR4 uses the predicted value for the new UKI and covers
the shim and the complete UKI, including the kernel and initrd.  When Secure
Boot is enforcing, PCR7 uses the predicted Secure Boot policy and shim's
authority measurement for the certificate that verifies the UKI; without
Secure Boot PCR7 is not bound.  On systemd 261 and later, a measured UKI boot
runs systemd-pcrosseparator.service in the initrd, which extends PCR 0-7, 9,
12-14 with the os-separator measurement before cryptsetup.target.  The
predicted PCR0, PCR2, PCR4 and PCR12 values, and PCR7 when it is bound,
include that extension, and PCR13 is bound to the separator value instead of
zero.  PCR13 is zero only when the separator does not run; a sysext or confext
is not supported.  PCR15 is zero because systemd-cryptsetup measures the
volume key into it only after the token has been unsealed.

PCR12 starts at zero.  systemd-stub measures a cpio archive of the global
credentials in ESP/loader/credentials into it.  On systemd 259 and later that
includes systemd-tpm2-setup's NvPCR anchor secret,
nvpcr-anchor.<entry-token>.cred.  Other credentials, command-line addons and
configuration extensions add measurements that are not predicted, so they are
rejected.  If the anchor is missing on systemd 259 or later, the next boot may
create it and change PCR12; the script warns that the TPM token will stop
unlocking and the passphrase will be requested, and that rerunning luksury
after the reboot re-enrolls with the anchor.  The root crypttab entry is
updated with tpm2-device=auto, tpm2-measure-pcr=15 and
tpm2-measure-bank=sha256.

TPM2 enrollment requires the tpm2 command from tpm2-tools and dracut's
tpm2-tss module.  Dracut only includes that module when the command is
present; without it the initrd has no libtss2 and cannot unlock the volume,
so the requirements are checked before any token is enrolled.

The bootstrap itself does not build a UKI.  A real "install" only bootstraps the
installation, writes /var/lib/luksury/install-options.json, installs the
initramfs post-update hook, creates the EFI boot entry when needed, updates the
root crypttab entry and prepares the recovery key.  It then regenerates the
default entry's initrd with update-initramfs; the post-update hook calls
"luksury --hook-rebuild", which is the only code path that builds, signs and
installs a UKI.  The same hook is used for later initrd regenerations.  The
hook's initrd path is used only to check that it is the default entry's
initrd; the UKI is built from that generated file.  The initrd is confined to
the boot filesystems, must look like an initrd, and is copied to a root-only
work directory before the build.

A change to the embedded command line, kernel or initrd is covered by PCR4,
which measures the complete UKI.  While Secure Boot is enforcing, a change to
the Secure Boot policy or the signer shim uses for the UKI is also covered by
PCR7; an externally supplied command line or sysext requires re-enrolling.  A
change to the ESP's global credentials, including the systemd NvPCR anchor, is
covered by PCR12.  Changing whether the systemd os-separator measurement runs,
for example by setting systemd.tpm2_measured_os=no, also requires re-enrolling.
Rerun the installer after a shim-signed or Secure Boot policy update, or after
enabling or disabling Secure Boot, so the TPM token is bound to the new values.

Before re-enrolling the TPM2 token the script checks the recovery key in
/var/lib/luksury/recovery.key (mode 0600).  It is generated once, during the
first enrollment, and is never replaced.  If it is later missing or no
longer unlocks the volume, the script stops rather than creating a new one.
That key authorizes later PCR updates.  The recovery key is never printed.

The enrolled TPM2 token is recorded in /var/lib/luksury/tpm2-state.json
(mode 0600).  Every install removes all existing systemd-tpm2 tokens and
keyslots before enrolling the new token, so no stale or weak TPM2 enrollment
can keep unlocking the volume.

A real install installs the update hook automatically.  It copies itself to
/usr/local/sbin/luksury, installs a bash wrapper below
/usr/local/lib/luksury, and installs only the initramfs post-update hook below
/etc/initramfs/post-update.d.  There is no systemd path unit, timer or kernel
postinst trigger.  The hook calls "luksury --hook-rebuild", which rebuilds and
signs the UKI only when the generated initrd belongs to the default boot
entry.  It verifies that python3, dracut and the required commands are present
and otherwise skips with a warning.  A dry run never installs the hook,
regenerates an initrd or creates a UKI.

To undo the installation, run:

    sudo ./luksury.py remove --dry-run
    sudo ./luksury.py remove

This removes the UKI, the private shim copy, its EFI boot entries, the update
hook, the installed copy in /usr/local, all systemd-tpm2 enrollments, the
recovery key itself
(using cryptsetup luksRemoveKey) and its token, the tpm2-* options in the root
crypttab entry, the install options and the state files under
/var/lib/luksury.  The MOK signing key and its MOK enrollment are left in
place, because deleting them requires a separate MokManager deletion and a
reboot; remove them manually with 'mokutil --delete' if desired.  It refuses
to remove the last usable LUKS keyslot and verifies an alternative unlock
before removing keyslots.
"""

from __future__ import annotations

import argparse
import ctypes.util
import fnmatch
import functools
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import BinaryIO

ESP_DEFAULT = Path("/boot/efi")
EFI_NAME = "luksury.efi"
SHIM_NAME = "shimx64.efi"
MMX_NAME = "mmx64.efi"
# shim resolves its default second stage relative to its own directory.  The
# UKI therefore needs a private copy of shim and this fixed second-stage name;
# relying on the boot entry's optional data is firmware-dependent.
SHIM_DIR_NAME = "luksury"
SECOND_STAGE_NAME = "grubx64.efi"
STUB_DEFAULT = Path("/usr/lib/systemd/boot/efi/linuxx64.efi.stub")
SHIM_SIGNED_DEFAULT = Path("/usr/lib/shim/shimx64.efi.signed")
MMX_DEFAULT = Path("/usr/lib/shim/mmx64.efi")
GRUB_CFG = Path("/boot/grub/grub.cfg")
GRUBENV = Path("/boot/grub/grubenv")
ETC_DEFAULT_GRUB = Path("/etc/default/grub")
KERNEL_CMDLINE = Path("/etc/kernel/cmdline")
OS_RELEASE = Path("/etc/os-release")
DPKG_INFO_DIR = Path("/var/lib/dpkg/info")

LOADER_GUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
EFIVAR_DIR = Path("/sys/firmware/efi/efivars")
SYSTEMD_BOOT = "systemd-boot"
EFI_GLOBAL_VARIABLE_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
SHIM_LOCK_GUID = "605dab50-e046-4300-abb6-3dd810dd8b23"
SECURE_BOOT_DB_GUID = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"

TPM_EVENT_LOG = Path("/sys/kernel/security/tpm0/binary_bios_measurements")
TPM_PCRS_DIR = Path("/sys/class/tpm/tpm0")
CRYPTTAB = Path("/etc/crypttab")
# PCR7 is only bound while Secure Boot is enforcing; it carries the Secure
# Boot policy and the authority shim uses for the UKI.  Without Secure Boot
# that value is not a boot-chain policy, so the token relies on PCR4, which
# measures the shim and the complete UKI (kernel and initrd included).
CRYPTENROLL_PCRS_WITH_PCR7 = (0, 2, 4, 7, 12, 13, 15)
CRYPTENROLL_PCRS_WITHOUT_PCR7 = (0, 2, 4, 12, 13, 15)
CRYPTTAB_TPM2_MEASURE_PCR = 15
CRYPTTAB_TPM2_MEASURE_BANK = "sha256"
# A failed boot must not start an initrd shell after the root has already been
# unlocked.  The UKI is on the ESP, so an initrd shell would be a convenient
# way to read the decrypted root device or the key.
INITRD_SHELL_CMDLINE = ("rd.shell=0", "rd.emergency=reboot")
# Options that can open a shell, run an arbitrary init, pause the boot for a
# shell or select an emergency/rescue/debug target.  A stale debugging option
# from /etc/kernel/cmdline must not undo the hardening above.  Names are
# compared before the first '='; the value is irrelevant.
INITRD_UNSAFE_CMDLINE = frozenset({
    "-b",                          # systemd alias for emergency mode
    "1", "s", "S", "single",       # rescue/single-user aliases
    "emergency", "rescue",         # systemd target shortcuts
    "init", "rdinit",              # arbitrary PID 1 / initramfs init
    "rd.break",                    # dracut shell at a breakpoint
    "rd.cmdline",                  # rd.cmdline=ask adds cmdline at boot
    "rd.debug",                    # dracut debug output
    "rd.rescue",
    "rd.systemd.break",
    "rd.systemd.debug-shell", "rd.systemd.debug_shell",
    "rd.systemd.run",
    "rd.systemd.unit",
    "systemd.break",
    "systemd.crash-shell", "systemd.crash_shell",
    "systemd.debug-shell", "systemd.debug_shell",
    "systemd.run",
    "systemd.unit",
})
# Units that systemd.wants=/systemd.requires= must not pull into the boot.
INITRD_UNSAFE_UNITS = frozenset({
    "debug-shell.service",
    "emergency.service",
    "emergency.target",
    "rescue.service",
    "rescue.target",
})
CRYPTTAB_TPM2_OPTIONS = (
    "tpm2-device",
    "tpm2-measure-pcr",
    "tpm2-measure-bank",
)
CRYPTTAB_BACKUP_SUFFIX = ".luksury.bak"


def cryptenroll_pcrs(secure_boot: bool) -> tuple[int, ...]:
    """Return the PCRs bound to a TPM2 token for this Secure Boot state."""
    return (
        CRYPTENROLL_PCRS_WITH_PCR7
        if secure_boot
        else CRYPTENROLL_PCRS_WITHOUT_PCR7
    )


RECOVERY_KEY_FILE = Path("/var/lib/luksury/recovery.key")
TPM2_STATE_FILE = Path("/var/lib/luksury/tpm2-state.json")
TPM2_STATE_VERSION = 1
MOK_KEY_FILE = Path("/var/lib/luksury/mok.key")
MOK_CERT_FILE = Path("/var/lib/luksury/mok.crt")
MOK_DER_FILE = Path("/var/lib/luksury/mok.der")
# MokManager always requires a password to authorize a queued enrollment.  A
# fixed, publicly documented password avoids generating or storing a secret.
MOK_PASSWORD = "luksury"
MOK_PASSWORD_HASH_FILE = Path("/var/lib/luksury/mok-password.hash")
# Password file written by older versions that generated a random password.
LEGACY_MOK_PASSWORD_FILE = Path("/var/lib/luksury/mok-password")
MOK_SUBJECT = "/CN=luksury UKI signing key/"
MOK_CERT_DAYS = 3650
SIGNATURE_SLACK = 64 * 1024
# dracut only includes its tpm2-tss module when the tpm2 command from
# tpm2-tools is installed.  The module supplies libtss2 and the systemd-tpm2
# cryptsetup plugin to the initrd; without it systemd-cryptsetup cannot use
# the token and falls back to a passphrase.
DRACUT_MODULE_DIRS = (
    Path("/usr/lib/dracut/modules.d"),
    Path("/usr/libexec/dracut/modules.d"),
)
TPM2_REQUIRED_LIBRARIES = (
    ("tss2-esys", "libtss2-esys.so.0"),
    ("tss2-tcti-device", "libtss2-tcti-device.so.0"),
)
INSTALL_OPTIONS_FILE = Path("/var/lib/luksury/install-options.json")
INSTALL_OPTIONS_VERSION = 1
# Leading bytes of the initrd formats we are willing to copy.  This is a
# sanity check, not a trust anchor; it keeps the build from accidentally
# embedding an arbitrary file (for example a LUKS key).
INITRD_MAGIC = (
    b"\x1f\x8b",              # gzip
    b"\x28\xb5\x2f\xfd",      # zstd
    b"\xfd7zXZ\x00",          # xz
    b"\x04\x22\x4d\x18",      # lz4
    b"BZh",                   # bzip2
    b"\x5d\x00\x00",          # lzma
    b"070701",                # uncompressed cpio
    b"070702",                # uncompressed cpio with crc
    b"\x89LZO",               # lzo
    b"\x1f\x9e",              # compress
    b"\x02\x21\x4c\x18",      # lzop
    b"7z\xbc\xaf\x27\x1c",    # 7z
)
BOOT_ROOTS_EXTRA = (Path("/boot"), Path("/efi"), ESP_DEFAULT)
SYSTEMD_TPM2_TOKEN = "systemd-tpm2"
SYSTEMD_RECOVERY_TOKEN = "systemd-recovery"
INSTALL_BIN = Path("/usr/local/sbin/luksury")
INSTALL_LIB_DIR = Path("/usr/local/lib/luksury")
HOOK_PATH = INSTALL_LIB_DIR / "hook.sh"
SYSTEMD_UNIT_DIR = Path("/etc/systemd/system")
INITRAMFS_POST_UPDATE_DIR = Path("/etc/initramfs/post-update.d")
KERNEL_POSTINST_DIR = Path("/etc/kernel/postinst.d")
TRUSTED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
BUILD_LOCK_FILE = Path("/run/luksury.lock")
NON_INTERACTIVE = False
# systemd's recovery keys are 8 groups of eight modhex characters.
RECOVERY_KEY_RE = re.compile(
    r"^[cbdefghijklnrtuv]{8}(?:-[cbdefghijklnrtuv]{8}){7}$"
)
# Default pre-UKI PCR4 prefix used when the firmware event log is unavailable.
# The event log is preferred because a machine may have additional pre-UKI
# measurements.  These values were confirmed from an AMI firmware event log:
# action 3d6772b4..., separator df3f6198..., prefix 7a94ffe8...
PCR4_FIRMWARE_ACTION = b"Calling EFI Application from Boot Option"
PCR4_FIRMWARE_SEPARATOR = b"\x00\x00\x00\x00"
PCR_ALGORITHM_DEFAULT = "sha256"
# systemd 261 runs systemd-pcrosseparator.service in the initrd on measured
# UKI boots.  Before cryptsetup.target it extends PCR 0-7, 9, 12-14 with this
# digest, so every bound PCR except 15 includes it.
OS_SEPARATOR_EVENT = b"os-separator"
SYSTEMD_PCROSSEPARATOR_UNIT = "systemd-pcrosseparator.service"
SYSTEMD_PCROSSEPARATOR_DIRS = (
    Path("/etc/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/lib/systemd/system"),
)
# systemd-stub v252 through v257 called LoadImage() for the embedded kernel,
# which made firmware measure it into PCR4.  v258 and later either start the
# kernel directly or use shim's loader or security-override path; in both
# cases a PE section that was already authenticated as part of the UKI is not
# measured again.  Use --pcr4-kernel/--pcr4-no-kernel to override the gate.
PCR4_KERNEL_STUB_MIN = 252
PCR4_KERNEL_STUB_EXCLUSIVE = 258
# systemd 259 and later write the NvPCR anchor credential to the ESP.  The
# systemd-stub global credentials archive, including that file, is measured
# into PCR12.  Older systems never create the anchor here.
PCR12_ESP_ANCHOR_STUB_MIN = 259
PCR12_ESP_ANCHOR_PREFIX = "nvpcr-anchor."
# Applications that can terminate the pre-UKI PCR4 prefix.  The next boot is
# expected to load the new shim at the position of the first of these.  Other
# EFI applications measured by firmware, for example a firmware boot manager,
# must remain in the prefix.
PCR4_BOOT_CHAIN_PATTERNS = (
    "shim*.efi",
    "grub*.efi",
    "core.efi",
    "systemd-boot*.efi",
    "bootx64.efi",
    "mmx64.efi",
    "fbx64.efi",
    "fallback.efi",
    "mokmanager.efi",
    EFI_NAME.lower(),
)
EV_NO_ACTION = 0x00000003
EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001
EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003
EV_EFI_VARIABLE_AUTHORITY = 0x8000000A
TCG_HASH_ALGORITHMS = {
    0x0004: "sha1",
    0x000B: "sha256",
    0x000C: "sha384",
    0x000D: "sha512",
}

KERNEL_CMDS = {"linux", "linuxefi", "linux16"}
INITRD_CMDS = {"initrd", "initrdefi", "initrd16"}
MENU_RE = re.compile(r"^\s*(?:menuentry|submenu)\b")
VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


class UkiError(Exception):
    """A user-facing failure."""


def log(message: str) -> None:
    print(f"==> {message}", flush=True)


def vlog(message: str, verbose: bool) -> None:
    if verbose:
        print(f"    {message}", flush=True)


def warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr, flush=True)


def sanitize_environment() -> None:
    """Remove interpreter and loader injection from this root process."""
    os.environ["PATH"] = TRUSTED_PATH
    for name in (
        "BASH_ENV",
        "CDPATH",
        "ENV",
        "GLOBIGNORE",
        "IFS",
        "LUKSURY_BIN",
        "LUKSURY_HOOK_ACTIVE",
        "LUKSURY_LOCK_FILE",
        "LD_AUDIT",
        "LD_DEBUG",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "PYTHONBREAKPOINT",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONWARNINGS",
    ):
        os.environ.pop(name, None)


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        proc = subprocess.run(
            [str(part) for part in cmd],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise UkiError(f"required command not found: {cmd[0]}") from exc

    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        if detail:
            raise UkiError(f"command failed: {shlex.join(cmd)}\n{detail}")
        raise UkiError(f"command failed: {shlex.join(cmd)}")
    return proc


def run_capture_bytes(
    cmd: list[str], *, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    try:
        proc = subprocess.run(
            [str(part) for part in cmd],
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise UkiError(f"required command not found: {cmd[0]}") from exc

    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).decode(
            "utf-8", "replace"
        ).strip()
        if detail:
            raise UkiError(f"command failed: {shlex.join(cmd)}\n{detail}")
        raise UkiError(f"command failed: {shlex.join(cmd)}")
    return proc


# ---------------------------------------------------------------------------
# GRUB configuration parsing
# ---------------------------------------------------------------------------


@dataclass
class BootEntry:
    kind: str  # "menuentry" or "submenu"
    title: str
    entry_id: str | None
    start: int
    end: int
    parent: "BootEntry | None" = None
    children: list["BootEntry"] = field(default_factory=list)


@dataclass
class ResolvedBoot:
    """Kernel, initrds and command line for the default boot entry.

    ``cmdline`` comes from trusted settings on the encrypted root, not from
    the boot entry on the ESP; ``cmdline_source`` records which file was used.
    """

    loader: str
    title: str
    entry_id: str | None
    source: str
    cmdline_source: str
    kernel: str
    initrds: list[str]
    cmdline: list[str]
    release: str | None
    initrd_roots: tuple[Path, ...] = ()


def logical_lines(text: str) -> list[str]:
    """Join GRUB backslash continuations into single logical lines."""
    result: list[str] = []
    pending = ""
    for raw in text.splitlines():
        if pending:
            raw = pending + raw.lstrip()
            pending = ""
        right = raw.rstrip()
        if right.endswith("\\"):
            pending = right[:-1] + " "
            continue
        result.append(raw)
    if pending:
        result.append(pending)
    return result


def find_unquoted(text: str, target: str) -> int | None:
    quote: str | None = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch == "#":
            return None
        elif ch == target:
            return i
        i += 1
    return None


def brace_delta(line: str) -> int:
    """Count braces outside quotes and comments."""
    delta = 0
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch == "#":
            break
        elif ch == "{":
            delta += 1
        elif ch == "}":
            delta -= 1
        i += 1
    return delta


def parse_menu_header(line: str) -> tuple[str, str, str | None] | None:
    stripped = line.strip()
    brace = find_unquoted(stripped, "{")
    if brace is None:
        return None
    header = stripped[:brace].strip()
    try:
        tokens = shlex.split(header, posix=True)
    except ValueError:
        match = re.match(r"^(menuentry|submenu)\s+(['\"])(.*?)\2", header)
        if not match:
            return None
        tokens = [match.group(1), match.group(3)]

    if not tokens or tokens[0] not in ("menuentry", "submenu"):
        return None

    title: str | None = None
    entry_id: str | None = None
    options_with_arg = {"--class", "--users", "--hotkey", "--id"}
    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token in options_with_arg:
            if token == "--id" and i + 1 < len(tokens):
                entry_id = tokens[i + 1]
            i += 2
        elif token.startswith("-"):
            i += 1
        else:
            if title is None:
                title = token
            else:
                entry_id = token
            i += 1

    return tokens[0], title or "", entry_id


def parse_grub_cfg(text: str) -> tuple[list[str], list[BootEntry]]:
    """Return logical lines and top-level menu entries.

    Entries inside ``if`` blocks are still top-level menu entries; only nesting
    inside another menuentry/submenu changes the parent.  The brace-depth array
    is used solely to find the matching closing brace of each entry.
    """
    lines = logical_lines(text)
    deltas = [brace_delta(line) for line in lines]

    depth_before: list[int] = []
    depth = 0
    for delta in deltas:
        depth_before.append(depth)
        depth += delta

    nodes: list[BootEntry] = []
    for i, line in enumerate(lines):
        if not MENU_RE.match(line):
            continue
        parsed = parse_menu_header(line)
        if parsed is None:
            continue
        kind, title, entry_id = parsed
        base = depth_before[i]
        if base + deltas[i] <= base:
            continue

        end = None
        for k in range(i + 1, len(lines)):
            if depth_before[k] + deltas[k] <= base:
                end = k
                break
        if end is None:
            raise UkiError(f"unterminated {kind} at line {i + 1}: {line.strip()}")

        nodes.append(
            BootEntry(
                kind=kind,
                title=title,
                entry_id=entry_id,
                start=i,
                end=end,
            )
        )

    stack: list[BootEntry] = []
    for node in nodes:
        while stack and stack[-1].end <= node.start:
            stack.pop()
        if stack:
            node.parent = stack[-1]
            stack[-1].children.append(node)
        stack.append(node)

    return lines, [node for node in nodes if node.parent is None]


def flatten(nodes: list[BootEntry]):
    for node in nodes:
        yield node
        yield from flatten(node.children)


def read_grubenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        data = path.read_bytes()
    except OSError:
        return values

    for raw in data.split(b"\n"):
        line = raw.decode("utf-8", "replace").strip("\x00")
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def effective_default(lines: list[str], env: dict[str, str]) -> tuple[str | None, str]:
    next_entry = (env.get("next_entry") or "").strip()
    if next_entry:
        return next_entry, "grubenv next_entry"

    candidates: list[str] = []
    for line in lines:
        match = re.match(r"^\s*set\s+default=(.*)$", line)
        if not match:
            continue
        raw = match.group(1).strip()
        try:
            parts = shlex.split(raw, posix=True, comments=True)
        except ValueError:
            parts = [raw.strip("'\"")]
        candidates.append(parts[0] if parts else "")

    if not candidates:
        return None, "no set default"

    value = candidates[-1]
    if value in ("${saved_entry}", "$saved_entry", "saved"):
        saved = (env.get("saved_entry") or "").strip()
        return (saved or None), "grubenv saved_entry"
    if value in ("${next_entry}", "$next_entry"):
        nxt = (env.get("next_entry") or "").strip()
        return (nxt or None), "grubenv next_entry"
    if value in ("${GRUB_DEFAULT}", "$GRUB_DEFAULT"):
        fallback = etc_default_spec(ETC_DEFAULT_GRUB)
        return fallback, f"{ETC_DEFAULT_GRUB}: GRUB_DEFAULT"
    return value, "set default"


def etc_default_spec(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    for line in text.splitlines():
        match = re.match(r"^\s*GRUB_DEFAULT=(.*)$", line)
        if not match:
            continue
        try:
            parts = shlex.split(match.group(1), posix=True, comments=True)
        except ValueError:
            parts = [match.group(1).strip("'\"")]
        return parts[0] if parts else None
    return None


def read_kernel_cmdline(path: Path = KERNEL_CMDLINE) -> list[str] | None:
    """Read the systemd-boot command line from the encrypted root."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    if not text:
        return []
    return split_options(text)


def read_grub_cmdline(path: Path = ETC_DEFAULT_GRUB) -> list[str] | None:
    """Read GRUB_CMDLINE_LINUX and GRUB_CMDLINE_LINUX_DEFAULT."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    values: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(
            r"^\s*(GRUB_CMDLINE_LINUX(?:_DEFAULT)?)=(.*)$", line
        )
        if not match:
            continue
        try:
            parts = shlex.split(
                match.group(2), posix=True, comments=True
            )
        except ValueError:
            parts = [match.group(2).strip("'\"")]
        values[match.group(1)] = " ".join(parts)

    tokens: list[str] = []
    for key in ("GRUB_CMDLINE_LINUX", "GRUB_CMDLINE_LINUX_DEFAULT"):
        value = values.get(key)
        if value:
            tokens.extend(split_options(value))
    return tokens


def grub_installed() -> bool:
    """Return True when GRUB is installed and can supply trusted settings."""
    return GRUB_CFG.is_file() and ETC_DEFAULT_GRUB.is_file()


def active_root_device() -> str | None:
    """Return the device backing /, preferring its device-mapper name."""
    name = root_mapper_name()
    if name:
        return f"/dev/mapper/{name}"

    proc = run(["findmnt", "-no", "SOURCE", "--target", "/"], check=False)
    source = proc.stdout.strip()
    if not source.startswith("/dev/"):
        return None
    return source.split("[", 1)[0]


def strip_boot_only(tokens: list[str]) -> list[str]:
    return [
        token
        for token in tokens
        if not token.startswith(("initrd=", "BOOT_IMAGE="))
    ]


def is_unsafe_initrd_option(token: str) -> bool:
    """Return True for an option that could expose a shell after unlock."""
    name, _, value = token.partition("=")
    if name in INITRD_UNSAFE_CMDLINE:
        return True
    if name in ("systemd.wants", "systemd.requires"):
        unit = value.strip().rsplit("/", 1)[-1]
        return unit in INITRD_UNSAFE_UNITS
    return False


def harden_initrd_cmdline(tokens: list[str]) -> list[str]:
    """Drop shell-enabling options and force dracut to reboot instead."""
    desired = {
        option.split("=", 1)[0]: option for option in INITRD_SHELL_CMDLINE
    }
    result: list[str] = []
    for token in tokens:
        name = token.split("=", 1)[0]
        replacement = desired.get(name)
        if replacement is not None:
            if token != replacement:
                warn(
                    f"replacing embedded command line option {token!r} "
                    f"with {replacement!r}"
                )
            continue
        if is_unsafe_initrd_option(token):
            warn(f"dropping unsafe kernel command line option {token!r}")
            continue
        result.append(token)
    return result + list(INITRD_SHELL_CMDLINE)


def replace_cmdline_root(tokens: list[str], root: str) -> list[str]:
    result = [token for token in tokens if not token.startswith("root=")]
    result.insert(0, f"root={root}")
    return result


def cmdline_from_root_settings(loader: str) -> tuple[list[str], str]:
    """Read the command line from trusted settings on the encrypted root."""
    if loader == SYSTEMD_BOOT:
        tokens = read_kernel_cmdline()
        source = str(KERNEL_CMDLINE)
        if tokens is None:
            tokens = read_grub_cmdline()
            source = str(ETC_DEFAULT_GRUB)
            if tokens is not None:
                warn(
                    f"missing {KERNEL_CMDLINE}; using {ETC_DEFAULT_GRUB} as "
                    "the trusted command line"
                )
        if tokens is None:
            raise UkiError(
                f"missing {KERNEL_CMDLINE} and {ETC_DEFAULT_GRUB}; refusing "
                "to use the BLS command line"
            )
    else:
        tokens = read_grub_cmdline()
        source = str(ETC_DEFAULT_GRUB)
        if tokens is None:
            raise UkiError(
                f"missing {ETC_DEFAULT_GRUB}; refusing to use the GRUB "
                "entry command line"
            )

    tokens = strip_boot_only(tokens)
    active_root = active_root_device()
    if active_root is not None:
        tokens = replace_cmdline_root(tokens, active_root)
    return harden_initrd_cmdline(tokens), source


def warn_ignored_entry_cmdline(
    entry_tokens: list[str],
    root_tokens: list[str],
    source: str,
) -> None:
    """Warn about entry arguments that are not in the trusted cmdline."""
    ignored = ("initrd=", "root=", "BOOT_IMAGE=")
    root_set = {
        token for token in root_tokens if not token.startswith(ignored)
    }
    extra = [
        token
        for token in entry_tokens
        if not token.startswith(ignored) and token not in root_set
    ]
    if extra:
        warn(
            f"{source} contains kernel arguments ignored for the UKI: "
            + " ".join(extra)
        )


def has_kernel(entry: BootEntry, lines: list[str]) -> bool:
    for raw in lines[entry.start + 1 : entry.end]:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        command = line.split(None, 1)[0]
        if command in KERNEL_CMDS:
            return True
    return False


def first_leaf_with_kernel(entry: BootEntry | None, lines: list[str]) -> BootEntry | None:
    if entry is None:
        return None
    if entry.kind == "submenu":
        for child in entry.children:
            found = first_leaf_with_kernel(child, lines)
            if found is not None:
                return found
        return None
    return entry if has_kernel(entry, lines) else None


def find_node(level: list[BootEntry], key: str) -> BootEntry | None:
    for node in level:
        if node.title == key or (node.entry_id is not None and node.entry_id == key):
            return node
    if key.isdigit() and int(key) < len(level):
        return level[int(key)]
    return None


def resolve_default(
    spec: str | None, top: list[BootEntry], lines: list[str]
) -> BootEntry | None:
    if not top:
        return None

    if spec is not None:
        spec = spec.strip().strip("'\"")
    if spec and re.fullmatch(r"\d+(?:>\d+)*", spec):
        level = top
        node: BootEntry | None = None
        for part in spec.split(">"):
            index = int(part)
            if index < 0 or index >= len(level):
                raise UkiError(f"default entry {spec!r}: index {index} is out of range")
            node = level[index]
            level = node.children
        return first_leaf_with_kernel(node, lines)

    if spec:
        exact = [
            node
            for node in flatten(top)
            if node.title == spec
            or (node.entry_id is not None and node.entry_id == spec)
        ]
        if exact:
            return first_leaf_with_kernel(exact[0], lines)

        if ">" in spec:
            level = top
            node = None
            for part in spec.split(">"):
                part = part.strip().strip("'\"")
                node = find_node(level, part)
                if node is None:
                    raise UkiError(
                        f"default entry {spec!r}: component {part!r} was not found"
                    )
                level = node.children
            return first_leaf_with_kernel(node, lines)

        warn(f"default GRUB entry {spec!r} was not found; using the first bootable entry")

    for node in top:
        found = first_leaf_with_kernel(node, lines)
        if found is not None:
            return found
    return None


def collect_vars(body: list[str]) -> dict[str, str]:
    variables: dict[str, str] = {}
    for raw in body:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^set\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if not match:
            continue
        value = match.group(2).strip()
        try:
            parts = shlex.split(value, posix=True, comments=True)
        except ValueError:
            parts = [value.strip("'\"")]
        variables[match.group(1)] = " ".join(parts)
    return variables


def expand(token: str, variables: dict[str, str]) -> str:
    def repl(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        return variables.get(name, match.group(0))

    return VAR_RE.sub(repl, token)


def extract_boot(
    entry: BootEntry, lines: list[str]
) -> tuple[str | None, list[str], list[str]]:
    body = lines[entry.start + 1 : entry.end]
    variables = collect_vars(body)

    kernel: str | None = None
    kernels: list[str] = []
    initrds: list[str] = []
    cmdline: list[str] = []

    for raw in body:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = shlex.split(line, posix=True, comments=True)
        except ValueError:
            continue
        if not tokens:
            continue

        command = tokens[0]
        if command in KERNEL_CMDS:
            args = [expand(token, variables) for token in tokens[1:]]
            args = [arg for arg in args if arg]
            if not args:
                continue
            kernels.append(args[0])
            if kernel is None:
                kernel = args[0]
                cmdline = args[1:]
        elif command in INITRD_CMDS:
            for token in tokens[1:]:
                expanded = expand(token, variables)
                if expanded:
                    initrds.append(expanded)

    if len(kernels) > 1:
        warn(
            f"entry {entry.title!r} has {len(kernels)} linux commands; "
            f"using the first ({kernel})"
        )

    cleaned: list[str] = []
    for token in cmdline:
        if token.startswith("BOOT_IMAGE="):
            continue
        if re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", token):
            continue
        if "$" in token:
            warn(f"unexpanded variable in kernel command line: {token}")
        cleaned.append(token)

    return kernel, initrds, cleaned


def _resolved_root(path: Path) -> Path:
    try:
        return path.resolve(strict=True)
    except (OSError, RuntimeError):
        try:
            return path.resolve()
        except (OSError, RuntimeError):
            return path


def _resolve_under(root: Path, path: Path, label: str) -> Path:
    """Resolve ``path`` and require it to stay below the resolved ``root``."""
    try:
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UkiError(f"cannot resolve {label} root {root}: {exc}") from exc
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise UkiError(f"cannot resolve {label} {path}: {exc}") from exc
    if not resolved.is_relative_to(resolved_root):
        raise UkiError(f"{label} {path} escapes {resolved_root}")
    return resolved


def install_shim_dir(esp: Path, efi_dir: Path) -> Path:
    """Return the private shim directory, confined to the resolved ESP."""
    if efi_dir.is_absolute() or ".." in efi_dir.parts:
        raise UkiError(f"invalid UKI directory: {efi_dir}")
    try:
        resolved_esp = esp.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UkiError(f"cannot resolve ESP {esp}: {exc}") from exc
    if not resolved_esp.is_dir():
        raise UkiError(f"ESP directory not found: {resolved_esp}")
    candidate = resolved_esp / efi_dir / SHIM_DIR_NAME
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise UkiError(
            f"cannot resolve UKI directory {candidate}: {exc}"
        ) from exc
    if not resolved.is_relative_to(resolved_esp):
        raise UkiError(
            f"UKI directory {candidate} escapes the ESP {resolved_esp}"
        )
    return resolved


def install_destination(esp: Path, efi_dir: Path) -> Path:
    """Return the UKI path, confined to the resolved ESP."""
    return install_shim_dir(esp, efi_dir) / SECOND_STAGE_NAME


def installed_shim_path(esp: Path, efi_dir: Path) -> Path:
    """Return the private copy of shim-signed's shim."""
    return install_shim_dir(esp, efi_dir) / SHIM_NAME


def installed_shim_relative(efi_dir: Path) -> str:
    """Return the boot-entry loader path for the private shim copy."""
    return "\\" + str(efi_dir / SHIM_DIR_NAME / SHIM_NAME).replace("/", "\\")


def _dedupe_roots(roots: list[Path]) -> tuple[Path, ...]:
    result: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        resolved = _resolved_root(root)
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        result.append(resolved)
    return tuple(result)


def initrd_roots(esp_override: Path | None = None) -> tuple[Path, ...]:
    """Return the directories an initrd may legitimately live below."""
    roots: list[Path] = list(BOOT_ROOTS_EXTRA)
    if esp_override is not None:
        roots.append(esp_override)
    try:
        esp, boot = systemd_boot_roots(esp_override)
        roots.extend((esp, boot))
    except UkiError:
        pass
    return _dedupe_roots(roots)


def _confined_file(candidate: Path, roots: tuple[Path, ...], label: str) -> Path:
    if ".." in candidate.parts:
        raise UkiError(f"invalid {label} path: {candidate} contains '..'")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UkiError(f"{label} path does not exist: {candidate}") from exc
    if not resolved.is_file():
        raise UkiError(f"{label} path is not a regular file: {candidate}")
    if not any(resolved.is_relative_to(root) for root in roots):
        raise UkiError(
            f"{label} path is outside the boot filesystems: {candidate} "
            f"(resolved to {resolved})"
        )
    return resolved


def _path_candidates(path: str) -> list[Path]:
    stripped = path.strip()
    if stripped.startswith("("):
        close = stripped.find(")")
        if close != -1:
            stripped = stripped[close + 1 :]
    if not stripped.startswith("/"):
        stripped = "/" + stripped

    candidates = [Path(stripped)]
    if not stripped.startswith("/boot/"):
        candidates.append(Path("/boot") / stripped.lstrip("/"))
    return candidates


def resolve_boot_path(
    path: str,
    roots: tuple[Path, ...] | None = None,
    *,
    label: str = "boot",
) -> str:
    """Map a GRUB path to a host path.

    When ``roots`` is given the resolved file must be below one of them.
    This is used for initrds; kernels may live outside /boot and are copied and
    checksum-verified before use.
    """
    errors: list[str] = []
    for candidate in _path_candidates(path):
        if ".." in candidate.parts:
            errors.append(f"{candidate}: contains '..'")
            continue
        try:
            if roots is not None:
                return str(_confined_file(candidate, roots, label))
            resolved = candidate.resolve(strict=True)
            if resolved.is_file():
                return str(resolved)
            errors.append(f"{candidate}: not a regular file")
        except (OSError, RuntimeError) as exc:
            errors.append(f"{candidate}: {exc}")
        except UkiError as exc:
            errors.append(str(exc))

    detail = f" ({'; '.join(errors)})" if errors else ""
    raise UkiError(f"invalid {label} path {path!r}{detail}")


def kernel_release(path: str) -> str | None:
    base = os.path.basename(os.path.realpath(path))
    match = re.match(r"vmlinuz(?:-|\.)?(.+)$", base)
    return match.group(1) if match else None


def resolve_grub_boot(esp: Path | None = None) -> ResolvedBoot:
    if not GRUB_CFG.is_file():
        raise UkiError(f"missing {GRUB_CFG}")
    try:
        text = GRUB_CFG.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise UkiError(f"cannot read {GRUB_CFG}: {exc}") from exc

    lines, top = parse_grub_cfg(text)
    env = read_grubenv(GRUBENV)
    spec, source = effective_default(lines, env)
    if spec is None:
        fallback = etc_default_spec(ETC_DEFAULT_GRUB)
        if fallback is not None:
            spec = fallback
            source = f"{ETC_DEFAULT_GRUB}: GRUB_DEFAULT"
    if spec == "saved":
        spec = (env.get("saved_entry") or "").strip() or None
        source = "grubenv saved_entry"

    entry = resolve_default(spec, top, lines)
    if entry is None:
        raise UkiError("could not find a bootable default GRUB entry")

    kernel, initrds, entry_cmdline = extract_boot(entry, lines)
    if kernel is None:
        raise UkiError(f"default entry {entry.title!r} has no linux command")

    cmdline, cmdline_source = cmdline_from_root_settings("grub")
    warn_ignored_entry_cmdline(
        entry_cmdline, cmdline, f"{GRUB_CFG}: {entry.title}"
    )

    roots = initrd_roots(esp)
    kernel_path = resolve_boot_path(kernel, label="kernel")
    initrd_paths = [
        resolve_boot_path(path, roots, label="initrd") for path in initrds
    ]
    if len(initrd_paths) != 1:
        raise UkiError(
            f"default GRUB entry {entry.title!r} has {len(initrd_paths)} "
            "initrds; luksury requires a dracut single-initrd entry"
        )
    return ResolvedBoot(
        loader="GRUB",
        title=entry.title,
        entry_id=entry.entry_id,
        source=source,
        cmdline_source=cmdline_source,
        kernel=kernel_path,
        initrds=initrd_paths,
        cmdline=cmdline,
        release=kernel_release(kernel_path),
        initrd_roots=roots,
    )


# ---------------------------------------------------------------------------
# PE / section handling
# ---------------------------------------------------------------------------


@dataclass
class PESection:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int


@dataclass
class PEInfo:
    image_base: int
    section_alignment: int
    size_of_image: int
    size_of_headers: int
    checksum_offset: int
    certificate_table_offset: int
    certificate_table_size: int
    sections: list[PESection]


def parse_pe_data(data: bytes, source: str) -> PEInfo:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise UkiError(f"{source} is not a PE file")
    elf_new = int.from_bytes(data[0x3C:0x40], "little")
    if elf_new + 24 > len(data) or data[elf_new : elf_new + 4] != b"PE\0\0":
        raise UkiError(f"{source} is not a PE file")

    coff = elf_new + 4
    number_of_sections = int.from_bytes(data[coff + 2 : coff + 4], "little")
    optional_size = int.from_bytes(data[coff + 16 : coff + 18], "little")
    optional = coff + 20
    if optional + optional_size > len(data):
        raise UkiError(f"{source}: truncated PE optional header")

    magic = int.from_bytes(data[optional : optional + 2], "little")
    if magic == 0x20B:
        image_base = int.from_bytes(data[optional + 24 : optional + 32], "little")
        data_directory_offset = optional + 112
    elif magic == 0x10B:
        image_base = int.from_bytes(data[optional + 28 : optional + 32], "little")
        data_directory_offset = optional + 96
    else:
        raise UkiError(f"{source}: unsupported PE magic 0x{magic:x}")

    section_alignment = int.from_bytes(data[optional + 32 : optional + 36], "little")
    size_of_image = int.from_bytes(data[optional + 56 : optional + 60], "little")
    size_of_headers = int.from_bytes(data[optional + 60 : optional + 64], "little")
    if section_alignment == 0:
        raise UkiError(f"{source}: invalid SectionAlignment 0")

    optional_end = optional + optional_size
    checksum_offset = optional + 64
    certificate_table_offset = data_directory_offset + 4 * 8
    if checksum_offset + 4 > optional_end:
        raise UkiError(f"{source}: PE optional header is too short for CheckSum")
    if certificate_table_offset + 8 > optional_end:
        raise UkiError(
            f"{source}: PE optional header lacks a certificate table entry"
        )
    certificate_table_size = int.from_bytes(
        data[certificate_table_offset + 4 : certificate_table_offset + 8], "little"
    )

    table = optional + optional_size
    sections: list[PESection] = []
    for index in range(number_of_sections):
        offset = table + index * 40
        if offset + 40 > len(data):
            raise UkiError(f"{source}: truncated section table")
        name = data[offset : offset + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size = int.from_bytes(data[offset + 8 : offset + 12], "little")
        virtual_address = int.from_bytes(data[offset + 12 : offset + 16], "little")
        raw_size = int.from_bytes(data[offset + 16 : offset + 20], "little")
        raw_pointer = int.from_bytes(data[offset + 20 : offset + 24], "little")
        sections.append(
            PESection(name, virtual_size, virtual_address, raw_size, raw_pointer)
        )

    return PEInfo(
        image_base=image_base,
        section_alignment=section_alignment,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        checksum_offset=checksum_offset,
        certificate_table_offset=certificate_table_offset,
        certificate_table_size=certificate_table_size,
        sections=sections,
    )


def parse_pe(path: Path) -> PEInfo:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise UkiError(f"cannot read {path}: {exc}") from exc
    return parse_pe_data(data, str(path))


def pe_hash_bytes(
    data: bytes, algorithm: str = "sha256", source: str = "PE image"
) -> bytes:
    """Hash a PE image the way UEFI firmware does for PCR4.

    This is the Authenticode "PE Image Hash": the checksum and certificate
    table directory entry are treated as zero, sections are hashed in file
    order, and any trailing data before the certificate table is included.
    """
    info = parse_pe_data(data, source)
    try:
        digest = hashlib.new(algorithm)
    except ValueError as exc:
        raise UkiError(f"unsupported hash algorithm {algorithm!r}") from exc

    if info.size_of_headers > len(data):
        raise UkiError(f"{source}: SizeOfHeaders exceeds file size")
    if info.size_of_headers < info.certificate_table_offset + 8:
        raise UkiError(f"{source}: SizeOfHeaders does not cover the PE data directory")
    if info.checksum_offset > info.certificate_table_offset:
        raise UkiError(f"{source}: malformed PE optional header")

    digest.update(data[: info.checksum_offset])
    digest.update(
        data[info.checksum_offset + 4 : info.certificate_table_offset]
    )
    digest.update(
        data[info.certificate_table_offset + 8 : info.size_of_headers]
    )

    cursor = info.size_of_headers
    for section in sorted(info.sections, key=lambda item: item.raw_pointer):
        end = section.raw_pointer + section.raw_size
        if end > len(data):
            raise UkiError(f"{source}: section {section.name} extends past end of file")
        digest.update(data[section.raw_pointer:end])
        cursor += section.raw_size

    if len(data) > cursor:
        certificate_size = info.certificate_table_size
        if certificate_size > len(data) - cursor:
            raise UkiError(f"{source}: certificate table exceeds trailing data")
        digest.update(data[cursor : len(data) - certificate_size])
        if len(data) % 8:
            digest.update(b"\0" * (8 - len(data) % 8))

    return digest.digest()


def pe_image_hash(path: Path, algorithm: str = "sha256") -> bytes:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise UkiError(f"cannot read {path}: {exc}") from exc
    return pe_hash_bytes(data, algorithm, str(path))


def pe_section_image(path: Path, name: str) -> bytes | None:
    """Return a section as systemd-stub maps it into memory.

    The stub passes VirtualSize bytes to LoadImage(), using the file contents
    up to SizeOfRawData and zero-filling the remainder.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise UkiError(f"cannot read {path}: {exc}") from exc
    info = parse_pe_data(data, str(path))

    for section in info.sections:
        if section.name != name:
            continue
        size = section.virtual_size or section.raw_size
        raw_size = min(section.raw_size, size)
        end = section.raw_pointer + raw_size
        if end > len(data):
            raise UkiError(
                f"{path}: section {section.name} extends past end of file"
            )
        image = data[section.raw_pointer:end]
        if len(image) < size:
            image += b"\0" * (size - len(image))
        return image
    return None


def _version_tuple(value: str) -> tuple[int, ...] | None:
    match = re.match(r"(\d+(?:\.\d+)*)", value.strip())
    if match is None:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def stub_version(stub: Path) -> tuple[int, ...] | None:
    """Return the systemd-stub version recorded in the stub itself."""
    try:
        magic = pe_section_image(stub, ".sdmagic")
    except UkiError:
        magic = None
    if magic is not None:
        text = magic.split(b"\0", 1)[0].decode("utf-8", "replace")
        match = re.search(r"systemd-stub\s+(\d+(?:\.\d+)*)", text)
        if match is not None:
            return tuple(int(part) for part in match.group(1).split("."))

    try:
        sbat = pe_section_image(stub, ".sbat")
    except UkiError:
        sbat = None
    if sbat is None:
        return None

    distro_version: tuple[int, ...] | None = None
    generic_version: tuple[int, ...] | None = None
    for raw in sbat.split(b"\0", 1)[0].splitlines():
        fields = [field.strip() for field in raw.split(b",")]
        if len(fields) < 5:
            continue
        component = fields[0]
        version = _version_tuple(fields[4].decode("ascii", "replace"))
        if version is None:
            continue
        if component == b"systemd-stub":
            return version
        if component == b"systemd":
            generic_version = version
            continue
        if (
            component.startswith(b"systemd-stub.")
            or component.startswith(b"systemd.")
        ) and distro_version is None:
            distro_version = version
    return generic_version or distro_version


def shim_version(shim: Path) -> tuple[int, ...] | None:
    """Return the shim version from its SBAT section, if present."""
    try:
        sbat = pe_section_image(shim, ".sbat")
    except UkiError:
        return None
    if sbat is None:
        return None

    distro_version: tuple[int, ...] | None = None
    generic_version: tuple[int, ...] | None = None
    for raw in sbat.split(b"\0", 1)[0].splitlines():
        fields = [field.strip() for field in raw.split(b",")]
        if len(fields) < 5:
            continue
        component = fields[0]
        version = _version_tuple(fields[4].decode("ascii", "replace"))
        if version is None:
            continue
        if component == b"shim":
            generic_version = version
            continue
        if component.startswith(b"shim.") and distro_version is None:
            distro_version = version
    return distro_version or generic_version


def version_string(version: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in version)


def boot_chain_measures_kernel_in_pcr4(stub: Path) -> bool:
    """Return whether the embedded .linux section is measured into PCR4."""
    version = stub_version(stub)
    if version is None:
        raise UkiError(
            f"{stub}: cannot determine the systemd-stub version; "
            "use --pcr4-kernel or --pcr4-no-kernel"
        )
    return PCR4_KERNEL_STUB_MIN <= version[0] < PCR4_KERNEL_STUB_EXCLUSIVE


def extend_pcr(current: bytes, digest: bytes, algorithm: str = "sha256") -> bytes:
    try:
        size = hashlib.new(algorithm).digest_size
    except ValueError as exc:
        raise UkiError(f"unsupported hash algorithm {algorithm!r}") from exc
    if len(current) != size or len(digest) != size:
        raise UkiError(
            f"{algorithm} digest size mismatch: expected {size} bytes"
        )
    return hashlib.new(algorithm, current + digest).digest()


def os_separator_digest(algorithm: str = "sha256") -> bytes:
    """Return the digest systemd-pcrextend extends for os-separator."""
    try:
        return hashlib.new(algorithm, OS_SEPARATOR_EVENT).digest()
    except ValueError as exc:
        raise UkiError(f"unsupported hash algorithm {algorithm!r}") from exc


def os_separator_pcr(algorithm: str = "sha256") -> bytes:
    """Return the PCR value after the systemd os-separator measurement."""
    try:
        size = hashlib.new(algorithm).digest_size
    except ValueError as exc:
        raise UkiError(f"unsupported hash algorithm {algorithm!r}") from exc
    return extend_pcr(bytes(size), os_separator_digest(algorithm), algorithm)


# systemd-stub's pack_cpio() trailer.  The namesize field is the only
# uppercase hexadecimal field in the systemd literal, so keep it byte-exact.
CPIO_NEWC_TRAILER = (
    b"070701"
    + b"00000000" * 4
    + b"00000001"
    + b"00000000" * 6
    + b"0000000B"
    + b"00000000"
    + b"TRAILER!!!\0\0\0\0"
)


def cpio_newc_entry(name: str, data: bytes, mode: int, inode: int) -> bytes:
    """Serialize one file or directory entry the way systemd-stub does."""
    name_bytes = name.encode("ascii") + b"\0"
    fields = (
        inode,
        mode,
        0,  # uid
        0,  # gid
        1,  # nlink
        0,  # mtime
        len(data),
        0,  # devmajor
        0,  # devminor
        0,  # rdevmajor
        0,  # rdevminor
        len(name_bytes),
        0,  # check
    )
    header = b"070701" + b"".join(
        f"{value:08x}".encode("ascii") for value in fields
    )
    entry = header + name_bytes
    entry += b"\0" * (-len(entry) % 4)
    entry += data
    entry += b"\0" * (-len(entry) % 4)
    return entry


def cpio_newc_dir(path: str, mode: int, inode: int) -> bytes:
    return cpio_newc_entry(path, b"", mode | 0o040000, inode)


def global_credential_files(esp: Path) -> list[Path]:
    """Return the global credentials systemd-stub packs from the ESP."""
    directory = esp / "loader" / "credentials"
    try:
        entries = list(directory.iterdir())
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise UkiError(f"cannot read {directory}: {exc}") from exc

    files: list[Path] = []
    for entry in entries:
        name = entry.name
        if name.startswith(".") or not name.lower().endswith(".cred"):
            continue
        if len(name) > 255:
            continue
        try:
            name.encode("ascii")
        except UnicodeEncodeError:
            continue
        if entry.is_file():
            files.append(entry)
    files.sort(key=lambda path: path.name)
    return files


def global_credentials_cpio_digest(
    files: list[Path], algorithm: str = "sha256"
) -> bytes:
    """Hash the global credentials cpio archive systemd-stub measures."""
    if not files:
        raise UkiError("no global credentials to pack")

    buffer = bytearray()
    inode = 1
    buffer += cpio_newc_dir(".extra", 0o555, inode)
    inode += 1
    buffer += cpio_newc_dir(".extra/global_credentials", 0o500, inode)
    inode += 1
    for path in files:
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise UkiError(f"cannot read credential {path}: {exc}") from exc
        buffer += cpio_newc_entry(
            f".extra/global_credentials/{path.name}",
            data,
            0o100000 | 0o400,
            inode,
        )
        inode += 1
    buffer += CPIO_NEWC_TRAILER

    try:
        digest = hashlib.new(algorithm)
    except ValueError as exc:
        raise UkiError(f"unsupported hash algorithm {algorithm!r}") from exc
    digest.update(buffer)
    return digest.digest()



def boot_chain_pcr4_measurements(
    shim: Path,
    uki: Path,
    algorithm: str = "sha256",
    include_embedded_kernel: bool = True,
) -> tuple[bytes, ...]:
    """Return the PCR4 measurements made during a shim-chained UKI boot.

    Firmware measures the shim first, then shim measures the UKI.  Older
    systemd-stub releases also caused the embedded .linux kernel to be
    measured.  The order is shim, UKI, .linux.
    """
    measurements = [
        pe_image_hash(shim, algorithm),
        pe_image_hash(uki, algorithm),
    ]
    if include_embedded_kernel:
        kernel = pe_section_image(uki, ".linux")
        if kernel is None:
            raise UkiError(f"{uki}: UKI has no .linux section")
        measurements.append(
            pe_hash_bytes(kernel, algorithm, f"{uki}:.linux")
        )
    return tuple(measurements)


@dataclass(frozen=True)
class TcgEvent:
    pcr: int
    event_type: int
    digests: dict[str, bytes]
    event_data: bytes


@dataclass(frozen=True)
class Pcr4Prediction:
    """PCR4 values for a shim-chained UKI boot."""

    prefix: bytes
    prefix_source: str
    measurements: tuple[bytes, ...]
    predicted: bytes


def firmware_pcr4_prefix(algorithm: str = "sha256") -> bytes:
    """Return the default PCR4 prefix used when the event log is unavailable.

    The firmware normally measures the "Calling EFI Application from Boot
    Option" action and the EV_SEPARATOR before loading the boot option.  The
    event log is preferred because a machine may have additional pre-UKI
    measurements; this is only the fallback.
    """
    try:
        action = hashlib.new(algorithm, PCR4_FIRMWARE_ACTION).digest()
        separator = hashlib.new(algorithm, PCR4_FIRMWARE_SEPARATOR).digest()
        prefix = bytes(hashlib.new(algorithm).digest_size)
    except ValueError as exc:
        raise UkiError(f"unsupported hash algorithm {algorithm!r}") from exc

    prefix = extend_pcr(prefix, action, algorithm)
    return extend_pcr(prefix, separator, algorithm)


def _event_log_u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise UkiError("truncated TPM2 event log")
    return int.from_bytes(data[offset : offset + 2], "little")


def _event_log_u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise UkiError("truncated TPM2 event log")
    return int.from_bytes(data[offset : offset + 4], "little")


def parse_tcg2_event_log(data: bytes) -> list[TcgEvent]:
    """Parse a TCG2 firmware event log.

    The first record is the legacy TCG_PCR_EVENT carrying the
    ``Spec ID Event03`` header; all following records are TCG_PCR_EVENT2.
    """
    if len(data) < 36:
        raise UkiError("TPM2 event log is too short")

    event_type = _event_log_u32(data, 4)
    event_size = _event_log_u32(data, 28)
    end = 32 + event_size
    if end > len(data):
        raise UkiError("truncated TPM2 event log header")

    header = data[32:end]
    if event_type != EV_NO_ACTION or not header.startswith(b"Spec ID Event03"):
        raise UkiError(
            "unsupported TPM2 event log: missing 'Spec ID Event03' header"
        )
    if len(header) < 28:
        raise UkiError("truncated TPM2 event log specification header")

    algorithm_count = _event_log_u32(header, 24)
    offset = 28
    algorithm_sizes: dict[int, int] = {}
    for _ in range(algorithm_count):
        algorithm = _event_log_u16(header, offset)
        size = _event_log_u16(header, offset + 2)
        offset += 4
        algorithm_sizes[algorithm] = size

    # Skip vendorInfoSize/vendorInfo if present.
    if offset < len(header):
        vendor_size = header[offset]
        offset += 1 + vendor_size
        if offset > len(header):
            raise UkiError("truncated TPM2 event log vendor info")

    events: list[TcgEvent] = []
    position = end
    while position < len(data):
        if not any(data[position:]):
            break
        pcr = _event_log_u32(data, position)
        event_type = _event_log_u32(data, position + 4)
        digest_count = _event_log_u32(data, position + 8)
        position += 12

        digests: dict[str, bytes] = {}
        for _ in range(digest_count):
            algorithm = _event_log_u16(data, position)
            position += 2
            size = algorithm_sizes.get(algorithm)
            if size is None:
                raise UkiError(
                    f"TPM2 event log uses unknown hash algorithm 0x{algorithm:04x}"
                )
            if position + size > len(data):
                raise UkiError("truncated TPM2 event log digest")
            name = TCG_HASH_ALGORITHMS.get(algorithm)
            if name is not None:
                digests[name] = data[position : position + size]
            position += size

        event_data_size = _event_log_u32(data, position)
        position += 4
        if position + event_data_size > len(data):
            raise UkiError("truncated TPM2 event log event data")
        event_data = data[position : position + event_data_size]
        position += event_data_size

        events.append(
            TcgEvent(
                pcr=pcr,
                event_type=event_type,
                digests=digests,
                event_data=event_data,
            )
        )

    return events


def read_tcg2_event_log(path: Path = TPM_EVENT_LOG) -> list[TcgEvent]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise UkiError(f"cannot read TPM event log {path}: {exc}") from exc
    return parse_tcg2_event_log(data)


def _device_path_name(device_path: bytes) -> str | None:
    offset = 0
    while offset + 4 <= len(device_path):
        node_type = device_path[offset]
        node_subtype = device_path[offset + 1]
        node_length = int.from_bytes(
            device_path[offset + 2 : offset + 4], "little"
        )
        if node_length < 4 or offset + node_length > len(device_path):
            return None
        if node_type == 0x7F:
            break
        if node_type == 0x04 and node_subtype == 0x04:
            name = device_path[offset + 4 : offset + node_length].decode(
                "utf-16-le", "replace"
            )
            return name.split("\x00", 1)[0]
        offset += node_length
    return None


def device_path_file_name(event_data: bytes) -> str | None:
    """Return the file name from an EFI_IMAGE_LOAD_EVENT device path.

    Some firmware writes a ``lengthOfDevicePath`` that does not match the
    event payload.  In that case, fall back to the remaining payload, which
    is what the event log provides.
    """
    if len(event_data) < 32:
        return None

    payload = event_data[32:]
    length = int.from_bytes(event_data[24:32], "little")
    candidates: list[bytes] = []
    if 4 <= length <= len(payload):
        candidates.append(payload[:length])
    if length != len(payload):
        candidates.append(payload)

    for device_path in candidates:
        name = _device_path_name(device_path)
        if name is not None:
            return name
    return None


def is_boot_chain_file_name(name: str) -> bool:
    """Return True for a boot loader or UKI file name."""
    lowered = name.lower()
    return any(
        fnmatch.fnmatch(lowered, pattern)
        for pattern in PCR4_BOOT_CHAIN_PATTERNS
    )


def is_boot_chain_path(path: str | None) -> bool:
    """Return True for shim, GRUB, systemd-boot or a luksury UKI path."""
    if not path:
        return False
    name = path.replace("/", "\\").rsplit("\\", 1)[-1]
    return is_boot_chain_file_name(name)


def _replay_pcr4_prefix(
    records: list[TcgEvent], algorithm: str
) -> bytes:
    try:
        prefix = bytes(hashlib.new(algorithm).digest_size)
    except ValueError as exc:
        raise UkiError(f"unsupported hash algorithm {algorithm!r}") from exc

    for record in records:
        digest = record.digests.get(algorithm)
        if digest is None:
            raise UkiError(
                f"PCR4 event has no {algorithm} digest; refusing to predict "
                "PCR4"
            )
        prefix = extend_pcr(prefix, digest, algorithm)
    return prefix


def pcr4_prefix_from_records(
    records: list[TcgEvent],
    algorithm: str = "sha256",
    *,
    stop_hashes: set[bytes] | None = None,
) -> tuple[bytes | None, str]:
    """Return the PCR4 prefix before the first boot-chain application.

    Replay stops at shim, GRUB, systemd-boot or the current UKI, whichever is
    first.  Earlier firmware measurements, such as a firmware boot manager
    application, remain in the prefix.  The stop application can be
    identified by its PE digest or, when firmware wrote a broken device path,
    by its file name.
    """
    pcr4_records = [
        record
        for record in records
        if record.pcr == 4 and record.event_type != EV_NO_ACTION
    ]
    if not pcr4_records:
        return None, "default"

    if stop_hashes:
        for index, record in enumerate(pcr4_records):
            digest = record.digests.get(algorithm)
            if digest is not None and digest in stop_hashes:
                return _replay_pcr4_prefix(
                    pcr4_records[:index], algorithm
                ), "eventlog"

    for index, record in enumerate(pcr4_records):
        if record.event_type != EV_EFI_BOOT_SERVICES_APPLICATION:
            continue
        if is_boot_chain_path(device_path_file_name(record.event_data)):
            return _replay_pcr4_prefix(
                pcr4_records[:index], algorithm
            ), "eventlog"

    raise UkiError(
        "cannot identify shim, GRUB, systemd-boot or the UKI in the PCR4 "
        "event log; refusing to predict PCR4"
    )


def pcr4_prefix_from_event_log(
    event_log: Path = TPM_EVENT_LOG,
    algorithm: str = "sha256",
    *,
    stop_hashes: set[bytes] | None = None,
) -> tuple[bytes | None, str]:
    """Return the PCR4 prefix before the first boot-chain application.

    The firmware event log is replayed until shim, GRUB, systemd-boot or the
    current UKI appears.  That application and everything after it are
    excluded, because the next boot is expected to load the new shim at that
    position.  ``stop_hashes`` identifies those applications by PE digest;
    a device-path file name is used as a fallback.  If the log is missing or
    malformed, ``(None, "default")`` is returned; if it is usable but no
    boot-chain application can be found, prediction fails instead of binding
    a wrong policy.
    """
    try:
        records = read_tcg2_event_log(event_log)
    except UkiError:
        return None, "default"
    return pcr4_prefix_from_records(
        records, algorithm, stop_hashes=stop_hashes
    )


def precompute_pcr4(
    shim: Path,
    uki: Path,
    *,
    event_log: Path = TPM_EVENT_LOG,
    algorithm: str = "sha256",
    include_embedded_kernel: bool = True,
    stop_hashes: set[bytes] | None = None,
) -> Pcr4Prediction:
    """Compute the next boot's PCR4 for a shim-chained UKI boot.

    The pre-shim prefix is taken from the firmware event log when possible.
    Replay stops at shim, GRUB, systemd-boot or the current UKI, because the
    next boot is expected to load the new shim at that position.  If the log
    is unavailable or unusable, the built-in action/separator prefix is used.
    The predicted value extends the prefix with the new shim, the new UKI and,
    when applicable, the embedded kernel.
    """
    measurements = boot_chain_pcr4_measurements(
        shim, uki, algorithm, include_embedded_kernel
    )
    prefix, source = pcr4_prefix_from_event_log(
        event_log, algorithm, stop_hashes=stop_hashes
    )
    if prefix is None:
        prefix = firmware_pcr4_prefix(algorithm)
        source = "default"

    predicted = prefix
    for digest in measurements:
        predicted = extend_pcr(predicted, digest, algorithm)

    return Pcr4Prediction(
        prefix=prefix,
        prefix_source=source,
        measurements=measurements,
        predicted=predicted,
    )


def pcr4_boot_target_hashes(
    esp: Path,
    current_uki: Path | None,
    algorithm: str = "sha256",
) -> set[bytes]:
    """Return PE hashes of applications that terminate the PCR4 prefix."""
    candidates: list[Path] = []
    if current_uki is not None and current_uki.is_file():
        candidates.append(current_uki)

    try:
        for path in esp.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() != ".efi":
                continue
            if not is_boot_chain_file_name(path.name):
                continue
            candidates.append(path)
    except (OSError, RuntimeError) as exc:
        warn(f"cannot scan {esp} for boot loaders: {exc}")

    hashes: set[bytes] = set()
    seen: set[Path] = set()
    for path in candidates:
        try:
            resolved = path.resolve()
        except (OSError, RuntimeError):
            resolved = path
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            hashes.add(pe_image_hash(path, algorithm))
        except UkiError as exc:
            warn(f"cannot hash boot loader {path}: {exc}")
    return hashes


def current_uki_kernel_in_pcr4(
    uki: Path, algorithm: str = "sha256"
) -> bool | None:
    """Return whether this boot measured the UKI's .linux into PCR4.

    Returns ``None`` when the current boot's event log does not contain the
    UKI, for example when the system was booted through GRUB.  This is more
    reliable than the stub version gate, because whether firmware measures
    the kernel in shim's security-override path depends on the firmware.
    """
    kernel = pe_section_image(uki, ".linux")
    if kernel is None:
        return None
    try:
        kernel_digest = pe_hash_bytes(kernel, algorithm, f"{uki}:.linux")
        uki_digest = pe_image_hash(uki, algorithm)
        records = read_tcg2_event_log()
    except UkiError:
        return None

    saw_uki = False
    for record in records:
        if (
            record.pcr != 4
            or record.event_type != EV_EFI_BOOT_SERVICES_APPLICATION
        ):
            continue
        digest = record.digests.get(algorithm)
        if digest == uki_digest:
            saw_uki = True
            continue
        if saw_uki and digest == kernel_digest:
            return True
    return False if saw_uki else None


# ---------------------------------------------------------------------------
# PCR7 prediction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Pcr7Prediction:
    """PCR7 value for the next shim-chained boot with Secure Boot enforcing."""

    value: bytes
    source: str
    authority: str
    subject: str | None = None


@dataclass(frozen=True)
class Pcr12Prediction:
    """PCR12 value before the userspace os-separator extension."""

    value: bytes
    source: str
    credentials: tuple[Path, ...]
    cpio_digest: bytes | None


@dataclass(frozen=True)
class EfiSignatureEntry:
    signature_type: uuid.UUID
    owner: uuid.UUID
    payload: bytes
    raw: bytes


@dataclass(frozen=True)
class TrustAnchor:
    name: str
    guid: uuid.UUID
    raw: bytes
    cert_der: bytes
    subject: str | None


def _uuid_from_le(data: bytes) -> uuid.UUID:
    if len(data) != 16:
        raise UkiError("truncated EFI GUID")
    return uuid.UUID(bytes_le=data)


def parse_efi_signature_lists(data: bytes) -> list[EfiSignatureEntry]:
    """Parse EFI_SIGNATURE_LIST data into its signature entries."""
    entries: list[EfiSignatureEntry] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 28:
            raise UkiError("truncated EFI signature list")
        signature_type = _uuid_from_le(data[offset : offset + 16])
        list_size = int.from_bytes(data[offset + 16 : offset + 20], "little")
        header_size = int.from_bytes(data[offset + 20 : offset + 24], "little")
        signature_size = int.from_bytes(
            data[offset + 24 : offset + 28], "little"
        )
        if (
            list_size < 28 + header_size
            or signature_size < 16
            or offset + list_size > len(data)
        ):
            raise UkiError("malformed EFI signature list")

        entry_offset = offset + 28 + header_size
        end = offset + list_size
        while entry_offset + signature_size <= end:
            raw = data[entry_offset : entry_offset + signature_size]
            entries.append(
                EfiSignatureEntry(
                    signature_type=signature_type,
                    owner=_uuid_from_le(raw[:16]),
                    payload=raw[16:],
                    raw=raw,
                )
            )
            entry_offset += signature_size

        if not list_size:
            break
        offset += list_size
    return entries


def read_efi_signature_entries(
    name: str, guid: str
) -> list[EfiSignatureEntry]:
    data = read_efivar_bytes(name, guid)
    if not data:
        return []
    return parse_efi_signature_lists(data)


def find_signature_entry(
    entries: list[EfiSignatureEntry], cert_der: bytes
) -> EfiSignatureEntry | None:
    for entry in entries:
        if entry.payload == cert_der:
            return entry
    return None


def certificate_der_bytes(cert: Path) -> bytes:
    proc = run_capture_bytes(
        ["openssl", "x509", "-in", str(cert), "-outform", "DER"]
    )
    if not proc.stdout:
        raise UkiError(f"cannot convert certificate {cert} to DER")
    return proc.stdout


def certificate_subject(cert: Path) -> str:
    proc = run(["openssl", "x509", "-in", str(cert), "-noout", "-subject"])
    value = proc.stdout.strip()
    if value.lower().startswith("subject="):
        value = value.split("=", 1)[1].strip()
    return value or str(cert)


def certificate_is_expired(cert: Path) -> bool:
    proc = run(
        ["openssl", "x509", "-in", str(cert), "-checkend", "0", "-noout"],
        check=False,
    )
    return proc.returncode != 0


def certificate_has_module_signing_eku(cert: Path) -> bool:
    proc = run(["openssl", "x509", "-in", str(cert), "-noout", "-text"])
    return "1.3.6.1.4.1.2312.16.1.2" in proc.stdout


def key_matches_certificate(key: Path, cert: Path) -> bool:
    cert_pub = run(
        ["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"]
    ).stdout.strip()
    key_pub = run(["openssl", "pkey", "-in", str(key), "-pubout"]).stdout.strip()
    return bool(cert_pub) and cert_pub == key_pub


def validate_signing_key_pair(key: Path, cert: Path) -> None:
    if not key.is_file():
        raise UkiError(f"signing key not found: {key}")
    if not cert.is_file():
        raise UkiError(f"signing certificate not found: {cert}")
    try:
        key_head = key.read_text(encoding="ascii", errors="replace")
    except OSError as exc:
        raise UkiError(f"cannot read signing key {key}: {exc}") from exc
    if "ENCRYPTED" in key_head:
        raise UkiError(
            f"signing key {key} is encrypted; luksury requires an "
            "unencrypted key for non-interactive signing"
        )
    if certificate_is_expired(cert):
        raise UkiError(
            f"signing certificate {cert} is expired; refusing to reuse it"
        )
    if certificate_has_module_signing_eku(cert):
        raise UkiError(
            f"signing certificate {cert} carries the module-signing EKU, "
            "which shim rejects for boot images; use a code-signing key"
        )
    if not key_matches_certificate(key, cert):
        raise UkiError(f"signing key {key} does not match certificate {cert}")


@dataclass(frozen=True)
class SigningMaterial:
    key: Path
    cert: Path
    der: bytes
    cert_der: bytes
    state: str
    subject: str


def signing_state(cert_der: bytes) -> str:
    if find_signature_entry(
        read_efi_signature_entries("db", SECURE_BOOT_DB_GUID), cert_der
    ) is not None:
        return "enrolled"
    if find_signature_entry(
        read_efi_signature_entries("MokListRT", SHIM_LOCK_GUID), cert_der
    ) is not None:
        return "enrolled"
    if find_signature_entry(
        read_efi_signature_entries("MokNew", SHIM_LOCK_GUID), cert_der
    ) is not None:
        return "pending"
    return "untrusted"


def load_signing_material(args: argparse.Namespace) -> SigningMaterial:
    key = Path(getattr(args, "signing_key", None) or MOK_KEY_FILE)
    cert = Path(getattr(args, "signing_cert", None) or MOK_CERT_FILE)
    if not key.exists() and not cert.exists():
        if getattr(args, "signing_key", None) or getattr(
            args, "signing_cert", None
        ):
            raise UkiError(
                f"configured signing key {key} and certificate {cert} do "
                "not exist"
            )
        return SigningMaterial(
            key=key,
            cert=cert,
            der=b"",
            cert_der=b"",
            state="missing",
            subject="",
        )
    validate_signing_key_pair(key, cert)
    cert_der = certificate_der_bytes(cert)
    return SigningMaterial(
        key=key,
        cert=cert,
        der=cert_der,
        cert_der=cert_der,
        state=signing_state(cert_der),
        subject=certificate_subject(cert),
    )


def _write_public_file(path: Path, data: bytes, mode: int = 0o644) -> None:
    parent = path.parent
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    atomic_replace(path, mode, lambda handle: handle.write(data))


def generate_signing_material() -> SigningMaterial:
    """Generate a dedicated MOK code-signing key and certificate."""
    require_tool("openssl")
    workdir = Path(tempfile.mkdtemp(prefix="luksury-mok-"))
    key_tmp = workdir / "mok.key"
    cert_tmp = workdir / "mok.crt"
    try:
        run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-days",
                str(MOK_CERT_DAYS),
                "-keyout",
                str(key_tmp),
                "-out",
                str(cert_tmp),
                "-subj",
                MOK_SUBJECT,
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
                "-addext",
                "extendedKeyUsage=codeSigning",
            ]
        )
        validate_signing_key_pair(key_tmp, cert_tmp)
        key_data = key_tmp.read_bytes()
        cert_data = cert_tmp.read_bytes()
        cert_der = certificate_der_bytes(cert_tmp)

        parent = MOK_KEY_FILE.parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass
        write_private_file(MOK_KEY_FILE, key_data)
        _write_public_file(MOK_CERT_FILE, cert_data)
        _write_public_file(MOK_DER_FILE, cert_der)
        log(f"generated MOK signing key {MOK_KEY_FILE}")
        log(f"generated MOK signing certificate {MOK_CERT_FILE}")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    args = argparse.Namespace(
        signing_key=str(MOK_KEY_FILE), signing_cert=str(MOK_CERT_FILE)
    )
    return load_signing_material(args)


def _pending_mok_contains(cert_der: bytes) -> bool:
    return find_signature_entry(
        read_efi_signature_entries("MokNew", SHIM_LOCK_GUID), cert_der
    ) is not None


def import_mok_certificate(
    cert_der: bytes, *, dry_run: bool = False
) -> None:
    """Queue a certificate for enrollment in MokManager at the next boot.

    MokManager requires a password for the request; luksury uses a fixed one
    so no secret is generated or stored.
    """
    if _pending_mok_contains(cert_der):
        return

    pending = read_efi_signature_entries("MokNew", SHIM_LOCK_GUID)
    if pending:
        raise UkiError(
            "a different MOK enrollment is already pending; complete it or "
            "run 'mokutil --revoke-import' before installing luksury"
        )
    if dry_run:
        log("would queue the MOK signing certificate for enrollment")
        return

    mokutil = require_tool("mokutil", "/usr/bin/mokutil")
    _write_public_file(MOK_DER_FILE, cert_der)
    password_hash = run(
        [mokutil, f"--generate-hash={MOK_PASSWORD}"]
    ).stdout.strip()
    if not password_hash:
        raise UkiError("mokutil did not return a password hash")
    write_private_file(
        MOK_PASSWORD_HASH_FILE, password_hash.encode("ascii")
    )
    try:
        run(
            [
                mokutil,
                "--hash-file",
                str(MOK_PASSWORD_HASH_FILE),
                "--import",
                str(MOK_DER_FILE),
            ]
        )
    finally:
        try:
            MOK_PASSWORD_HASH_FILE.unlink()
        except OSError:
            pass

    fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
    if not _pending_mok_contains(cert_der):
        raise UkiError(
            "mokutil reported success but the certificate is not present in "
            "MokNew; refusing to continue"
        )
    log("queued the luksury MOK certificate for enrollment")
    log(f"MOK certificate SHA-256: {fingerprint}")
    log(f"MOK enrollment password: {MOK_PASSWORD}")


def _cleanup_mok_password() -> None:
    for path in (LEGACY_MOK_PASSWORD_FILE, MOK_PASSWORD_HASH_FILE):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            warn(f"cannot remove {path}: {exc}")


def revoke_pending_mok_request(*, dry_run: bool = False) -> None:
    """Cancel a pending luksury MOK request when it is the only one."""
    if not MOK_CERT_FILE.is_file():
        return
    try:
        cert_der = certificate_der_bytes(MOK_CERT_FILE)
    except UkiError:
        return
    try:
        pending = read_efi_signature_entries("MokNew", SHIM_LOCK_GUID)
    except UkiError:
        return
    ours = [entry for entry in pending if entry.payload == cert_der]
    if not ours:
        return
    if len(pending) != len(ours):
        warn(
            "other MOK enrollments are pending; leaving the luksury MOK "
            "request in place"
        )
        return
    if shutil.which("mokutil") is None:
        if not dry_run:
            warn(
                "mokutil is not installed; the pending luksury MOK "
                "enrollment request remains queued"
            )
        return
    if dry_run:
        log("would revoke the pending luksury MOK enrollment request")
        return
    result = run(["mokutil", "--revoke-import"], check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        warn(
            "cannot revoke the pending luksury MOK enrollment request"
            + (f": {detail}" if detail else "")
        )
        return
    log("revoked the pending luksury MOK enrollment request")
    _cleanup_mok_password()


def mok_pending_instructions(
    material: SigningMaterial, *, secure_boot: bool = True
) -> None:
    if material.state != "pending":
        return
    log(f"MOK enrollment password: {MOK_PASSWORD}")
    if secure_boot:
        log(
            "reboot to enroll the luksury signing certificate in MokManager; "
            "the TPM token is bound to the post-enrollment PCR7 value"
        )
    else:
        log(
            "reboot to enroll the luksury signing certificate in MokManager; "
            "Secure Boot is disabled, so the TPM token does not bind PCR7"
        )


def ensure_signing_material(
    args: argparse.Namespace,
    *,
    dry_run: bool = False,
    enroll_mok: bool = True,
) -> SigningMaterial:
    """Create and validate the UKI signing key, queuing MOK when needed."""
    material = load_signing_material(args)
    if material.state == "missing":
        if getattr(args, "signing_key", None) or getattr(
            args, "signing_cert", None
        ):
            raise UkiError(
                "the configured signing key or certificate does not exist"
            )
        if dry_run:
            if enroll_mok:
                log(
                    f"would generate a MOK signing key at {MOK_KEY_FILE} and "
                    "queue its certificate for enrollment"
                )
            else:
                log(
                    f"would generate a UKI signing key at {MOK_KEY_FILE}; "
                    "Secure Boot is disabled, so it would not be queued for "
                    "MOK enrollment"
                )
            return material
        if enroll_mok and read_efi_signature_entries(
            "MokNew", SHIM_LOCK_GUID
        ):
            raise UkiError(
                "a MOK enrollment is already pending but the luksury "
                "signing key/certificate is missing; restore them or run "
                "'mokutil --revoke-import' before generating a new key"
            )
        if enroll_mok:
            require_tool("mokutil", "/usr/bin/mokutil")
        material = generate_signing_material()

    if material.state == "untrusted":
        if not enroll_mok:
            log(
                "Secure Boot is disabled; signing with the untrusted "
                f"certificate {material.cert} without MOK enrollment"
            )
        elif dry_run:
            log("would queue the MOK signing certificate for enrollment")
        else:
            import_mok_certificate(material.cert_der, dry_run=False)
            material = replace(
                material,
                state="pending",
            )

    if material.state == "enrolled":
        _cleanup_mok_password()
        log(f"using signing certificate {material.cert}")

    args.signing_key = str(material.key.resolve())
    args.signing_cert = str(material.cert.resolve())
    return material


def efi_variable_event_data(
    name: str, guid: uuid.UUID, data: bytes
) -> bytes:
    name_bytes = name.encode("utf-16-le")
    return (
        guid.bytes_le
        + (len(name_bytes) // 2).to_bytes(8, "little")
        + len(data).to_bytes(8, "little")
        + name_bytes
        + data
    )


def parse_efi_variable_event(
    data: bytes,
) -> tuple[uuid.UUID, str, bytes] | None:
    if len(data) < 32:
        return None
    guid = _uuid_from_le(data[:16])
    name_length = int.from_bytes(data[16:24], "little")
    data_length = int.from_bytes(data[24:32], "little")
    if 32 + name_length * 2 + data_length > len(data):
        return None
    name_end = 32 + name_length * 2
    try:
        name = data[32:name_end].decode("utf-16-le", "replace")
    except UnicodeDecodeError:
        return None
    return guid, name.split("\0", 1)[0], data[name_end : name_end + data_length]


def _replay_pcr_records(
    records: list[TcgEvent], pcr: int, algorithm: str
) -> bytes:
    try:
        value = bytes(hashlib.new(algorithm).digest_size)
    except ValueError as exc:
        raise UkiError(f"unsupported hash algorithm {algorithm!r}") from exc
    for record in records:
        if record.pcr != pcr or record.event_type == EV_NO_ACTION:
            continue
        digest = record.digests.get(algorithm)
        if digest is None:
            raise UkiError(
                f"PCR{pcr} event has no {algorithm} digest; refusing to "
                f"predict PCR{pcr}"
            )
        value = extend_pcr(value, digest, algorithm)
    return value


def _record_file_name(record: TcgEvent) -> str | None:
    if record.event_type != EV_EFI_BOOT_SERVICES_APPLICATION:
        return None
    return device_path_file_name(record.event_data)


def boot_used_luksury_uki(
    records: list[TcgEvent] | None = None,
    *,
    uki: Path | None = None,
    algorithm: str = "sha256",
    expected_path: str | None = None,
) -> bool:
    """Return True when the current boot loaded a luksury UKI.

    When ``uki`` is supplied, identify it by its PE digest (or, without an
    event log, by its full ``StubImageIdentifier`` path).  The fallback by
    file name is only for installations from before the private shim copy:
    the current UKI is now named ``grubx64.efi``, and accepting that name
    alone would mistake a GRUB boot for a UKI boot.
    """
    if uki is not None:
        if not uki.is_file():
            return False
        try:
            digest = pe_image_hash(uki, algorithm)
        except UkiError:
            digest = None
        if digest is not None:
            if records is not None:
                for record in records:
                    if (
                        record.event_type
                        != EV_EFI_BOOT_SERVICES_APPLICATION
                    ):
                        continue
                    if record.digests.get(algorithm) == digest:
                        return True
            identifier = read_efivar("StubImageIdentifier")
            if identifier and expected_path is not None:
                return (
                    _normalize_efi_path(identifier).lstrip("\\")
                    == _normalize_efi_path(expected_path).lstrip("\\")
                )
        return False

    if records is not None:
        for record in reversed(records):
            name = _record_file_name(record)
            if name is not None:
                return name.lower() == EFI_NAME.lower()
    identifier = read_efivar("StubImageIdentifier")
    if not identifier:
        return False
    normalized = identifier.replace("/", "\\").lower()
    return normalized.rsplit("\\", 1)[-1] == EFI_NAME.lower()


def find_shim_application(
    records: list[TcgEvent], shim: Path, algorithm: str
) -> int:
    """Return the event-log index of the shim application measurement."""
    shim_hash = pe_image_hash(shim, algorithm)
    applications: list[tuple[int, TcgEvent]] = [
        (index, record)
        for index, record in enumerate(records)
        if record.pcr == 4
        and record.event_type == EV_EFI_BOOT_SERVICES_APPLICATION
    ]

    if not applications:
        raise UkiError(
            "cannot identify the boot chain in the PCR4 event log; refusing "
            "to predict PCR7"
        )

    shim_index: int | None = None
    for index, record in applications:
        if record.digests.get(algorithm) == shim_hash:
            shim_index = index
            break
    if shim_index is None:
        for index, record in applications:
            name = _record_file_name(record) or ""
            if fnmatch.fnmatch(name.lower(), "shim*.efi"):
                digest = record.digests.get(algorithm)
                if digest is not None and digest != shim_hash:
                    raise UkiError(
                        "the current boot used a different shim than the one "
                        "installed by shim-signed; reboot before enrolling "
                        "PCR7"
                    )
                shim_index = index
                break
    if shim_index is None:
        raise UkiError(
            "the current boot was not through a shim; boot the shim entry "
            "once before enrolling PCR7"
        )
    for index, record in applications:
        if index >= shim_index:
            break
        name = _record_file_name(record)
        if name is not None and is_boot_chain_file_name(name):
            raise UkiError(
                "the current boot chain has a loader measurement before "
                "shim; boot the shim entry directly before enrolling "
                "PCR7"
            )
    return shim_index


def validate_pcr7_secure_boot_variables(records: list[TcgEvent]) -> None:
    expected = {
        "SecureBoot": EFI_GLOBAL_VARIABLE_GUID,
        "PK": EFI_GLOBAL_VARIABLE_GUID,
        "KEK": EFI_GLOBAL_VARIABLE_GUID,
        "db": SECURE_BOOT_DB_GUID,
        "dbx": SECURE_BOOT_DB_GUID,
    }
    for record in records:
        if record.pcr != 7 or record.event_type == EV_NO_ACTION:
            continue
        parsed = parse_efi_variable_event(record.event_data)
        if parsed is None:
            continue
        _guid, name, data = parsed
        if record.event_type == EV_EFI_VARIABLE_DRIVER_CONFIG:
            variable_guid = expected.get(name)
            if variable_guid is not None:
                current = read_efivar_bytes(name, variable_guid)
                if current is None or current != data:
                    raise UkiError(
                        f"Secure Boot variable {name} changed since boot; "
                        "reboot before enrolling PCR7"
                    )
        elif record.event_type == EV_EFI_VARIABLE_AUTHORITY and name == "SbatLevel":
            current = read_efivar_bytes("SbatLevelRT", SHIM_LOCK_GUID)
            if current is not None and current != data:
                raise UkiError(
                    "the SBAT policy changed since boot; reboot before "
                    "enrolling PCR7"
                )


def _entry_pem(entry: EfiSignatureEntry, workdir: Path, index: int) -> Path:
    der = workdir / f"anchor-{index}.der"
    pem = workdir / f"anchor-{index}.pem"
    der.write_bytes(entry.payload)
    run(
        [
            "openssl",
            "x509",
            "-inform",
            "DER",
            "-in",
            str(der),
            "-out",
            str(pem),
        ]
    )
    return pem


def find_trust_anchor(
    uki: Path,
    material: SigningMaterial,
    workdir: Path,
) -> TrustAnchor:
    """Find the db/MOK entry shim will use to verify the signed UKI."""
    sbverify = require_tool("sbverify")
    verify = run(
        [sbverify, "--cert", str(material.cert), str(uki)],
        check=False,
    )
    if verify.returncode != 0:
        raise UkiError(
            f"the built UKI is not verifiable with {material.cert}; "
            "refusing to predict PCR7"
        )

    candidates: list[tuple[str, uuid.UUID, EfiSignatureEntry]] = []
    for name, guid, entry in (
        (
            "db",
            uuid.UUID(SECURE_BOOT_DB_GUID),
            read_efi_signature_entries("db", SECURE_BOOT_DB_GUID),
        ),
        (
            "MokListRT",
            uuid.UUID(SHIM_LOCK_GUID),
            read_efi_signature_entries("MokListRT", SHIM_LOCK_GUID),
        ),
        (
            "MokListRT",
            uuid.UUID(SHIM_LOCK_GUID),
            read_efi_signature_entries("MokNew", SHIM_LOCK_GUID),
        ),
    ):
        for item in entry:
            candidates.append((name, guid, item))

    exact = [
        (name, guid, item)
        for name, guid, item in candidates
        if item.payload == material.cert_der
    ]
    if exact:
        name, guid, item = exact[0]
        return TrustAnchor(
            name,
            guid,
            bytes(item.raw),
            material.cert_der,
            material.subject,
        )

    for index, (name, guid, item) in enumerate(candidates):
        if item.signature_type != uuid.UUID(
            "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
        ):
            continue
        pem = _entry_pem(item, workdir, index)
        check = run(
            [sbverify, "--cert", str(pem), str(uki)],
            check=False,
        )
        if check.returncode == 0:
            return TrustAnchor(
                name, guid, bytes(item.raw), item.payload, material.subject
            )

    raise UkiError(
        "the signing certificate is not enrolled in db, MokListRT or MokNew; "
        "reboot and complete MOK enrollment before enrolling PCR7"
    )


def check_pcr7_sidecars_supported(esp: Path, efi_dir: Path) -> None:
    """Refuse PCR prediction when sidecars add extra measurements."""
    extra_dirs = [
        esp / efi_dir / f"{EFI_NAME}.extra.d",
        install_destination(esp, efi_dir).with_name(
            f"{SECOND_STAGE_NAME}.extra.d"
        ),
    ]
    for directory in (esp / "loader" / "extensions", *extra_dirs):
        if not directory.is_dir():
            continue
        try:
            entries = list(directory.iterdir())
        except OSError as exc:
            raise UkiError(f"cannot read {directory}: {exc}") from exc
        for entry in entries:
            if entry.is_file() and entry.name.lower().endswith(".raw"):
                raise UkiError(
                    f"{entry}: systemd-stub sysext/confext images are not "
                    "supported when predicting PCR12/PCR13"
                )

    for directory in (esp / "loader" / "addons", *extra_dirs):
        if not directory.is_dir():
            continue
        try:
            entries = list(directory.iterdir())
        except OSError as exc:
            raise UkiError(f"cannot read {directory}: {exc}") from exc
        for entry in entries:
            if entry.is_file() and entry.name.lower().endswith(".addon.efi"):
                raise UkiError(
                    f"{entry}: systemd-stub addons are not supported when "
                    "predicting PCR7/PCR12"
                )


# ---------------------------------------------------------------------------
# PCR12 prediction
# ---------------------------------------------------------------------------


def check_pcr12_sidecars_supported(esp: Path, efi_dir: Path) -> None:
    """Refuse PCR12 prediction when credentials add extra measurements."""
    check_pcr7_sidecars_supported(esp, efi_dir)
    extra_dirs = [
        esp / efi_dir / f"{EFI_NAME}.extra.d",
        install_destination(esp, efi_dir).with_name(
            f"{SECOND_STAGE_NAME}.extra.d"
        ),
    ]
    for directory in extra_dirs:
        if not directory.is_dir():
            continue
        try:
            entries = list(directory.iterdir())
        except OSError as exc:
            raise UkiError(f"cannot read {directory}: {exc}") from exc
        for entry in entries:
            if entry.is_file() and entry.name.lower().endswith(".cred"):
                raise UkiError(
                    f"{entry}: per-UKI systemd credentials are not supported "
                    "when predicting PCR12"
                )


def precompute_pcr12(
    esp: Path,
    efi_dir: Path,
    *,
    stub: Path,
    algorithm: str = "sha256",
) -> Pcr12Prediction:
    """Predict the next boot's PCR12 for a shim-chained UKI boot.

    PCR12 starts at zero and systemd-stub extends it with the cpio archive of
    the global credentials in ESP/loader/credentials.  On systemd 259 and
    later that archive contains the NvPCR anchor credential that
    systemd-tpm2-setup writes there.  The userspace os-separator extension is
    applied by the caller.
    """
    check_pcr12_sidecars_supported(esp, efi_dir)
    files = global_credential_files(esp)
    has_anchor = any(
        path.name.lower().startswith(PCR12_ESP_ANCHOR_PREFIX)
        for path in files
    )

    version = stub_version(stub)
    if (
        version is not None
        and version[0] >= PCR12_ESP_ANCHOR_STUB_MIN
        and not has_anchor
    ):
        warn(
            "the systemd NvPCR anchor credential is missing from "
            f"{esp / 'loader' / 'credentials'}; PCR12 will change when the "
            "next boot creates it. The TPM token will then stop unlocking "
            "and the LUKS passphrase will be requested. Rerun luksury after "
            "the reboot to re-enroll PCR12"
        )

    try:
        size = hashlib.new(algorithm).digest_size
    except ValueError as exc:
        raise UkiError(f"unsupported hash algorithm {algorithm!r}") from exc

    value = bytes(size)
    cpio_digest: bytes | None = None
    if files:
        cpio_digest = global_credentials_cpio_digest(files, algorithm)
        value = extend_pcr(value, cpio_digest, algorithm)

    return Pcr12Prediction(
        value=value,
        source="esp credentials" if files else "zero",
        credentials=tuple(files),
        cpio_digest=cpio_digest,
    )


def precompute_pcr7(
    uki: Path,
    shim: Path,
    material: SigningMaterial,
    *,
    workdir: Path,
    esp: Path,
    efi_dir: Path,
    current_uki: Path | None = None,
    event_log: Path = TPM_EVENT_LOG,
    algorithm: str = "sha256",
) -> Pcr7Prediction:
    """Predict the next boot's PCR7 for shim -> signed UKI."""
    current = read_tpm_pcr(7, algorithm)
    expected_path: str | None = None
    if current_uki is not None:
        try:
            expected_path = "\\" + str(
                current_uki.relative_to(esp)
            ).replace("/", "\\")
        except ValueError:
            expected_path = None
    try:
        records = read_tcg2_event_log(event_log)
    except UkiError:
        same_signer = False
        if current_uki is not None and current_uki.is_file():
            sbverify = require_tool("sbverify")
            check = run(
                [sbverify, "--cert", str(material.cert), str(current_uki)],
                check=False,
            )
            same_signer = check.returncode == 0
        if (
            boot_used_luksury_uki(
                uki=current_uki,
                algorithm=algorithm,
                expected_path=expected_path,
            )
            and same_signer
        ):
            warn(
                "cannot read the firmware event log; using the current PCR7 "
                "because this boot already used a luksury UKI signed by the "
                "same certificate"
            )
            return Pcr7Prediction(
                current, "tpm", "current", material.subject
            )
        raise UkiError(
            "cannot read the firmware event log and the current boot did "
            "not use a luksury UKI signed by this certificate; refusing to "
            "predict PCR7"
        ) from None

    replayed = _replay_pcr_records(records, 7, algorithm)
    validate_pcr7_secure_boot_variables(records)
    if replayed != current:
        same_signer = False
        if current_uki is not None and current_uki.is_file():
            sbverify = require_tool("sbverify")
            check = run(
                [sbverify, "--cert", str(material.cert), str(current_uki)],
                check=False,
            )
            same_signer = check.returncode == 0
        if (
            boot_used_luksury_uki(
                records,
                uki=current_uki,
                algorithm=algorithm,
                expected_path=expected_path,
            )
            and same_signer
        ):
            warn(
                "PCR7 event-log replay does not match the current value; "
                "using the current PCR7 because this boot used a luksury UKI "
                "signed by the same certificate"
            )
            return Pcr7Prediction(
                current, "tpm", "current", material.subject
            )
        raise UkiError(
            "PCR7 event-log replay does not match the current PCR7 value; "
            "refusing to predict PCR7"
        )

    check_pcr7_sidecars_supported(esp, efi_dir)
    shim_index = find_shim_application(records, shim, algorithm)
    anchor = find_trust_anchor(uki, material, workdir)

    value = bytes(hashlib.new(algorithm).digest_size)
    for index, record in enumerate(records):
        if record.pcr != 7 or record.event_type == EV_NO_ACTION:
            continue
        digest = record.digests.get(algorithm)
        if digest is None:
            raise UkiError(
                f"PCR7 event has no {algorithm} digest; refusing to "
                "predict PCR7"
            )
        if index <= shim_index:
            value = extend_pcr(value, digest, algorithm)
            continue

        parsed = parse_efi_variable_event(record.event_data)
        name = parsed[1] if parsed is not None else None
        if record.event_type == EV_EFI_VARIABLE_AUTHORITY:
            if name in ("Shim", "db", "MokListRT"):
                continue
            if name is None:
                raise UkiError(
                    "cannot classify a PCR7 authority event; refusing to "
                    "predict PCR7"
                )
        value = extend_pcr(value, digest, algorithm)

    anchor_data = efi_variable_event_data(anchor.name, anchor.guid, anchor.raw)
    value = extend_pcr(
        value,
        hashlib.new(algorithm, anchor_data).digest(),
        algorithm,
    )
    return Pcr7Prediction(
        value=value,
        source="eventlog",
        authority=anchor.name,
        subject=material.subject,
    )


def next_boot_tpm2_pcrs(
    algorithm: str,
    pcr4_preboot: bytes,
    pcr7: Pcr7Prediction | None,
    *,
    pcr12_preboot: bytes,
    current_separator: bool,
    target_separator: bool,
) -> dict[int, bytes]:
    """Return the PCR values expected when the next UKI boots.

    ``pcr4_preboot`` is the event-log based PCR4 before systemd's userspace
    separator.  ``pcr12_preboot`` is zero or the global credentials cpio
    measurement before that separator.  ``pcr7`` carries either a pre-boot
    event-log value or the current PCR7 value; the latter already includes
    this boot's separator.  It is ``None`` when Secure Boot is disabled, in
    which case PCR7 is omitted from the binding; PCR4 still measures the shim
    and the complete UKI, including the kernel and initrd.  PCR0 and PCR2 are
    stable firmware values and only need the separator difference between the
    current and the next boot applied.  PCR13 is zero unless the separator
    runs, and PCR15 is zero until the token is unsealed.
    """
    try:
        size = hashlib.new(algorithm).digest_size
    except ValueError as exc:
        raise UkiError(f"unsupported hash algorithm {algorithm!r}") from exc
    zero = bytes(size)
    separator = os_separator_digest(algorithm)

    pcr0 = read_tpm_pcr(0, algorithm)
    pcr2 = read_tpm_pcr(2, algorithm)
    if current_separator == target_separator:
        # The running boot already has the same number of separator
        # extensions as the next boot will have.
        pass
    elif target_separator:
        pcr0 = extend_pcr(pcr0, separator, algorithm)
        pcr2 = extend_pcr(pcr2, separator, algorithm)
    else:
        raise UkiError(
            "the current boot applied the systemd os-separator measurement "
            "but the next boot will not; refusing to predict PCR0/PCR2"
        )

    pcr4 = pcr4_preboot
    if target_separator:
        pcr4 = extend_pcr(pcr4, separator, algorithm)

    pcr12 = pcr12_preboot
    if target_separator:
        pcr12 = extend_pcr(pcr12, separator, algorithm)

    pcr13 = os_separator_pcr(algorithm) if target_separator else zero
    values = {
        0: pcr0,
        2: pcr2,
        4: pcr4,
        12: pcr12,
        13: pcr13,
        15: zero,
    }

    if pcr7 is not None:
        pcr7_value = pcr7.value
        if pcr7.source == "eventlog":
            if current_separator:
                raise UkiError(
                    "internal error: event-log PCR7 prediction while the "
                    "current boot applied the os-separator measurement"
                )
            if target_separator:
                pcr7_value = extend_pcr(pcr7_value, separator, algorithm)
        else:
            # precompute_pcr7 only returns the current value when this boot
            # used a luksury UKI, so it already includes this boot's
            # separator.
            if current_separator != target_separator:
                raise UkiError(
                    "cannot reuse the current PCR7 value because the next "
                    "boot changes the systemd os-separator measurement; boot "
                    "the luksury UKI before enrolling"
                )
        values[7] = pcr7_value

    return values


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def sign_uki(
    unsigned: Path,
    material: SigningMaterial,
    workdir: Path,
) -> Path:
    sbsign = require_tool("sbsign")
    sbverify = require_tool("sbverify")
    if parse_pe(unsigned).certificate_table_size:
        raise UkiError(
            f"{unsigned} already has a certificate table; refusing to add a "
            "second signature"
        )
    signed = workdir / "luksury-signed.efi"
    run(
        [
            sbsign,
            "--key",
            str(material.key),
            "--cert",
            str(material.cert),
            "--output",
            str(signed),
            str(unsigned),
        ]
    )
    verify = run(
        [sbverify, "--cert", str(material.cert), str(signed)],
        check=False,
    )
    if verify.returncode != 0:
        raise UkiError(
            f"sbsign produced {signed}, but sbverify rejected it with "
            f"{material.cert}"
        )
    info = parse_pe(signed)
    if info.certificate_table_size == 0:
        raise UkiError(f"signed UKI {signed} has no certificate table")
    log(f"signed UKI with {material.cert}")
    return signed


# ---------------------------------------------------------------------------
# TPM2 enrollment / crypttab
# ---------------------------------------------------------------------------


@dataclass
class CrypttabEntry:
    name: str
    source: str
    keyfile: str | None
    options: list[str]


def run_interactive(cmd: list[str]) -> None:
    log(shlex.join([str(part) for part in cmd]))
    try:
        proc = subprocess.run(
            [str(part) for part in cmd],
            stdin=subprocess.DEVNULL if NON_INTERACTIVE else None,
        )
    except FileNotFoundError as exc:
        raise UkiError(f"required command not found: {cmd[0]}") from exc
    if proc.returncode != 0:
        raise UkiError(f"command failed: {shlex.join(cmd)}")


def run_capture_stdout(cmd: list[str]) -> str:
    """Run a command and capture its stdout.

    stderr is captured too, so a generated secret is never echoed through
    diagnostics or QR codes.  Interactive passphrase/PIN prompts are written
    to /dev/tty by systemd and remain usable.
    """
    log(shlex.join([str(part) for part in cmd]))
    try:
        proc = subprocess.run(
            [str(part) for part in cmd],
            stdin=subprocess.DEVNULL if NON_INTERACTIVE else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise UkiError(f"required command not found: {cmd[0]}") from exc
    if proc.returncode != 0:
        # Do not include stderr here: systemd-cryptenroll may render a
        # freshly generated recovery key as a QR code on that stream.
        raise UkiError(f"command failed: {shlex.join(cmd)}")
    return proc.stdout


def require_tool(name: str, *fallbacks: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    for candidate in fallbacks:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise UkiError(f"required command not found: {name}")


def require_dracut(update_initramfs: str | None = None) -> str:
    """Require a dracut-based initramfs generator and return update-initramfs."""
    if shutil.which("dracut") is None and not os.path.isfile("/usr/bin/dracut"):
        raise UkiError(
            "dracut is required; luksury only supports dracut-based initrds"
        )

    update = update_initramfs or require_tool(
        "update-initramfs",
        "/usr/sbin/update-initramfs",
        "/sbin/update-initramfs",
        "/usr/bin/update-initramfs",
    )
    proc = run([update, "--version"], check=False)
    version = ((proc.stdout or "") + "\n" + (proc.stderr or "")).lower()
    if "dracut" not in version:
        raise UkiError(
            "update-initramfs is not the dracut wrapper; luksury requires a "
            "dracut-based system"
        )
    return update


def tpm2_package_problems() -> list[str]:
    """Return missing host packages needed for TPM2 unlock from the initrd.

    dracut's systemd-cryptsetup module only adds its tpm2-tss module when the
    tpm2 command from tpm2-tools is installed.  Without that module the
    initrd has no libtss2, so systemd-cryptsetup cannot use an existing
    systemd-tpm2 token and silently falls back to a passphrase.
    """
    problems: list[str] = []
    if shutil.which("tpm2") is None and not (
        os.path.isfile("/usr/bin/tpm2")
        and os.access("/usr/bin/tpm2", os.X_OK)
    ):
        problems.append("tpm2-tools (the tpm2 command)")

    if not any(
        directory.is_dir()
        and any(directory.glob("*tpm2-tss/module-setup.sh"))
        for directory in DRACUT_MODULE_DIRS
    ):
        problems.append("the dracut tpm2-tss module (dracut-core)")

    for library, soname in TPM2_REQUIRED_LIBRARIES:
        if ctypes.util.find_library(library) is None:
            problems.append(soname)

    return problems


def require_tpm2_packages() -> None:
    """Refuse TPM2 enrollment when the initrd cannot unlock the volume."""
    problems = tpm2_package_problems()
    if not problems:
        return
    raise UkiError(
        "TPM2 unlock requires the TPM2 userspace stack in the initrd; "
        f"missing: {', '.join(problems)}. Install tpm2-tools and dracut's "
        "tpm2-tss module (dracut-core on Debian/Ubuntu) and rerun; otherwise "
        "the initrd will fall back to a passphrase"
    )


def read_tpm_pcr(index: int, algorithm: str = "sha256") -> bytes:
    try:
        size = hashlib.new(algorithm).digest_size
    except ValueError as exc:
        raise UkiError(f"unsupported hash algorithm {algorithm!r}") from exc

    path = TPM_PCRS_DIR / f"pcr-{algorithm}" / str(index)
    try:
        value = bytes.fromhex(path.read_text().strip())
    except (OSError, ValueError) as exc:
        raise UkiError(
            f"cannot read PCR {index} ({algorithm}) from {path}: {exc}"
        ) from exc
    if len(value) != size:
        raise UkiError(
            f"PCR {index} ({algorithm}) has {len(value)} bytes, expected {size}"
        )
    return value


def systemd_has_os_separator() -> bool:
    """Return whether this systemd provides the 261+ os-separator unit."""
    for directory in SYSTEMD_PCROSSEPARATOR_DIRS:
        path = directory / SYSTEMD_PCROSSEPARATOR_UNIT
        if path.is_symlink():
            try:
                if os.readlink(path) == "/dev/null":
                    return False
            except OSError:
                continue
        if path.is_file():
            return True
    return False


def cmdline_disables_measured_os(cmdline: list[str]) -> bool:
    """Return True when the target command line disables TPM measurements."""
    for arg in cmdline:
        key, separator, value = arg.partition("=")
        if key != "systemd.tpm2_measured_os" or not separator:
            continue
        if value.strip().lower() in ("0", "no", "false", "off"):
            return True
    return False


def target_uses_os_separator(cmdline: list[str]) -> bool:
    """Return whether the next measured UKI boot will extend the os-separator.

    The unit only runs from the initrd with
    ConditionSecurity=measured-os, so a luksury UKI boot gets the measurement
    unless the command line explicitly disables it.
    """
    if not systemd_has_os_separator():
        return False
    return not cmdline_disables_measured_os(cmdline)


def current_boot_os_separator(algorithm: str = "sha256") -> bool:
    """Return whether this boot already applied the os-separator measurement.

    PCR13 is zero when neither a sysext nor the separator was measured, and
    equals the separator digest after systemd-pcrosseparator ran.  Any other
    value means a sysext or confext was measured in, which this script does
    not support.
    """
    try:
        size = hashlib.new(algorithm).digest_size
    except ValueError as exc:
        raise UkiError(f"unsupported hash algorithm {algorithm!r}") from exc
    value = read_tpm_pcr(13, algorithm)
    if value == bytes(size):
        return False
    if value == os_separator_pcr(algorithm):
        return True
    raise UkiError(
        "PCR13 is neither zero nor the systemd os-separator value; a sysext "
        "or confext appears to be active, so the next boot's PCR13 cannot be "
        "predicted. Boot the luksury UKI without extensions before enrolling"
    )


def tpm2_pcr_spec(algorithm: str, values: dict[int, bytes]) -> str:
    """Build a systemd-cryptenroll --tpm2-pcrs specification.

    ``values`` contains the expected values for every bound PCR at unlock
    time.  With Secure Boot enforcing the set includes PCR7; without it PCR7
    is omitted and PCR4 covers the shim and the complete UKI (kernel and
    initrd).  On systemd 261+ measured UKI boots the set includes the
    userspace os-separator extension for PCR 0-7, 12 and 13; PCR15 is still
    zero because systemd-cryptsetup measures the volume key into it only
    after the token has been unsealed.
    """
    try:
        size = hashlib.new(algorithm).digest_size
    except ValueError as exc:
        raise UkiError(f"unsupported hash algorithm {algorithm!r}") from exc

    pcrs = tuple(sorted(values))
    if pcrs not in (
        CRYPTENROLL_PCRS_WITH_PCR7,
        CRYPTENROLL_PCRS_WITHOUT_PCR7,
    ):
        raise UkiError(
            "TPM2 PCR binding must contain exactly "
            f"{list(CRYPTENROLL_PCRS_WITH_PCR7)} or "
            f"{list(CRYPTENROLL_PCRS_WITHOUT_PCR7)}; got {list(pcrs)}"
        )
    for index in pcrs:
        if len(values[index]) != size:
            raise UkiError(
                f"{algorithm} PCR{index} digest size mismatch: "
                f"expected {size} bytes"
            )

    return "+".join(
        f"{index}:{algorithm}={values[index].hex()}"
        for index in pcrs
    )


def split_crypttab_options(value: str) -> list[str]:
    if not value:
        return []
    options: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ",":
            options.append("".join(current))
            current = []
        else:
            current.append(char)
    options.append("".join(current))
    return [option for option in options if option]


def parse_crypttab(path: Path = CRYPTTAB) -> list[CrypttabEntry]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise UkiError(f"cannot read {path}: {exc}") from exc

    entries: list[CrypttabEntry] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 3:
            continue
        entries.append(
            CrypttabEntry(
                name=fields[0],
                source=fields[1],
                keyfile=fields[2],
                options=split_crypttab_options(
                    fields[3] if len(fields) > 3 else ""
                ),
            )
        )
    return entries


def set_crypttab_option(
    options: list[str], key: str, value: str
) -> tuple[list[str], bool]:
    prefix = key + "="
    desired = f"{key}={value}"
    existing = [option for option in options if option.startswith(prefix)]
    if existing == [desired]:
        return options, False
    updated = [
        option for option in options if not option.startswith(prefix)
    ]
    updated.append(desired)
    return updated, True


def update_crypttab_tpm2(
    path: Path,
    entry_name: str,
    *,
    dry_run: bool = False,
    remove: bool = False,
) -> bool:
    """Ensure the root entry auto-unlocks and measures into PCR 15.

    With ``remove``, strip the TPM2 options added by luksury instead.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise UkiError(f"cannot read {path}: {exc}") from exc

    lines = text.splitlines(keepends=True)
    changed = False
    updated_line = ""
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 3 or fields[0] != entry_name:
            continue

        name, source, keyfile = fields[:3]
        options = split_crypttab_options(
            fields[3] if len(fields) > 3 else ""
        )
        if remove:
            options = [
                option
                for option in options
                if not any(
                    option.startswith(f"{key}=")
                    for key in CRYPTTAB_TPM2_OPTIONS
                )
            ]
        else:
            for key, value in (
                ("tpm2-device", "auto"),
                (
                    "tpm2-measure-pcr",
                    str(CRYPTTAB_TPM2_MEASURE_PCR),
                ),
                ("tpm2-measure-bank", CRYPTTAB_TPM2_MEASURE_BANK),
            ):
                options, _ = set_crypttab_option(options, key, value)

        updated_line = f"{name} {source} {keyfile}"
        if options:
            updated_line += f" {','.join(options)}"
        if line.endswith("\n"):
            updated_line += "\n"
        if updated_line != line:
            lines[index] = updated_line
            changed = True
        break
    else:
        raise UkiError(f"no crypttab entry named {entry_name!r} in {path}")

    if not changed:
        return False

    if dry_run:
        action = "update" if not remove else "restore"
        log(f"would {action} {path}: {updated_line.strip()}")
        return True

    backup = path.with_name(path.name + CRYPTTAB_BACKUP_SUFFIX)
    try:
        shutil.copy2(path, backup)
    except OSError as exc:
        warn(f"cannot back up {path} to {backup}: {exc}")

    temporary = path.with_name(f".{path.name}.luksury.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write("".join(lines))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, path.stat().st_mode & 0o7777)
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise

    action = "restored" if remove else "updated"
    log(f"{action} {path}: {updated_line.strip()}")
    return True


def crypttab_device(entry: CrypttabEntry) -> Path:
    source = entry.source
    for prefix, directory in (
        ("UUID=", "by-uuid"),
        ("PARTUUID=", "by-partuuid"),
        ("LABEL=", "by-label"),
        ("PARTLABEL=", "by-partlabel"),
    ):
        if source.startswith(prefix):
            return Path("/dev/disk") / directory / source[len(prefix):]
    return Path(source)


def root_mapper_name() -> str | None:
    try:
        lines = Path("/proc/self/mountinfo").read_text(
            encoding="utf-8"
        ).splitlines()
    except OSError:
        return None

    for line in lines:
        fields = line.split()
        if len(fields) < 5 or fields[4] != "/":
            continue
        try:
            major, minor = fields[2].split(":", 1)
            return Path(
                f"/sys/dev/block/{major}:{minor}/dm/name"
            ).read_text().strip()
        except (OSError, ValueError):
            return None
    return None


def find_root_crypttab_entry(path: Path = CRYPTTAB) -> CrypttabEntry:
    entries = parse_crypttab(path)
    name = root_mapper_name()
    if name is None:
        raise UkiError("cannot determine the device-mapper name of /")
    for entry in entries:
        if entry.name == name:
            return entry
    raise UkiError(f"no crypttab entry named {name!r} in {path}")


def crypttab_unlock_key_file(entry: CrypttabEntry) -> Path | None:
    if any(
        option.startswith("keyfile-offset=")
        or option.startswith("keyfile-size=")
        for option in entry.options
    ):
        return None

    candidates: list[Path] = []
    if entry.keyfile and entry.keyfile not in ("none", "-"):
        candidates.append(Path(entry.keyfile))
    candidates.append(
        Path("/etc/cryptsetup-keys.d") / f"{entry.name}.key"
    )
    candidates.append(
        Path("/run/cryptsetup-keys.d") / f"{entry.name}.key"
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def cryptsetup_binary() -> str:
    return require_tool(
        "cryptsetup", "/usr/sbin/cryptsetup", "/sbin/cryptsetup"
    )


def luks2_metadata(device: Path) -> dict:
    proc = run(
        [
            cryptsetup_binary(),
            "luksDump",
            "--dump-json-metadata",
            str(device),
        ]
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise UkiError(
            f"cannot parse LUKS2 metadata for {device}: {exc}"
        ) from exc


def luks2_token_types(device: Path) -> set[str]:
    metadata = luks2_metadata(device)
    tokens = metadata.get("tokens", {})
    if not isinstance(tokens, dict):
        return set()
    return {
        token["type"]
        for token in tokens.values()
        if isinstance(token, dict) and isinstance(token.get("type"), str)
    }


def key_file_unlocks(device: Path, key_file: Path) -> bool:
    """Return whether key_file is a passphrase that unlocks device."""
    if not key_file.is_file():
        return False
    proc = run(
        [
            cryptsetup_binary(),
            "open",
            "--test-passphrase",
            "--type",
            "luks2",
            "--key-file",
            str(key_file),
            str(device),
        ],
        check=False,
    )
    return proc.returncode == 0


def atomic_replace(
    destination: Path,
    mode: int,
    write: Callable[[BinaryIO], None],
    *,
    ignore_chmod_error: bool = False,
    root: Path | None = None,
) -> None:
    """Atomically replace destination with data produced by write()."""
    if root is not None:
        parent = _resolve_under(root, destination.parent, "destination")
        destination = parent / destination.name
    else:
        parent = destination.parent

    parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=str(parent)
    )
    identity: tuple[int, int] | None = None
    try:
        with os.fdopen(fd, "wb") as handle:
            write(handle)
            handle.flush()
            os.fsync(handle.fileno())
            try:
                os.fchmod(handle.fileno(), mode)
            except OSError:
                if not ignore_chmod_error:
                    raise
            info = os.fstat(handle.fileno())
            identity = (info.st_dev, info.st_ino)
        try:
            current = os.lstat(temporary)
        except OSError as exc:
            raise UkiError(
                f"cannot inspect temporary file {temporary}: {exc}"
            ) from exc
        if (
            not stat.S_ISREG(current.st_mode)
            or identity is None
            or (current.st_dev, current.st_ino) != identity
        ):
            raise UkiError(
                f"temporary file {temporary} was replaced while writing"
            )
        os.replace(temporary, destination)
        try:
            directory_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def write_private_file(path: Path, data: bytes) -> None:
    """Atomically write a root-only file, creating a private directory."""
    parent = path.parent
    created = False
    try:
        parent.mkdir(parents=True, mode=0o700)
        created = True
    except FileExistsError:
        pass
    if created:
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass

    atomic_replace(path, 0o600, lambda handle: handle.write(data))


def add_recovery_key(
    device: Path,
    *,
    unlock_key_file: Path | None = None,
    use_tpm2: bool = False,
) -> str:
    """Generate and enroll a systemd recovery key, returning its value.

    systemd-cryptenroll writes the key itself to stdout, while its
    diagnostics and optional QR code go to stderr.
    """
    command = [
        require_tool(
            "systemd-cryptenroll", "/usr/bin/systemd-cryptenroll"
        ),
        "--recovery-key",
    ]
    if unlock_key_file is not None:
        command.append(f"--unlock-key-file={unlock_key_file}")
    elif use_tpm2:
        command.append("--unlock-tpm2-device=auto")
    command.append(str(device))

    log(f"generating a recovery key for {device}")
    output = run_capture_stdout(command).strip()
    if not RECOVERY_KEY_RE.match(output):
        raise UkiError(
            "systemd-cryptenroll did not return a usable recovery key"
        )
    return output


def ensure_recovery_key(
    device: Path,
    *,
    key_file: Path = RECOVERY_KEY_FILE,
    unlock_key_file: Path | None = None,
) -> Path:
    """Make sure the one-time recovery key is present and still works.

    The key is never rotated or replaced.  If it exists but no longer
    unlocks the volume, or if the volume has a recovery key whose value is
    not stored at key_file, stop instead of generating a new one.
    """
    if key_file.is_file() and key_file_unlocks(device, key_file):
        log(f"using recovery key from {key_file}")
        return key_file

    if key_file.exists():
        raise UkiError(
            f"recovery key {key_file} exists but does not unlock {device}; "
            "refusing to replace it"
        )

    token_types = luks2_token_types(device)
    if SYSTEMD_RECOVERY_TOKEN in token_types:
        raise UkiError(
            f"a recovery key is already enrolled on {device} but its value "
            f"is not stored in {key_file}; restore the key instead of "
            "creating a new one"
        )

    if unlock_key_file is not None and not key_file_unlocks(
        device, unlock_key_file
    ):
        warn(f"{unlock_key_file} does not unlock {device}")
        unlock_key_file = None

    use_tpm2 = (
        unlock_key_file is None and SYSTEMD_TPM2_TOKEN in token_types
    )

    try:
        recovery_key = add_recovery_key(
            device,
            unlock_key_file=unlock_key_file,
            use_tpm2=use_tpm2,
        )
    except UkiError:
        if not use_tpm2:
            raise
        warn(
            "unlocking with the existing TPM2 token failed; "
            "retrying with a passphrase"
        )
        recovery_key = add_recovery_key(device)

    write_private_file(key_file, recovery_key.encode("ascii"))
    if not key_file_unlocks(device, key_file):
        raise UkiError(
            f"stored recovery key {key_file} does not unlock {device}"
        )
    log(f"stored recovery key in {key_file} (mode 0600)")
    return key_file


def tokens_from_metadata(metadata: dict, token_type: str) -> dict[int, dict]:
    """Return LUKS2 tokens of one type keyed by token ID."""
    tokens = metadata.get("tokens", {})
    result: dict[int, dict] = {}
    if not isinstance(tokens, dict):
        return result
    for token_id, token in tokens.items():
        if not isinstance(token, dict):
            continue
        if token.get("type") != token_type:
            continue
        try:
            number = int(token_id)
        except (TypeError, ValueError):
            continue
        result[number] = token
    return result


def tpm2_tokens_from_metadata(metadata: dict) -> dict[int, dict]:
    """Return systemd-tpm2 tokens keyed by LUKS2 token ID."""
    return tokens_from_metadata(metadata, SYSTEMD_TPM2_TOKEN)


def recovery_tokens_from_metadata(metadata: dict) -> dict[int, dict]:
    """Return systemd-recovery tokens keyed by LUKS2 token ID."""
    return tokens_from_metadata(metadata, SYSTEMD_RECOVERY_TOKEN)


def tpm2_tokens(device: Path) -> dict[int, dict]:
    return tpm2_tokens_from_metadata(luks2_metadata(device))


def tpm2_token_slots(token: dict) -> set[int]:
    slots: set[int] = set()
    keyslots = token.get("keyslots", [])
    if isinstance(keyslots, list):
        for slot in keyslots:
            try:
                slots.add(int(slot))
            except (TypeError, ValueError):
                continue
    return slots


def read_tpm2_state(path: Path, device_uuid: str | None) -> dict | None:
    """Read the stored token state, ignoring stale or malformed files."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as exc:
        warn(f"cannot read TPM2 state {path}: {exc}")
        return None

    try:
        state = json.loads(text)
    except json.JSONDecodeError as exc:
        warn(f"cannot parse TPM2 state {path}: {exc}")
        return None
    if not isinstance(state, dict):
        warn(f"ignoring TPM2 state {path}: not a JSON object")
        return None
    if state.get("version") != TPM2_STATE_VERSION:
        warn(
            f"ignoring TPM2 state {path}: unsupported version "
            f"{state.get('version')!r}"
        )
        return None
    if device_uuid is not None and state.get("device_uuid") != device_uuid:
        warn(
            f"ignoring TPM2 state {path}: it belongs to volume "
            f"{state.get('device_uuid')!r}, not {device_uuid}"
        )
        return None
    if not isinstance(state.get("token_id"), int):
        warn(f"ignoring TPM2 state {path}: invalid token_id")
        return None
    return state


def save_tpm2_state(
    path: Path,
    *,
    device: Path,
    device_uuid: str | None,
    token_id: int,
    keyslot: int | None,
    algorithm: str,
    token: dict,
) -> None:
    pcrs_value = token.get("tpm2-pcrs", [])
    pcrs = (
        [pcr for pcr in pcrs_value if isinstance(pcr, int)]
        if isinstance(pcrs_value, list)
        else []
    )
    bank = token.get("tpm2-pcr-bank")
    if not isinstance(bank, str):
        bank = algorithm
    policy_hash = token.get("tpm2-policy-hash")
    if not isinstance(policy_hash, str):
        policy_hash = None
    state = {
        "version": TPM2_STATE_VERSION,
        "device": str(device),
        "device_uuid": device_uuid,
        "token_id": token_id,
        "keyslot": keyslot,
        "pcr_bank": bank,
        "pcrs": pcrs,
        "policy_hash": policy_hash,
    }
    data = json.dumps(state, indent=2, sort_keys=True) + "\n"
    write_private_file(path, data.encode("utf-8"))


def remove_tpm2_token(device: Path, token_id: int) -> None:
    run(
        [
            cryptsetup_binary(),
            "token",
            "remove",
            "--batch-mode",
            "--token-id",
            str(token_id),
            str(device),
        ]
    )


def tpm2_token_pcrs(token: dict) -> tuple[int, ...]:
    pcrs_value = token.get("tpm2-pcrs", [])
    pcrs = (
        [pcr for pcr in pcrs_value if isinstance(pcr, int)]
        if isinstance(pcrs_value, list)
        else []
    )
    return tuple(sorted(pcrs))


def tpm2_token_matches_binding(
    token: dict, algorithm: str, pcrs: tuple[int, ...]
) -> bool:
    return (
        tpm2_token_pcrs(token) == tuple(sorted(pcrs))
        and token.get("tpm2-pcr-bank") == algorithm
    )


def find_enrolled_tpm2_token(
    metadata: dict,
    *,
    algorithm: str,
    expected_pcrs: tuple[int, ...],
    target_slot: int | None,
    previous_slots: set[int],
) -> tuple[int, dict] | None:
    """Find the token just added by systemd-cryptenroll."""
    tokens = tpm2_tokens_from_metadata(metadata)
    matching = [
        (token_id, token)
        for token_id, token in tokens.items()
        if tpm2_token_matches_binding(token, algorithm, expected_pcrs)
    ]
    keyslots: set[int] = set()
    raw_keyslots = metadata.get("keyslots", {})
    if isinstance(raw_keyslots, dict):
        for slot in raw_keyslots:
            try:
                keyslots.add(int(slot))
            except (TypeError, ValueError):
                continue

    candidates: list[tuple[int, dict]] = []
    if target_slot is not None:
        candidates = [
            (token_id, token)
            for token_id, token in matching
            if target_slot in tpm2_token_slots(token)
        ]
    if not candidates:
        candidates = [
            (token_id, token)
            for token_id, token in matching
            if tpm2_token_slots(token)
            and tpm2_token_slots(token) & keyslots
            and not tpm2_token_slots(token) <= previous_slots
        ]
    if not candidates:
        candidates = [
            (token_id, token)
            for token_id, token in matching
            if tpm2_token_slots(token)
            and tpm2_token_slots(token) & keyslots
        ]
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])


def cryptenroll_tpm2(
    device: Path,
    pcrs: dict[int, bytes],
    *,
    algorithm: str = "sha256",
    unlock_key_file: Path | None = None,
    state_file: Path = TPM2_STATE_FILE,
) -> None:
    """Bind a LUKS2 volume to the measured UKI boot.

    ``pcrs`` contains the expected value for every bound PCR when the next
    UKI boots.  PCR7 is present only when Secure Boot is enforcing; without
    it PCR4 measures the shim and the complete UKI, including the kernel and
    initrd.  On systemd 261+ measured UKI boots this includes the
    os-separator extension for PCR 0-7, 12 and 13; PCR15 is still zero because
    the volume key is measured into it only after the token is unsealed.
    Every old systemd-tpm2 token is removed; the new token is recorded in
    ``state_file``.
    """
    require_tpm2_packages()
    expected_pcrs = tuple(sorted(pcrs))
    cryptsetup = cryptsetup_binary()
    check = run(
        [cryptsetup, "isLuks", "--type", "luks2", str(device)],
        check=False,
    )
    if check.returncode != 0:
        raise UkiError(f"{device} is not a LUKS2 volume")

    metadata = luks2_metadata(device)
    device_uuid = metadata.get("uuid")
    if not isinstance(device_uuid, str):
        device_uuid = None
    keyslots = {str(slot) for slot in metadata.get("keyslots", {})}
    tpm2_token_map = tpm2_tokens_from_metadata(metadata)
    tpm2_slot_numbers: set[int] = set()
    for token in tpm2_token_map.values():
        tpm2_slot_numbers.update(tpm2_token_slots(token))
    tpm2_slots = {str(slot) for slot in tpm2_slot_numbers}
    has_tpm2 = bool(tpm2_slot_numbers)

    if keyslots and keyslots <= tpm2_slots:
        raise UkiError(
            f"refusing to wipe the only keyslots on {device}: "
            "no non-TPM2 keyslot would remain"
        )

    spec = tpm2_pcr_spec(algorithm, pcrs)
    command = [
        require_tool(
            "systemd-cryptenroll", "/usr/bin/systemd-cryptenroll"
        ),
        "--tpm2-device=auto",
        "--tpm2-pcrlock=",
        "--tpm2-public-key=",
        f"--tpm2-pcrs={spec}",
        # systemd-cryptenroll enrolls first and then wipes every old TPM2
        # keyslot/token, excluding the newly added token.
        "--wipe-slot=tpm2",
    ]

    use_tpm2_unlock = False
    if unlock_key_file is not None:
        command.append(f"--unlock-key-file={unlock_key_file}")
    elif has_tpm2:
        command.append("--unlock-tpm2-device=auto")
        use_tpm2_unlock = True

    command.append(str(device))
    if 7 in expected_pcrs:
        log(
            "PCR7 uses the predicted Secure Boot policy and shim authority "
            "measurement; PCR12 includes the ESP global credentials, "
            "systemd's os-separator is included where the next boot applies "
            "it, and PCR15 is bound to zero"
        )
    else:
        log(
            "Secure Boot is disabled, so PCR7 is not bound; PCR4 measures "
            "the shim and the complete UKI, including the kernel and initrd. "
            "PCR12 includes the ESP global credentials, systemd's "
            "os-separator is included where the next boot applies it, and "
            "PCR15 is bound to zero"
        )

    log(f"enrolling TPM2 for {device}")
    log(f"PCR binding: {spec}")
    try:
        run_interactive(command)
    except UkiError:
        if not use_tpm2_unlock:
            raise
        warn(
            "unlocking with the existing TPM2 token failed; "
            "retrying with a passphrase"
        )
        command.remove("--unlock-tpm2-device=auto")
        run_interactive(command)

    new_metadata = luks2_metadata(device)
    enrolled_token = find_enrolled_tpm2_token(
        new_metadata,
        algorithm=algorithm,
        expected_pcrs=expected_pcrs,
        target_slot=None,
        previous_slots=tpm2_slot_numbers,
    )
    new_keyslot: int | None = None
    if enrolled_token is None:
        warn(
            "cannot identify the newly enrolled TPM2 token; "
            f"not updating {state_file}"
        )
    else:
        new_token_id, new_token = enrolled_token
        # --wipe-slot=tpm2 removes the old keyslots and their tokens.  Remove
        # any token-only leftovers too, so an old weak enrollment cannot
        # survive.
        for token_id in sorted(tpm2_tokens_from_metadata(new_metadata)):
            if token_id == new_token_id:
                continue
            log(f"removing leftover TPM2 token {token_id}")
            remove_tpm2_token(device, token_id)
        verify_tpm2_token(device, algorithm, expected_pcrs)

        new_metadata = luks2_metadata(device)
        new_token = tpm2_tokens_from_metadata(new_metadata).get(new_token_id)
        if new_token is None:
            warn(f"TPM2 token {new_token_id} disappeared after cleanup")
        else:
            new_slots = sorted(tpm2_token_slots(new_token))
            if len(new_slots) == 1:
                new_keyslot = new_slots[0]
            new_uuid = new_metadata.get("uuid")
            if not isinstance(new_uuid, str):
                new_uuid = device_uuid
            save_tpm2_state(
                state_file,
                device=device,
                device_uuid=new_uuid,
                token_id=new_token_id,
                keyslot=new_keyslot,
                algorithm=algorithm,
                token=new_token,
            )
            log(f"recorded TPM2 token {new_token_id} in {state_file}")


def verify_tpm2_token(
    device: Path, algorithm: str, expected_pcrs: tuple[int, ...]
) -> None:
    tokens = tpm2_tokens(device)
    if len(tokens) != 1:
        raise UkiError(
            f"expected exactly one systemd-tpm2 token on {device}, "
            f"found {len(tokens)}"
        )
    token_id, token = next(iter(tokens.items()))
    pcrs = sorted(
        pcr
        for pcr in token.get("tpm2-pcrs", [])
        if isinstance(pcr, int)
    )
    bank = token.get("tpm2-pcr-bank")
    expected = list(tuple(sorted(expected_pcrs)))
    if pcrs != expected or bank != algorithm:
        raise UkiError(
            f"TPM2 token {token_id} on {device} has PCRs {pcrs} and bank "
            f"{bank!r}, expected {expected}/{algorithm}"
        )
    log(
        f"TPM2 token verified: PCRs {pcrs}, bank {bank}, "
        f"policy {token.get('tpm2-policy-hash', 'unknown')}"
    )


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def compute_vmas(info: PEInfo, sizes: list[tuple[str, int]]) -> dict[str, int]:
    """Place new sections after the stub's existing image contents.

    objcopy wants absolute VMAs for PE sections and subtracts ImageBase when
    writing the section's RVA.  Ubuntu's stub has a non-zero ImageBase, so
    hard-coded low VMAs would make objcopy emit "section below image base".
    """
    end = info.image_base + info.size_of_image
    for section in info.sections:
        end = max(
            end,
            info.image_base
            + section.virtual_address
            + max(section.virtual_size, section.raw_size),
        )

    cursor = align_up(end, info.section_alignment)
    vmas: dict[str, int] = {}
    for name, size in sizes:
        cursor = align_up(cursor, info.section_alignment)
        vmas[name] = cursor
        cursor += size
    return vmas


def planned_sizes(
    osrel: Path,
    kernel: str,
    initrds: list[str],
    cmdline: list[str],
    release: str | None,
) -> list[tuple[str, int]]:
    sizes: list[tuple[str, int]] = [
        (".osrel", osrel.stat().st_size),
        (".cmdline", len(cmdline_bytes(cmdline))),
    ]
    if release:
        sizes.append((".uname", len(release.encode("utf-8"))))
    sizes.append((".linux", os.path.getsize(kernel)))

    if len(initrds) != 1:
        raise UkiError(
            f"expected exactly one initrd, got {len(initrds)}; "
            "luksury requires a dracut single-initrd entry"
        )
    sizes.append((".initrd", os.path.getsize(initrds[0])))
    return sizes


def cmdline_bytes(cmdline: list[str]) -> bytes:
    # objcopy drops zero-sized sections, so keep a single space for an empty
    # command line instead of silently omitting .cmdline.
    return (" ".join(cmdline) or " ").encode("utf-8")


def build_uki(
    stub: Path,
    osrel: Path,
    kernel: str,
    initrds: list[str],
    cmdline: list[str],
    release: str | None,
    workdir: Path,
    verbose: bool,
) -> Path:
    info = parse_pe(stub)

    cmdline_path = workdir / "cmdline"
    cmdline_path.write_bytes(cmdline_bytes(cmdline))

    uname_path: Path | None = None
    if release:
        uname_path = workdir / "uname"
        uname_path.write_text(release, encoding="utf-8")

    if len(initrds) != 1:
        raise UkiError(
            f"expected exactly one initrd, got {len(initrds)}; "
            "luksury requires a dracut single-initrd entry"
        )
    initrd_path = Path(initrds[0])

    sections: list[tuple[str, Path]] = [
        (".osrel", osrel),
        (".cmdline", cmdline_path),
    ]
    if uname_path is not None:
        sections.append((".uname", uname_path))
    sections.append((".linux", Path(kernel)))
    sections.append((".initrd", initrd_path))

    sizes = [(name, path.stat().st_size) for name, path in sections]
    vmas = compute_vmas(info, sizes)

    output = workdir / "luksury.efi"
    command = ["objcopy"]
    for name, path in sections:
        command.extend(
            [
                "--add-section",
                f"{name}={path}",
                "--change-section-vma",
                f"{name}=0x{vmas[name]:x}",
            ]
        )
    command.extend([str(stub), str(output)])

    log("building UKI with objcopy")
    for name, size in sizes:
        vlog(f"{name:9s} size={size:>10d} vma=0x{vmas[name]:x}", verbose)

    proc = run(command)
    stderr = (proc.stderr or "").strip()
    if stderr:
        for line in stderr.splitlines():
            warn(f"objcopy: {line}")
        lowered = stderr.lower()
        if "section below image base" in lowered or "rva truncated" in lowered:
            raise UkiError("objcopy produced invalid section addresses")

    verify_uki(output, dict(sizes))
    return output


def verify_uki(path: Path, expected: dict[str, int]) -> None:
    info = parse_pe(path)
    by_name = {section.name: section for section in info.sections}

    for name, size in expected.items():
        section = by_name.get(name)
        if section is None:
            raise UkiError(f"built UKI is missing the {name} section")
        if section.virtual_size != size:
            raise UkiError(
                f"built UKI section {name} has size {section.virtual_size}, "
                f"expected {size}"
            )

    vmas = [
        info.image_base + section.virtual_address
        for section in info.sections
        if section.name in expected
    ]
    if len(vmas) != len(set(vmas)):
        raise UkiError("built UKI has overlapping added sections")


# ---------------------------------------------------------------------------
# systemd-boot configuration parsing
# ---------------------------------------------------------------------------


@dataclass
class LoaderEntry:
    """A systemd-boot menu entry (Type #1 or Type #2)."""

    id: str
    path: Path
    root: Path
    kind: str  # "linux", "uki", "efi" or "type2"
    title: str
    version: str | None
    sort_key: str | None
    machine_id: str | None
    linux: str | None = None
    efi: str | None = None
    initrds: list[str] = field(default_factory=list)
    options: list[str] = field(default_factory=list)
    tries_left: int | None = None
    tries_done: int | None = None

    def host_path(self, value: str) -> str:
        return partition_path(self.root, value)


def read_efivar_bytes(name: str, guid: str) -> bytes | None:
    """Read an EFI variable value, stripping efivarfs attributes."""
    path = EFIVAR_DIR / f"{name}-{guid}"
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < 4:
        return None
    return data[4:]


def read_efivar(name: str) -> str | None:
    """Read a Boot Loader Interface string variable from efivarfs."""
    data = read_efivar_bytes(name, LOADER_GUID)
    if data is None or not data:
        return None
    try:
        value = data.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    return value.split("\0", 1)[0].strip()


def efi_boolean(name: str, guid: str = EFI_GLOBAL_VARIABLE_GUID) -> bool | None:
    data = read_efivar_bytes(name, guid)
    if data is None:
        return None
    return bool(data and data[-1] == 1)


def require_uefi_boot() -> bool:
    """Require UEFI and return whether Secure Boot is enforcing.

    Secure Boot is optional.  When it is disabled PCR7 is not bound; the TPM2
    token then relies on PCR4, which measures the shim and the complete UKI
    (the kernel and initrd included), for boot-chain integrity.
    """
    if not EFIVAR_DIR.is_dir():
        raise UkiError("the system is not booted through UEFI")

    secure = efi_boolean("SecureBoot")
    if secure is None:
        raise UkiError("cannot read the SecureBoot EFI variable")
    if not secure:
        warn(
            "Secure Boot is disabled; PCR7 will not be bound. The shim and "
            "UKI measurement in PCR4 covers the kernel and initrd"
        )
        return False

    setup = efi_boolean("SetupMode")
    if setup:
        raise UkiError(
            "the firmware is in Setup Mode; enroll your platform keys and "
            "leave Setup Mode before installing luksury"
        )

    if efi_boolean("AuditMode"):
        raise UkiError(
            "the firmware is in Secure Boot Audit Mode; enable enforcing "
            "mode before installing luksury"
        )

    if efi_boolean("MokSBStateRT", SHIM_LOCK_GUID):
        raise UkiError(
            "shim signature validation is disabled (MokSBState); enable it "
            "with 'mokutil --enable-validation' first"
        )
    return True


def shim_signed_path() -> Path:
    """Return shim-signed's shim, validating that it is signed."""
    shim = SHIM_SIGNED_DEFAULT
    if not shim.is_file():
        raise UkiError(
            f"shim-signed's shim not found at {shim}; install shim-signed"
        )
    try:
        info = parse_pe(shim)
    except UkiError as exc:
        raise UkiError(f"invalid shim-signed shim {shim}: {exc}") from exc
    if info.certificate_table_size == 0:
        raise UkiError(f"shim-signed's shim {shim} is not signed")
    return shim


def shim_signed_mmx_path() -> Path:
    """Return MokManager from shim-signed."""
    mmx = MMX_DEFAULT
    if not mmx.is_file():
        raise UkiError(
            f"MokManager not found at {mmx}; install shim-signed"
        )
    return mmx


def bootctl_path(option: str) -> Path | None:
    if shutil.which("bootctl") is None:
        return None
    proc = run(["bootctl", option], check=False)
    if proc.returncode != 0:
        return None
    lines = proc.stdout.strip().splitlines()
    if not lines or not lines[0].strip():
        return None
    return Path(lines[0].strip())


def has_loader_config(root: Path) -> bool:
    try:
        if (root / "loader" / "loader.conf").is_file():
            return True
        entries = root / "loader" / "entries"
        return any(
            path.is_file() and path.name.lower().endswith(".conf")
            for path in entries.iterdir()
        )
    except OSError:
        return False


def systemd_boot_configured(esp_override: Path | None = None) -> bool:
    """Return True when the ESP/XBOOTLDR carries systemd-boot configuration."""
    if esp_override is not None:
        # An explicit --esp must be valid; do not hide the error behind the
        # generic "cannot determine the boot loader" message.
        esp, boot = systemd_boot_roots(esp_override)
    else:
        try:
            esp, boot = systemd_boot_roots()
        except UkiError:
            return False

    roots = [esp]
    if os.path.realpath(boot) != os.path.realpath(esp):
        roots.append(boot)
    return any(has_loader_config(root) for root in roots)


def detect_boot_loader(esp_override: Path | None = None) -> str:
    """Return the boot loader that owns the default boot entry.

    The Boot Loader Interface variables describe the loader used for the
    current boot, which is the most reliable signal.  When they do not identify
    systemd-boot or GRUB, the firmware may have booted a unified kernel image
    directly (systemd-stub does not set LoaderInfo) or the loader may not
    publish the interface (GRUB does not).  In that case prefer GRUB when it
    is installed, so that its configuration supplies the trusted command
    line, and fall back to systemd-boot otherwise.
    """
    info = read_efivar("LoaderInfo")
    if info:
        lowered = info.lower()
        if SYSTEMD_BOOT in lowered:
            return SYSTEMD_BOOT
        if "grub" in lowered:
            return "grub"

    if shutil.which("bootctl"):
        proc = run(["bootctl", "status"], check=False)
        for line in (proc.stdout + "\n" + proc.stderr).splitlines():
            match = re.match(r"^\s*Product:\s*(.*)$", line)
            if not match:
                continue
            product = match.group(1).lower()
            if SYSTEMD_BOOT in product:
                return SYSTEMD_BOOT
            if "grub" in product:
                return "grub"

    if grub_installed():
        return "grub"
    if systemd_boot_configured(esp_override):
        return SYSTEMD_BOOT
    raise UkiError(
        "cannot determine the boot loader: the current boot reports no loader, "
        "no systemd-boot entries were found, and GRUB is not installed "
        f"({GRUB_CFG} and {ETC_DEFAULT_GRUB} are required)"
    )


def efi_architecture() -> str:
    machine = platform.machine().lower()
    return {
        "x86_64": "x64",
        "amd64": "x64",
        "i386": "ia32",
        "i486": "ia32",
        "i586": "ia32",
        "i686": "ia32",
        "aarch64": "aa64",
        "arm64": "aa64",
        "armv7l": "arm",
        "riscv64": "riscv64",
        "loongarch64": "loongarch64",
    }.get(machine, machine)


def partition_path(root: Path, value: str) -> str:
    """Map an entry path relative to its partition root onto the host.

    The final path must remain inside ``root``; this rejects symlink escapes and
    absolute host paths.
    """
    value = value.strip().replace("\\", "/")
    parts = [part for part in value.split("/") if part not in ("", ".")]
    if not parts or ".." in parts:
        raise UkiError(f"invalid boot entry path: {value!r}")
    candidate = root.joinpath(*parts)
    try:
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UkiError(f"cannot resolve boot partition {root}: {exc}") from exc
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UkiError(f"boot entry path does not exist: {value!r}") from exc
    if not resolved.is_file():
        raise UkiError(f"boot entry path is not a regular file: {value!r}")
    if not resolved.is_relative_to(resolved_root):
        raise UkiError(
            f"boot entry path escapes its partition: {value!r} "
            f"(resolved to {resolved})"
        )
    return str(resolved)


def split_options(value: str) -> list[str]:
    try:
        return shlex.split(value, posix=True)
    except ValueError:
        return value.split()


def parse_counters(name: str, suffix: str) -> tuple[int | None, int | None]:
    stem = name[: -len(suffix)] if name.lower().endswith(suffix) else name
    match = re.search(r"\+(\d+)(?:-(\d+))?$", stem)
    if not match:
        return None, None
    return int(match.group(1)), int(match.group(2) or 0)


def read_loader_conf(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return values

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(\S+)(?:[ \t]+(.*))?$", line)
        if not match:
            continue
        values[match.group(1)] = (match.group(2) or "").strip()
    return values


def read_pe_section(path: Path, name: str) -> bytes | None:
    try:
        info = parse_pe(path)
        data = path.read_bytes()
    except (OSError, UkiError):
        return None

    for section in info.sections:
        if section.name == name:
            end = section.raw_pointer + section.raw_size
            return data[section.raw_pointer : end].rstrip(b"\0")
    return None


def parse_os_release_data(data: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in data.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key.strip()] = value
    return values


def type2_metadata(path: Path) -> tuple[str, str | None, str | None]:
    values = parse_os_release_data(read_pe_section(path, ".osrel") or b"")
    title = (
        values.get("PRETTY_NAME")
        or values.get("NAME")
        or values.get("ID")
        or path.stem
    )
    version = values.get("VERSION_ID") or values.get("IMAGE_VERSION")
    sort_key = values.get("IMAGE_ID") or values.get("ID")
    return title, version, sort_key


def parse_bls_entry(path: Path, root: Path) -> LoaderEntry | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        warn(f"cannot read {path}: {exc}")
        return None

    title: str | None = None
    version: str | None = None
    sort_key: str | None = None
    machine_id: str | None = None
    linux: str | None = None
    uki: str | None = None
    efi: str | None = None
    initrds: list[str] = []
    options: list[str] = []
    architecture: str | None = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(\S+)[ \t]+(.*)$", line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        if key == "title":
            title = value
        elif key == "version":
            version = value
        elif key == "sort-key":
            sort_key = value
        elif key == "machine-id":
            machine_id = value
        elif key == "linux":
            linux = value
        elif key == "uki":
            uki = value
        elif key == "efi":
            efi = value
        elif key == "initrd":
            if value:
                initrds.append(value)
        elif key == "options":
            options.append(value)
        elif key == "architecture":
            architecture = value

    if architecture and architecture.lower() != efi_architecture().lower():
        return None

    if linux:
        kind = "linux"
    elif uki:
        kind = "uki"
    elif efi:
        kind = "efi"
    else:
        return None

    entry = LoaderEntry(
        id=path.name.lower(),
        path=path,
        root=root,
        kind=kind,
        title=title or path.stem,
        version=version,
        sort_key=sort_key,
        machine_id=machine_id,
        linux=linux,
        efi=efi,
        initrds=initrds,
        options=options,
    )
    entry.tries_left, entry.tries_done = parse_counters(path.name, ".conf")

    try:
        loader = entry.host_path(linux or uki or efi or "")
    except UkiError:
        warn(f"ignoring {path}: invalid loader path")
        return None
    if not os.path.isfile(loader):
        warn(f"ignoring {path}: {loader} does not exist")
        return None
    return entry


def parse_type2_entry(path: Path) -> LoaderEntry:
    title, version, sort_key = type2_metadata(path)
    entry = LoaderEntry(
        id=path.name.lower(),
        path=path,
        root=path.parent,
        kind="type2",
        title=title,
        version=version,
        sort_key=sort_key,
        machine_id=None,
    )
    entry.tries_left, entry.tries_done = parse_counters(path.name, ".efi")
    return entry


def natural_key(text: str) -> list[tuple[int, object]]:
    key: list[tuple[int, object]] = []
    for token in re.split(r"(\d+)", text or ""):
        if token.isdigit():
            key.append((0, int(token)))
        else:
            key.append((1, token.lower()))
    return key


def compare_natural(left: str, right: str) -> int:
    a, b = natural_key(left), natural_key(right)
    return (a > b) - (a < b)


def compare_text(left: str, right: str) -> int:
    return (left > right) - (left < right)


def compare_loader_entries(left: LoaderEntry, right: LoaderEntry) -> int:
    # Bad boot-count entries sort last, like systemd-boot.
    left_bad = left.tries_left == 0
    right_bad = right.tries_left == 0
    if left_bad != right_bad:
        return 1 if left_bad else -1

    left_sorted = left.sort_key is not None
    right_sorted = right.sort_key is not None
    if left_sorted != right_sorted:
        return -1 if left_sorted else 1

    if left_sorted and right_sorted:
        result = compare_text(left.sort_key or "", right.sort_key or "")
        if result:
            return result
        result = compare_text(left.machine_id or "", right.machine_id or "")
        if result:
            return result
        result = compare_natural(left.version or "", right.version or "")
        if result:
            return -result

    return -compare_natural(left.id, right.id)


def load_systemd_boot_entries(esp: Path, boot: Path) -> list[LoaderEntry]:
    roots = [esp]
    if os.path.realpath(boot) != os.path.realpath(esp):
        roots.append(boot)

    entries: list[LoaderEntry] = []
    for root in roots:
        for directory, kind in (
            (root / "loader" / "entries", "type1"),
            (root / "EFI" / "Linux", "type2"),
        ):
            try:
                children = sorted(directory.iterdir(), key=lambda item: item.name.lower())
            except OSError:
                continue

            for path in children:
                name = path.name
                if name.startswith(".") or name.lower().startswith("auto-"):
                    continue
                if not path.is_file():
                    continue
                if kind == "type1":
                    if not name.lower().endswith(".conf"):
                        continue
                    entry = parse_bls_entry(path, root)
                else:
                    if not name.lower().endswith(".efi"):
                        continue
                    entry = parse_type2_entry(path)
                if entry is not None:
                    entries.append(entry)

    entries.sort(key=functools.cmp_to_key(compare_loader_entries))
    return entries


def match_loader_entry(entries: list[LoaderEntry], pattern: str) -> LoaderEntry | None:
    pattern = pattern.strip().lower()
    if not pattern:
        return None
    for entry in entries:
        if fnmatch.fnmatchcase(entry.id, pattern):
            return entry
    return None


def select_loader_entry(
    entries: list[LoaderEntry], esp: Path
) -> tuple[LoaderEntry, str]:
    conf = read_loader_conf(esp / "loader" / "loader.conf")
    oneshot = read_efivar("LoaderEntryOneShot")
    default_var = read_efivar("LoaderEntryDefault")
    last_booted = read_efivar("LoaderEntryLastBooted")
    config_default = conf.get("default")

    def lookup(pattern: str | None, source: str) -> tuple[LoaderEntry, str] | None:
        if not pattern:
            return None
        entry = match_loader_entry(entries, pattern)
        if entry is not None:
            return entry, source
        if pattern.strip().lower().startswith("auto-"):
            raise UkiError(
                f"default systemd-boot entry {pattern!r} ({source}) is an "
                "automatic entry, not a Linux kernel entry"
            )
        return None

    for pattern, source in (
        (oneshot, "LoaderEntryOneShot EFI variable"),
        (
            last_booted
            if default_var and default_var.strip().lower() == "@saved"
            else default_var,
            "LoaderEntryLastBooted EFI variable"
            if default_var and default_var.strip().lower() == "@saved"
            else "LoaderEntryDefault EFI variable",
        ),
    ):
        found = lookup(pattern, source)
        if found is not None:
            return found

    if config_default:
        if config_default.strip().lower() == "@saved":
            if not (default_var and default_var.strip().lower() == "@saved"):
                found = lookup(last_booted, "LoaderEntryLastBooted EFI variable")
                if found is not None:
                    return found
        else:
            found = lookup(config_default, "loader.conf default")
            if found is not None:
                return found

    if not entries:
        raise UkiError(f"no systemd-boot entries found on {esp}")
    return entries[0], "automatic selection"


def systemd_boot_roots(esp_override: Path | None = None) -> tuple[Path, Path]:
    if esp_override is not None:
        if not esp_override.is_dir():
            raise UkiError(f"ESP directory not found: {esp_override}")
        return esp_override, esp_override

    esp = bootctl_path("-p")
    boot = bootctl_path("-x")
    if esp is None:
        for candidate in (Path("/efi"), Path("/boot"), ESP_DEFAULT):
            if (
                (candidate / "loader" / "loader.conf").is_file()
                or (candidate / "loader" / "entries").is_dir()
            ):
                esp = candidate
                break
    if esp is None:
        raise UkiError(
            "booted with systemd-boot but cannot locate the ESP; pass --esp"
        )
    if boot is None:
        boot = esp
    if not esp.is_dir():
        raise UkiError(f"ESP directory not found: {esp}")
    return esp, boot


def resolve_systemd_boot(esp_override: Path | None = None) -> ResolvedBoot:
    esp, boot = systemd_boot_roots(esp_override)
    entries = load_systemd_boot_entries(esp, boot)
    if not entries:
        raise UkiError(f"no systemd-boot entries found in {esp} or {boot}")

    entry, source = select_loader_entry(entries, esp)
    current = read_efivar("LoaderEntrySelected")
    if current and current.strip().lower() != entry.id:
        log(f"currently booted entry: {current.strip()} (default entry differs)")

    if entry.kind == "type2":
        raise UkiError(
            f"default systemd-boot entry {entry.id!r} is a Type #2 unified "
            "kernel image; its kernel and initrd are embedded"
        )
    if entry.kind == "uki":
        raise UkiError(
            f"default systemd-boot entry {entry.id!r} uses the uki= key; its "
            "kernel and initrd are embedded"
        )
    if entry.kind == "efi":
        raise UkiError(
            f"default systemd-boot entry {entry.id!r} boots {entry.efi!r}, "
            "which is not a Linux kernel"
        )

    assert entry.linux is not None
    kernel = entry.host_path(entry.linux)
    initrds = [entry.host_path(path) for path in entry.initrds]
    if len(initrds) != 1:
        raise UkiError(
            f"default systemd-boot entry {entry.id!r} has {len(initrds)} "
            "initrds; luksury requires a dracut single-initrd entry"
        )
    roots = _dedupe_roots([esp, boot])

    cmdline, cmdline_source = cmdline_from_root_settings(SYSTEMD_BOOT)
    warn_ignored_entry_cmdline(
        split_options(" ".join(entry.options)),
        cmdline,
        str(entry.path),
    )

    return ResolvedBoot(
        loader=SYSTEMD_BOOT,
        title=entry.title,
        entry_id=entry.id,
        source=source,
        cmdline_source=cmdline_source,
        kernel=kernel,
        initrds=initrds,
        cmdline=cmdline,
        release=entry.version or kernel_release(kernel),
        initrd_roots=roots,
    )


# ---------------------------------------------------------------------------
# ESP / efibootmgr
# ---------------------------------------------------------------------------


def check_tools(no_boot_entry: bool) -> None:
    tools = ["objcopy", "findmnt", "openssl", "sbsign", "sbverify"]
    if not no_boot_entry:
        tools.extend(["efibootmgr", "lsblk"])
    for tool in tools:
        if shutil.which(tool) is None:
            raise UkiError(f"required command not found: {tool}")


def esp_device(esp: Path) -> tuple[str, str, int]:
    source = run(["findmnt", "-no", "SOURCE", "--target", str(esp)]).stdout.strip()
    if not source:
        raise UkiError(f"cannot determine the device backing {esp}")
    source = os.path.realpath(source)

    proc = run(["lsblk", "-no", "PKNAME,PARTN", source])
    fields = proc.stdout.split()
    if len(fields) < 2:
        raise UkiError(f"cannot determine disk/partition for {source}")

    parent, part_number = fields[0], fields[1]
    disk = parent if parent.startswith("/dev/") else f"/dev/{parent}"
    try:
        partition = int(part_number)
    except ValueError as exc:
        raise UkiError(f"invalid partition number {part_number!r} for {source}") from exc
    return source, disk, partition


def efi_entries() -> list[dict[str, object]]:
    output = run(["efibootmgr", "-v"]).stdout
    entries: list[dict[str, object]] = []
    current: dict[str, object] | None = None

    for line in output.splitlines():
        match = re.match(r"^Boot([0-9A-Fa-f]{4})(\*?)\s+(.*)$", line)
        if match:
            current = {
                "id": match.group(1).upper(),
                "active": bool(match.group(2)),
                "label": match.group(3).strip(),
                "text": line,
                "options": b"",
            }
            entries.append(current)
        elif current is not None and line.startswith((" ", "\t")):
            current["text"] = str(current["text"]) + "\n" + line
            data_match = re.match(
                r"^\s*data:\s*((?:[0-9A-Fa-f]{2}\s*)+)$", line
            )
            if data_match:
                try:
                    current["options"] = bytes.fromhex(
                        data_match.group(1)
                    )
                except ValueError:
                    current["options"] = b""

    return entries


def loader_matches(text: str, loader: str) -> bool:
    normalized = text.replace("/", "\\")
    while "\\\\" in normalized:
        normalized = normalized.replace("\\\\", "\\")
    return loader.lower() in normalized.lower()


def efi_entry_main_text(entry: dict[str, object]) -> str:
    return str(entry["text"]).split("\n", 1)[0]


def efi_entry_options_text(entry: dict[str, object]) -> str:
    data = entry.get("options", b"")
    if not isinstance(data, bytes) or not data:
        return ""
    try:
        text = data.decode("utf-16-le")
    except UnicodeDecodeError:
        return ""
    return text.split("\0", 1)[0].strip()


def _normalize_efi_path(value: str) -> str:
    normalized = value.replace("/", "\\").lower()
    while "\\\\" in normalized:
        normalized = normalized.replace("\\\\", "\\")
    return normalized.strip()


def efi_entry_has_path(entry: dict[str, object], path: str) -> bool:
    wanted = _normalize_efi_path(path)
    if not wanted:
        return False
    return (
        wanted in _normalize_efi_path(efi_entry_main_text(entry))
        or wanted in _normalize_efi_path(efi_entry_options_text(entry))
    )


def efi_entry_loader_matches(
    entry: dict[str, object], loader: str
) -> bool:
    return loader_matches(efi_entry_main_text(entry), loader)


def boot_order() -> list[str]:
    output = run(["efibootmgr"]).stdout
    match = re.search(r"^BootOrder:\s*(.*)$", output, re.MULTILINE)
    if not match:
        return []
    return [part.strip().upper() for part in match.group(1).split(",") if part.strip()]


def ensure_boot_entry(esp: Path, label: str, loader: str) -> None:
    """Create the EFI entry that loads the private shim copy.

    shim resolves its default second stage relative to its own directory.
    The entry must therefore load the private shim and must not pass the UKI
    as optional data: some firmware drops that data, and shim then falls back
    to whatever ``grubx64.efi`` sits next to it.
    """
    entries = efi_entries()
    legacy = [
        entry for entry in entries if efi_entry_has_path(entry, EFI_NAME)
    ]
    if legacy:
        ids = ", ".join(f"Boot{entry['id']}" for entry in legacy)
        warn(
            f"legacy luksury boot entries still exist: {ids}; run "
            "'luksury remove' before installing to avoid booting them"
        )
    existing = [
        entry
        for entry in entries
        if efi_entry_loader_matches(entry, loader)
        and not efi_entry_options_text(entry)
    ]

    if existing:
        ids = ", ".join(f"Boot{entry['id']}" for entry in existing)
        log(f"boot entry already exists: {ids}")
        for entry in existing:
            if not entry["active"]:
                warn(f"Boot{entry['id']} exists but is inactive")
        return

    had_order = boot_order()
    source, disk, partition = esp_device(esp)
    log(f"ESP {esp} is {source} ({disk}, partition {partition})")

    create = [
        "efibootmgr",
        "--create",
        "--disk",
        disk,
        "--part",
        str(partition),
        "--label",
        label,
        "--loader",
        loader,
    ]

    run(create)

    entries = efi_entries()
    created = [
        entry
        for entry in entries
        if efi_entry_loader_matches(entry, loader)
        and not efi_entry_options_text(entry)
    ]
    if not created:
        raise UkiError("efibootmgr did not create the expected boot entry")

    new_id = str(created[0]["id"])
    log(f"created Boot{new_id} ({loader})")

    new_order = [new_id] + [item for item in had_order if item != new_id]
    result = run(
        ["efibootmgr", "--bootorder", ",".join(new_order)],
        check=False,
    )
    if result.returncode != 0:
        warn(
            "created the boot entry but could not set BootOrder; "
            f"run 'efibootmgr --bootorder {','.join(new_order)}' manually"
        )
    else:
        log(f"BootOrder: {','.join(new_order)}")


# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------


def install_atomic(
    source: Path, destination: Path, *, root: Path | None = None
) -> None:
    with source.open("rb") as src:
        atomic_replace(
            destination,
            0o644,
            lambda handle: shutil.copyfileobj(src, handle, 1024 * 1024),
            ignore_chmod_error=True,
            root=root,
        )


def files_identical(left: Path, right: Path) -> bool:
    """Return True when both files exist and have the same contents."""
    try:
        if left.stat().st_size != right.stat().st_size:
            return False
        with left.open("rb") as first, right.open("rb") as second:
            while True:
                chunk = first.read(1024 * 1024)
                if chunk != second.read(1024 * 1024):
                    return False
                if not chunk:
                    return True
    except OSError:
        return False


def ensure_shim_loader(
    esp: Path, efi_dir: Path, shim: Path, mmx: Path
) -> None:
    """Copy shim-signed's shim and MokManager into the private shim dir."""
    directory = install_shim_dir(esp, efi_dir)
    for source, name in ((shim, SHIM_NAME), (mmx, MMX_NAME)):
        destination = directory / name
        if destination.is_file() and files_identical(source, destination):
            continue
        install_atomic(source, destination, root=esp)
        log(f"installed {destination}")


def check_space(esp: Path, needed: int) -> None:
    try:
        free = shutil.disk_usage(esp).free
    except OSError:
        return
    if free < needed:
        raise UkiError(
            f"not enough free space on {esp}: need about "
            f"{needed // (1024 * 1024)} MiB, "
            f"have {free // (1024 * 1024)} MiB"
        )


# ---------------------------------------------------------------------------
# Update hook installation
# ---------------------------------------------------------------------------


HOOK_SCRIPT = r"""#!/bin/bash -p
# Installed automatically by luksury.py.
set -u

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset BASH_ENV ENV CDPATH GLOBIGNORE IFS \
      LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG \
      PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONINSPECT PYTHONUSERBASE \
      PYTHONWARNINGS PYTHONBREAKPOINT \
      LUKSURY_BIN LUKSURY_LOCK_FILE LUKSURY_HOOK_ACTIVE

LUKSURY_BIN=/usr/local/sbin/luksury
LOCK_FILE=/run/luksury.lock
PYTHON=/usr/bin/python3

log() {
    printf 'luksury-hook: %s\n' "$*" >&2
    if command -v logger >/dev/null 2>&1; then
        logger -t luksury-hook -p warning -- "$*" 2>/dev/null || true
    fi
}

skip() {
    log "$*; skipping UKI rebuild"
    exit 0
}

if [ "$(id -u)" -ne 0 ]; then
    skip "not running as root"
fi

if ! command -v flock >/dev/null 2>&1; then
    skip "flock not found"
fi

mode=${1:-}
shift || true

if [ "$mode" != "debian-post-update" ]; then
    skip "unknown hook mode: $mode"
fi

version=${1:-}
initrd=${2:-}
if [ -z "$initrd" ]; then
    skip "no initrd path from update-initramfs"
fi

if ! exec 9>"$LOCK_FILE"; then
    skip "cannot open lock file $LOCK_FILE"
fi
# The post-update hook must eventually build the UKI.  Wait for another build
# to finish instead of skipping it.
if ! flock 9; then
    log "cannot take the build lock"
    exit 0
fi

set -- --hook-rebuild --lock-held --non-interactive
[ -n "$version" ] && set -- "$@" --kernel-release "$version"
set -- "$@" --initrd "$initrd"

log "checking UKI (mode=$mode)"

if [ ! -x "$LUKSURY_BIN" ]; then
    skip "$LUKSURY_BIN not found or not executable"
fi
if [ ! -x "$PYTHON" ]; then
    skip "python3 not found at $PYTHON"
fi
if ! "$PYTHON" -I -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
    skip "python3 >= 3.9 is required"
fi
if ! "$PYTHON" -I -c 'import argparse, dataclasses, fnmatch, functools, hashlib, json, os, pathlib, platform, re, shlex, shutil, stat, subprocess, sys, tempfile, uuid' >/dev/null 2>&1; then
    skip "required Python modules are unavailable"
fi

for cmd in objcopy findmnt openssl sbsign sbverify; do
    command -v "$cmd" >/dev/null 2>&1 || skip "required command not found: $cmd"
done
if ! command -v dracut >/dev/null 2>&1 && [ ! -x /usr/bin/dracut ]; then
    skip "dracut not found"
fi

if command -v cryptsetup >/dev/null 2>&1 || [ -x /usr/sbin/cryptsetup ] || [ -x /sbin/cryptsetup ]; then
    have_cryptsetup=1
else
    have_cryptsetup=0
fi
if command -v systemd-cryptenroll >/dev/null 2>&1 || [ -x /usr/bin/systemd-cryptenroll ]; then
    have_systemd_cryptenroll=1
else
    have_systemd_cryptenroll=0
fi
if [ "$have_cryptsetup" = "1" ] && [ "$have_systemd_cryptenroll" = "1" ]; then
    :
elif [ -e /var/lib/luksury/tpm2-state.json ]; then
    skip "cryptsetup or systemd-cryptenroll not found but a TPM2 enrollment is recorded"
else
    log "cryptsetup or systemd-cryptenroll not found; rebuilding without TPM2 enrollment"
    set -- "$@" --no-enroll-tpm2
fi

if ! "$PYTHON" -I "$LUKSURY_BIN" "$@"; then
    log "UKI rebuild failed"
fi
exit 0
"""


DEBIAN_POST_UPDATE_WRAPPER = f"""#!/bin/sh
exec {HOOK_PATH} debian-post-update "$@"
"""


def write_system_file(path: Path, content: str, mode: int) -> None:
    """Write a root-owned system file atomically if its content changed."""
    data = content.encode("utf-8")
    try:
        if path.is_file() and path.read_bytes() == data:
            if (path.stat().st_mode & 0o777) != mode:
                os.chmod(path, mode)
            return
    except OSError:
        pass

    atomic_replace(path, mode, lambda handle: handle.write(data))
    log(f"installed {path}")


def install_self() -> None:
    """Copy the running script to the system binary directory."""
    source = Path(__file__).resolve()
    target = INSTALL_BIN
    try:
        if source == target or paths_same(source, target):
            if (target.stat().st_mode & 0o777) != 0o755:
                os.chmod(target, 0o755)
            return
        if target.is_file() and target.read_bytes() == source.read_bytes():
            if (target.stat().st_mode & 0o777) != 0o755:
                os.chmod(target, 0o755)
            return

        with source.open("rb") as src:
            atomic_replace(
                target,
                0o755,
                lambda handle: shutil.copyfileobj(src, handle, 1024 * 1024),
            )
    except OSError as exc:
        raise UkiError(f"cannot install {target}: {exc}") from exc
    log(f"installed {target}")


def install_debian_hooks() -> None:
    path = INITRAMFS_POST_UPDATE_DIR / "zz-luksury"
    write_system_file(path, DEBIAN_POST_UPDATE_WRAPPER, 0o755)


def remove_legacy_systemd_units(
    *, dry_run: bool = False, verbose: bool = False
) -> None:
    """Remove the old path/timer/service units and kernel postinst hook.

    luksury now builds the UKI only from the initramfs post-update hook.
    Existing installations may still have the old units enabled, so install
    and remove both clean them up.
    """
    units = (
        "luksury-rebuild.path",
        "luksury-rebuild.timer",
        "luksury-rebuild.service",
    )
    systemctl = shutil.which("systemctl")
    if dry_run:
        if systemctl is not None:
            log("would disable and stop legacy luksury-rebuild units")
            log("would reload the systemd manager configuration")
    elif systemctl is not None and Path("/run/systemd/system").is_dir():
        for unit in ("luksury-rebuild.path", "luksury-rebuild.timer"):
            run([systemctl, "disable", "--now", unit], check=False)
        run([systemctl, "stop", "luksury-rebuild.service"], check=False)
        run([systemctl, "daemon-reload"], check=False)

    try:
        wants_links = sorted(
            SYSTEMD_UNIT_DIR.glob("*.wants/luksury-rebuild.*")
        )
    except OSError:
        wants_links = []
    for path in wants_links:
        remove_path(path, dry_run=dry_run, verbose=verbose)

    for name in units:
        remove_path(
            SYSTEMD_UNIT_DIR / name, dry_run=dry_run, verbose=verbose
        )
    remove_path(
        KERNEL_POSTINST_DIR / "zzz-luksury",
        dry_run=dry_run,
        verbose=verbose,
    )

    if (
        not dry_run
        and systemctl is not None
        and Path("/run/systemd/system").is_dir()
    ):
        run([systemctl, "daemon-reload"], check=False)


def ensure_update_hook() -> None:
    """Install or refresh the initramfs post-update hook."""
    if os.geteuid() != 0:
        raise UkiError("must be run as root to install the update hook")
    try:
        install_self()
        write_system_file(HOOK_PATH, HOOK_SCRIPT, 0o755)
    except (OSError, UkiError) as exc:
        raise UkiError(f"cannot install update hook: {exc}") from exc

    try:
        install_debian_hooks()
        remove_legacy_systemd_units()
    except (OSError, UkiError) as exc:
        raise UkiError(f"cannot install distribution hook: {exc}") from exc


def read_os_release(path: Path = OS_RELEASE) -> dict[str, str]:
    try:
        return parse_os_release_data(path.read_bytes())
    except OSError:
        return {}


def sanitize_efi_component(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip().lower())
    return value.strip(".-_") or "linux"


def default_efi_dir(values: dict[str, str]) -> Path:
    identifier = (values.get("ID") or "").strip()
    if not identifier:
        id_like = (values.get("ID_LIKE") or "").split()
        identifier = id_like[0] if id_like else ""
    if not identifier:
        identifier = values.get("NAME") or ""
    return Path("EFI") / sanitize_efi_component(identifier)


def default_boot_label(values: dict[str, str]) -> str:
    name = (
        values.get("NAME")
        or values.get("PRETTY_NAME")
        or values.get("ID")
        or "Linux"
    )
    return f"{name.strip()} UKI"


def install_paths(args: argparse.Namespace) -> tuple[Path, str]:
    """Return the resolved UKI directory and EFI boot label."""
    os_release = read_os_release(OS_RELEASE)
    efi_dir = args.efi_dir or default_efi_dir(os_release)
    label = args.label or default_boot_label(os_release)
    return efi_dir, label


def save_install_options(args: argparse.Namespace) -> None:
    """Persist the options the non-interactive hook must reuse."""
    data = {
        "version": INSTALL_OPTIONS_VERSION,
        "esp": str(args.esp) if args.esp else None,
        "efi_dir": str(args.efi_dir) if args.efi_dir else None,
        "label": args.label,
        "no_enroll_tpm2": bool(args.no_enroll_tpm2),
        "unlock_key_file": (
            str(args.unlock_key_file) if args.unlock_key_file else None
        ),
        "pcr4_no_kernel": bool(args.pcr4_no_kernel),
        "pcr4_kernel": bool(args.pcr4_kernel),
        "signing_key": str(args.signing_key) if args.signing_key else None,
        "signing_cert": str(args.signing_cert) if args.signing_cert else None,
        "verbose": bool(args.verbose),
    }
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    write_private_file(INSTALL_OPTIONS_FILE, payload.encode("utf-8"))


def load_install_options() -> dict:
    try:
        text = INSTALL_OPTIONS_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError) as exc:
        raise UkiError(f"cannot read install options: {exc}") from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UkiError(f"cannot parse install options: {exc}") from exc
    if not isinstance(data, dict):
        raise UkiError("invalid install options: not a JSON object")
    if data.get("version") != INSTALL_OPTIONS_VERSION:
        raise UkiError("invalid install options: unsupported version")
    return data


def apply_install_options(args: argparse.Namespace) -> None:
    """Apply persisted options to the hook's argument namespace."""
    options = load_install_options()
    if not options:
        return

    if args.esp is None and options.get("esp"):
        args.esp = str(options["esp"])
    if args.efi_dir is None and options.get("efi_dir"):
        try:
            args.efi_dir = efi_dir_arg(str(options["efi_dir"]))
        except argparse.ArgumentTypeError as exc:
            raise UkiError(f"invalid stored efi_dir: {exc}") from exc
    if args.label is None and options.get("label"):
        args.label = str(options["label"])
    if args.unlock_key_file is None and options.get("unlock_key_file"):
        args.unlock_key_file = Path(str(options["unlock_key_file"]))
    if args.signing_key is None and options.get("signing_key"):
        args.signing_key = str(options["signing_key"])
    if args.signing_cert is None and options.get("signing_cert"):
        args.signing_cert = str(options["signing_cert"])
    for name in (
        "no_enroll_tpm2",
        "pcr4_no_kernel",
        "pcr4_kernel",
        "verbose",
    ):
        if options.get(name):
            setattr(args, name, True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def efi_dir_arg(value: str) -> Path:
    if not value.strip():
        raise argparse.ArgumentTypeError("must not be empty")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise argparse.ArgumentTypeError(
            "must be a relative path below the ESP"
        )
    return path


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=(
            "Bootstrap the luksury installation.  The first run requires "
            "UEFI and works with Secure Boot enabled or disabled.  It "
            "creates/reuses a UKI signing key, queues a MOK enrollment only "
            "when Secure Boot is enforcing, installs the update hook, "
            "prepares the recovery key/crypttab and regenerates the initrd; "
            "only the post-update hook builds, signs and installs the UKI."
        ),
        epilog=(
            "A real bootstrap installs the update hook and regenerates the "
            "initrd; the generated UKI is built and signed by the hook and "
            "loaded through shim-signed's shim.  When Secure Boot is "
            "enforcing, "
            "the MOK enrollment is confirmed in MokManager after a reboot; "
            "when it is disabled, no MOK enrollment is needed and PCR7 is not "
            "bound.  The installer never reboots automatically.  Use "
            "--dry-run to inspect without changing anything.  Run 'luksury "
            "remove --help' to uninstall the luksury artifacts again."
        ),
    )
    parser.add_argument(
        "--esp",
        default=None,
        help=(
            "ESP mount point (default: auto-detected for systemd-boot, "
            f"{ESP_DEFAULT} otherwise)"
        ),
    )
    parser.add_argument(
        "--efi-dir",
        type=efi_dir_arg,
        default=None,
        help=(
            "UKI directory relative to the ESP (default: EFI/<ID> from "
            "/etc/os-release)"
        ),
    )
    parser.add_argument(
        "--label",
        default=None,
        help=(
            "efibootmgr entry label (default: <NAME> UKI from "
            "/etc/os-release)"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show what would be installed/changed, without changing anything",
    )
    parser.add_argument(
        "--no-boot-entry",
        action="store_true",
        help="do not create an efibootmgr entry during bootstrap",
    )
    parser.add_argument(
        "--pcr4-no-kernel",
        action="store_true",
        help=(
            "do not include a separate PCR4 measurement for the embedded "
            ".linux kernel (overrides the systemd-stub version gate)"
        ),
    )
    parser.add_argument(
        "--pcr4-kernel",
        action="store_true",
        help=(
            "force a separate PCR4 measurement for the embedded .linux "
            "kernel (used only when the current boot's event log cannot "
            "show what the firmware measured)"
        ),
    )
    parser.add_argument(
        "--no-enroll-tpm2",
        action="store_true",
        help=(
            "skip TPM2 enrollment in the hook and do not prepare the "
            "crypttab/recovery key"
        ),
    )
    parser.add_argument(
        "--unlock-key-file",
        type=Path,
        default=None,
        help=(
            "key file used to authorize TPM2 enrollment (default: use the "
            "existing TPM2 token, then prompt)"
        ),
    )
    parser.add_argument(
        "--signing-key",
        type=Path,
        default=None,
        help=(
            "PEM private key used to sign the UKI (default: the luksury "
            "MOK key in /var/lib/luksury)"
        ),
    )
    parser.add_argument(
        "--signing-cert",
        type=Path,
        default=None,
        help=(
            "PEM signing certificate enrolled in db or MOK (default: the "
            "luksury MOK certificate in /var/lib/luksury)"
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="show section sizes and addresses",
    )
    parser.add_argument(
        "--hook-rebuild",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--kernel-release", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--initrd", type=Path, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--force", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--lock-held", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser


def remove_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=(
            "Remove the luksury artifacts: the UKI, matching EFI boot "
            "entries, the update hook, the installed copy, all systemd-tpm2 "
            "enrollments, the recovery key itself and its token, crypttab "
            "options, install options and state files.  The MOK signing key "
            "and its MOK enrollment are left in place."
        ),
        epilog=(
            "No confirmation is requested.  Use --dry-run first to inspect "
            "what would be removed.  When keyslots would be removed, an "
            "existing passphrase may be requested to verify that an "
            "alternative unlock remains."
        ),
    )
    parser.add_argument(
        "--esp",
        default=None,
        help=(
            "ESP mount point (default: auto-detected for systemd-boot, "
            f"{ESP_DEFAULT} otherwise)"
        ),
    )
    parser.add_argument(
        "--efi-dir",
        type=efi_dir_arg,
        default=None,
        help=(
            "UKI directory relative to the ESP (default: EFI/<ID> from "
            "/etc/os-release, plus any other luksury.efi found)"
        ),
    )
    parser.add_argument(
        "--unlock-key-file",
        type=Path,
        default=None,
        help=(
            "key file used to authorize removal of LUKS keyslots (default: "
            "the stored recovery key, then prompt)"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show what would be removed, without changing anything",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="also report artifacts that were already absent",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser


def main_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=(
            "Bootstrap the luksury installation and regenerate the initrd; the "
            "post-update hook builds and signs the UKI.  Or remove the "
            "luksury artifacts again."
        ),
        epilog=(
            "Run 'luksury install --help' or 'luksury remove --help' for "
            "the options of each command."
        ),
    )
    subparsers = parser.add_subparsers(
        dest="command", metavar="COMMAND"
    )

    build = build_arg_parser()
    subparsers.add_parser(
        "install",
        parents=[build],
        add_help=False,
        allow_abbrev=False,
        help="bootstrap the update hook and regenerate the initrd (default)",
        description=build.description,
        epilog=build.epilog,
    )

    remove = remove_arg_parser()
    subparsers.add_parser(
        "remove",
        parents=[remove],
        add_help=False,
        allow_abbrev=False,
        help="remove all installed artifacts",
        description=remove.description,
        epilog=remove.epilog,
    )
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    if argv is None:
        argv = sys.argv[1:]
    arguments = list(argv)
    if arguments and arguments[0] == "build":
        arguments[0] = "install"
    if not arguments or arguments[0] not in (
        "install",
        "remove",
        "-h",
        "--help",
    ):
        arguments.insert(0, "install")

    return main_arg_parser().parse_args(arguments)


def acquire_build_lock(lock_held: bool = False) -> int | None:
    """Take the build lock unless the update hook already owns it."""
    if lock_held:
        return None

    import fcntl

    try:
        fd = os.open(BUILD_LOCK_FILE, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as exc:
        raise UkiError(f"cannot open build lock {BUILD_LOCK_FILE}: {exc}") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise UkiError("another luksury build is already running") from exc
    return fd


def main(argv: list[str] | None = None) -> int:
    global NON_INTERACTIVE

    args = parse_args(argv)
    sanitize_environment()
    NON_INTERACTIVE = args.non_interactive
    lock_fd: int | None = None
    try:
        if os.geteuid() != 0:
            raise UkiError("must be run as root (try: sudo ./luksury.py)")
        lock_fd = acquire_build_lock(
            bool(getattr(args, "lock_held", False))
        )
        if args.command == "remove":
            return run_remove(args)
        if args.hook_rebuild:
            return run_hook_rebuild(args)
        return run_install(args, lock_fd)
    except UkiError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"error: permission denied: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except OSError:
                pass


def resolve_boot_entry(
    loader: str, esp_override: Path | None
) -> tuple[Path, ResolvedBoot]:
    if loader == SYSTEMD_BOOT:
        esp, _ = systemd_boot_roots(esp_override)
        return esp, resolve_systemd_boot(esp_override)
    esp = esp_override or ESP_DEFAULT
    return esp, resolve_grub_boot(esp)


def validate_resolved_boot(boot: ResolvedBoot) -> None:
    """Validate paths before they are copied into the build directory."""
    if not os.path.isfile(boot.kernel):
        raise UkiError(f"kernel not found: {boot.kernel}")
    if os.path.getsize(boot.kernel) == 0:
        raise UkiError(f"kernel is empty: {boot.kernel}")
    if len(boot.initrds) != 1:
        raise UkiError(
            f"default entry {boot.title!r} has {len(boot.initrds)} initrds; "
            "luksury requires a dracut single-initrd entry"
        )

    roots = boot.initrd_roots or initrd_roots()
    for path in boot.initrds:
        try:
            resolved = Path(path).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise UkiError(f"initrd not found: {path}: {exc}") from exc
        if not resolved.is_file():
            raise UkiError(f"initrd is not a regular file: {path}")
        if not any(resolved.is_relative_to(root) for root in roots):
            raise UkiError(f"initrd is outside the boot filesystems: {path}")
        if os.path.getsize(resolved) == 0:
            raise UkiError(f"initrd is empty: {path}")

    if not any(arg.startswith("root=") for arg in boot.cmdline):
        warn(f"default entry {boot.title!r} has no root= in its command line")
    if not boot.release:
        warn(
            f"cannot determine kernel release from {boot.kernel}; "
            "omitting .uname"
        )


def validate_prepared_boot(boot: ResolvedBoot) -> None:
    """Validate the private kernel/initrd copies used for the build."""
    if not os.path.isfile(boot.kernel):
        raise UkiError(f"prepared kernel not found: {boot.kernel}")
    if os.path.getsize(boot.kernel) == 0:
        raise UkiError(f"prepared kernel is empty: {boot.kernel}")
    try:
        with open(boot.kernel, "rb") as handle:
            magic = handle.read(2)
    except OSError as exc:
        raise UkiError(f"cannot read {boot.kernel}: {exc}") from exc
    if magic != b"MZ":
        warn(f"{boot.kernel} does not look like a PE kernel image")

    if len(boot.initrds) != 1:
        raise UkiError(
            f"default entry {boot.title!r} has {len(boot.initrds)} initrds; "
            "luksury requires a dracut single-initrd entry"
        )
    path = boot.initrds[0]
    if not os.path.isfile(path):
        raise UkiError(f"prepared initrd not found: {path}")
    if os.path.getsize(path) == 0:
        raise UkiError(f"prepared initrd is empty: {path}")


# ---------------------------------------------------------------------------
# Initrd handling
# ---------------------------------------------------------------------------


def _looks_like_initrd(path: Path) -> bool:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise UkiError(f"initrd {path} is not a regular file")
            head = handle.read(8)
    except OSError as exc:
        raise UkiError(f"cannot read initrd {path}: {exc}") from exc
    return any(head.startswith(magic) for magic in INITRD_MAGIC)


def _copy_to_workdir(source: Path, workdir: Path, prefix: str) -> Path:
    """Copy a file into the root-only work directory as a private temp file."""
    fd, temporary = tempfile.mkstemp(prefix=prefix, dir=str(workdir))
    try:
        try:
            source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise UkiError(f"cannot open {source}: {exc}") from exc
        with os.fdopen(source_fd, "rb") as src, os.fdopen(fd, "wb") as out:
            info = os.fstat(src.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise UkiError(f"{source} is not a regular file")
            shutil.copyfileobj(src, out, 1024 * 1024)
            out.flush()
            os.fsync(out.fileno())
            try:
                os.fchmod(out.fileno(), 0o600)
            except OSError:
                pass
            out_info = os.fstat(out.fileno())
        try:
            current = os.lstat(temporary)
        except OSError as exc:
            raise UkiError(
                f"cannot inspect temporary file {temporary}: {exc}"
            ) from exc
        if (
            not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino)
            != (out_info.st_dev, out_info.st_ino)
        ):
            raise UkiError(
                f"temporary file {temporary} was replaced while writing"
            )
        return Path(temporary)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def copy_kernel_to_workdir(path: Path | str, workdir: Path) -> Path:
    """Take a private copy of the kernel before any sanity check or build."""
    return _copy_to_workdir(Path(path), workdir, "kernel-")


def copy_initrd(
    path: Path | str,
    workdir: Path,
    roots: tuple[Path, ...],
) -> Path:
    """Copy a confined initrd into the root-only work directory."""
    resolved = _confined_file(Path(path), roots, "initrd")
    copied = _copy_to_workdir(resolved, workdir, "initrd-")
    if not _looks_like_initrd(copied):
        try:
            copied.unlink()
        except OSError:
            pass
        raise UkiError(f"{resolved} does not look like an initrd")
    return copied


def prepare_resolved_boot(
    boot: ResolvedBoot, workdir: Path
) -> ResolvedBoot:
    """Copy kernel and initrds, then verify the private copies."""
    kernel_copy = copy_kernel_to_workdir(boot.kernel, workdir)
    roots = boot.initrd_roots or initrd_roots()
    initrd_copies = [
        copy_initrd(path, workdir, roots) for path in boot.initrds
    ]
    prepared = replace(
        boot,
        kernel=str(kernel_copy),
        initrds=[str(path) for path in initrd_copies],
        initrd_roots=(),
    )
    validate_prepared_boot(prepared)
    verify_kernel_authenticity(
        Path(prepared.kernel),
        boot.release,
        reference_path=Path(boot.kernel),
    )
    return prepared


# ---------------------------------------------------------------------------
# Kernel authenticity
# ---------------------------------------------------------------------------


def _hash_file(path: Path, digest) -> bytes:
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise UkiError(f"cannot read {path}: {exc}") from exc
    return digest.digest()


def file_md5(path: Path) -> bytes:
    # dpkg still records MD5; keep working when the host is in FIPS mode.
    return _hash_file(path, hashlib.md5(usedforsecurity=False))


def parse_md5sum_line(line: str) -> tuple[str, str] | None:
    fields = line.split(None, 1)
    if len(fields) != 2:
        return None
    digest, name = fields
    if len(digest) != 32:
        return None
    try:
        int(digest, 16)
    except ValueError:
        return None
    name = name.lstrip("*")
    while name.startswith("./"):
        name = name[2:]
    return digest.lower(), name.lstrip("/")


def kernel_md5sum_targets(kernel: Path, release: str | None) -> set[str]:
    targets: set[str] = set()
    try:
        real = os.path.realpath(kernel)
        targets.add(os.path.relpath(real, "/"))
    except ValueError:
        pass
    if release:
        targets.add(f"boot/vmlinuz-{release}")
    return targets


def dpkg_kernel_md5sums(kernel: Path, release: str | None) -> list[str]:
    """Return dpkg-recorded MD5 sums for the kernel, if any."""
    targets = kernel_md5sum_targets(kernel, release)
    if not targets or not DPKG_INFO_DIR.is_dir():
        return []

    digests: list[str] = []
    seen_files: set[Path] = set()
    for pattern in ("linux-image-*.md5sums", "*.md5sums"):
        for info in sorted(DPKG_INFO_DIR.glob(pattern)):
            if info in seen_files:
                continue
            seen_files.add(info)
            try:
                text = info.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                record = parse_md5sum_line(line)
                if record is not None and record[1] in targets:
                    digests.append(record[0])
        if digests:
            break
    return digests


def verify_kernel_authenticity(
    kernel: Path,
    release: str | None,
    *,
    reference_path: Path | None = None,
) -> None:
    """Check a kernel copy against the dpkg MD5 checksum of the source."""
    reference = reference_path or kernel
    release = release or kernel_release(str(reference))
    suffix = f" [{release}]" if release else ""
    log(f"verifying kernel authenticity{suffix}")

    digests = dpkg_kernel_md5sums(reference, release)
    if digests:
        actual = file_md5(kernel).hex()
        if actual in digests:
            label = f"vmlinuz-{release}" if release else kernel.name
            log(f"kernel authenticity: matches dpkg md5sum for {label}")
            return
        raise UkiError(
            f"kernel {reference} does not match the dpkg md5sum; refusing to "
            "build a UKI"
        )

    raise UkiError(
        f"cannot verify kernel authenticity for {reference}: no dpkg "
        "checksum; refusing to build a UKI"
    )


def run_main(
    args: argparse.Namespace,
    *,
    boot: ResolvedBoot,
    esp: Path,
    secure_boot: bool | None = None,
) -> int:
    stub = STUB_DEFAULT
    check_tools(args.no_boot_entry)
    if secure_boot is None:
        secure_boot = require_uefi_boot()
    if args.pcr4_kernel and args.pcr4_no_kernel:
        raise UkiError(
            "--pcr4-kernel and --pcr4-no-kernel are mutually exclusive"
        )

    if not stub.is_file():
        raise UkiError(f"systemd stub not found: {stub}")
    if not OS_RELEASE.is_file():
        raise UkiError(f"missing {OS_RELEASE}")

    efi_dir, label = install_paths(args)
    try:
        esp = esp.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UkiError(f"cannot resolve ESP {esp}: {exc}") from exc
    destination = install_destination(esp, efi_dir)
    shim = shim_signed_path()
    mmx = shim_signed_mmx_path()

    material = load_signing_material(args)
    if material.state == "missing":
        raise UkiError(
            "no UKI signing key is configured; run the installer first"
        )
    if material.state not in ("enrolled", "pending"):
        if secure_boot:
            raise UkiError(
                "the UKI signing certificate is not enrolled or pending; run "
                "the installer interactively to queue it"
            )
        log(
            "Secure Boot is disabled; signing with the untrusted certificate "
            f"{material.cert} without MOK enrollment"
        )

    enroll = not args.no_enroll_tpm2
    if enroll and material.state == "pending":
        if secure_boot:
            log(
                "MOK signing certificate is pending enrollment; the TPM "
                "token will be bound to the post-enrollment PCR7 value"
            )
        else:
            log(
                "MOK signing certificate is pending enrollment; Secure Boot "
                "is disabled and the TPM token does not bind PCR7"
            )

    workdir = Path(tempfile.mkdtemp(prefix="luksury-"))
    try:
        validate_resolved_boot(boot)
        prepared = prepare_resolved_boot(boot, workdir)

        kernel_path = prepared.kernel
        initrd_paths = prepared.initrds
        cmdline = prepared.cmdline
        release = prepared.release

        crypttab_entry: CrypttabEntry | None = None
        if enroll:
            try:
                crypttab_entry = find_root_crypttab_entry(CRYPTTAB)
                changed = update_crypttab_tpm2(
                    CRYPTTAB, crypttab_entry.name
                )
                if changed:
                    hint = (
                        f"update-initramfs -u -k {release}"
                        if release
                        else "update-initramfs -u -k <release>"
                    )
                    warn(
                        "crypttab changed; regenerate the default entry's "
                        f"initrd externally (for example with {hint}) before "
                        "rebooting so it includes the new TPM2 options"
                    )
            except UkiError as exc:
                warn(f"TPM2 enrollment disabled: {exc}")
                enroll = False
                crypttab_entry = None

        log(
            f"default {boot.loader} entry: {boot.title!r}"
            + (f" (id {boot.entry_id})" if boot.entry_id else "")
            + f", resolved from {boot.source}"
        )
        log(f"kernel:  {kernel_path}" + (f"  [{release}]" if release else ""))
        for path in initrd_paths:
            log(f"initrd:  {path}")
        log(f"cmdline ({boot.cmdline_source}): {' '.join(cmdline)}")
        log(f"UKI:     {destination}")
        log(f"shim:    {shim}")

        if not esp.is_dir():
            raise UkiError(f"ESP directory not found: {esp}")

        sizes = planned_sizes(
            OS_RELEASE, kernel_path, initrd_paths, cmdline, release
        )
        loader_size = 0
        shim_dir = install_shim_dir(esp, efi_dir)
        for source, name in ((shim, SHIM_NAME), (mmx, MMX_NAME)):
            copy = shim_dir / name
            if not (copy.is_file() and files_identical(source, copy)):
                loader_size += source.stat().st_size
        check_space(
            esp,
            sum(size for _, size in sizes)
            + SIGNATURE_SLACK
            + loader_size,
        )
        ensure_shim_loader(esp, efi_dir, shim, mmx)
        shim = installed_shim_path(esp, efi_dir)
        log(f"shim copy: {shim}")
        log(f"stub:    {stub}")

        unsigned = build_uki(
            stub=stub,
            osrel=OS_RELEASE,
            kernel=kernel_path,
            initrds=initrd_paths,
            cmdline=cmdline,
            release=release,
            workdir=workdir,
            verbose=args.verbose,
        )
        built = sign_uki(unsigned, material, workdir)

        include_kernel: bool | None = None
        if enroll:
            forced: bool | None = None
            if args.pcr4_kernel:
                forced = True
            elif args.pcr4_no_kernel:
                forced = False
            try:
                detected = (
                    current_uki_kernel_in_pcr4(
                        destination, PCR_ALGORITHM_DEFAULT
                    )
                    if destination.is_file()
                    else None
                )
                if detected is not None:
                    include_kernel = detected
                    source = "current boot's PCR4 event log"
                    if forced is not None and forced != detected:
                        warn(
                            "ignoring the --pcr4-kernel/--pcr4-no-kernel "
                            "override: the current boot's PCR4 event log "
                            f"shows the kernel is "
                            f"{'measured' if detected else 'not measured'}"
                        )
                elif forced is not None:
                    include_kernel = forced
                    source = "forced"
                else:
                    include_kernel = boot_chain_measures_kernel_in_pcr4(
                        stub
                    )
                    stub_ver = stub_version(stub)
                    shim_ver = shim_version(shim)
                    stub_label = (
                        version_string(stub_ver)
                        if stub_ver is not None
                        else "unknown"
                    )
                    shim_label = (
                        version_string(shim_ver)
                        if shim_ver is not None
                        else "unknown"
                    )
                    source = (
                        f"systemd-stub {stub_label}, shim {shim_label}"
                    )
                log(
                    "PCR4 kernel measurement: "
                    f"{'yes' if include_kernel else 'no'} ({source})"
                )
            except UkiError as exc:
                warn(
                    "cannot determine the PCR4 kernel measurement: "
                    f"{exc}"
                )
                include_kernel = None

        prediction: Pcr4Prediction | None = None
        prediction7: Pcr7Prediction | None = None
        prediction12: Pcr12Prediction | None = None
        if enroll and include_kernel is not None:
            # destination still contains the currently installed UKI.  Its
            # digest identifies the UKI event even when firmware wrote a
            # malformed device path.
            stop_hashes = pcr4_boot_target_hashes(
                esp,
                destination if destination.is_file() else None,
                PCR_ALGORITHM_DEFAULT,
            )
            stop_hashes.add(pe_image_hash(shim, PCR_ALGORITHM_DEFAULT))
            log(f"PCR4 boot-chain targets: {len(stop_hashes)}")
            try:
                prediction = precompute_pcr4(
                    shim,
                    built,
                    algorithm=PCR_ALGORITHM_DEFAULT,
                    include_embedded_kernel=include_kernel,
                    stop_hashes=stop_hashes,
                )
            except UkiError as exc:
                warn(f"cannot predict PCR4: {exc}")
                prediction = None

            if prediction is not None:
                log(
                    f"PCR4 firmware prefix ({prediction.prefix_source}): "
                    f"{prediction.prefix.hex()}"
                )
                labels = ("shim", "UKI", ".linux")
                for index, digest in enumerate(prediction.measurements):
                    label = labels[index] if index < len(labels) else "?"
                    log(f"PCR4 {label:7s} {digest.hex()}")
                log(
                    f"PCR4 predicted (shim-chained UKI): "
                    f"{prediction.predicted.hex()}"
                )

            if secure_boot:
                try:
                    prediction7 = precompute_pcr7(
                        built,
                        shim,
                        material,
                        workdir=workdir,
                        esp=esp,
                        efi_dir=efi_dir,
                        current_uki=destination,
                        algorithm=PCR_ALGORITHM_DEFAULT,
                    )
                except UkiError as exc:
                    warn(f"cannot predict PCR7: {exc}")
                    prediction7 = None

                if prediction7 is not None:
                    log(
                        f"PCR7 predicted ({prediction7.source}, "
                        f"{prediction7.authority}): {prediction7.value.hex()}"
                    )
            else:
                log(
                    "Secure Boot is disabled: PCR7 is not bound; PCR4 "
                    "covers the shim, kernel and initrd through the UKI"
                )

            try:
                prediction12 = precompute_pcr12(
                    esp,
                    efi_dir,
                    stub=stub,
                    algorithm=PCR_ALGORITHM_DEFAULT,
                )
            except UkiError as exc:
                warn(f"cannot predict PCR12: {exc}")
                prediction12 = None

            if prediction12 is not None:
                if prediction12.cpio_digest is not None:
                    log(
                        "PCR12 global credentials cpio "
                        f"({len(prediction12.credentials)} file(s)): "
                        f"{prediction12.cpio_digest.hex()}"
                    )
                    for path in prediction12.credentials:
                        log(f"PCR12 credential: {path.name}")
                log(
                    f"PCR12 predicted ({prediction12.source}): "
                    f"{prediction12.value.hex()}"
                )
        elif enroll:
            warn(
                "TPM2 enrollment skipped: cannot determine whether "
                "systemd-stub measures the embedded kernel into PCR4"
            )

        binding: dict[int, bytes] | None = None
        if (
            prediction is not None
            and prediction12 is not None
            and (prediction7 is not None or not secure_boot)
        ):
            target_separator = target_uses_os_separator(cmdline)
            try:
                current_separator = current_boot_os_separator(
                    PCR_ALGORITHM_DEFAULT
                )
                binding = next_boot_tpm2_pcrs(
                    PCR_ALGORITHM_DEFAULT,
                    prediction.predicted,
                    prediction7,
                    pcr12_preboot=prediction12.value,
                    current_separator=current_separator,
                    target_separator=target_separator,
                )
            except UkiError as exc:
                warn(f"cannot compute the TPM2 PCR binding: {exc}")
            else:
                log(
                    "systemd os-separator: "
                    f"current={'yes' if current_separator else 'no'}, "
                    f"next={'yes' if target_separator else 'no'}"
                )
                for index in sorted(binding):
                    log(f"PCR{index:<2d} binding {binding[index].hex()}")
                if 7 not in binding:
                    log(
                        "PCR7 is not part of the binding; PCR4 binds the "
                        "complete UKI, which contains the kernel and initrd"
                    )

        measured_digest: bytes | None = None
        if prediction is not None:
            measured_digest = pe_image_hash(built, PCR_ALGORITHM_DEFAULT)
        install_atomic(built, destination, root=esp)
        installed_size = destination.stat().st_size
        log(f"installed {destination} ({installed_size} bytes)")
        if measured_digest is not None and (
            pe_image_hash(destination, PCR_ALGORITHM_DEFAULT)
            != measured_digest
        ):
            raise UkiError(
                f"installed UKI {destination} does not match the image used "
                "for the PCR4 prediction"
            )

        if not args.no_boot_entry:
            ensure_boot_entry(
                esp, label, installed_shim_relative(efi_dir)
            )

        enrolled = False
        if enroll and crypttab_entry is not None and binding is not None:
            device = crypttab_device(crypttab_entry)
            keyfile = args.unlock_key_file or crypttab_unlock_key_file(
                crypttab_entry
            )
            try:
                keyfile = ensure_recovery_key(
                    device,
                    key_file=RECOVERY_KEY_FILE,
                    unlock_key_file=keyfile,
                )
                cryptenroll_tpm2(
                    device,
                    binding,
                    algorithm=PCR_ALGORITHM_DEFAULT,
                    unlock_key_file=keyfile,
                    state_file=TPM2_STATE_FILE,
                )
                enrolled = True
            except UkiError as exc:
                warn(f"TPM2 enrollment failed: {exc}")
        elif enroll and crypttab_entry is not None:
            warn(
                "TPM2 enrollment skipped: no complete TPM2 PCR binding "
                "available"
            )

        if enrolled:
            log(
                "TPM2 enrollment updated; reboot to use the new TPM2 PCR "
                "binding"
            )

        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def run_install(args: argparse.Namespace, lock_fd: int | None = None) -> int:
    """Bootstrap luksury; the post-update hook is the only UKI builder."""
    check_tools(args.no_boot_entry)
    secure_boot = require_uefi_boot()

    if not OS_RELEASE.is_file():
        raise UkiError(f"missing {OS_RELEASE}")
    efi_dir, label = install_paths(args)

    esp_override = Path(args.esp) if args.esp else None
    loader = detect_boot_loader(esp_override)
    esp, boot = resolve_boot_entry(loader, esp_override)
    try:
        esp = esp.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UkiError(f"cannot resolve ESP {esp}: {exc}") from exc
    destination = install_destination(esp, efi_dir)
    shim = shim_signed_path()
    mmx = shim_signed_mmx_path()

    update_initramfs = require_dracut()
    release = boot.release or kernel_release(boot.kernel)
    if not release:
        raise UkiError(
            "cannot determine the default entry's kernel release; "
            "refusing to regenerate initrds because luksury only "
            "regenerates the default entry's initrd"
        )

    if not args.no_enroll_tpm2:
        try:
            find_root_crypttab_entry(CRYPTTAB)
        except UkiError:
            # No encrypted root to enroll.  The normal TPM2 preparation
            # disables enrollment below; do not require TPM2 packages here.
            pass
        else:
            require_tpm2_packages()

    if args.dry_run:
        material = load_signing_material(args)
        log("would install the luksury update hook and options")
        log(f"would use kernel: {boot.kernel}")
        for path in boot.initrds:
            log(f"would use initrd: {path}")
        log(
            "would copy shim-signed's shim and MokManager to "
            f"{install_shim_dir(esp, efi_dir)}"
        )
        log(f"would install the UKI as {destination}")
        if not secure_boot:
            log(
                "Secure Boot is disabled: PCR7 would not be bound; PCR4 "
                "would bind the shim and the complete UKI (kernel and initrd)"
            )
        if material.state == "missing":
            if secure_boot and read_efi_signature_entries(
                "MokNew", SHIM_LOCK_GUID
            ):
                raise UkiError(
                    "a MOK enrollment is already pending but the luksury "
                    "signing key/certificate is missing; restore them or run "
                    "'mokutil --revoke-import' before generating a new key"
                )
            if secure_boot and shutil.which("mokutil") is None:
                raise UkiError(
                    "mokutil is required to enroll the generated signing key"
                )
            if secure_boot:
                log(
                    f"would generate a MOK signing key at {MOK_KEY_FILE} and "
                    "queue it for enrollment"
                )
            else:
                log(
                    f"would generate a UKI signing key at {MOK_KEY_FILE}; "
                    "Secure Boot is disabled, so it would not be queued for "
                    "MOK enrollment"
                )
        elif material.state == "untrusted":
            if secure_boot:
                if read_efi_signature_entries("MokNew", SHIM_LOCK_GUID):
                    raise UkiError(
                        "a different MOK enrollment is already pending; "
                        "complete it or run 'mokutil --revoke-import' first"
                    )
                if shutil.which("mokutil") is None:
                    raise UkiError(
                        "mokutil is required to enroll the signing certificate"
                    )
                log("would queue the MOK signing certificate for enrollment")
            else:
                log(
                    "would sign the UKI with the untrusted certificate "
                    f"{material.cert}; Secure Boot is disabled, so no MOK "
                    "enrollment is needed"
                )
        elif material.state == "pending":
            if secure_boot:
                log("MOK signing certificate is pending enrollment")
            else:
                log(
                    "MOK signing certificate is pending; Secure Boot is "
                    "disabled and the TPM token will not bind PCR7"
                )
        else:
            log(f"would sign the UKI with {material.cert}")
        if args.no_boot_entry:
            log(
                "would not create an EFI boot entry; create one with "
                f"loader {installed_shim_relative(efi_dir)} and no "
                f"optional data (the UKI is {destination})"
            )
        else:
            log(
                "would create/refresh the EFI boot entry with loader "
                f"{installed_shim_relative(efi_dir)}"
            )
        if not args.no_enroll_tpm2:
            log("would update the root crypttab TPM2 options")
            log("would prepare the recovery key")
        else:
            log("would skip TPM2 enrollment")
        log(f"would run: {update_initramfs} -u -k {release}")
        log("dry run: nothing was changed")
        return 0

    ensure_signing_material(args, enroll_mok=secure_boot)

    args.esp = str(esp)
    args.efi_dir = efi_dir
    args.label = label
    if args.unlock_key_file is not None:
        args.unlock_key_file = args.unlock_key_file.resolve()
    save_install_options(args)
    ensure_update_hook()

    if not args.no_enroll_tpm2:
        try:
            crypttab_entry = find_root_crypttab_entry(CRYPTTAB)
            require_tpm2_packages()
            update_crypttab_tpm2(CRYPTTAB, crypttab_entry.name)
            device = crypttab_device(crypttab_entry)
            keyfile = args.unlock_key_file or crypttab_unlock_key_file(
                crypttab_entry
            )
            ensure_recovery_key(
                device,
                key_file=RECOVERY_KEY_FILE,
                unlock_key_file=keyfile,
            )
        except UkiError as exc:
            raise UkiError(
                f"cannot prepare TPM2 enrollment: {exc}; fix the cause or "
                "rerun with --no-enroll-tpm2"
            ) from exc

    # The post-update hook takes /run/luksury.lock itself.  Release our copy
    # before invoking update-initramfs so the hook can run.
    if lock_fd is not None:
        import fcntl

        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError as exc:
            raise UkiError(
                f"cannot release the build lock before initrd regeneration: "
                f"{exc}"
            ) from exc

    log(
        f"regenerating the default entry's initrd for {release} with "
        f"{update_initramfs} -u -k {release}"
    )
    run_interactive([update_initramfs, "-u", "-k", release])

    if not destination.is_file():
        raise UkiError(
            f"the post-update hook did not create {destination}; "
            "check the journal for luksury-hook messages"
        )
    newest = newest_input_mtime(boot, CRYPTTAB)
    try:
        current = destination.stat().st_mtime_ns
    except OSError:
        current = 0
    # FAT has a coarse timestamp granularity; allow two seconds of slack.
    if newest and current + 2_000_000_000 < newest:
        raise UkiError(
            f"{destination} was not updated by the post-update hook; "
            "check the journal for luksury-hook messages"
        )

    ensure_shim_loader(esp, efi_dir, shim, mmx)

    if not args.no_boot_entry:
        ensure_boot_entry(
            esp, label, installed_shim_relative(efi_dir)
        )

    material = load_signing_material(args)
    if material.state == "enrolled":
        _cleanup_mok_password()
    elif material.state == "pending":
        mok_pending_instructions(material, secure_boot=secure_boot)
    elif material.state == "untrusted" and not secure_boot:
        log(
            "Secure Boot is disabled; the UKI was signed with the untrusted "
            f"certificate {material.cert} without MOK enrollment"
        )

    if not args.no_enroll_tpm2:
        try:
            entry = find_root_crypttab_entry(CRYPTTAB)
            device = crypttab_device(entry)
            tokens = tpm2_tokens(device)
            if not tokens:
                warn(
                    "the post-update hook did not create a systemd-tpm2 "
                    "token; check the journal for luksury-hook messages"
                )
            else:
                verify_tpm2_token(
                    device,
                    PCR_ALGORITHM_DEFAULT,
                    cryptenroll_pcrs(secure_boot),
                )
        except UkiError as exc:
            warn(f"cannot verify the TPM2 enrollment: {exc}")

    if not args.no_enroll_tpm2 and not secure_boot:
        log(
            "Secure Boot is disabled: the TPM2 token is bound without PCR7; "
            "PCR4 covers the kernel and initrd"
        )
    if args.no_enroll_tpm2:
        log("bootstrap complete; TPM2 enrollment was skipped")
    else:
        log("bootstrap complete; the post-update hook built the UKI")
    return 0


@dataclass
class LuksRemovalPlan:
    """Keyslots and tokens that a remove run may safely delete."""

    device: Path
    token_ids: set[int]
    recovery_token_ids: set[int]
    keyslots: set[int]
    delete_state: bool
    remove_recovery_key: bool
    unlock_key_file: Path | None


def metadata_keyslots(metadata: dict) -> set[int]:
    """Return the keyslot IDs present in LUKS2 metadata."""
    keyslots = metadata.get("keyslots", {})
    result: set[int] = set()
    if not isinstance(keyslots, dict):
        return result
    for slot in keyslots:
        try:
            result.add(int(slot))
        except (TypeError, ValueError):
            continue
    return result


def plan_luks_removal(args: argparse.Namespace) -> LuksRemovalPlan | None:
    """Work out which LUKS artifacts can be removed without locking out.

    This runs before anything is modified.  It refuses to remove the last
    usable keyslot and requires a verified alternative unlock before deleting
    keyslots.
    """
    state_path = TPM2_STATE_FILE
    recovery_path = RECOVERY_KEY_FILE
    state_present = state_path.exists()
    recovery_present = recovery_path.exists()

    try:
        entry = find_root_crypttab_entry(CRYPTTAB)
    except UkiError as exc:
        if state_present or recovery_present:
            raise UkiError(
                f"cannot clean up LUKS artifacts: {exc}; remove {state_path} "
                f"and {recovery_path} manually if the volume no longer exists"
            ) from exc
        return None

    device = crypttab_device(entry)
    try:
        metadata = luks2_metadata(device)
    except UkiError as exc:
        raise UkiError(
            f"cannot inspect {device} to clean up LUKS artifacts: {exc}"
        ) from exc

    device_uuid = metadata.get("uuid")
    if not isinstance(device_uuid, str):
        device_uuid = None
    all_slots = metadata_keyslots(metadata)
    tpm2 = tpm2_tokens_from_metadata(metadata)
    recovery = recovery_tokens_from_metadata(metadata)

    state = read_tpm2_state(state_path, device_uuid) if state_present else None
    token_ids: set[int] = set()
    keyslots: set[int] = set()

    if state is not None:
        token_id = state["token_id"]
        if token_id in tpm2:
            token_ids.add(token_id)
            token_slots = tpm2_token_slots(tpm2[token_id])
            stored_slot = state.get("keyslot")
            if isinstance(stored_slot, int):
                if stored_slot in token_slots:
                    keyslots.add(stored_slot)
                else:
                    warn(
                        f"TPM2 state {state_path} records keyslot "
                        f"{stored_slot}, but token {token_id} does not use it; "
                        "ignoring the stale keyslot"
                    )
        else:
            warn(
                f"TPM2 state {state_path} references token {token_id}, but "
                "that token no longer exists; ignoring its stored keyslot"
            )

    candidates = set(tpm2)
    if candidates:
        if not token_ids:
            listed = ", ".join(str(item) for item in sorted(candidates))
            warn(
                "no usable TPM2 state; removing all systemd-tpm2 tokens: "
                f"{listed}"
            )
        token_ids |= candidates

    for token_id in list(token_ids):
        keyslots.update(tpm2_token_slots(tpm2[token_id]))

    # A token bound to the same keyslot must be removed with it.
    changed = True
    while changed:
        changed = False
        for token_id, token in tpm2.items():
            if token_id in token_ids:
                continue
            slots = tpm2_token_slots(token)
            if slots & keyslots:
                token_ids.add(token_id)
                keyslots.update(slots)
                changed = True

    recovery_token_ids: set[int] = set()
    recovery_keyslots: set[int] = set()
    remove_recovery_key = False
    unlock_key_file: Path | None = None

    if recovery_present:
        try:
            if key_file_unlocks(device, recovery_path):
                remove_recovery_key = True
                unlock_key_file = recovery_path
            else:
                warn(
                    f"stored recovery key {recovery_path} does not unlock "
                    f"{device}; leaving the recovery key and its token in place"
                )
        except UkiError as exc:
            warn(f"cannot test recovery key {recovery_path}: {exc}")

        if len(recovery) == 1:
            token_id, token = next(iter(recovery.items()))
            if remove_recovery_key:
                recovery_token_ids.add(token_id)
                recovery_keyslots = tpm2_token_slots(token)
        elif len(recovery) > 1:
            listed = ", ".join(str(item) for item in sorted(recovery))
            warn(
                "multiple systemd-recovery tokens found "
                f"({listed}); removing only orphaned recovery tokens"
            )

    # Remove orphaned recovery tokens even when the recovery key is absent.
    for token_id, token in recovery.items():
        if token_id in recovery_token_ids:
            continue
        slots = tpm2_token_slots(token)
        if not slots or not (slots & all_slots):
            recovery_token_ids.add(token_id)
            warn(f"removing orphaned recovery token {token_id}")

    # Never kill a keyslot that another token still depends on.
    removed_tokens = token_ids | recovery_token_ids
    for token_id, token in {**tpm2, **recovery}.items():
        if token_id in removed_tokens:
            continue
        slots = tpm2_token_slots(token)
        shared = keyslots & slots
        if shared:
            listed = ", ".join(str(item) for item in sorted(shared))
            warn(
                f"keyslot(s) {listed} are still used by token {token_id}; "
                "leaving them in place"
            )
            keyslots -= shared
        if remove_recovery_key and (recovery_keyslots & slots):
            listed = ", ".join(
                str(item) for item in sorted(recovery_keyslots & slots)
            )
            warn(
                f"recovery keyslot(s) {listed} are still used by token "
                f"{token_id}; leaving the recovery key in place"
            )
            remove_recovery_key = False

    keyslots &= all_slots
    recovery_keyslots &= all_slots
    if remove_recovery_key:
        # luksRemoveKey removes the matching keyslot itself; do not try to
        # kill it again via luksKillSlot.
        keyslots -= recovery_keyslots

    explicit_key = getattr(args, "unlock_key_file", None)
    explicit_unlocks = False
    if explicit_key is not None:
        try:
            if explicit_key.is_file() and key_file_unlocks(
                device, explicit_key
            ):
                explicit_unlocks = True
                if unlock_key_file is None:
                    unlock_key_file = explicit_key
            else:
                warn(f"{explicit_key} does not unlock {device}")
        except UkiError as exc:
            warn(f"cannot test key file {explicit_key}: {exc}")

    unscheduled_recovery = [
        token_id
        for token_id, token in recovery.items()
        if token_id not in recovery_token_ids
        and (tpm2_token_slots(token) & all_slots)
    ]
    if unscheduled_recovery:
        listed = ", ".join(str(item) for item in sorted(unscheduled_recovery))
        message = (
            f"cannot safely remove recovery token(s) {listed} from {device}: "
            "the stored recovery key is missing or does not unlock the "
            "volume, or multiple recovery enrollments exist; restore the "
            "recovery key or remove those tokens manually"
        )
        if args.dry_run:
            warn(message)
        else:
            raise UkiError(message)

    # If the recovery key remains, it is a verified alternative.  If an
    # explicit key file unlocks and is not the recovery key we are removing,
    # it is also a verified alternative.
    verified_remaining = False
    if recovery_present and not remove_recovery_key:
        try:
            verified_remaining = key_file_unlocks(device, recovery_path)
        except UkiError as exc:
            warn(f"cannot verify recovery key {recovery_path}: {exc}")
    if (
        explicit_unlocks
        and explicit_key is not None
        and not (
            recovery_present
            and remove_recovery_key
            and paths_same(explicit_key, recovery_path)
        )
    ):
        verified_remaining = True

    removal_slots = set(keyslots)
    if remove_recovery_key:
        if recovery_keyslots:
            removal_slots |= recovery_keyslots
        elif len(all_slots - keyslots) < 2:
            raise UkiError(
                f"refusing to remove the recovery key from {device}: "
                "cannot identify its keyslot and no other keyslot would remain"
            )

    remaining = all_slots - removal_slots
    if removal_slots and not remaining:
        raise UkiError(
            f"refusing to remove the last usable LUKS keyslot on {device}; "
            "add a passphrase or key file first"
        )
    if (removal_slots or remove_recovery_key) and not verified_remaining:
        if args.dry_run:
            warn(
                "cannot verify a remaining LUKS keyslot in dry-run mode; "
                "the real removal will require an alternative unlock"
            )
        elif NON_INTERACTIVE:
            raise UkiError(
                "refusing to remove LUKS keyslots without a verified "
                "alternative unlock; pass --unlock-key-file or run "
                "interactively"
            )
        else:
            log(
                "verifying that an alternative passphrase can still unlock "
                f"{device}"
            )
            run_interactive(
                [
                    cryptsetup_binary(),
                    "open",
                    "--test-passphrase",
                    "--type",
                    "luks2",
                    str(device),
                ]
            )
            verified_remaining = True

    if (
        not token_ids
        and not recovery_token_ids
        and not recovery
        and not state_present
        and not recovery_present
    ):
        return None

    return LuksRemovalPlan(
        device=device,
        token_ids=token_ids,
        recovery_token_ids=recovery_token_ids,
        keyslots=keyslots,
        delete_state=state_present,
        remove_recovery_key=remove_recovery_key,
        unlock_key_file=unlock_key_file,
    )


def remove_keyslot_authorized(
    device: Path,
    slot: int,
    unlock_key_file: Path | None,
    *,
    dry_run: bool,
) -> bool:
    """Remove one LUKS keyslot, prompting for a passphrase if necessary."""
    cryptsetup = cryptsetup_binary()
    base = [
        cryptsetup,
        "luksKillSlot",
        "--type",
        "luks2",
    ]
    command = list(base)
    if unlock_key_file is not None:
        # The key-file path must not prompt.
        command.append("--batch-mode")
        command.extend(["--key-file", str(unlock_key_file)])
    command.extend([str(device), str(slot)])

    if dry_run:
        log(f"would remove LUKS keyslot {slot} from {device}")
        return True

    if unlock_key_file is not None:
        result = run(command, check=False)
        if result.returncode == 0:
            log(f"removed LUKS keyslot {slot} from {device}")
            return True
        detail = (result.stderr or result.stdout).strip()
        warn(
            f"cannot remove LUKS keyslot {slot} with {unlock_key_file}"
            + (f": {detail}" if detail else "")
        )
        if NON_INTERACTIVE:
            return False
        warn("retrying with an interactive passphrase")

    try:
        run_interactive([*base, str(device), str(slot)])
    except UkiError as exc:
        warn(f"cannot remove LUKS keyslot {slot} from {device}: {exc}")
        return False
    log(f"removed LUKS keyslot {slot} from {device}")
    return True


def remove_token(
    device: Path, token_id: int, kind: str, *, dry_run: bool
) -> bool:
    if dry_run:
        log(f"would remove {kind} token {token_id} from {device}")
        return True
    try:
        remove_tpm2_token(device, token_id)
    except UkiError as exc:
        warn(f"cannot remove {kind} token {token_id} from {device}: {exc}")
        return False
    log(f"removed {kind} token {token_id} from {device}")
    return True


def execute_luks_removal(
    plan: LuksRemovalPlan, *, dry_run: bool
) -> bool:
    """Remove planned keyslots and tokens, keeping metadata on failure."""
    success = True
    for slot in sorted(plan.keyslots):
        if not remove_keyslot_authorized(
            plan.device,
            slot,
            plan.unlock_key_file,
            dry_run=dry_run,
        ):
            success = False

    if not success:
        warn(
            "LUKS keyslots could not all be removed; leaving tokens and "
            "stored keys in place so the cleanup can be retried"
        )
        return False

    if plan.remove_recovery_key:
        if dry_run:
            log(f"would remove the recovery key from {plan.device}")
        else:
            result = run(
                [
                    cryptsetup_binary(),
                    "luksRemoveKey",
                    "--batch-mode",
                    "--type",
                    "luks2",
                    "--key-file",
                    str(RECOVERY_KEY_FILE),
                    str(plan.device),
                ],
                check=False,
            )
            if result.returncode != 0:
                detail = (result.stderr or result.stdout).strip()
                warn(
                    "cannot remove the recovery key from "
                    f"{plan.device}" + (f": {detail}" if detail else "")
                )
                return False
            log(f"removed the recovery key from {plan.device}")

    existing_tpm2 = set() if dry_run else set(tpm2_tokens(plan.device))
    for token_id in sorted(plan.token_ids):
        if not dry_run and token_id not in existing_tpm2:
            log(f"TPM2 token {token_id} is already gone")
            continue
        success &= remove_token(
            plan.device, token_id, "TPM2", dry_run=dry_run
        )

    if dry_run:
        existing_recovery = {}
        existing_slots = set()
    else:
        recovery_metadata = luks2_metadata(plan.device)
        existing_recovery = recovery_tokens_from_metadata(recovery_metadata)
        existing_slots = metadata_keyslots(recovery_metadata)

    recovery_token_ids = set(plan.recovery_token_ids)
    for token_id, token in existing_recovery.items():
        slots = tpm2_token_slots(token)
        if not slots or not (slots & existing_slots):
            recovery_token_ids.add(token_id)

    for token_id in sorted(recovery_token_ids):
        if not dry_run and token_id not in existing_recovery:
            log(f"recovery token {token_id} is already gone")
            continue
        success &= remove_token(
            plan.device, token_id, "recovery", dry_run=dry_run
        )

    if not dry_run:
        try:
            remaining_tpm2 = tpm2_tokens(plan.device)
        except UkiError as exc:
            warn(f"cannot verify TPM2 token removal on {plan.device}: {exc}")
            remaining_tpm2 = {}
            success = False
        if remaining_tpm2:
            listed = ", ".join(str(item) for item in sorted(remaining_tpm2))
            warn(
                f"systemd-tpm2 token(s) still present on {plan.device}: "
                f"{listed}"
            )
            success = False
        try:
            remaining_recovery = recovery_tokens_from_metadata(
                luks2_metadata(plan.device)
            )
        except UkiError as exc:
            warn(
                f"cannot verify recovery token removal on {plan.device}: "
                f"{exc}"
            )
            remaining_recovery = {}
            success = False
        unexpected = set(remaining_recovery) - set(plan.recovery_token_ids)
        if unexpected:
            listed = ", ".join(str(item) for item in sorted(unexpected))
            warn(
                f"systemd-recovery token(s) remain on {plan.device} and "
                f"were not removed: {listed}"
            )
            success = False

    return success


def remove_path(path: Path, *, dry_run: bool, verbose: bool = False) -> None:
    """Remove a file or symlink, ignoring one that is already absent."""
    try:
        present = path.exists() or path.is_symlink()
    except OSError:
        present = False
    if not present:
        if verbose:
            log(f"not present: {path}")
        return
    if dry_run:
        log(f"would remove {path}")
        return
    try:
        path.unlink()
    except FileNotFoundError:
        return
    log(f"removed {path}")


def remove_dir_if_empty(
    path: Path, *, dry_run: bool, verbose: bool = False
) -> None:
    """Remove an installation directory only when nothing remains in it."""
    try:
        if not path.is_dir() or os.path.ismount(path):
            return
        if any(path.iterdir()):
            return
    except OSError:
        return

    if dry_run:
        log(f"would remove empty directory {path}")
        return
    try:
        path.rmdir()
    except OSError as exc:
        if verbose:
            log(f"cannot remove empty directory {path}: {exc}")
        return
    log(f"removed empty directory {path}")


def remove_update_hooks(*, dry_run: bool, verbose: bool = False) -> None:
    """Remove the post-update hook and any legacy update units."""
    remove_legacy_systemd_units(dry_run=dry_run, verbose=verbose)
    remove_path(
        INITRAMFS_POST_UPDATE_DIR / "zz-luksury",
        dry_run=dry_run,
        verbose=verbose,
    )


def resolve_removal_esp(args: argparse.Namespace) -> tuple[Path, str]:
    """Best-effort ESP and boot loader selection for an uninstall."""
    esp_override = Path(args.esp) if args.esp else None
    try:
        loader = detect_boot_loader(esp_override)
    except (UkiError, OSError, RuntimeError):
        loader = "grub"

    if esp_override is not None:
        esp = esp_override
    elif loader == SYSTEMD_BOOT:
        try:
            esp, _ = systemd_boot_roots()
        except (UkiError, OSError, RuntimeError):
            esp = ESP_DEFAULT
    else:
        esp = ESP_DEFAULT
    return esp, loader


def find_uki_files(esp: Path, efi_dir: Path) -> list[Path]:
    """Return the current luksury UKI.

    Legacy ``luksury.efi`` files are deliberately ignored: the old layout is
    not part of the current installation and ``remove`` must not touch it.
    """
    try:
        root = esp.resolve(strict=True)
    except (OSError, RuntimeError):
        return []
    if not root.is_dir():
        return []

    try:
        path = install_destination(esp, efi_dir)
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError, UkiError):
        return []
    if not resolved.is_relative_to(root):
        warn(f"ignoring {path}: it resolves outside the ESP {root}")
        return []
    if not resolved.is_file():
        return []
    return [path]


def remove_efi_boot_entries(
    efi_dir: Path, *, dry_run: bool, verbose: bool = False
) -> bool:
    """Delete every efibootmgr entry that loads the private shim copy."""
    if shutil.which("efibootmgr") is None:
        if verbose:
            warn("efibootmgr is not installed; no EFI entries were removed")
        return True
    try:
        entries = efi_entries()
    except UkiError as exc:
        warn(f"cannot read EFI boot entries: {exc}")
        return True

    loader = installed_shim_relative(efi_dir)
    matches = [
        entry for entry in entries if efi_entry_loader_matches(entry, loader)
    ]
    if not matches:
        if verbose:
            log("no luksury EFI boot entries found")
        return True

    success = True
    for entry in matches:
        command = [
            "efibootmgr",
            "--delete-bootnum",
            "--bootnum",
            str(entry["id"]),
        ]
        if dry_run:
            log(f"would run: {shlex.join(command)}")
            continue
        result = run(command, check=False)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            warn(
                f"cannot delete Boot{entry['id']}"
                + (f": {detail}" if detail else "")
            )
            success = False
        else:
            log(f"removed Boot{entry['id']} ({entry['label']})")
    return success


def remove_efi_files(
    esp: Path, efi_dir: Path, *, dry_run: bool, verbose: bool = False
) -> None:
    """Remove the current UKI, private shim files and empty EFI directories."""
    try:
        root = esp.resolve(strict=True)
    except (OSError, RuntimeError):
        root = None

    paths = find_uki_files(esp, efi_dir)
    shim_dir = esp / efi_dir / SHIM_DIR_NAME
    if root is not None:
        try:
            shim_dir = shim_dir.resolve(strict=False)
        except (OSError, RuntimeError):
            pass
        if shim_dir.is_relative_to(root):
            for name in (SHIM_NAME, MMX_NAME):
                path = shim_dir / name
                if path.is_file():
                    paths.append(path)
        else:
            warn(f"ignoring {shim_dir}: it resolves outside the ESP {root}")

    paths = list({str(path): path for path in paths}.values())
    parents = {path.parent for path in paths}
    if root is not None and shim_dir.is_relative_to(root):
        parents.add(shim_dir)
    parents.add((esp / efi_dir))
    parents.add(esp)

    safe_parents: set[Path] = set()
    for parent in parents:
        if root is None:
            continue
        try:
            resolved = parent.resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        if resolved.is_relative_to(root):
            safe_parents.add(resolved)
        else:
            warn(f"ignoring {parent}: it resolves outside the ESP {root}")
    parents = safe_parents

    for path in paths:
        remove_path(path, dry_run=dry_run, verbose=verbose)

    if root is not None and shim_dir.is_relative_to(root):
        try:
            temporary = sorted(
                shim_dir.glob(f".{SECOND_STAGE_NAME}.*")
            )
        except OSError:
            temporary = []
        for path in temporary:
            remove_path(path, dry_run=dry_run, verbose=verbose)

    for parent in sorted(parents):
        if parent == root:
            continue
        remove_dir_if_empty(parent, dry_run=dry_run, verbose=verbose)


def run_remove(args: argparse.Namespace) -> int:
    dry_run = args.dry_run
    verbose = args.verbose

    esp, _ = resolve_removal_esp(args)
    os_release = read_os_release(OS_RELEASE)
    efi_dir = args.efi_dir or default_efi_dir(os_release)

    # This is the only step that can abort the whole removal.  It runs
    # before anything is changed so a lockout cannot be half-applied.
    luks_plan = plan_luks_removal(args)

    log(f"removing luksury artifacts from {esp}")
    revoke_pending_mok_request(dry_run=dry_run)
    remove_update_hooks(dry_run=dry_run, verbose=verbose)
    efi_ok = remove_efi_boot_entries(
        efi_dir, dry_run=dry_run, verbose=verbose
    )
    remove_efi_files(
        esp, efi_dir, dry_run=dry_run, verbose=verbose
    )

    luks_ok = True
    if luks_plan is not None:
        luks_ok = execute_luks_removal(luks_plan, dry_run=dry_run)
        if luks_ok:
            if luks_plan.delete_state:
                remove_path(
                    TPM2_STATE_FILE,
                    dry_run=dry_run,
                    verbose=verbose,
                )
            if luks_plan.remove_recovery_key:
                remove_path(
                    RECOVERY_KEY_FILE,
                    dry_run=dry_run,
                    verbose=verbose,
                )
            elif RECOVERY_KEY_FILE.exists():
                warn(
                    "leaving the recovery enrollment and "
                    f"{RECOVERY_KEY_FILE} in place"
                )
        else:
            warn(
                "LUKS cleanup is incomplete; keeping "
                f"{TPM2_STATE_FILE} and {RECOVERY_KEY_FILE}"
            )

    crypttab_ok = True
    crypttab_changed = False
    try:
        entry = find_root_crypttab_entry(CRYPTTAB)
    except UkiError as exc:
        entry = None
        if CRYPTTAB.is_file() and verbose:
            log(f"crypttab not updated: {exc}")

    if entry is not None:
        try:
            crypttab_changed = update_crypttab_tpm2(
                CRYPTTAB,
                entry.name,
                dry_run=dry_run,
                remove=True,
            )
        except UkiError as exc:
            warn(f"crypttab was not updated: {exc}")
            crypttab_ok = False

    if crypttab_changed:
        warn(
            "crypttab changed; regenerate the initrd externally so it no "
            "longer contains the removed TPM2 options"
        )

    if crypttab_ok:
        backup = CRYPTTAB.with_name(
            CRYPTTAB.name + CRYPTTAB_BACKUP_SUFFIX
        )
        remove_path(backup, dry_run=dry_run, verbose=verbose)

    # Remove the old allow-list file from installations that predate the
    # switch to building from the just-generated initrd.
    remove_path(
        Path("/var/lib/luksury/initrd-hashes.json"),
        dry_run=dry_run,
        verbose=verbose,
    )
    remove_path(INSTALL_OPTIONS_FILE, dry_run=dry_run, verbose=verbose)

    for directory in (
        TPM2_STATE_FILE.parent,
        RECOVERY_KEY_FILE.parent,
    ):
        remove_dir_if_empty(directory, dry_run=dry_run, verbose=verbose)

    ok = efi_ok and luks_ok and crypttab_ok
    if ok or dry_run:
        remove_path(INSTALL_BIN, dry_run=dry_run, verbose=verbose)
        remove_path(HOOK_PATH, dry_run=dry_run, verbose=verbose)
        remove_dir_if_empty(
            INSTALL_LIB_DIR, dry_run=dry_run, verbose=verbose
        )
    else:
        warn(
            f"cleanup is incomplete; keeping {INSTALL_BIN} so the removal "
            "can be retried"
        )

    remove_path(BUILD_LOCK_FILE, dry_run=dry_run, verbose=verbose)

    if dry_run:
        log("dry run: nothing was changed")
        return 0
    if not ok:
        return 1
    if MOK_KEY_FILE.exists() or MOK_CERT_FILE.exists():
        log(
            f"left the MOK signing key {MOK_KEY_FILE} and its enrollment in "
            "place; use 'mokutil --delete' to remove the certificate"
        )
    log("removed the luksury installation")
    return 0


def paths_same(left: Path, right: Path) -> bool:
    """Return True when two paths refer to the same file."""
    try:
        if os.path.samefile(left, right):
            return True
    except OSError:
        pass
    return os.path.realpath(left) == os.path.realpath(right)


def newest_input_mtime(boot: ResolvedBoot, crypttab: Path) -> int:
    """Return the newest mtime among the default entry's inputs."""
    newest = 0
    paths: list[Path] = [Path(boot.kernel), crypttab]
    paths.extend(Path(path) for path in boot.initrds)
    for path in paths:
        try:
            newest = max(newest, path.stat().st_mtime_ns)
        except OSError:
            continue
    return newest


def hook_tpm2_ready(
    args: argparse.Namespace, *, secure_boot: bool
) -> bool:
    """Check whether a non-interactive TPM2 update is safe.

    The first bootstrap prepares the recovery key before regenerating the
    initrd.  If a TPM2 token is already present, the hook must have a usable
    authorization (the stored recovery key or an explicit key file) before it
    replaces the UKI; otherwise the new PCR binding would not match the old
    token.  It must also have the TPM2 userspace stack, otherwise the new
    initrd cannot unlock the volume at all.  The UKI signing key must exist.
    Its certificate must be enrolled or pending only while Secure Boot is
    enforcing.
    """
    if args.no_enroll_tpm2:
        return True

    material = load_signing_material(args)
    if material.state == "missing":
        warn("UKI signing key is missing; skipping UKI rebuild")
        return False
    if material.state == "untrusted":
        if secure_boot:
            warn(
                "UKI signing certificate is not enrolled or pending; skipping "
                "UKI rebuild to avoid creating an unbootable image"
            )
            return False
        log(
            "Secure Boot is disabled; signing with the untrusted certificate "
            f"{material.cert} without MOK enrollment"
        )
    if material.state == "pending":
        if secure_boot:
            log(
                "MOK signing certificate is pending enrollment; TPM2 "
                "enrollment will target the post-enrollment PCR7 value"
            )
        else:
            log(
                "MOK signing certificate is pending enrollment; Secure Boot "
                "is disabled and the TPM2 token will not bind PCR7"
            )

    try:
        entry = find_root_crypttab_entry(CRYPTTAB)
    except UkiError as exc:
        warn(f"TPM2 enrollment not applicable ({exc}); rebuilding without it")
        args.no_enroll_tpm2 = True
        return True

    device = crypttab_device(entry)
    try:
        tokens = luks2_token_types(device)
    except UkiError as exc:
        warn(
            f"cannot inspect TPM2 tokens on {device}: {exc}; "
            "skipping UKI rebuild"
        )
        return False

    missing = tpm2_package_problems()
    if missing:
        detail = (
            "TPM2 unlock requires the TPM2 userspace stack in the initrd; "
            f"missing: {', '.join(missing)}"
        )
        if SYSTEMD_TPM2_TOKEN in tokens:
            warn(
                f"{detail}; skipping UKI rebuild to keep TPM2 unlock working. "
                "Install tpm2-tools and the dracut tpm2-tss module, then rerun"
            )
            return False
        warn(f"{detail}; rebuilding without TPM2 enrollment")
        args.no_enroll_tpm2 = True
        return True

    if SYSTEMD_TPM2_TOKEN not in tokens:
        # First enrollment.  The bootstrap has prepared a recovery key or an
        # explicit key file; let run_main enroll the new token.
        return True

    key_files: list[Path] = []
    if args.unlock_key_file is not None:
        key_files.append(args.unlock_key_file)
    key_files.append(RECOVERY_KEY_FILE)
    tested: list[Path] = []
    for key_file in key_files:
        if key_file in tested:
            continue
        tested.append(key_file)
        try:
            if key_file.is_file() and key_file_unlocks(device, key_file):
                return True
        except UkiError as exc:
            warn(f"cannot test recovery key {key_file}: {exc}")
    warn(
        "none of the configured recovery keys unlock "
        f"{device}; skipping UKI rebuild to keep TPM2 unlock working "
        f"(tried {', '.join(str(path) for path in tested)})"
    )
    return False


def run_hook_rebuild(args: argparse.Namespace) -> int:
    """Build/rebuild the UKI from a post-initrd-update hook.

    This is the only path that creates a UKI.  It runs when the generated
    initrd is the resolved default boot entry's single initrd, or when the UKI
    is missing.  The initrd is confined and sanity-checked, then copied to a
    root-only work directory.  The UKI is built from that generated file, not
    from the default entry's path, and signed with the persisted MOK key.
    """
    apply_install_options(args)
    if args.dry_run:
        raise UkiError("--dry-run cannot be combined with --hook-rebuild")
    try:
        secure_boot = require_uefi_boot()
    except UkiError as exc:
        warn(f"the system is not suitable for a UKI rebuild ({exc}); skipping")
        return 0
    material = load_signing_material(args)
    if material.state == "missing":
        warn("UKI signing key is missing; skipping UKI rebuild")
        return 0
    if material.state == "untrusted":
        if secure_boot:
            warn(
                "UKI signing certificate is not enrolled or pending; skipping "
                "UKI rebuild to avoid creating an unbootable image"
            )
            return 0
        log(
            "Secure Boot is disabled; signing with the untrusted certificate "
            f"{material.cert} without MOK enrollment"
        )
    if material.state == "enrolled":
        _cleanup_mok_password()
    os_release = read_os_release(OS_RELEASE)
    efi_dir = args.efi_dir or default_efi_dir(os_release)
    esp_override = Path(args.esp) if args.esp else None
    try:
        loader = detect_boot_loader(esp_override)
        esp, boot = resolve_boot_entry(loader, esp_override)
    except UkiError as exc:
        warn(f"cannot resolve the default boot entry: {exc}; skipping")
        return 0
    try:
        esp = esp.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        warn(f"cannot resolve ESP {esp}: {exc}; skipping")
        return 0
    destination = install_destination(esp, efi_dir)
    # update-initramfs passes the kernel release; keep .uname and the dpkg
    # checksum lookup aligned with the initrd that triggered this rebuild.
    release = args.kernel_release or boot.release
    build_boot = replace(boot, release=release)

    if args.initrd is not None:
        if len(boot.initrds) != 1 or not paths_same(
            args.initrd, Path(boot.initrds[0])
        ):
            log(
                f"updated initrd {args.initrd} is not the default entry's "
                "initrd; skipping"
            )
            return 0
        # The default entry's path is only used for the membership check.
        # Build from the file update-initramfs just generated.
        build_boot = replace(build_boot, initrds=[str(args.initrd)])
    else:
        if not args.force:
            newest = newest_input_mtime(boot, CRYPTTAB)
            try:
                current = destination.stat().st_mtime_ns
            except OSError:
                current = 0
            if current and newest and current >= newest:
                log(f"UKI {destination} is up to date; skipping")
                return 0

    if not destination.is_file():
        log(f"creating new UKI {destination}")

    if not hook_tpm2_ready(args, secure_boot=secure_boot):
        return 0

    args.no_boot_entry = True
    return run_main(
        args, boot=build_boot, esp=esp, secure_boot=secure_boot
    )


if __name__ == "__main__":
    sys.exit(main())
