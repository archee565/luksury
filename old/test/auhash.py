#!/usr/bin/env python3
import hashlib
import struct
import sys


def get_authenticode_hash(path, algo="sha256"):
    """
    Compute the Authenticode hash of a PE file.
    Corresponds to the hash Microsoft uses for WinVerifyTrust.
    """

    with open(path, "rb") as f:
        data = f.read()

    # ---- Parse PE headers ----

    # DOS header: PE header pointer
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]

    # PE signature
    if data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        raise ValueError("Not a valid PE file")

    # File + Optional header start
    coff_header_offset = e_lfanew + 4
    (machine,
     num_sections,
     _, _, _,  # skip timestamp, symbol table ptr, symbol count
     size_optional_header,
     characteristics) = struct.unpack_from("<HHIIIHH", data, coff_header_offset)

    optional_header_offset = coff_header_offset + 20

    # Optional header: magic determines 32/64 bit
    magic = struct.unpack_from("<H", data, optional_header_offset)[0]
    is_pe32_plus = (magic == 0x20B)

    # Security directory entry index = 4th entry in data directories
    # offset depends on PE32 vs PE32+
    security_dir_offset = optional_header_offset + (112 if is_pe32_plus else 96)

    security_dir_va, security_dir_size = struct.unpack_from(
        "<II", data, security_dir_offset)

    # The security directory contains the WIN_CERTIFICATE,
    # which must be excluded from hashing.
    security_entry_file_offset = security_dir_va
    security_entry_end = security_entry_file_offset + security_dir_size

    # ---- Compute hash over required PE regions ----
    hasher = hashlib.new(algo)

    # A) Everything from start → start of WIN_CERTIFICATE
    hasher.update(data[:security_entry_file_offset])

    # B) Skip WIN_CERTIFICATE entirely
    # security_entry_file_offset → security_entry_end is excluded

    # C) Everything after WIN_CERTIFICATE → end of file
    hasher.update(data[security_entry_end:])

    return hasher.hexdigest()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: authenticode_hash.py <file.exe>")
        sys.exit(1)

    pe_path = sys.argv[1]
    try:
        h = get_authenticode_hash(pe_path)
        print(f"Authenticode SHA-256: {h}")
    except Exception as e:
        print("Error:", e)
        sys.exit(1)
