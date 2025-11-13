/*
 *   Copyright (C) 2023 SUSE LLC
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Written by Olaf Kirch <okir@suse.com>
 */

#include <stdlib.h>
#include <string.h>
#include "store.h"
#include "util.h"
#include "tpm.h"

/* We do not have automatic conversion of TPM2B_PUBLIC to RSA yet (and so far we haven't needed it) */
#undef WITH_NATIVE_TO_RSA_CONVERSTION

tpm_rsa_key_t *
stored_key_read_rsa_private(const stored_key_t *sk)
{
	switch (sk->format) {
	case STORED_KEY_FMT_PEM:
		return tpm_rsa_key_read_private(sk->path);
	}

	error("Unable to read RSA private key from file \"%s\": unsupported format\n", sk->path);
	return NULL;
}

bool
stored_key_write_rsa_private(const stored_key_t *sk, const tpm_rsa_key_t *key)
{
	if (!sk->is_private) {
		error("Refusing to write RSA private key to file \"%s\": file is supposed to contain public key\n", sk->path);
		return false;
	}

	switch (sk->format) {
	case STORED_KEY_FMT_PEM:
		return tpm_rsa_key_write_private(sk->path, key);
	}

	error("Unable to write RSA private key to file \"%s\": unsupported format\n", sk->path);
	return false;
}

tpm_rsa_key_t *
stored_key_read_rsa_public(const stored_key_t *sk)
{
	debug2("Trying to read RSA public key from %s file %s\n",
			sk->is_private? "private" : "public",
			sk->path);

	/* If the stored object is actually a private key, just read it and go with it. */
	if (sk->is_private)
		return stored_key_read_rsa_private(sk);

	switch (sk->format) {
	case STORED_KEY_FMT_PEM:
		return tpm_rsa_key_read_public(sk->path);

	case STORED_KEY_FMT_NATIVE:
		error("Unable to read RSA public key from native file \"%s\": automatic conversion not implemented\n", sk->path);
		return NULL;
	}

	error("Unable to read RSA public key from file \"%s\": unsupported format\n", sk->path);
	return NULL;
}

bool
stored_key_write_rsa_public(const stored_key_t *sk, const tpm_rsa_key_t *key)
{
	switch (sk->format) {
	case STORED_KEY_FMT_PEM:
		return tpm_rsa_key_write_public(sk->path, key);

	/* If the format is native, automatically convert the RSA key to a native TPM2B_PUBLIC blob */
	case STORED_KEY_FMT_NATIVE:
		{
			TPM2B_PUBLIC *native_key;
			bool ok;

			native_key = tpm_rsa_key_to_tss2(key);
			if (native_key == NULL) {
				error("Error writing RSA public key to native file %s: failed to convert key\n", sk->path);
				return false;
			}

			ok = tss_write_public_key(sk->path, native_key);
			free(native_key);
			return ok;
		}
	}

	error("Unable to write RSA public key to file \"%s\": unsupported format\n", sk->path);
	return false;
}

TPM2B_PUBLIC *
stored_key_read_native_public(const stored_key_t *sk)
{
	debug2("Trying to read TPM formatted public key from %s file %s\n",
			sk->is_private? "private" : "public",
			sk->path);

	switch (sk->format) {
	case STORED_KEY_FMT_NATIVE:
		return tss_read_public_key(sk->path);

	case STORED_KEY_FMT_PEM:
		{
			tpm_rsa_key_t *rsa_key;
			TPM2B_PUBLIC *native_key;

			rsa_key = stored_key_read_rsa_public(sk);
			if (rsa_key == NULL)
				return NULL;

			native_key = tpm_rsa_key_to_tss2(rsa_key);
			tpm_rsa_key_free(rsa_key);

			if (native_key == NULL) {
				error("Error reading TPM public key from native file %s: failed to convert key\n", sk->path);
				return NULL;
			}

			return native_key;
		}
	}

	error("Unable to read native TPM public key from file \"%s\": unsupported format\n", sk->path);
	return NULL;
}

bool
stored_key_write_native_public(const stored_key_t *sk, const TPM2B_PUBLIC *native_key)
{
	switch (sk->format) {
	case STORED_KEY_FMT_NATIVE:
		return tss_write_public_key(sk->path, native_key);

	case STORED_KEY_FMT_PEM:
		error("Unable to write native public key to PEM file \"%s\": automatic conversion not implemented\n", sk->path);
		return false;
	}

	error("Unable to write native TPM public key to file \"%s\": unsupported format\n", sk->path);
	return NULL;
}

static const char *
stored_key_format_to_name(int fmt)
{
	switch (fmt) {
	case STORED_KEY_FMT_PEM:
		return "PEM";
	case STORED_KEY_FMT_NATIVE:
		return "native";
	}

	return "<unknown>";
}

void
stored_key_set_format(stored_key_t *sk, int objfmt)
{
	if (sk->format && sk->format != objfmt)
		fatal("Ambiguous key format for %s: %s vs %s\n", sk->path,
				stored_key_format_to_name(sk->format),
				stored_key_format_to_name(objfmt));
	sk->format = objfmt;
}

void
stored_key_set_path(stored_key_t *sk, const char *pathname)
{
	assign_string(&sk->path, pathname);

	if (pathname == NULL)
		fatal("%s: pathname is NULL\n", __func__);

	if (!strncasecmp(pathname, "pem:", 4)) {
		stored_key_set_format(sk, STORED_KEY_FMT_PEM);
		pathname += 4;
	} else
	if (!strncasecmp(pathname, "native:", 7)) {
		stored_key_set_format(sk, STORED_KEY_FMT_NATIVE);
		pathname += 7;
	} else
	if (path_has_file_extension(pathname, "pem"))
		stored_key_set_format(sk, STORED_KEY_FMT_PEM);
}

/*
 * Constructors
 */
static inline stored_key_t *
__stored_key_new(bool is_private, int objfmt, const char *pathname)
{
	stored_key_t *sk;

	sk = calloc(1, sizeof(*sk));
	sk->is_private = is_private;
	stored_key_set_path(sk, pathname);

	if (sk->format == 0)
		stored_key_set_format(sk, objfmt);

	return sk;
}

stored_key_t *
stored_key_new_public(int objfmt, const char *pathname)
{
	return __stored_key_new(false, objfmt, pathname);
}

stored_key_t *
stored_key_new_private(int objfmt, const char *pathname)
{
	return __stored_key_new(true, objfmt, pathname);
}

/*
 * Destructor
 */
void
stored_key_free(stored_key_t *sk)
{
	drop_string(&sk->path);
	free(sk);
}
