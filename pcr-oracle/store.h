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

#ifndef STORE_H
#define STORE_H

#include <stdbool.h>
#include <tss2/tss2_esys.h>

#include "types.h"
#include "rsa.h"

enum {
	STORED_KEY_FMT_PEM		= 1,
	STORED_KEY_FMT_NATIVE	= 2,	/* TSS marshaled */
};

struct stored_key {
	char *		path;
	bool		is_private;
	int		format;
};

extern stored_key_t *	stored_key_new_public(int objfmt, const char *pathname);
extern stored_key_t *	stored_key_new_private(int objfmt, const char *pathname);
extern void		stored_key_free(stored_key_t *);
extern tpm_rsa_key_t *	stored_key_read_rsa_public(const stored_key_t *);
extern bool		stored_key_write_rsa_public(const stored_key_t *, const tpm_rsa_key_t *key);
extern tpm_rsa_key_t *	stored_key_read_rsa_private(const stored_key_t *);
extern bool		stored_key_write_rsa_private(const stored_key_t *, const tpm_rsa_key_t *key);
extern TPM2B_PUBLIC *	stored_key_read_native_public(const stored_key_t *);
extern bool		stored_key_write_native_public(const stored_key_t *, const TPM2B_PUBLIC *);

extern TPM2B_PUBLIC *	stored_key_read_native_public(const stored_key_t *);
extern bool		stored_key_write_native_public(const stored_key_t *, const TPM2B_PUBLIC *key);

#endif /* STORE_H */

