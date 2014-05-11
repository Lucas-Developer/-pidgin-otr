/*
 *  Fingerprint verification API for Off-the-Record Messaging
 *  plugin for libpurple 3.
 *
 *  Copyright (C) 2004-2012  Ian Goldberg, Rob Smits,
 *                           Chris Alexander, Willy Lew,
 *                           Nikita Borisov
 *                           <otr@cypherpunks.ca>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __OTRG_FPRINT_VERIFICATOR_H__
#define __OTRG_FPRINT_VERIFICATOR_H__

typedef void (*OtrgFingerprintVerifyBackCb)(ConnContext *context,
	gpointer cb_data);
typedef void (*OtrgFingerprintVerifyCb)(ConnContext *context,
	OtrgFingerprintVerifyBackCb on_back, gpointer cb_data);

typedef struct
{
	gsize struct_size;

	const gchar *name;
	OtrgFingerprintVerifyCb verify_cb;
} OtrgFingerprintVerificator;

static inline gboolean
otrg_verificator_register(OtrgFingerprintVerificator* verf)
{
	PurplePlugin *otrg;

	otrg = purple_plugins_find_with_id("otr");

	if (otrg == NULL) {
		purple_debug_error("otr", "OTR plugin is not present");
		return FALSE;
	}

	return GPOINTER_TO_INT(purple_signal_emit_return_1(otrg,
		"otr-verificator-register", verf));
}

static inline void
otrg_verificator_unregister(OtrgFingerprintVerificator* verf)
{
	PurplePlugin *otrg;

	otrg = purple_plugins_find_with_id("otr");

	if (otrg == NULL) {
		purple_debug_error("otr", "OTR plugin is not present");
		return;
	}

	purple_signal_emit(otrg, "otr-verificator-unregister", verf);
}

#endif

/* vim: set tabstop=8 softtabstop=8 shiftwidth=8 noexpandtab: */
