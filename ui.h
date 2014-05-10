/*
 *  Off-the-Record Messaging plugin for pidgin
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
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __OTRG_UI_H__
#define __OTRG_UI_H__

#include "common.h"

typedef struct {
    void (*init)(void);

    void (*cleanup)(void);

    void (*update_fingerprint)(void);

    void (*update_keylist)(void);

    void (*config_buddy)(PurpleBuddy *buddy);

    void (*get_prefs)(OtrgUiPrefs *prefsp, PurpleAccount *account,
	    const char *name);
} OtrgUiUiOps;

/* Set the UI ops */
void otrg_ui_set_ui_ops(const OtrgUiUiOps *ops);

/* Get the UI ops */
const OtrgUiUiOps *otrg_ui_get_ui_ops(void);

/* Initialize the UI subsystem */
void otrg_ui_init(void);

/* Deinitialize the UI subsystem */
void otrg_ui_cleanup(void);

/* Call this function when the DSA key is updated; it will redraw the
 * UI. */
void otrg_ui_update_fingerprint(void);

/* Update the keylist, if it's visible */
void otrg_ui_update_keylist(void);

/* Send an OTR Query Message to attempt to start a connection */
void otrg_ui_connect_connection(ConnContext *context);

/* Drop a context to PLAINTEXT state */
void otrg_ui_disconnect_connection(ConnContext *context);

/* Forget a fingerprint */
void otrg_ui_forget_fingerprint(Fingerprint *fingerprint);

/* Configure OTR for a particular buddy */
void otrg_ui_config_buddy(PurpleBuddy *buddy);

/* Load the preferences for a particular account / username */
void otrg_ui_get_prefs(OtrgUiPrefs *prefsp, PurpleAccount *account,
	const char *name);

#endif

/* vim: set tabstop=8 softtabstop=4 shiftwidth=4 noexpandtab: */
