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

/* config.h */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* system headers */
#include <stdlib.h>

/* purple headers */
#include "util.h"
#include "account.h"

#ifdef ENABLE_NLS
/* internationalisation header */
#include <glib/gi18n-lib.h>
#else
#define _(x) (x)
#define N_(x) (x)
#endif

/* libotr headers */
#include <libotr/privkey.h>
#include <libotr/proto.h>
#include <libotr/message.h>

/* purple-otr headers */
#include "ui.h"
#include "dialogs.h"
#include "otr-plugin.h"

static const OtrgUiUiOps *ui_ops = NULL;

/* Set the UI ops */
void otrg_ui_set_ui_ops(const OtrgUiUiOps *ops)
{
    ui_ops = ops;
}

/* Get the UI ops */
const OtrgUiUiOps *otrg_ui_get_ui_ops(void)
{
    return ui_ops;
}

/* Initialize the OTR UI subsystem */
void otrg_ui_init(void)
{
    if (ui_ops != NULL) {
	ui_ops->init();
    }
}

/* Deinitialize the OTR UI subsystem */
void otrg_ui_cleanup(void)
{
    if (ui_ops != NULL) {
	ui_ops->cleanup();
    }
}

/* Call this function when the DSA key is updated; it will redraw the
 * UI, if visible. */
void otrg_ui_update_fingerprint(void)
{
    if (ui_ops != NULL) {
	ui_ops->update_fingerprint();
    }
}

/* Update the keylist, if it's visible */
void otrg_ui_update_keylist(void)
{
    if (ui_ops != NULL) {
	ui_ops->update_keylist();
    }
}

/* Send an OTR Query Message to attempt to start a connection */
void otrg_ui_connect_connection(ConnContext *context)
{
    /* Send an OTR Query to the other side. */
    PurpleAccount *account;
    char *msg;

    /* Don't do this if we're already ENCRYPTED */
    if (context == NULL || context->msgstate == OTRL_MSGSTATE_ENCRYPTED)
	return;

    account = purple_accounts_find(context->accountname, context->protocol);
    if (!account) {
	PurplePlugin *p = purple_find_prpl(context->protocol);
	msg = g_strdup_printf(_("Account %s (%s) could not be found"),
		context->accountname,
		(p && p->info->name) ? p->info->name : _("Unknown"));
	otrg_dialog_notify_error(context->accountname, context->protocol,
		context->username, _("Account not found"), msg, NULL);
	g_free(msg);
	return;
    }
    otrg_plugin_send_default_query(context, account);
}

/* Drop a context to PLAINTEXT state */
void otrg_ui_disconnect_connection(ConnContext *context)
{

    if (context == NULL)
	return;

    otrg_plugin_disconnect(context);
}

/* Forget a fingerprint */
void otrg_ui_forget_fingerprint(Fingerprint *fingerprint)
{
    ConnContext *context;
    ConnContext *context_iter;

    if (fingerprint == NULL) return;

    /* Don't do anything with the active fingerprint if we're in the
     * ENCRYPTED state. */
    context = fingerprint->context;

    for (context_iter = context->m_context;
	    context_iter && context_iter->m_context == context->m_context;
	    context_iter = context_iter->next) {

	if (context_iter->msgstate == OTRL_MSGSTATE_ENCRYPTED &&
		context_iter->active_fingerprint == fingerprint) return;
    }

    otrl_context_forget_fingerprint(fingerprint, 1);
    otrg_plugin_write_fingerprints();

    otrg_ui_update_keylist();
}

/* Configure OTR for a particular buddy */
void otrg_ui_config_buddy(PurpleBuddy *buddy)
{
    if (ui_ops != NULL) {
	ui_ops->config_buddy(buddy);
    }
}

/* vim: set tabstop=8 softtabstop=4 shiftwidth=4 noexpandtab: */
