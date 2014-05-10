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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* system headers */
#include <stdlib.h>

/* pidgin headers */
#include "notify.h"

/* libotr headers */
#include <libotr/proto.h>
#include <libotr/message.h>

/* pidgin-otr headers */
#include "dialogs.h"
#include "otr-plugin.h"

static const OtrgDialogUiOps *ui_ops = NULL;

/* Set the UI ops */
void otrg_dialog_set_ui_ops(const OtrgDialogUiOps *ops)
{
    ui_ops = ops;
}

/* Get the UI ops */
const OtrgDialogUiOps *otrg_dialog_get_ui_ops(void)
{
    return ui_ops;
}

/* Initialize the OTR dialog subsystem */
void otrg_dialog_init(void)
{
    ui_ops->init();
}

/* Deinitialize the OTR dialog subsystem */
void otrg_dialog_cleanup(void)
{
    ui_ops->cleanup();
}

/* This is just like pidgin_notify_message, except: (a) it doesn't grab
 * keyboard focus, (b) the button is "OK" instead of "Close", and (c)
 * the labels aren't limited to 2K. */
void otrg_dialog_notify_message(PurpleNotifyMsgType type,
	const char *accountname, const char *protocol, const char *username,
	const char *title, const char *primary, const char *secondary)
{
    ui_ops->notify_message(type, accountname, protocol, username,
	    title, primary, secondary);
}

/* Put up the error version of otrg_dialog_notify_message */
void otrg_dialog_notify_error(const char *accountname, const char *protocol,
	const char *username, const char *title, const char *primary,
	const char *secondary)
{
    otrg_dialog_notify_message(PURPLE_NOTIFY_MSG_ERROR, accountname,
	    protocol, username, title, primary, secondary);
}

/* Put up the warning version of otrg_dialog_notify_message */
void otrg_dialog_notify_warning(const char *accountname, const char *protocol,
	const char *username, const char *title, const char *primary,
	const char *secondary)
{
    otrg_dialog_notify_message(PURPLE_NOTIFY_MSG_WARNING, accountname,
	    protocol, username, title, primary, secondary);
}

/* Put up the info version of otrg_dialog_notify_message */
void otrg_dialog_notify_info(const char *accountname, const char *protocol,
	const char *username, const char *title, const char *primary,
	const char *secondary)
{
    otrg_dialog_notify_message(PURPLE_NOTIFY_MSG_INFO, accountname,
	    protocol, username, title, primary, secondary);
}

/* Display an OTR control message for the given accountname / protocol /
 * username conversation.  Return 0 on success, non-0 on error (in which
 * case the message will be displayed inline as a received message). */
int otrg_dialog_display_otr_message( const char *accountname,
	const char *protocol, const char *username, const char *msg,
	int force_create)
{
    return ui_ops->display_otr_message(accountname, protocol, username, msg,
	    force_create);
}

/* Put up a Please Wait dialog.  This dialog can not be cancelled.
 * Return a handle that must eventually be passed to
 * otrg_dialog_private_key_wait_done. */
OtrgDialogWaitHandle otrg_dialog_private_key_wait_start(const char *account,
	const char *protocol, OtrgDialogCancelCb cancel_cb, gpointer user_data)
{
    return ui_ops->private_key_wait_start(account, protocol,
	cancel_cb, user_data);
}

/* End a Please Wait dialog. */
void otrg_dialog_private_key_wait_done(OtrgDialogWaitHandle handle)
{
    ui_ops->private_key_wait_done(handle);
}

/* Show a dialog asking the user to verify the given fingerprint. */
void otrg_dialog_verify_fingerprint(Fingerprint *fprint)
{
    ui_ops->verify_fingerprint(fprint);
}

/* Show a dialog asking the user to give an SMP secret. */
void otrg_dialog_socialist_millionaires(ConnContext *context)
{
    ui_ops->socialist_millionaires(context, NULL, TRUE);
}

/* Show a dialog asking the user to give an SMP secret, prompting with a
 * question. */
void otrg_dialog_socialist_millionaires_q(ConnContext *context,
	char *question)
{
    ui_ops->socialist_millionaires(context, question, TRUE);
}

/* Update the status of an ongoing socialist millionaires protocol. */
void otrg_dialog_update_smp(ConnContext *context, OtrlSMPEvent smp_event,
	double progress_level)
{
    ui_ops->update_smp(context, smp_event, progress_level);
}

/* Call this when a context transitions to ENCRYPTED. */
void otrg_dialog_connected(ConnContext *context)
{
    ui_ops->connected(context);
}

/* Call this when a context transitions to PLAINTEXT. */
void otrg_dialog_disconnected(ConnContext *context)
{
    ui_ops->disconnected(context);
}

/* Call this when we receive a Key Exchange message that doesn't cause
 * our state to change (because it was just the keys we knew already). */
void otrg_dialog_stillconnected(ConnContext *context)
{
    ui_ops->stillconnected(context);
}

/* Call this if the remote user terminates his end of an ENCRYPTED
 * connection, and lets us know. */
void otrg_dialog_finished(const char *accountname, const char *protocol,
	const char *username)
{
    ui_ops->finished(accountname, protocol, username);
}

/* Set all OTR buttons to "sensitive" or "insensitive" as appropriate.
 * Call this when accounts are logged in or out. */
void otrg_dialog_resensitize_all(void)
{
    ui_ops->resensitize_all();
}

/* Set up the per-conversation information display */
void otrg_dialog_new_conv(PurpleConversation *conv)
{
    ui_ops->new_conv(conv);
}

/* Remove the per-conversation information display */
void otrg_dialog_remove_conv(PurpleConversation *conv)
{
    ui_ops->remove_conv(conv);
}

/* vim: set tabstop=8 softtabstop=4 shiftwidth=4 noexpandtab: */
