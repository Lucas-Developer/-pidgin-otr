/*
 *  Off-the-Record Messaging plugin for libpurple 3
 *  Copyright (C) 2004-2012  Ian Goldberg, Rob Smits,
 *                           Chris Alexander, Willy Lew,
 *                           Lisa Du, Nikita Borisov
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

/* config.h */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* system headers */
#include <glib.h>

/* purple headers */
#include "debug.h"
#include "image-store.h"

#ifdef ENABLE_NLS
/* internationalisation headers */
#include <glib/gi18n-lib.h>
#else
#define _(x) (x)
#define N_(x) (x)
#endif

/* libotr headers */
#include <libotr/privkey.h>

/* purple-otr headers */
#include "common.h"
#include "dialogs.h"
#include "fprint-verificator.h"
#include "otr-plugin.h"
#include "purple3-dialog.h"
#include "ui.h"

/* static buffers size for short messages */
#define OTRG_STR_BUFF_SIZE 1024

#define GTK_STOCK_HELP "gtk-help"

typedef struct {
	void *dialog_handle;
	OtrgDialogCancelCb cancel_cb;
	gpointer cancel_data;
} OtrgDialogWaitHandlePurple3;

static PurpleE2eeProvider *provider = NULL;

static PurpleE2eeState *e2ee_state_not_private = NULL;
static PurpleE2eeState *e2ee_state_private = NULL;
static PurpleE2eeState *e2ee_state_unverified = NULL;
static PurpleE2eeState *e2ee_state_finished = NULL;

static GRegex *otrg_purple3_htmltag_re = NULL;

static OtrgFingerprintVerificator otrg_purple3_fpv_oneway;
static OtrgFingerprintVerificator otrg_purple3_fpv_twoway;
static OtrgFingerprintVerificator otrg_purple3_fpv_manual;

static GList *
otrg_purple3_conv_menu_cb(PurpleConversation *conv);

static void
otrg_purple3_check_incoming_instance_change(PurpleAccount *account,
	char *sender, char *message, PurpleConversation *conv,
	PurpleMessageFlags flags);

static void
otrg_purple3_dialog_resensitize(PurpleConversation *conv);

const gchar*
otrg_purple3_account_full_name(const char *protocol, const char *account)
{
	PurplePlugin *p;
	const gchar *protocol_print;
	static gchar full_name[OTRG_STR_BUFF_SIZE];

	p = purple_find_prpl(protocol);
	protocol_print = (p ? p->info->name : _("Unknown"));

	g_snprintf(full_name, sizeof(full_name), "%s (%s)",
		account, protocol_print);

	return full_name;
}

PurpleE2eeState *
otrg_purple3_trustlevel_to_e2eestate(TrustLevel level)
{
	switch (level) {
		case TRUST_NOT_PRIVATE:
			return e2ee_state_not_private;
		case TRUST_UNVERIFIED:
			return e2ee_state_unverified;
		case TRUST_PRIVATE:
			return e2ee_state_private;
		case TRUST_FINISHED:
			return e2ee_state_finished;
	}

	return NULL;
}

static gboolean
otrg_purple3_dialog_init(void)
{
	provider = purple_e2ee_provider_new();
	purple_e2ee_provider_set_name(provider, _("OTR"));
	purple_e2ee_provider_set_conv_menu_cb(provider, otrg_purple3_conv_menu_cb);

	if (!purple_e2ee_provider_register(provider)) {
		purple_debug_fatal("otr", "Couldn't register a e2ee provider");
		purple_notify_error(otrg_plugin_handle,
			_("E2EE plugin registration failed"),
			_("Couldn't register OTR plugin."), NULL, NULL);
		return FALSE;
	}

	e2ee_state_not_private = purple_e2ee_state_new(provider);
	purple_e2ee_state_set_name(e2ee_state_not_private, _("Not private"));
	purple_e2ee_state_set_stock_icon(e2ee_state_not_private, "not-private");
	e2ee_state_private = purple_e2ee_state_new(provider);
	purple_e2ee_state_set_name(e2ee_state_private, _("Private"));
	purple_e2ee_state_set_stock_icon(e2ee_state_private, "private");
	e2ee_state_unverified = purple_e2ee_state_new(provider);
	purple_e2ee_state_set_name(e2ee_state_unverified, _("Unverified"));
	purple_e2ee_state_set_stock_icon(e2ee_state_unverified, "unverified");
	e2ee_state_finished = purple_e2ee_state_new(provider);
	purple_e2ee_state_set_name(e2ee_state_finished, _("Finished"));
	purple_e2ee_state_set_stock_icon(e2ee_state_finished, "finished");

	otrg_purple3_htmltag_re = g_regex_new("<[^>]*>",
		G_REGEX_DOTALL | G_REGEX_OPTIMIZE, 0, NULL);

	otrg_verificator_register(&otrg_purple3_fpv_oneway);
	otrg_verificator_register(&otrg_purple3_fpv_twoway);
	otrg_verificator_register(&otrg_purple3_fpv_manual);

	purple_signal_connect(purple_conversations_get_handle(),
		"received-im-msg", otrg_plugin_handle,
		PURPLE_CALLBACK(otrg_purple3_check_incoming_instance_change),
		NULL);

	return TRUE;
}

static void
otrg_purple3_dialog_cleanup(void)
{
	if (provider == NULL) {
		purple_debug_fatal("otr", "Wasn't registered");
		return;
	}

	purple_signal_disconnect(purple_conversations_get_handle(),
		"received-im-msg", otrg_plugin_handle,
		PURPLE_CALLBACK(otrg_purple3_check_incoming_instance_change));

	otrg_verificator_unregister(&otrg_purple3_fpv_oneway);
	otrg_verificator_unregister(&otrg_purple3_fpv_twoway);
	otrg_verificator_unregister(&otrg_purple3_fpv_manual);

	g_regex_unref(otrg_purple3_htmltag_re);
	otrg_purple3_htmltag_re = NULL;

	purple_e2ee_state_unref(e2ee_state_not_private);
	e2ee_state_not_private = NULL;
	purple_e2ee_state_unref(e2ee_state_private);
	e2ee_state_private = NULL;
	purple_e2ee_state_unref(e2ee_state_unverified);
	e2ee_state_unverified = NULL;
	purple_e2ee_state_unref(e2ee_state_finished);
	e2ee_state_finished = NULL;
	purple_e2ee_provider_unregister(provider);
	purple_e2ee_provider_free(provider);
	provider = NULL;
}

static void
otrg_purple3_dialog_new_conv(PurpleConversation *conv)
{
	otrg_conversation_init_vars(conv);

	if (otrg_conversation_is_otr_enabled(conv))
		otrg_plugin_conv_to_selected_context(conv, TRUE);

	otrg_purple3_dialog_resensitize(conv);
}

static void
otrg_purple3_dialog_remove_conv(PurpleConversation *conv)
{
	gpointer *wait_handle;

	wait_handle = g_object_get_data(G_OBJECT(conv), "otr-wait-handle");
	if (wait_handle) {
		purple_request_close(PURPLE_REQUEST_WAIT, wait_handle);
		g_object_set_data(G_OBJECT(conv), "otr-wait-handle", NULL);
		g_object_set_data(G_OBJECT(conv), "otr-wait-instance", NULL);
	}

	otrg_conversation_cleanup_vars(conv);
}

/* this is used as a fallback for otrg_purple3_dialog_display_otr_message */
static void
otrg_purple3_dialog_notify_message(PurpleNotifyMsgType type,
	const char *accountname, const char *protocol, const char *username,
	const char *title, const char *primary, const char *secondary)
{
	PurpleAccount *account;
	gchar *primary_new, *secondary_new;

	account = purple_accounts_find(accountname, protocol);

	primary_new = primary ? g_regex_replace(otrg_purple3_htmltag_re,
		primary, -1, 0, "", 0, NULL) : NULL;
	secondary_new = secondary ? g_regex_replace(otrg_purple3_htmltag_re,
		secondary, -1, 0, "", 0, NULL) : NULL;

	purple_notify_message(otrg_plugin_handle, type, title, primary_new,
		secondary_new, purple_request_cpar_from_account(account),
		NULL, NULL);

	g_free(primary_new);
	g_free(secondary_new);
}

static void
otrg_purple3_otr_message(PurpleConversation *conv, const gchar *msg)
{
	purple_conversation_write(conv, NULL, msg, PURPLE_MESSAGE_SYSTEM,
		time(NULL));
}

/* similiar to GTK version */
static int
otrg_purple3_dialog_display_otr_message(const char *accountname,
	const char *protocol, const char *username, const char *msg,
	int force_create)
{
	PurpleConversation *conv = otrg_plugin_userinfo_to_conv(accountname,
		protocol, username, force_create);

	if (!conv)
		return -1;

	otrg_purple3_otr_message(conv, msg);

	return 0;
}

static void
otrg_purple3_dialog_private_key_wait_cancel(gpointer _handle)
{
	OtrgDialogWaitHandlePurple3 *handle = _handle;

	handle->dialog_handle = NULL;
	handle->cancel_cb(handle->cancel_data);
	g_free(handle);
}

static OtrgDialogWaitHandle
otrg_purple3_dialog_private_key_wait_start(const char *accountname,
	const char *protocol, OtrgDialogCancelCb cancel_cb, gpointer user_data)
{
	OtrgDialogWaitHandlePurple3 *handle = g_new0(OtrgDialogWaitHandlePurple3, 1);
	PurpleAccount *account;
	gchar *secondary;

	account = purple_accounts_find(accountname, protocol);

	secondary = g_strdup_printf(_("Generating private key for %s..."),
		otrg_purple3_account_full_name(protocol, accountname));

	handle->cancel_cb = cancel_cb;
	handle->cancel_data = user_data;
	handle->dialog_handle = purple_request_wait(otrg_plugin_handle,
		_("Generating private key"), NULL, secondary, FALSE,
		otrg_purple3_dialog_private_key_wait_cancel,
		purple_request_cpar_from_account(account), handle);

	return handle;
}

static void
otrg_purple3_dialog_private_key_wait_done(OtrgDialogWaitHandle _handle)
{
	OtrgDialogWaitHandlePurple3 *handle = _handle;
	purple_request_close(PURPLE_REQUEST_ACTION, handle->dialog_handle);
	g_free(handle);
}

/******************************************************************************
 * Common fingerprint verification routines.
 ******************************************************************************/

typedef struct
{
	OtrgContextClone *cclone;
	OtrgFingerprintClone *fpclone;
	OtrgFingerprintVerifyBackCb on_back;
	gpointer on_back_data;
} OtrgPurple3FPVData;

static void
otrg_purple3_fpv_data_free(OtrgPurple3FPVData *data)
{
	otrg_context_clone_free(data->cclone);
	otrg_fingerprint_clone_free(data->fpclone);
	g_free(data);
}

static void
otrg_purple3_fpv_back(OtrgPurple3FPVData *cbdata, PurpleRequestFields *fields)
{
	ConnContext *context;

	context = otrg_context_get_origin(cbdata->cclone);

	if (cbdata->on_back && context)
		cbdata->on_back(context, cbdata->on_back_data);

	otrg_purple3_fpv_data_free(cbdata);
}

static void
otrg_purple3_fpv_help(gpointer _context)
{
	const gchar *context = _context;
	gchar *url;

	url = g_strdup_printf("%s%s%s%s",
		AUTHENTICATE_HELPURL, _("?lang=en"),
		context ? "&context=" : "",
		context ? context : "");
	purple_notify_uri(otrg_plugin_handle, url);
	g_free(url);
}

static OtrgPurple3FPVData *
otrg_purple3_fpv_prepare(Fingerprint *fprint, ConnContext *context,
	OtrgFingerprintVerifyBackCb on_back, gpointer on_back_data,
	PurpleRequestCommonParameters *cpar, const gchar *help_context)
{
	OtrgPurple3FPVData *cbdata;

	g_return_val_if_fail(context != NULL, NULL);
	g_return_val_if_fail(cpar != NULL, NULL);

	purple_request_cpar_set_account(cpar,
		purple_accounts_find(context->accountname, context->protocol));
	purple_request_cpar_set_html(cpar, TRUE);
	purple_request_cpar_set_compact(cpar, TRUE);
	purple_request_cpar_set_help_cb(cpar, otrg_purple3_fpv_help,
		(gpointer)help_context);

	cbdata = g_new0(OtrgPurple3FPVData, 1);
	cbdata->cclone = otrg_context_clone(context);
	if (fprint)
		cbdata->fpclone = otrg_fingerprint_clone(fprint);

	if (on_back) {
		purple_request_cpar_set_extra_actions(cpar, _("_Back"),
			otrg_purple3_fpv_back, NULL);
		cbdata->on_back = on_back;
		cbdata->on_back_data = on_back_data;
	}

	return cbdata;
}

/******************************************************************************
 * Socialist millionaires progress dialog.
 ******************************************************************************/

static void
otrg_purple3_smp_cancel(gpointer _conv)
{
	PurpleConversation *conv = _conv;
	otrl_instag_t their_instance;
	ConnContext *context;

	their_instance = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(conv),
		"otr-wait-instance"));

	g_object_set_data(G_OBJECT(conv), "otr-wait-handle", NULL);
	g_object_set_data(G_OBJECT(conv), "otr-wait-instance", NULL);

	context = otrg_plugin_conv_to_context(conv, their_instance, FALSE);

	g_return_if_fail(context != NULL);

	otrg_plugin_abort_smp(context);
}

static void
otrg_purple3_smp_close(PurpleConversation *conv)
{
	gpointer dialog_handle;
	OtrgPurple3FPVData *cbdata;

	dialog_handle = g_object_get_data(G_OBJECT(conv), "otr-smp-dialog");
	cbdata = g_object_get_data(G_OBJECT(conv), "otr-smp-dialog-data");
	g_object_set_data(G_OBJECT(conv), "otr-smp-dialog", NULL);
	g_object_set_data(G_OBJECT(conv), "otr-smp-dialog-data", NULL);

	if (dialog_handle != NULL) {
		purple_request_close(PURPLE_REQUEST_FIELDS, dialog_handle);
		otrg_purple3_fpv_data_free(cbdata);
	}
}

static void
otrg_purple3_dialog_update_smp(ConnContext *context, OtrlSMPEvent smp_event,
	double progress_level)
{
	PurpleConversation *conv = otrg_plugin_context_to_conv(context, FALSE);
	gpointer *wait_handle;
	const gchar *title;
	gchar *primary;
	otrl_instag_t their_instance;
	gboolean is_answering, is_running;
	PurpleRequestCommonParameters *cpar;

	g_return_if_fail(conv != NULL);

	wait_handle = g_object_get_data(G_OBJECT(conv), "otr-wait-handle");
	their_instance = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(conv),
		"otr-wait-instance"));
	is_answering = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(conv),
		"otr-wait-is-answering"));
	is_running = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(conv),
		"otr-wait-running"));

	if (!is_running) {
		purple_debug_misc("otr", "smp is not in progress");
		return;
	}

	if (is_answering) {
		title = _("Authenticating to Buddy");
		primary = g_strdup_printf(_("Authenticating to %s"),
			context->username);
	} else {
		title = _("Authenticating Buddy");
		primary = g_strdup_printf(_("Authenticating %s"),
			context->username);
	}

	if (their_instance > 0 && context->their_instance != their_instance) {
		purple_debug_error("otr",
			"update smp: instances doesn't match");
		g_free(primary);
		return;
	}
	if (!wait_handle && smp_event == OTRL_SMPEVENT_IN_PROGRESS) {
		PurpleRequestCommonParameters *cparw;

		cparw = purple_request_cpar_from_conversation(conv);

		wait_handle = purple_request_wait(otrg_plugin_handle, title,
			primary, _("Waiting for buddy..."), TRUE,
			otrg_purple3_smp_cancel, cparw, conv);

		g_object_set_data(G_OBJECT(conv), "otr-wait-handle", wait_handle);
	}

	cpar = purple_request_cpar_from_conversation(conv);
	purple_request_cpar_set_parent_from(cpar, wait_handle);

	if (smp_event == OTRL_SMPEVENT_IN_PROGRESS) {
		if (progress_level < 0.1)
			progress_level = 0.1;
		purple_request_wait_progress(wait_handle, progress_level);
		purple_request_cpar_unref(cpar);
	} else if (smp_event == OTRL_SMPEVENT_SUCCESS) {
		const gchar *secondary = _("Authentication successful.");

		if (!otrg_fingerprint_is_trusted(context->active_fingerprint)) {
			secondary = _("Your buddy has successfully "
				"authenticated you.  You may want to "
				"authenticate your buddy as well by asking your"
				" own question.");
		}

		purple_notify_info(otrg_plugin_handle, title, primary,
			secondary, cpar);
	} else if (smp_event == OTRL_SMPEVENT_ABORT) {
		purple_notify_warning(otrg_plugin_handle, title, primary,
			_("The remote user has aborted authentication."), cpar);
	} else if (smp_event == OTRL_SMPEVENT_CHEATED) {
		/* XXX: is it a good warning? */
		purple_notify_warning(otrg_plugin_handle, title, primary,
			_("The remote user is not following the authentication "
			"protocol. The conversation is, most probably, "
			"cheated."), cpar);
	} else if (smp_event == OTRL_SMPEVENT_FAILURE) {
		purple_notify_warning(otrg_plugin_handle, title, primary,
			_("The remote user failed to authenticate."), cpar);
	} else {
		purple_debug_error("otr", "Unknown smp event: %d", smp_event);
		purple_notify_error(otrg_plugin_handle, title, primary,
			_("Authentication failed: unknown error."), cpar);
	}

	if (smp_event != OTRL_SMPEVENT_IN_PROGRESS)
		otrg_purple3_smp_close(conv);

	g_free(primary);

	if (wait_handle && smp_event != OTRL_SMPEVENT_IN_PROGRESS) {
		purple_request_close(PURPLE_REQUEST_WAIT, wait_handle);
		g_object_set_data(G_OBJECT(conv), "otr-wait-handle", NULL);
		g_object_set_data(G_OBJECT(conv), "otr-wait-instance", NULL);
		g_object_set_data(G_OBJECT(conv), "otr-wait-is-answering",
			NULL);
		g_object_set_data(G_OBJECT(conv), "otr-wait-running", NULL);
	}
}

/******************************************************************************
 * Manual fingerprint verification.
 ******************************************************************************/

static void
otrg_purple3_fpv_manual_ok(OtrgPurple3FPVData *cbdata,
	PurpleRequestFields *fields)
{
	Fingerprint *fprint;
	gboolean trust;

	fprint = otrg_fingerprint_get_origin(cbdata->fpclone);
	otrg_purple3_fpv_data_free(cbdata);

	if (fprint == NULL)
		return;

	trust = purple_request_fields_get_bool(fields, "verified");
	otrl_context_set_trust(fprint, trust ? "verified" : "");

	/* Write the new info to disk, redraw the ui, and redraw the OTR
	 * buttons. */
	otrg_plugin_write_fingerprints();
	otrg_ui_update_keylist();
	otrg_dialog_resensitize_all();
}

static void
otrg_purple3_fpv_manual_cancel(OtrgPurple3FPVData *cbdata,
	PurpleRequestFields *fields)
{
	otrg_purple3_fpv_data_free(cbdata);
}

static gboolean
otrg_purple3_fpv_manual_validator(PurpleRequestField *field, gchar **errmsg,
	gpointer _verified_old)
{
	gboolean verified_old, verified_new;

	verified_old = GPOINTER_TO_INT(_verified_old);
	verified_new = purple_request_field_bool_get_value(field);

	return (verified_new != verified_old);
}

static void
otrg_purple3_fpv_manual_verify(Fingerprint *fprint, ConnContext *context,
	OtrgFingerprintVerifyBackCb on_back, gpointer on_back_data)
{
	OtrgPurple3FPVData *cbdata;
	gchar our_hash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	gchar their_hash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	gchar *primary, *secondary;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;
	PurpleRequestCommonParameters *cpar;
	gboolean previously_verified;

	g_return_if_fail(context != NULL || fprint != NULL);

	if (fprint == NULL)
		fprint = context->active_fingerprint;
	else if (context == NULL)
		context = fprint->context;

	g_return_if_fail(fprint != NULL);
	g_return_if_fail(context != NULL);
	g_return_if_fail(fprint->fingerprint != NULL);

	g_strlcpy(our_hash, _("[none]"), OTRL_PRIVKEY_FPRINT_HUMAN_LEN);
	otrl_privkey_fingerprint(otrg_plugin_userstate, our_hash,
		context->accountname, context->protocol);

	otrl_privkey_hash_to_human(their_hash, fprint->fingerprint);

	primary = g_strdup_printf(_("Verify fingerprint for %s"),
		context->username);

	secondary = g_strdup_printf(_("<small>%s %s</small>\n\n"
		"Fingerprint for you, %s:\n<tt>%s</tt>\n\n"
		"Purported fingerprint for %s:\n<tt>%s</tt>"),
		_("To verify the fingerprint, contact your buddy via some "
		"<i>other</i> authenticated channel, such as the telephone "
		"or GPG-signed email.  Each of you should tell your fingerprint"
		" to the other."),
		_("If everything matches up, you should indicate in the above "
		"dialog that you <b>have</b> verified the fingerprint."),
		otrg_purple3_account_full_name(context->protocol,
			context->accountname),
		our_hash, context->username, their_hash);

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	previously_verified = otrg_fingerprint_is_trusted(fprint);
	field = purple_request_field_bool_new("verified",
		_("I have verified that this is in fact the correct"),
		previously_verified);
	purple_request_field_set_validator(field,
		otrg_purple3_fpv_manual_validator,
		GINT_TO_POINTER(previously_verified));
	purple_request_field_group_add_field(group, field);

	cpar = purple_request_cpar_new();
	purple_request_cpar_set_icon(cpar, PURPLE_REQUEST_ICON_WARNING);

	cbdata = otrg_purple3_fpv_prepare(fprint, context, on_back,
		on_back_data, cpar, "fingerprint");

	purple_request_fields(otrg_plugin_handle, _("Verify fingerprint"),
		primary, secondary, fields,
		_("OK"), (GCallback)otrg_purple3_fpv_manual_ok,
		_("Cancel"), (GCallback)otrg_purple3_fpv_manual_cancel,
		cpar, cbdata);

	g_free(primary);
	g_free(secondary);
}

static void
otrg_purple3_fpv_manual_verify_ctx(ConnContext *context,
	OtrgFingerprintVerifyBackCb on_back, gpointer on_back_data)
{
	g_return_if_fail(context != NULL);

	otrg_purple3_fpv_manual_verify(NULL, context, on_back, on_back_data);
}

static void
otrg_purple3_fpv_manual_verify_fprint(Fingerprint *fprint)
{
	g_return_if_fail(fprint != NULL);

	otrg_purple3_fpv_manual_verify(fprint, NULL, NULL, NULL);
}

static OtrgFingerprintVerificator otrg_purple3_fpv_manual =
{
	sizeof(OtrgFingerprintVerificator),
	N_("Manual fingerprint verification"),
	otrg_purple3_fpv_manual_verify_ctx
};

/******************************************************************************
 * Common one- and two- way verification routines.
 ******************************************************************************/

static void
otrg_purple3_fpv_onetwoway_ok(OtrgPurple3FPVData *cbdata,
	PurpleRequestFields *fields)
{
	ConnContext *context;
	const gchar *question = NULL, *secret;
	PurpleConversation *conv;
	gboolean is_answering;

	context = otrg_context_get_origin(cbdata->cclone);
	otrg_purple3_fpv_data_free(cbdata);

	if (context == NULL)
		return;
	conv = otrg_plugin_context_to_conv(context, TRUE);
	g_object_set_data(G_OBJECT(conv), "otr-smp-dialog", NULL);

	is_answering = purple_request_fields_get_bool(fields, "is_answering");

	/* two way verification doesn't have question field */
	if (!is_answering && purple_request_fields_exists(fields, "question"))
		question = purple_request_fields_get_string(fields, "question");
	secret = purple_request_fields_get_string(fields, "secret");
	g_return_if_fail(secret != NULL);

	g_object_set_data(G_OBJECT(conv), "otr-wait-is-answering",
		GINT_TO_POINTER(is_answering));
	g_object_set_data(G_OBJECT(conv), "otr-wait-instance",
		GINT_TO_POINTER(context->their_instance));
	g_object_set_data(G_OBJECT(conv), "otr-wait-running",
		GINT_TO_POINTER(TRUE));
	otrg_purple3_dialog_update_smp(context, OTRL_SMPEVENT_IN_PROGRESS, 0.0);
	if (is_answering) {
		otrg_plugin_continue_smp(context, (const guchar*)secret,
			strlen(secret));
	} else {
		otrg_plugin_start_smp(context, question, (const guchar*)secret,
			strlen(secret));
	}
}

static void
otrg_purple3_fpv_onetwoway_cancel(OtrgPurple3FPVData *cbdata,
	PurpleRequestFields *fields)
{
	ConnContext *context;
	PurpleConversation *conv;
	gboolean is_answering;

	context = otrg_context_get_origin(cbdata->cclone);
	otrg_purple3_fpv_data_free(cbdata);

	if (context == NULL)
		return;

	conv = otrg_plugin_context_to_conv(context, FALSE);
	if (conv)
		g_object_set_data(G_OBJECT(conv), "otr-smp-dialog", NULL);

	is_answering = purple_request_fields_get_bool(fields, "is_answering");

	if (is_answering)
		otrg_plugin_abort_smp(context);
}

/******************************************************************************
 * One way verification.
 ******************************************************************************/

static void
otrg_purple3_fpv_oneway_dialog(ConnContext *context, const gchar *question,
	OtrgFingerprintVerifyBackCb on_back, gpointer on_back_data)
{
	gchar *primary, *secondary, *tmp;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;
	PurpleRequestCommonParameters *cpar;
	OtrgPurple3FPVData *cbdata;
	gboolean is_answering = (question != NULL);
	PurpleConversation *conv;
	gpointer dialog_handle;

	g_return_if_fail(context != NULL);

	conv = otrg_plugin_context_to_conv(context, TRUE);

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	primary = g_strdup_printf(_("Authenticate %s"), context->username);

	if (is_answering) {
		secondary = g_strdup_printf("<small>%s</small>",
			_("Your buddy is attempting to determine if he or she "
			"is really talking to you, or if it's someone "
			"pretending to be you.  Your buddy has asked a "
			"question, indicated below.  To authenticate to your "
			"buddy, enter the answer and click OK."));
	} else {
		secondary = g_strdup_printf("<small>%s</small>",
			_("To authenticate using a question, pick a question "
			"whose answer is known only to you and your buddy.  "
			"Enter this question and this answer, then wait for "
			"your buddy to enter the answer too.  If the answers "
			"don't match, then you may be talking to an "
			"imposter."));
	}

	field = purple_request_field_bool_new("is_answering", "", is_answering);
	purple_request_field_set_visible(field, FALSE);
	purple_request_field_group_add_field(group, field);

	if (is_answering) {
		field = purple_request_field_string_new("asked_question", _("This is "
			"the question asked by your buddy:"), question, FALSE);
		purple_request_field_set_sensitive(field, FALSE);
	} else {
		field = purple_request_field_string_new("question",
			_("Enter question here:"), "", FALSE);
		purple_request_field_set_required(field, TRUE);
	}
	purple_request_field_group_add_field(group, field);

	field = purple_request_field_string_new("secret",
		_("Enter secret answer here (case sensitive):"), "", FALSE);
	purple_request_field_set_required(field, TRUE);
	purple_request_field_group_add_field(group, field);

	if (otrg_fingerprint_is_trusted(context->active_fingerprint) &&
		!is_answering)
	{
		tmp = g_strdup_printf(
			"<small><span foreground='darkgreen'>%s</span></small>",
			_("This buddy is already authenticated."));
		field = purple_request_field_label_new("alreadyauth", tmp);
		g_free(tmp);
		purple_request_field_group_add_field(group, field);
	}

	cpar = purple_request_cpar_new();
	purple_request_cpar_set_icon(cpar, PURPLE_REQUEST_ICON_DIALOG);

	cbdata = otrg_purple3_fpv_prepare(NULL, context, on_back,
		on_back_data, cpar, is_answering ? "answer" : "question");

	dialog_handle = purple_request_fields(otrg_plugin_handle,
		_("Authenticate Buddy"), primary, secondary, fields,
		_("OK"), (GCallback)otrg_purple3_fpv_onetwoway_ok,
		_("Cancel"), (GCallback)otrg_purple3_fpv_onetwoway_cancel,
		cpar, cbdata);
	g_object_set_data(G_OBJECT(conv), "otr-smp-dialog", dialog_handle);
	g_object_set_data(G_OBJECT(conv), "otr-smp-dialog-data", cbdata);

	g_free(primary);

	if (is_answering) {
		g_object_set_data(G_OBJECT(conv), "otr-wait-running",
			GINT_TO_POINTER(TRUE));
	}
}

static void
otrg_purple3_fpv_oneway_verify(ConnContext *context,
	OtrgFingerprintVerifyBackCb on_back, gpointer on_back_data)
{
	otrg_purple3_fpv_oneway_dialog(context, NULL, on_back, on_back_data);
}

static void
otrg_purple3_fpv_oneway_answer(ConnContext *context, const gchar *question)
{
	otrg_purple3_fpv_oneway_dialog(context, question, NULL, NULL);
}

static OtrgFingerprintVerificator otrg_purple3_fpv_oneway =
{
	sizeof(OtrgFingerprintVerificator),
	N_("Question and answer"),
	otrg_purple3_fpv_oneway_verify
};

/******************************************************************************
 * Two way verification.
 ******************************************************************************/


static void
otrg_purple3_fpv_twoway_dialog(ConnContext *context, gboolean is_answering,
	OtrgFingerprintVerifyBackCb on_back, gpointer on_back_data)
{
	gchar *primary, *secondary, *tmp;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;
	PurpleRequestCommonParameters *cpar;
	OtrgPurple3FPVData *cbdata;
	PurpleConversation *conv;
	gpointer dialog_handle;

	g_return_if_fail(context != NULL);

	conv = otrg_plugin_context_to_conv(context, TRUE);

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	primary = g_strdup_printf(_("Authenticate %s"), context->username);

	secondary = g_strdup_printf("<small>%s</small>",
		_("To authenticate, pick a secret known only to you and your "
		"buddy.  Enter this secret, then wait for your buddy to enter "
		"it too.  If the secrets don't match, then you may be talking "
		"to an imposter."));

	field = purple_request_field_bool_new("is_answering", "", is_answering);
	purple_request_field_set_visible(field, FALSE);
	purple_request_field_group_add_field(group, field);

	field = purple_request_field_string_new("secret",
		_("Enter secret here:"), "", FALSE);
	purple_request_field_set_required(field, TRUE);
	purple_request_field_group_add_field(group, field);

	if (otrg_fingerprint_is_trusted(context->active_fingerprint))
	{
		tmp = g_strdup_printf(
			"<small><span foreground='darkgreen'>%s</span></small>",
			_("This buddy is already authenticated."));
		field = purple_request_field_label_new("alreadyauth", tmp);
		g_free(tmp);
		purple_request_field_group_add_field(group, field);
	}

	cpar = purple_request_cpar_new();
	purple_request_cpar_set_icon(cpar, PURPLE_REQUEST_ICON_DIALOG);

	cbdata = otrg_purple3_fpv_prepare(NULL, context, on_back,
		on_back_data, cpar, is_answering ? "secretresp" : "secret");

	dialog_handle = purple_request_fields(otrg_plugin_handle,
		_("Authenticate Buddy"), primary, secondary, fields,
		_("OK"), (GCallback)otrg_purple3_fpv_onetwoway_ok,
		_("Cancel"), (GCallback)otrg_purple3_fpv_onetwoway_cancel,
		cpar, cbdata);
	g_object_set_data(G_OBJECT(conv), "otr-smp-dialog", dialog_handle);
	g_object_set_data(G_OBJECT(conv), "otr-smp-dialog-data", cbdata);

	g_free(primary);

	if (is_answering) {
		g_object_set_data(G_OBJECT(conv), "otr-wait-running",
			GINT_TO_POINTER(TRUE));
	}
}

static void
otrg_purple3_fpv_twoway_verify(ConnContext *context,
	OtrgFingerprintVerifyBackCb on_back, gpointer on_back_data)
{
	otrg_purple3_fpv_twoway_dialog(context, FALSE, on_back, on_back_data);
}

static void
otrg_purple3_fpv_twoway_answer(ConnContext *context)
{
	otrg_purple3_fpv_twoway_dialog(context, TRUE, NULL, NULL);
}

static OtrgFingerprintVerificator otrg_purple3_fpv_twoway =
{
	sizeof(OtrgFingerprintVerificator),
	N_("Shared secret"),
	otrg_purple3_fpv_twoway_verify
};

/******************************************************************************
 * Common verification window.
 ******************************************************************************/

static void
purple3_dialog_verification_method_choose(ConnContext *context,
	gpointer default_verf);

static void
purple3_dialog_verification_method_choosen(OtrgContextClone *cclone,
	PurpleRequestFields *fields)
{
	OtrgFingerprintVerificator *verf;
	ConnContext *context;
	PurpleConversation *conv;

	context = otrg_context_get_origin(cclone);
	otrg_context_clone_free(cclone);
	g_return_if_fail(context != NULL);

	conv = otrg_plugin_context_to_conv(context, FALSE);
	if (conv) {
		g_object_set_data(G_OBJECT(conv), "otr-verifychoose-dialog",
			NULL);
	}

	verf = purple_request_fields_get_choice(fields, "method");
	g_return_if_fail(verf != NULL);

	verf->verify_cb(context, purple3_dialog_verification_method_choose,
		verf);
}

static void
purple3_dialog_verification_method_choose_cancel(OtrgContextClone *cclone,
	PurpleRequestFields *fields)
{
	ConnContext *context;
	PurpleConversation *conv;

	context = otrg_context_get_origin(cclone);
	otrg_context_clone_free(cclone);

	conv = otrg_plugin_context_to_conv(context, FALSE);
	if (conv) {
		g_object_set_data(G_OBJECT(conv), "otr-verifychoose-dialog",
			NULL);
	}
}

static void
purple3_dialog_verification_method_choose_close(PurpleConversation *conv)
{
	void *dialog_handle;
	OtrgContextClone *cclone;

	dialog_handle = g_object_get_data(G_OBJECT(conv),
		"otr-verifychoose-dialog");
	cclone = g_object_get_data(G_OBJECT(conv),
		"otr-verifychoose-dialog-data");
	g_object_set_data(G_OBJECT(conv), "otr-verifychoose-dialog", NULL);

	if (!dialog_handle)
		return;

	purple_request_close(PURPLE_REQUEST_FIELDS, dialog_handle);
	otrg_context_clone_free(cclone);
}

static void
purple3_dialog_verification_method_choose(ConnContext *context,
	gpointer default_verf)
{
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;
	PurpleRequestCommonParameters *cpar;
	gchar *primary;
	GSList *it;
	OtrgContextClone *cclone;
	PurpleConversation *conv;
	void *dialog_handle;

	g_return_if_fail(context != NULL);
	g_return_if_fail(otrg_fprint_verificators != NULL);

	if (context->active_fingerprint == NULL) {
		purple_debug_warning("otr", "Selected context is not active");
		return;
	}

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	field = purple_request_field_choice_new("method",
		_("How would you like to authenticate your buddy?"),
		default_verf);
	it = otrg_fprint_verificators;
	while (it != NULL) {
		OtrgFingerprintVerificator *verf = it->data;
		it = g_slist_next(it);

		purple_request_field_choice_add(field, _(verf->name), verf);
	}
	purple_request_field_group_add_field(group, field);

	primary = g_strdup_printf(_("Authenticate %s"), context->username);

	cpar = purple_request_cpar_from_account(
		purple_accounts_find(context->accountname, context->protocol));
	purple_request_cpar_set_icon(cpar, PURPLE_REQUEST_ICON_DIALOG);
	purple_request_cpar_set_compact(cpar, TRUE);
	purple_request_cpar_set_help_cb(cpar, otrg_purple3_fpv_help, NULL);

	cclone = otrg_context_clone(context);
	dialog_handle = purple_request_fields(otrg_plugin_handle,
		_("Authenticate Buddy"),
		primary, _("Authenticating a buddy helps ensure that the person"
		" you are talking to is who he or she claims to be."), fields,
		_("Next"), (GCallback)purple3_dialog_verification_method_choosen,
		_("_Cancel"),
		(GCallback)purple3_dialog_verification_method_choose_cancel,
		cpar, cclone);
	conv = otrg_plugin_context_to_conv(context, TRUE);
	g_object_set_data(G_OBJECT(conv), "otr-verifychoose-dialog",
		dialog_handle);
	g_object_set_data(G_OBJECT(conv), "otr-verifychoose-dialog-data",
		cclone);

	g_free(primary);
}

static void
otrg_purple3_dialog_verification_method_choose_new(ConnContext *context)
{
	purple3_dialog_verification_method_choose(context, NULL);
}


/******************************************************************************
 * Dialog e2ee menu.
 ******************************************************************************/

static void
otrg_purple3_conv_menu_connect(PurpleConversation *conv, gpointer _unused)
{
	PurpleE2eeState *state;
	const gchar *convname;
	gchar *msg;

	purple_conversation_present(conv);

	convname = purple_conversation_get_name(conv);

	state = purple_conversation_get_e2ee_state(conv);
	if (state == e2ee_state_private || state == e2ee_state_unverified) {
		msg = g_strdup_printf(_("Attempting to refresh the private "
			"conversation with %s..."), convname);
	} else {
		msg = g_strdup_printf(_("Attempting to start a private "
			"conversation with %s..."), convname);
	}

	otrg_purple3_otr_message(conv, msg);
	g_free(msg);

	otrg_plugin_send_default_query_conv(conv);
}

static void
otrg_purple3_conv_menu_disconnect(PurpleConversation *conv, gpointer _unused)
{
	ConnContext *context;

	context = otrg_plugin_conv_to_selected_context(conv, FALSE);
	if (!context)
		return;

	otrg_plugin_disconnect_all_instances(context);
}

static void
otrg_purple3_conv_menu_authenticate(PurpleConversation *conv, gpointer _unused)
{
	ConnContext *context;

	context = otrg_plugin_conv_to_selected_context(conv, FALSE);
	if (!context || context->msgstate != OTRL_MSGSTATE_ENCRYPTED)
		return;

	otrg_dialog_verify_method_selection(context);
}

static void
otrg_purple3_conv_choose_session_ok(PurpleConversation *conv,
	PurpleRequestFields *fields)
{
	otrl_instag_t instance;
	ConnContext *context;

	g_object_set_data(G_OBJECT(conv), "otr-choose-session-dialog", NULL);

	instance = GPOINTER_TO_INT(purple_request_fields_get_choice(fields,
		"session"));

	context = otrg_plugin_conv_to_context(conv, instance, FALSE);
	g_return_if_fail(context != NULL);

	otrg_conversation_set_selected_instag(conv, instance);

	otrg_purple3_dialog_resensitize(conv);
}

static void
otrg_purple3_conv_menu_choose_session(PurpleConversation *conv, gpointer _unusd)
{
	GList *contexts, *it;
	void *dialog_handle;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;
	PurpleRequestCommonParameters *cpar;
	GString *special_label;

	contexts = otrg_conversation_get_contexts(conv);

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	field = purple_request_field_choice_new("session",
		_("Choose active session:"), GINT_TO_POINTER(
		otrg_conversation_get_selected_instag(conv)));
	purple_request_field_group_add_field(group, field);

	special_label = g_string_new(_("Send to most secure"));
	g_string_append(special_label, " (");
	g_string_append_printf(special_label, _("Session %u"),
		otrg_context_instance_to_index(conv,
			otrg_plugin_conv_to_context(conv,
				OTRL_INSTAG_BEST, FALSE)));
	g_string_append(special_label, ")");
	purple_request_field_choice_add(field, special_label->str,
		GINT_TO_POINTER(OTRL_INSTAG_BEST));

	special_label = g_string_new(_("Send to most recent"));
	g_string_append(special_label, " (");
	g_string_append_printf(special_label, _("Session %u"),
		otrg_context_instance_to_index(conv,
			otrg_plugin_conv_to_context(conv,
				OTRL_INSTAG_RECENT_RECEIVED, FALSE)));
	g_string_append(special_label, ")");
	purple_request_field_choice_add(field, special_label->str,
		GINT_TO_POINTER(OTRL_INSTAG_RECENT_RECEIVED));

	for (it = g_list_first(contexts); it; it = g_list_next(it)) {
		ConnContext *session = it->data;
		GString *label;
		guint id;

		if (session->m_context == session &&
			session->msgstate == OTRL_MSGSTATE_PLAINTEXT)
		{
			continue;
		}

		label = g_string_new(NULL);

		id = otrg_context_instance_to_index(conv, session);
		g_string_append_printf(label, _("Session %u"), id);

		g_string_append_printf(label, " (%s)",
			purple_e2ee_state_get_name(
			otrg_purple3_trustlevel_to_e2eestate(
			otrg_plugin_context_to_trust(session))));

		purple_request_field_choice_add(field, label->str,
			GINT_TO_POINTER(session->their_instance));

		g_string_free(label, TRUE);
	}

	cpar = purple_request_cpar_from_conversation(conv);
	purple_request_cpar_set_icon(cpar, PURPLE_REQUEST_ICON_DIALOG);
	purple_request_cpar_set_compact(cpar, TRUE);

	dialog_handle = purple_request_fields(otrg_plugin_handle,
		_("Choose session"), _("Choose session"),
		NULL, fields, /* TODO: some nice description */
		_("OK"), (GCallback)otrg_purple3_conv_choose_session_ok,
		_("Cancel"), NULL, cpar, conv);
	g_object_set_data(G_OBJECT(conv), "otr-choose-session-dialog",
		dialog_handle);

	g_list_free(contexts);
}

static void
otrg_purple3_conv_menu_settings(PurpleConversation *conv, gpointer _unused)
{
	PurpleBuddy *buddy = otrg_purple_conversation_get_buddy(conv);

	if (!buddy) {
		purple_debug_warning("otr",
			"Selected conversation has no buddy");
		return;
	}

	otrg_ui_config_buddy(buddy);
}

static void
otrg_purple3_conv_menu_help(PurpleConversation *conv, gpointer _unused)
{
	gchar *url;

	url = g_strdup_printf("%s%s",
		LEVELS_HELPURL, _("?lang=en"));
	purple_notify_uri(otrg_plugin_handle, url);
	g_free(url);
}

static GList *
otrg_purple3_conv_menu_cb(PurpleConversation *conv)
{
	PurpleMenuAction *action;
	GList *menu = NULL;
	ConnContext *context;
	TrustLevel level;
	gboolean insecure, finished;

	context = otrg_plugin_conv_to_selected_context(conv, FALSE);
	if (!context)
		return NULL;

	level = otrg_plugin_context_to_trust(context);
	insecure = (level != TRUST_UNVERIFIED && level != TRUST_PRIVATE);
	finished = (level == TRUST_FINISHED);

	action = purple_menu_action_new(insecure ? _("Start _private "
		"conversation") : _("Refresh _private conversation"),
		(PurpleCallback)otrg_purple3_conv_menu_connect, NULL, NULL);
	menu = g_list_append(menu, action);

	action = purple_menu_action_new(_("_End private conversation"),
		(PurpleCallback)otrg_purple3_conv_menu_disconnect, NULL, NULL);
	if (insecure && !finished)
		purple_menu_action_set_callback(action, NULL);
	menu = g_list_append(menu, action);

	if (otrg_conversation_is_multi_instance(conv))
		menu = g_list_append(menu, NULL);

	action = purple_menu_action_new(_("_Authenticate buddy"),
		(PurpleCallback)otrg_purple3_conv_menu_authenticate, NULL, NULL);
	if (insecure)
		purple_menu_action_set_callback(action, NULL);
	menu = g_list_append(menu, action);

	if (otrg_conversation_is_multi_instance(conv)) {
		action = purple_menu_action_new(_("_Choose session"),
			(PurpleCallback)otrg_purple3_conv_menu_choose_session,
			NULL, NULL);
		menu = g_list_append(menu, action);
	}

	menu = g_list_append(menu, NULL);

	if (otrg_purple_conversation_get_buddy(conv)) {
		action = purple_menu_action_new(_("_Settings"),
			(PurpleCallback)otrg_purple3_conv_menu_settings, NULL, NULL);
		menu = g_list_append(menu, action);
	}

	action = purple_menu_action_new(_("_What's this?"),
		(PurpleCallback)otrg_purple3_conv_menu_help, NULL, NULL);
	purple_menu_action_set_stock_icon(action, GTK_STOCK_HELP);
	menu = g_list_append(menu, action);

	return menu;
}


/******************************************************************************
 * Dialog encryption state handling.
 ******************************************************************************/

static void
otrg_purple3_conv_update_state(ConnContext *context)
{
	PurpleConversation *conv;
	ConnContext *m_context = NULL;
	GList *contexts;
	guint contexts_count = 0;
	OtrlPolicy policy;

	g_return_if_fail(context != NULL);

	conv = otrg_plugin_context_to_conv(context, FALSE);
	if (conv == NULL)
		return;

	contexts = otrg_conversation_get_contexts(conv);
	if (contexts != NULL) {
		contexts_count = g_list_length(contexts);
		m_context = ((ConnContext *)contexts->data)->m_context;
		g_list_free(contexts);
	}
	if (m_context && m_context->msgstate == OTRL_MSGSTATE_PLAINTEXT)
		contexts_count--;
	otrg_conversation_set_multi_instance(conv, (contexts_count >= 2));

	policy = otrg_buddy_prefs_get_policy(
		purple_conversation_get_account(conv),
		purple_conversation_get_name(conv));
	if (policy == OTRL_POLICY_NEVER) {
		purple_conversation_set_e2ee_state(conv, NULL);
		return;
	}

	if (context == otrg_plugin_conv_to_selected_context(conv, FALSE)) {
		TrustLevel level;

		level = otrg_plugin_context_to_trust(context);
		purple_conversation_set_e2ee_state(conv,
			otrg_purple3_trustlevel_to_e2eestate(level));
	}
}

static void
otrg_purple3_check_incoming_instance_change(PurpleAccount *account,
	char *sender, char *message, PurpleConversation *conv,
	PurpleMessageFlags flags)
{
	otrl_instag_t last_received, current_inst, selected_instance;
	ConnContext *received_context;

	if (!conv)
		return;

	if (!otrg_conversation_is_otr_enabled(conv))
		return;

	selected_instance = otrg_conversation_get_selected_instag(conv);
	if (selected_instance != OTRL_INSTAG_RECENT_RECEIVED)
		return;

	last_received = otrg_conversation_get_last_received_instance(conv);

	received_context = otrg_plugin_conv_to_context(conv,
		OTRL_INSTAG_RECENT_RECEIVED, FALSE);
	g_return_if_fail(received_context != NULL);

	current_inst = received_context->their_instance;
	otrg_conversation_set_last_received_instance(conv, current_inst);

	if (last_received != current_inst)
		otrg_purple3_conv_update_state(received_context);
}

static void
_append_trust_icon(GString *msg, TrustLevel level)
{
	g_string_append_printf(msg, "<img src=\""
		PURPLE_IMAGE_STORE_STOCK_PROTOCOL "e2ee/%s\"> ",
		purple_e2ee_state_get_stock_icon(
			otrg_purple3_trustlevel_to_e2eestate(level)));
}

static void
otrg_purple3_dialog_connected(ConnContext *context)
{
	PurpleConversation *conv;
	GString *msg;
	TrustLevel level;
	const gchar *who;

	if (context == NULL)
		return;

	conv = otrg_plugin_context_to_conv(context, TRUE);
	if (conv == NULL)
		return;

	/* assign index */
	otrg_context_instance_to_index(conv, context);

	otrg_purple3_conv_update_state(context);

	level = otrg_plugin_context_to_trust(context);
	who = purple_conversation_get_name(conv);

	msg = g_string_new(NULL);
	_append_trust_icon(msg, level);

	if (level == TRUST_PRIVATE) {
		g_string_append_printf(msg,
			_("Private conversation with %s started."), who);
	} else if (level == TRUST_UNVERIFIED) {
		g_string_append_printf(msg, _("<a href=\"%s%s\">Unverified</a> "
			"conversation with %s started."), UNVERIFIED_HELPURL,
			_("?lang=en"), who);
	} else {
		/* This should never happen, since we know we're in ENCRYPTED.*/
		purple_debug_error("otr", "Not encrypted conversation started");
		return;
	}

	if (context->protocol_version == 1) {
		g_string_append(msg,
			_("  Warning: using old protocol version 1."));
	}

	if (purple_conversation_is_logging(conv)) {
		g_string_append(msg,
			_("  Your client is logging this conversation."));
	} else {
		g_string_append(msg,
			_("  Your client is not logging this conversation."));
	}

	otrg_purple3_otr_message(conv, msg->str);
	g_string_free(msg, TRUE);

	if (otrg_conversation_is_multi_instance(conv) &&
		!otrg_conversation_have_warned_instances(conv))
	{
		gchar *msg2;
		otrg_conversation_set_warned_instances(conv, TRUE);

		msg2 = g_strdup_printf(_("Your buddy is logged in multiple "
			"times and OTR has established <a href=\"%s%s\">"
			"multiple sessions</a>. Use the icon menu above if you "
			"wish to select the outgoing session."),
			SESSIONS_HELPURL, _("?lang=en"));
		otrg_purple3_otr_message(conv, msg2);
		g_free(msg2);
	}
}

static void
otrg_purple3_dialog_disconnected(ConnContext *context)
{
	PurpleConversation *conv;
	GString *msg;

	otrg_purple3_conv_update_state(context);

	conv = otrg_plugin_context_to_conv(context, FALSE);
	if (conv == NULL)
		return;

	otrg_purple3_smp_close(conv);
	purple3_dialog_verification_method_choose_close(conv);

	msg = g_string_new(NULL);
	_append_trust_icon(msg, TRUST_NOT_PRIVATE);
	g_string_append_printf(msg, _("Private conversation with %s lost."),
		purple_conversation_get_name(conv));
	otrg_purple3_otr_message(conv, msg->str);
	g_string_free(msg, TRUE);
}

static void
otrg_purple3_dialog_stillconnected(ConnContext *context)
{
	PurpleConversation *conv;
	GString *msg;
	TrustLevel level;
	const gchar *who;

	if (context == NULL)
		return;

	otrg_purple3_conv_update_state(context);

	conv = otrg_plugin_context_to_conv(context, TRUE);
	if (conv == NULL)
		return;

	level = otrg_plugin_context_to_trust(context);
	who = purple_conversation_get_name(conv);

	msg = g_string_new(NULL);
	_append_trust_icon(msg, level);

	if (level == TRUST_PRIVATE) {
		g_string_append_printf(msg, _("Successfully refreshed the "
			"private conversation with %s."), who);
	} else if (level == TRUST_UNVERIFIED) {
		g_string_append_printf(msg, _("Successfully refreshed the <a "
			"href=\"%s%s\">unverified</a> conversation with %s."),
			UNVERIFIED_HELPURL, _("?lang=en"), who);
	} else {
		/* This should never happen, since we know we're in ENCRYPTED.*/
		purple_debug_error("otr", "Not encrypted conversation "
			"restarted");
		return;
	}

	if (context->protocol_version == 1) {
		g_string_append(msg,
			_("  Warning: using old protocol version 1."));
	}

	otrg_purple3_otr_message(conv, msg->str);
	g_string_free(msg, TRUE);
}

static void
otrg_purple3_dialog_finished(const char *accountname, const char *protocol,
	const char *username)
{
	PurpleConversation *conv;
	ConnContext *context;
	GString *msg;

	conv = otrg_plugin_userinfo_to_conv(accountname, protocol,
		username, FALSE);

	if (!conv)
		return;

	otrg_purple3_smp_close(conv);
	purple3_dialog_verification_method_choose_close(conv);

	context = otrg_plugin_conv_to_selected_context(conv, TRUE);

	otrg_purple3_conv_update_state(context);

	msg = g_string_new(NULL);
	_append_trust_icon(msg, TRUST_FINISHED);
	g_string_append_printf(msg, _("%s has ended his/her private "
		"conversation with you; you should do the same."),
		purple_conversation_get_name(conv));
	otrg_purple3_otr_message(conv, msg->str);
	g_string_free(msg, TRUE);
}

static void
otrg_purple3_dialog_resensitize(PurpleConversation *conv)
{
	ConnContext *context;

	context = otrg_plugin_conv_to_selected_context(conv, FALSE);
	if (context)
		otrg_purple3_conv_update_state(context);
}

static void
otrg_purple3_dialog_resensitize_cb(PurpleConversation *conv, gpointer _unused)
{
	otrg_purple3_dialog_resensitize(conv);
}

static void
otrg_purple3_dialog_resensitize_all(void)
{
	g_list_foreach(purple_conversations_get_ims(),
		(GFunc)otrg_purple3_dialog_resensitize_cb, NULL);
}

/******************************************************************************
 * Dialog API implementation.
 ******************************************************************************/

static void
otrg_purple3_dialog_socialist_millionaires(ConnContext *context, char *question)
{
	g_return_if_fail(context != NULL);

	if (question)
		otrg_purple3_fpv_oneway_answer(context, question);
	else
		otrg_purple3_fpv_twoway_answer(context);
}

static const OtrgDialogUiOps purple3_dialog_ui_ops = {
	otrg_purple3_dialog_init,
	otrg_purple3_dialog_cleanup,
	otrg_purple3_dialog_notify_message,
	otrg_purple3_dialog_display_otr_message,
	otrg_purple3_dialog_private_key_wait_start,
	otrg_purple3_dialog_private_key_wait_done,
	otrg_purple3_fpv_manual_verify_fprint,
	otrg_purple3_dialog_verification_method_choose_new,
	otrg_purple3_dialog_socialist_millionaires,
	otrg_purple3_dialog_update_smp,
	otrg_purple3_dialog_connected,
	otrg_purple3_dialog_disconnected,
	otrg_purple3_dialog_stillconnected,
	otrg_purple3_dialog_finished,
	otrg_purple3_dialog_resensitize_all,
	otrg_purple3_dialog_new_conv,
	otrg_purple3_dialog_remove_conv
};

/* Get the GTK dialog UI ops */
const OtrgDialogUiOps *
otrg_purple3_dialog_get_ui_ops(void)
{
	return &purple3_dialog_ui_ops;
}

/* vim: set tabstop=8 softtabstop=8 shiftwidth=8 noexpandtab: */
