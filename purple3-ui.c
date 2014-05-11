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
#include "purple3-ui.h"
#include "ui.h"

typedef enum
{
	OTRG_PURPLE3_UI_PREFS_BTN_CONNECT,
	OTRG_PURPLE3_UI_PREFS_BTN_DISCONNECT,
	OTRG_PURPLE3_UI_PREFS_BTN_FORGET
} otrg_purple3_ui_prefs_btn_type;


static PurpleRequestDatasheet *otrg_purple3_ui_known_fprints = NULL;
static PurpleRequestDatasheet *otrg_purple3_ui_my_keys = NULL;

static void
otrg_purple3_ui_prefs_fill_known_fprints(PurpleRequestDatasheet *sheet);
static void
otrg_purple3_ui_prefs_fill_my_keys(PurpleRequestDatasheet *sheet);

static void
otrg_purple3_ui_account_change(PurpleAccount *account, gpointer _unused)
{
	otrg_ui_update_fingerprint();
}

static void
otrg_purple3_ui_init(void)
{
	purple_signal_connect(purple_accounts_get_handle(), "account-added",
		otrg_plugin_handle, PURPLE_CALLBACK(otrg_purple3_ui_account_change), NULL);
	purple_signal_connect(purple_accounts_get_handle(), "account-removed",
		otrg_plugin_handle, PURPLE_CALLBACK(otrg_purple3_ui_account_change), NULL);
}

static void
otrg_purple3_ui_cleanup(void)
{
	/* Signals are removed with plugin unload. */
}

static void
otrg_purple3_ui_update_fingerprint(void)
{
	if (otrg_purple3_ui_my_keys == NULL)
		return;

	otrg_purple3_ui_prefs_fill_my_keys(otrg_purple3_ui_my_keys);
}

static void
otrg_purple3_ui_update_keylist(void)
{
	if (otrg_purple3_ui_known_fprints == NULL)
		return;

	otrg_purple3_ui_prefs_fill_known_fprints(otrg_purple3_ui_known_fprints);
}

static gboolean
otrg_purple3_ui_commsett_field_is_sensitive(PurpleRequestField *field)
{
	PurpleRequestFields *fields;
	const gchar *field_id;
	gboolean enableotr;

	fields = purple_request_field_group_get_fields_list(
		purple_request_field_get_group(field));
	field_id = purple_request_field_get_id(field);

	if (purple_request_fields_exists(fields, "usedefault") &&
		purple_request_fields_get_bool(fields, "usedefault"))
	{
		return FALSE;
	}

	enableotr = purple_request_fields_get_bool(fields, "enableotr");

	if (g_strcmp0(field_id, "enableotr") == 0)
		return TRUE;
	else if (g_strcmp0(field_id, "automatic") == 0)
		return enableotr;
	else if (g_strcmp0(field_id, "onlypriv") == 0) {
		return enableotr &&
			purple_request_fields_get_bool(fields, "automatic");
	} else if (g_strcmp0(field_id, "avoidlog") == 0)
		return enableotr;
	else
		g_return_val_if_reached(FALSE);
}

static void
otrg_purple3_ui_commsett_fields(PurpleRequestFieldGroup *group,
	gboolean enabled, gboolean automatic, gboolean onlypriv,
	gboolean avoidlog)
{
	PurpleRequestField *field;

	field = purple_request_field_bool_new("enableotr",
		_("Enable private messaging"), enabled);
	purple_request_field_set_sensitivity_cb(field,
		otrg_purple3_ui_commsett_field_is_sensitive);
	purple_request_field_group_add_field(group, field);

	field = purple_request_field_bool_new("automatic",
		_("Automatically initiate private messaging"), automatic);
	purple_request_field_set_sensitivity_cb(field,
		otrg_purple3_ui_commsett_field_is_sensitive);
	purple_request_field_group_add_field(group, field);

	field = purple_request_field_bool_new("onlypriv",
		_("Require private messaging"), onlypriv);
	purple_request_field_set_sensitivity_cb(field,
		otrg_purple3_ui_commsett_field_is_sensitive);
	purple_request_field_group_add_field(group, field);

	field = purple_request_field_bool_new("avoidlog",
		_("Don't log OTR conversations"), avoidlog);
	purple_request_field_set_sensitivity_cb(field,
		otrg_purple3_ui_commsett_field_is_sensitive);
	purple_request_field_group_add_field(group, field);
}

static void
otrg_purple3_ui_config_buddy_ok(PurpleBuddy *buddy,
	PurpleRequestFields *fields)
{
	gboolean p_usedefault, p_enabled, p_automatic, p_onlypriv, p_avoidlog;

	p_usedefault = purple_request_fields_get_bool(fields, "usedefault");
	p_enabled = purple_request_fields_get_bool(fields, "enableotr");
	p_automatic = purple_request_fields_get_bool(fields, "automatic");
	p_onlypriv = purple_request_fields_get_bool(fields, "onlypriv");
	p_avoidlog = purple_request_fields_get_bool(fields, "avoidlog");

	/* TODO: ensure buddy is not deleted */
	otrg_prefs_buddy_save(buddy, p_usedefault, p_enabled, p_automatic,
		p_onlypriv, p_avoidlog);
}

static void
otrg_purple3_ui_config_buddy(PurpleBuddy *buddy)
{
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;
	PurpleRequestCommonParameters *cpar;
	gboolean p_usedefault, p_enabled, p_automatic, p_onlypriv, p_avoidlog;
	gchar *pri;

	otrg_prefs_buddy_load(buddy, &p_usedefault, &p_enabled, &p_automatic,
		&p_onlypriv, &p_avoidlog);

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	field = purple_request_field_bool_new("usedefault",
		_("Use default OTR settings for this buddy"), p_usedefault);
	purple_request_field_group_add_field(group, field);

	otrg_purple3_ui_commsett_fields(group, p_enabled, p_automatic,
		p_onlypriv, p_avoidlog);

	pri = g_strdup_printf(_("OTR Settings for %s"),
		purple_buddy_get_contact_alias(buddy));

	cpar = purple_request_cpar_from_account(
		purple_buddy_get_account(buddy));
	purple_request_cpar_set_icon(cpar, PURPLE_REQUEST_ICON_DIALOG);

	purple_request_fields(otrg_plugin_handle, _("OTR Settings"),
		pri, NULL, fields,
		_("OK"), (GCallback)otrg_purple3_ui_config_buddy_ok,
		_("Cancel"), NULL,
		cpar, buddy);

	g_free(pri);
}

static void
otrg_purple3_ui_buddy_menu_settings(PurpleBlistNode *node, gpointer user_data)
{
	otrg_ui_config_buddy((PurpleBuddy *)node);
}

static void
otrg_purple3_ui_buddy_menu(PurpleBuddy *buddy, GList **menu)
{
	gboolean p_enabled, _unused;

	otrg_prefs_buddy_load(buddy, &_unused, &p_enabled, &_unused,
		&_unused, &_unused);

	if (!p_enabled) {
		PurpleMenuAction *act;
		act = purple_menu_action_new(_("OTR Settings"),
			(PurpleCallback)otrg_purple3_ui_buddy_menu_settings,
			NULL, NULL);
		*menu = g_list_append(*menu, act);
	}
}

static void
otrg_purple3_ui_prefs_ok(gpointer _unused, PurpleRequestFields *fields)
{
	gboolean p_enabled, p_automatic, p_onlypriv, p_avoidlog;

	p_enabled = purple_request_fields_get_bool(fields, "enableotr");
	p_automatic = purple_request_fields_get_bool(fields, "automatic");
	p_onlypriv = purple_request_fields_get_bool(fields, "onlypriv");
	p_avoidlog = purple_request_fields_get_bool(fields, "avoidlog");

	otrg_prefs_global_save(p_enabled, p_automatic, p_onlypriv, p_avoidlog);
}

static void
otrg_purple3_ui_prefs_add_account(PurpleRequestDatasheet *sheet,
	PurpleAccount *account)
{
	gchar *img;
	PurpleRequestDatasheetRecord *rec;
	gchar fingerprint_buf[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	const gchar *fingerprint;

	rec = purple_request_datasheet_record_add(sheet, account);

	img = g_strdup_printf("prpl/%s:%s",
		purple_account_get_protocol_id(account),
		purple_account_get_username(account));
	purple_request_datasheet_record_set_image_data(rec, 0, img);
	g_free(img);

	purple_request_datasheet_record_set_string_data(rec, 1,
		purple_account_get_username(account));

	purple_request_datasheet_record_set_string_data(rec, 2,
		purple_account_get_private_alias(account));

	purple_request_datasheet_record_set_string_data(rec, 3,
		purple_account_get_protocol_name(account));

	fingerprint = otrl_privkey_fingerprint(otrg_plugin_userstate,
		fingerprint_buf, purple_account_get_username(account),
		purple_account_get_protocol_id(account));
	if (!fingerprint)
		fingerprint = _("No key present");
	purple_request_datasheet_record_set_string_data(rec, 4, fingerprint);
}

static void
otrg_purple3_ui_prefs_fill_my_keys(PurpleRequestDatasheet *sheet)
{
	GHashTable *accset;
	const GList *it;
	GList *remove;

	accset = g_hash_table_new(g_direct_hash, g_direct_equal);

	for (it = purple_accounts_get_all(); it; it = g_list_next(it)) {
		PurpleAccount *account = it->data;

		otrg_purple3_ui_prefs_add_account(sheet, account);

		g_hash_table_insert(accset, account, (gpointer)TRUE);
	}

	remove = NULL;
	it = purple_request_datasheet_get_records(sheet);
	for (; it != NULL; it = g_list_next(it)) {
		PurpleRequestDatasheetRecord *rec = it->data;
		gpointer key = purple_request_datasheet_record_get_key(rec);
		if (g_hash_table_lookup(accset, key) != NULL)
			continue;
		remove = g_list_prepend(remove, key);
	}

	g_hash_table_destroy(accset);

	for (it = remove; it != NULL; it = g_list_next(it))
		purple_request_datasheet_record_remove(sheet, it->data);
	g_list_free(remove);
}

static void
otrg_purple3_ui_prefs_add_fprint(PurpleRequestDatasheet *sheet,
	Fingerprint *fprint)
{
	PurpleRequestDatasheetRecord *rec;
	ConnContext *context = fprint->context;
	gboolean is_used = FALSE;
	TrustLevel best_level = TRUST_NOT_PRIVATE;
	ConnContext *it;
	gchar hash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	gchar *img;
	PurpleBuddy *buddy = NULL;
	PurpleAccount *account;

	rec = purple_request_datasheet_record_add(sheet, fprint);

	img = g_strdup_printf("prpl/%s:%s", context->protocol,
		context->accountname);
	purple_request_datasheet_record_set_image_data(rec, 0, img);
	g_free(img);

	purple_request_datasheet_record_set_string_data(rec, 1,
		context->username);

	account = purple_accounts_find(context->accountname, context->protocol);
	if (account)
		buddy = purple_blist_find_buddy(account, context->username);
	purple_request_datasheet_record_set_string_data(rec, 2, buddy ?
		purple_buddy_get_alias(buddy) : "");

	for (it = context->m_context; it && it->m_context == context->m_context;
		it = it->next)
	{
		TrustLevel this_level;

		this_level = otrg_plugin_context_to_trust(it);

		if (this_level == TRUST_FINISHED &&
			best_level == TRUST_NOT_PRIVATE)
		{
			best_level = TRUST_FINISHED;
			is_used = TRUE;
		}

		if (it->active_fingerprint != fprint)
			continue;

		if (this_level == TRUST_PRIVATE) {
			best_level = TRUST_PRIVATE;
			is_used = TRUE;
		} else if (this_level == TRUST_UNVERIFIED &&
			best_level != TRUST_PRIVATE)
		{
			best_level = TRUST_UNVERIFIED;
			is_used = TRUE;
		}
	}

	if (!is_used) {
		purple_request_datasheet_record_set_image_data(rec, 3, NULL);
		purple_request_datasheet_record_set_string_data(rec,
			4, _("Unused"));
	} else {
		PurpleE2eeState *state;

		state = otrg_purple3_trustlevel_to_e2eestate(best_level);

		img = g_strdup_printf("e2ee/%s",
			purple_e2ee_state_get_stock_icon(state));
		purple_request_datasheet_record_set_image_data(rec, 3, img);
		g_free(img);

		purple_request_datasheet_record_set_string_data(rec, 4,
			purple_e2ee_state_get_name(state));
	}

	purple_request_datasheet_record_set_string_data(rec, 5,
		otrg_fingerprint_is_trusted(fprint) ? _("Yes") : _("No"));

	otrl_privkey_hash_to_human(hash, fprint->fingerprint);
	purple_request_datasheet_record_set_string_data(rec, 6, hash);

	purple_request_datasheet_record_set_string_data(rec, 7,
		otrg_purple3_account_full_name(context->protocol,
			context->accountname));
}

static void
otrg_purple3_ui_prefs_fill_known_fprints(PurpleRequestDatasheet *sheet)
{
	ConnContext *context;
	GHashTable *fpset;
	const GList *it;
	GList *remove;

	fpset = g_hash_table_new(g_direct_hash, g_direct_equal);

	context = otrg_plugin_userstate->context_root;
	for (; context != NULL; context = context->next) {
		Fingerprint *fingerprint;

		if (context->m_context != context)
			continue;

		fingerprint = context->fingerprint_root.next;
		for (; fingerprint != NULL; fingerprint = fingerprint->next) {
			otrg_purple3_ui_prefs_add_fprint(sheet, fingerprint);
			g_hash_table_insert(fpset, fingerprint, (gpointer)TRUE);
		}
	}

	remove = NULL;
	it = purple_request_datasheet_get_records(sheet);
	for (; it != NULL; it = g_list_next(it)) {
		PurpleRequestDatasheetRecord *rec = it->data;
		gpointer key = purple_request_datasheet_record_get_key(rec);
		if (g_hash_table_lookup(fpset, key) != NULL)
			continue;
		remove = g_list_prepend(remove, key);
	}

	g_hash_table_destroy(fpset);

	for (it = remove; it != NULL; it = g_list_next(it))
		purple_request_datasheet_record_remove(sheet, it->data);
	g_list_free(remove);
}

static void
otrg_purple3_ui_prefs_mykeys_destroyed(PurpleRequestDatasheet *sheet,
	gpointer _unused)
{
	if (sheet == otrg_purple3_ui_my_keys)
		otrg_purple3_ui_my_keys = NULL;
}

static void
otrg_purple3_ui_prefs_fprints_destroyed(PurpleRequestDatasheet *sheet,
	gpointer _unused)
{
	if (sheet == otrg_purple3_ui_known_fprints)
		otrg_purple3_ui_known_fprints = NULL;
}

static gboolean
otrg_purple3_ui_prefs_genkey_active(PurpleRequestDatasheetRecord *rec,
	gpointer _unused)
{
	PurpleAccount *account;
	gchar fingerprint_buf[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	gchar *fingerprint;

	if (rec == NULL)
		return FALSE;

	account = purple_request_datasheet_record_get_key(rec);

	fingerprint = otrl_privkey_fingerprint(otrg_plugin_userstate,
		fingerprint_buf, purple_account_get_username(account),
		purple_account_get_protocol_id(account));

	return (fingerprint == NULL);
}

static gboolean
otrg_purple3_ui_prefs_knownfp_common_active(PurpleRequestDatasheetRecord *rec,
	gpointer _type)
{
	Fingerprint *fprint;
	ConnContext *ctx;
	otrg_purple3_ui_prefs_btn_type type = GPOINTER_TO_INT(_type);

	if (rec == NULL)
		return FALSE;

	fprint = purple_request_datasheet_record_get_key(rec);

	if (!fprint->context || !fprint->context->m_context)
		return (type == OTRG_PURPLE3_UI_PREFS_BTN_FORGET);

	for (ctx = fprint->context; ctx && ctx->m_context ==
		fprint->context->m_context; ctx = ctx->next)
	{
		if (ctx->msgstate == OTRL_MSGSTATE_ENCRYPTED &&
			ctx->active_fingerprint == fprint)
		{
			if (type == OTRG_PURPLE3_UI_PREFS_BTN_DISCONNECT)
				return TRUE;
			if (type == OTRG_PURPLE3_UI_PREFS_BTN_FORGET)
				return FALSE;
		} else if (ctx->msgstate == OTRL_MSGSTATE_FINISHED) {
			if (type == OTRG_PURPLE3_UI_PREFS_BTN_CONNECT ||
				type == OTRG_PURPLE3_UI_PREFS_BTN_DISCONNECT)
			{
				return TRUE;
			}
		} else if (ctx->msgstate == OTRL_MSGSTATE_PLAINTEXT) {
			if (type == OTRG_PURPLE3_UI_PREFS_BTN_CONNECT)
				return TRUE;
		}
	}

	return (type == OTRG_PURPLE3_UI_PREFS_BTN_FORGET);
}

static void
otrg_purple3_ui_prefs_genkey_click(PurpleRequestDatasheetRecord *rec,
	gpointer _unused)
{
	PurpleAccount *account;

	account = purple_request_datasheet_record_get_key(rec);

	g_return_if_fail(account != NULL);

	otrg_plugin_privkeygen_start(purple_account_get_username(account),
		purple_account_get_protocol_id(account));
}

static void
otrg_purple3_ui_prefs_knownfp_start_click(PurpleRequestDatasheetRecord *rec,
	gpointer _unused)
{
	Fingerprint *fprint = purple_request_datasheet_record_get_key(rec);

	g_return_if_fail(fprint != NULL);
	g_return_if_fail(fprint->context != NULL);

	otrg_ui_connect_connection(fprint->context);
}

static void
otrg_purple3_ui_prefs_knownfp_end_click(PurpleRequestDatasheetRecord *rec,
	gpointer _unused)
{
	Fingerprint *fprint = purple_request_datasheet_record_get_key(rec);
	ConnContext *it, *mctx;

	g_return_if_fail(fprint != NULL);
	g_return_if_fail(fprint->context != NULL);

	mctx = fprint->context->m_context;

	for (it = mctx; it && it->m_context == mctx; it = it->next) {
		/* Don't do anything with fingerprints other than the active one
		 * if we're in the ENCRYPTED state */
		if (it->msgstate == OTRL_MSGSTATE_ENCRYPTED &&
			it->active_fingerprint != fprint)
		{
			break;
		}
		otrg_ui_disconnect_connection(it);
	}
}

static void
otrg_purple3_ui_prefs_knownfp_verf_click(PurpleRequestDatasheetRecord *rec,
	gpointer _unused)
{
	Fingerprint *fprint = purple_request_datasheet_record_get_key(rec);

	g_return_if_fail(fprint != NULL);

	otrg_dialog_verify_fingerprint(fprint);
}

static void
otrg_purple3_ui_prefs_knownfp_forget_click(PurpleRequestDatasheetRecord *rec,
	gpointer _unused)
{
	Fingerprint *fprint = purple_request_datasheet_record_get_key(rec);

	g_return_if_fail(fprint != NULL);

	otrg_ui_forget_fingerprint(fprint);
}

gpointer
otrg_purple3_ui_prefs(PurplePlugin *plugin)
{
	PurpleRequestCommonParameters *cpar;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;
	PurpleRequestDatasheet *sheet;
	PurpleRequestDatasheetAction *action;
	gpointer handle;
	gboolean p_enabled, p_automatic, p_onlypriv, p_avoidlog;
	const gchar *tab_names[] = {
		_("Default OTR Settings"),
		_("My private keys"),
		_("Known fingerprints"),
		NULL
	};

	g_return_val_if_fail(otrg_purple3_ui_known_fprints == NULL, NULL);

	fields = purple_request_fields_new();
	purple_request_fields_set_tab_names(fields, tab_names);

	group = purple_request_field_group_new(NULL);
	purple_request_field_group_set_tab(group, 0);
	purple_request_fields_add_group(fields, group);

	otrg_prefs_global_load(&p_enabled, &p_automatic,
		&p_onlypriv, &p_avoidlog);
	otrg_purple3_ui_commsett_fields(group, p_enabled, p_automatic,
		p_onlypriv, p_avoidlog);

	group = purple_request_field_group_new(NULL);
	purple_request_field_group_set_tab(group, 1);
	purple_request_fields_add_group(fields, group);

	sheet = purple_request_datasheet_new();
	otrg_purple3_ui_my_keys = sheet;
	purple_request_datasheet_add_column(sheet,
		PURPLE_REQUEST_DATASHEET_COLUMN_IMAGE, NULL);
	purple_request_datasheet_add_column(sheet,
		PURPLE_REQUEST_DATASHEET_COLUMN_STRING, _("Account"));
	purple_request_datasheet_add_column(sheet,
		PURPLE_REQUEST_DATASHEET_COLUMN_STRING, _("Alias"));
	purple_request_datasheet_add_column(sheet,
		PURPLE_REQUEST_DATASHEET_COLUMN_STRING, _("Protocol"));
	purple_request_datasheet_add_column(sheet,
		PURPLE_REQUEST_DATASHEET_COLUMN_STRING, _("Fingerprint"));
	otrg_purple3_ui_prefs_fill_my_keys(sheet);
	purple_signal_connect(sheet, "destroy", otrg_plugin_handle,
		PURPLE_CALLBACK(otrg_purple3_ui_prefs_mykeys_destroyed), NULL);
	action = purple_request_datasheet_action_new();
	purple_request_datasheet_action_set_label(action, _("Generate"));
	purple_request_datasheet_action_set_cb(action,
		otrg_purple3_ui_prefs_genkey_click, NULL);
	purple_request_datasheet_action_set_sens_cb(action,
		otrg_purple3_ui_prefs_genkey_active, NULL);
	purple_request_datasheet_add_action(sheet, action);
	field = purple_request_field_datasheet_new("my-keys", NULL, sheet);
	purple_request_field_group_add_field(group, field);

	group = purple_request_field_group_new(NULL);
	purple_request_field_group_set_tab(group, 2);
	purple_request_fields_add_group(fields, group);

	sheet = purple_request_datasheet_new();
	otrg_purple3_ui_known_fprints = sheet;
	purple_request_datasheet_add_column(sheet,
		PURPLE_REQUEST_DATASHEET_COLUMN_IMAGE, NULL);
	purple_request_datasheet_add_column(sheet,
		PURPLE_REQUEST_DATASHEET_COLUMN_STRING, _("Screenname"));
	purple_request_datasheet_add_column(sheet,
		PURPLE_REQUEST_DATASHEET_COLUMN_STRING, _("Alias"));
	purple_request_datasheet_add_column(sheet,
		PURPLE_REQUEST_DATASHEET_COLUMN_IMAGE, NULL);
	purple_request_datasheet_add_column(sheet,
		PURPLE_REQUEST_DATASHEET_COLUMN_STRING, _("Status"));
	purple_request_datasheet_add_column(sheet,
		PURPLE_REQUEST_DATASHEET_COLUMN_STRING, _("Verified"));
	purple_request_datasheet_add_column(sheet,
		PURPLE_REQUEST_DATASHEET_COLUMN_STRING, _("Fingerprint"));
	purple_request_datasheet_add_column(sheet,
		PURPLE_REQUEST_DATASHEET_COLUMN_STRING, _("Account"));
	otrg_purple3_ui_prefs_fill_known_fprints(sheet);
	purple_signal_connect(sheet, "destroy", otrg_plugin_handle,
		PURPLE_CALLBACK(otrg_purple3_ui_prefs_fprints_destroyed), NULL);
	action = purple_request_datasheet_action_new();
	purple_request_datasheet_action_set_label(action,
		_("Start private connection"));
	purple_request_datasheet_action_set_cb(action,
		otrg_purple3_ui_prefs_knownfp_start_click, NULL);
	purple_request_datasheet_action_set_sens_cb(action,
		otrg_purple3_ui_prefs_knownfp_common_active,
		GINT_TO_POINTER(OTRG_PURPLE3_UI_PREFS_BTN_CONNECT));
	purple_request_datasheet_add_action(sheet, action);
	action = purple_request_datasheet_action_new();
	purple_request_datasheet_action_set_label(action,
		_("End private connection"));
	purple_request_datasheet_action_set_cb(action,
		otrg_purple3_ui_prefs_knownfp_end_click, NULL);
	purple_request_datasheet_action_set_sens_cb(action,
		otrg_purple3_ui_prefs_knownfp_common_active,
		GINT_TO_POINTER(OTRG_PURPLE3_UI_PREFS_BTN_DISCONNECT));
	purple_request_datasheet_add_action(sheet, action);
	action = purple_request_datasheet_action_new();
	purple_request_datasheet_action_set_label(action,
		_("Verify fingerprint"));
	purple_request_datasheet_action_set_cb(action,
		otrg_purple3_ui_prefs_knownfp_verf_click, NULL);
	purple_request_datasheet_add_action(sheet, action);
	action = purple_request_datasheet_action_new();
	purple_request_datasheet_action_set_label(action,
		_("Forget fingerprint"));
	purple_request_datasheet_action_set_cb(action,
		otrg_purple3_ui_prefs_knownfp_forget_click, NULL);
	purple_request_datasheet_action_set_sens_cb(action,
		otrg_purple3_ui_prefs_knownfp_common_active,
		GINT_TO_POINTER(OTRG_PURPLE3_UI_PREFS_BTN_FORGET));
	purple_request_datasheet_add_action(sheet, action);
	field = purple_request_field_datasheet_new("known-fp", NULL, sheet);
	purple_request_field_group_add_field(group, field);

	cpar = purple_request_cpar_new();
	purple_request_cpar_set_icon(cpar, PURPLE_REQUEST_ICON_DIALOG);

	handle = purple_request_fields(otrg_plugin_handle,
		_("Off-the-Record Messaging"), NULL, NULL, fields,
		_("OK"), (GCallback)otrg_purple3_ui_prefs_ok,
		_("Cancel"), NULL,
		cpar, NULL);

	return handle;
}

static const OtrgUiUiOps otrg_purple3_ui_ui_ops = {
	otrg_purple3_ui_init,
	otrg_purple3_ui_cleanup,
	otrg_purple3_ui_update_fingerprint,
	otrg_purple3_ui_update_keylist,
	otrg_purple3_ui_config_buddy,
	otrg_purple3_ui_buddy_menu
};

const OtrgUiUiOps *
otrg_purple3_ui_get_ui_ops(void)
{
	return &otrg_purple3_ui_ui_ops;
}

/* vim: set tabstop=8 softtabstop=8 shiftwidth=8 noexpandtab: */
