/*
 *  Off-the-Record Messaging plugin for libpurple
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "common.h"

/* system headers */
#include <glib.h>
#include <glib/gstdio.h>

/* purple-otr headers */
#include "otr-plugin.h"
#include "dialogs.h"

#include "debug.h"

#if PURPLE_VERSION_CHECK(3,0,0)
#define otrg_conv_set_data(conv, key, data) \
	g_object_set_data(G_OBJECT(conv), (key), (data))
#define otrg_conv_get_data(conv, key) \
	g_object_get_data(G_OBJECT(conv), (key))
#else
#define otrg_conv_set_data(conv, key, data) \
	purple_conversation_set_data((conv), (key), (data))
#define otrg_conv_get_data(conv, key) \
	purple_conversation_get_data((conv), (key))
#define PURPLE_IS_IM_CONVERSATION(conv) \
	(purple_conversation_get_type(conv) == \
		PURPLE_CONV_TYPE_IM)
#define purple_blist_find_buddy purple_find_buddy
#endif


struct _OtrgFingerprintClone
{
	OtrgContextClone *cclone;
	guchar fingerprint[20];
};

struct _OtrgContextClone
{
	gchar *accountname, *username, *protocol;
	otrl_instag_t their_instance;
};

OtrgFingerprintClone *
otrg_fingerprint_clone(Fingerprint *fprint)
{
	OtrgFingerprintClone *clone;

	g_return_val_if_fail(fprint != NULL, NULL);

	clone = g_new(OtrgFingerprintClone, 1);

	clone->cclone = otrg_context_clone(fprint->context);
	memcpy(clone->fingerprint, fprint->fingerprint,
		sizeof(clone->fingerprint));

	return clone;
}

Fingerprint *
otrg_fingerprint_get_origin(OtrgFingerprintClone *clone)
{
	ConnContext *context;

	g_return_val_if_fail(clone != NULL, NULL);

	context = otrg_context_get_origin(clone->cclone);

	if (context == NULL)
		return NULL;

	return otrl_context_find_fingerprint(context, clone->fingerprint,
		0, NULL);
}

void
otrg_fingerprint_clone_free(OtrgFingerprintClone *clone)
{
	if (clone == NULL)
		return;

	otrg_context_clone_free(clone->cclone);
	g_free(clone);
}

OtrgContextClone *
otrg_context_clone(ConnContext *context)
{
	OtrgContextClone *clone;

	g_return_val_if_fail(context != NULL, NULL);

	clone = g_new(OtrgContextClone, 1);

	clone->accountname = g_strdup(context->accountname);
	clone->username = strdup(context->username);
	clone->protocol = strdup(context->protocol);
	clone->their_instance = context->their_instance;

	return clone;
}

ConnContext *
otrg_context_get_origin(OtrgContextClone *clone)
{
	g_return_val_if_fail(clone != NULL, NULL);

	return otrl_context_find(otrg_plugin_userstate, clone->username,
		clone->accountname, clone->protocol, clone->their_instance,
		FALSE, NULL, NULL, NULL);
}

void
otrg_context_clone_free(OtrgContextClone *clone)
{
	if (clone == NULL)
		return;

	g_free(clone->accountname);
	g_free(clone->username);
	g_free(clone->protocol);
	g_free(clone);
}

FILE *
otrg_fopen_with_mask(const gchar *file_name, const gchar *mode, guint _mask)
{
#ifndef WIN32
	mode_t mask = _mask;
#endif  /* !WIN32 */
	FILE *fh;

#ifndef WIN32
	mask = umask(mask);
#endif  /* WIN32 */
	fh = g_fopen(file_name, mode);
#ifndef WIN32
	umask (mask);
#endif  /* WIN32 */

	return fh;
}

gboolean
otrg_fingerprint_is_trusted(Fingerprint *fprint)
{
	g_return_val_if_fail(fprint != NULL, FALSE);

	return (fprint->trust && fprint->trust[0]);
}

GList *
otrg_conversation_get_contexts(PurpleConversation *conv)
{
	PurpleAccount *account;
	const gchar *accountname, *protocol;
	gchar *username;
	ConnContext *it = NULL;
	GList *contexts = NULL;

	g_return_val_if_fail(conv != NULL, NULL);

	g_return_val_if_fail(PURPLE_IS_IM_CONVERSATION(conv), NULL);

	account = purple_conversation_get_account(conv);
	accountname = purple_account_get_username(account);
	protocol = purple_account_get_protocol_id(account);
	username = g_strdup(purple_normalize(account,
		purple_conversation_get_name(conv)));

	for (it = otrg_plugin_userstate->context_root; it; it = it->next) {
		if (g_strcmp0(it->accountname, accountname) != 0)
			continue;
		if (g_strcmp0(it->protocol, protocol) != 0)
			continue;
		if (g_strcmp0(it->username, username) != 0)
			continue;
		contexts = g_list_append(contexts, it);
	}

	g_free(username);

	return contexts;
}

static void
otrg_conversation_set_common(PurpleConversation *conv, const gchar *key,
	gboolean value)
{
	gboolean *var;

	g_return_if_fail(conv != NULL);

	var = otrg_conv_get_data(conv, key);
	if (var == NULL) {
		purple_debug_error("otr", "otrg_conversation_set_common: key %s"
			" doesn't exists", key);
		return;
	}

	*var = value;
}

static gboolean
otrg_conversation_get_common(PurpleConversation *conv, const gchar *key)
{
	gboolean *var;

	g_return_val_if_fail(conv != NULL, FALSE);

	var = otrg_conv_get_data(conv, key);
	if (var == NULL) {
		purple_debug_error("otr", "otrg_conversation_get_common: key %s"
			" doesn't exists", key);
		return FALSE;
	}

	return *var;
}

void
otrg_conversation_init_vars(PurpleConversation *conv)
{
	otrg_conv_set_data(conv, "otr-conv_multi_instances",
		g_new0(gboolean, 1));
	otrg_conv_set_data(conv, "otr-warned_instances", g_new0(gboolean, 1));
	otrg_conv_set_data(conv, "otr-max_idx", g_new0(gint, 1));
	otrg_conv_set_data(conv, "otr-conv_to_idx", g_hash_table_new_full(
		g_direct_hash, g_direct_equal, NULL, g_free));
	otrg_conv_set_data(conv, "otr-last_received_ctx",
		g_new0(otrl_instag_t, 1));
	otrg_conversation_set_last_received_instance(conv, OTRL_INSTAG_BEST);
}

void
otrg_conversation_cleanup_vars(PurpleConversation *conv)
{
	g_free(otrg_conv_get_data(conv, "otr-conv_multi_instances"));
	otrg_conv_set_data(conv, "otr-conv_multi_instances", NULL);
	g_free(otrg_conv_get_data(conv, "otr-warned_instances"));
	otrg_conv_set_data(conv, "otr-warned_instances", NULL);
	g_free(otrg_conv_get_data(conv, "otr-max_idx"));
	otrg_conv_set_data(conv, "otr-max_idx", NULL);
	g_hash_table_destroy(otrg_conv_get_data(conv, "otr-conv_to_idx"));
	otrg_conv_set_data(conv, "otr-conv_to_idx", NULL);
	g_free(otrg_conv_get_data(conv, "otr-last_received_ctx"));
	otrg_conv_set_data(conv, "otr-last_received_ctx", NULL);
}

gboolean
otrg_conversation_is_otr_enabled(PurpleConversation *conv)
{
	g_return_val_if_fail(conv != NULL, FALSE);

	if (!PURPLE_IS_IM_CONVERSATION(conv))
		return FALSE;

	return (otrg_conv_get_data(conv, "otr-conv_to_idx") != NULL);
}

void
otrg_conversation_set_multi_instance(PurpleConversation *conv,
	gboolean is_multi_instance)
{
	otrg_conversation_set_common(conv, "otr-conv_multi_instances",
		is_multi_instance);
}

gboolean
otrg_conversation_is_multi_instance(PurpleConversation *conv)
{
	return otrg_conversation_get_common(conv, "otr-conv_multi_instances");
}

void
otrg_conversation_set_warned_instances(PurpleConversation *conv,
	gboolean is_warned)
{
	otrg_conversation_set_common(conv, "otr-warned_instances",
		is_warned);
}

gboolean
otrg_conversation_is_warned_instances(PurpleConversation *conv)
{
	return otrg_conversation_get_common(conv, "otr-warned_instances");
}

guint
otrg_context_instance_to_index(PurpleConversation *conv, ConnContext *context)
{
	GHashTable *conv_to_idx;
	gint *idx;

	g_return_val_if_fail(conv != NULL, 0);
	g_return_val_if_fail(context != NULL, 0);

	conv_to_idx = otrg_conv_get_data(conv, "otr-conv_to_idx");
	g_return_val_if_fail(conv_to_idx != NULL, 0);

	idx = g_hash_table_lookup(conv_to_idx, context);
	if (!idx) {
		gint *max_index = otrg_conv_get_data(conv, "otr-max_idx");
		g_return_val_if_fail(max_index != NULL, 0);

		idx = g_new0(gint, 1);
		g_hash_table_replace(conv_to_idx, context, idx);

		*idx = ++(*max_index);
	}

	return *idx;
}

void
otrg_conversation_set_last_received_instance(PurpleConversation *conv,
	otrl_instag_t instance)
{
	gboolean *var;

	g_return_if_fail(conv != NULL);

	var = otrg_conv_get_data(conv, "otr-last_received_ctx");
	g_return_if_fail(var != NULL);

	*var = instance;
}

otrl_instag_t
otrg_conversation_get_last_received_instance(PurpleConversation *conv)
{
	gboolean *var;

	g_return_val_if_fail(conv != NULL, OTRL_INSTAG_BEST);

	var = otrg_conv_get_data(conv, "otr-last_received_ctx");
	g_return_val_if_fail(var != NULL, OTRL_INSTAG_BEST);

	return *var;
}

void
otrg_prefs_global_load(gboolean *enabledp, gboolean *automaticp,
	gboolean *onlyprivatep, gboolean *avoidloggingp)
{
	if (purple_prefs_exists("/OTR/enabled")) {
		*enabledp = purple_prefs_get_bool("/OTR/enabled");
		*automaticp = purple_prefs_get_bool("/OTR/automatic");
		*onlyprivatep = purple_prefs_get_bool("/OTR/onlyprivate");
		*avoidloggingp = purple_prefs_get_bool("/OTR/avoidloggingotr");
	} else {
		*enabledp = TRUE;
		*automaticp = TRUE;
		*onlyprivatep = FALSE;
		*avoidloggingp = TRUE;
	}
}

void
otrg_prefs_global_save(gboolean enabled, gboolean automatic,
	gboolean onlyprivate, gboolean avoidloggingotr)
{
	if (!purple_prefs_exists("/OTR"))
		purple_prefs_add_none("/OTR");

	purple_prefs_set_bool("/OTR/enabled", enabled);
	purple_prefs_set_bool("/OTR/automatic", automatic);
	purple_prefs_set_bool("/OTR/onlyprivate", onlyprivate);
	purple_prefs_set_bool("/OTR/avoidloggingotr", avoidloggingotr);

	otrg_dialog_resensitize_all();
}

void
otrg_prefs_buddy_load(PurpleBuddy *buddy, gboolean *usedefaultp,
	gboolean *enabledp, gboolean *automaticp, gboolean *onlyprivatep,
	gboolean *avoidloggingotrp)
{
	PurpleBlistNode *node = &(buddy->node);

	*usedefaultp = !purple_blist_node_get_bool(node, "OTR/overridedefault");
	if (*usedefaultp) {
		otrg_prefs_global_load(enabledp, automaticp, onlyprivatep,
			avoidloggingotrp);
	} else {
		*enabledp = purple_blist_node_get_bool(node, "OTR/enabled");
		*automaticp = purple_blist_node_get_bool(node, "OTR/automatic");
		*onlyprivatep =
			purple_blist_node_get_bool(node, "OTR/onlyprivate");
		*avoidloggingotrp =
			purple_blist_node_get_bool(node, "OTR/avoidloggingotr");
	}
}

void
otrg_prefs_buddy_save(PurpleBuddy *buddy, gboolean usedefault,
	gboolean enabled, gboolean automatic, gboolean onlyprivate,
	gboolean avoidloggingotr)
{
	PurpleBlistNode *node = &(buddy->node);

	purple_blist_node_set_bool(node, "OTR/overridedefault", !usedefault);
	purple_blist_node_set_bool(node, "OTR/enabled", enabled);
	purple_blist_node_set_bool(node, "OTR/automatic", automatic);
	purple_blist_node_set_bool(node, "OTR/onlyprivate", onlyprivate);
	purple_blist_node_set_bool(node, "OTR/avoidloggingotr", avoidloggingotr);

	otrg_dialog_resensitize_all();
}

OtrlPolicy
otrg_buddy_prefs_get_policy(PurpleAccount *account, const char *name)
{
	const gchar *proto;
	PurpleBuddy *buddy;
	gboolean p_enabled, p_automatic, p_onlyprivate;
	gboolean _unused;

	proto = purple_account_get_protocol_id(account);
	if (!otrg_plugin_proto_supports_otr(proto))
		return OTRL_POLICY_NEVER;

	buddy = purple_blist_find_buddy(account, name);
	if (buddy) {
		otrg_prefs_buddy_load(buddy, &_unused, &p_enabled,
			&p_automatic, &p_onlyprivate, &_unused);
	} else {
		otrg_prefs_global_load(&p_enabled, &p_automatic,
			&p_onlyprivate, &_unused);
	}

	if (!p_enabled)
		return OTRL_POLICY_NEVER;
	if (p_automatic && p_onlyprivate)
		return OTRL_POLICY_ALWAYS;
	if (p_automatic)
		return OTRL_POLICY_OPPORTUNISTIC;
	return OTRL_POLICY_MANUAL;
}

gboolean
otrg_buddy_prefs_get_avoid_logging(PurpleAccount *account, const char *name)
{
	const gchar *proto;
	PurpleBuddy *buddy;
	gboolean p_enabled, p_avoidloggingotr;
	gboolean _unused;

	proto = purple_account_get_protocol_id(account);
	if (!otrg_plugin_proto_supports_otr(proto))
		return TRUE;

	buddy = purple_blist_find_buddy(account, name);
	if (buddy) {
		otrg_prefs_buddy_load(buddy, &_unused, &p_enabled,
			&_unused, &_unused, &p_avoidloggingotr);
	} else {
		otrg_prefs_global_load(&p_enabled, &_unused, &_unused,
			&p_avoidloggingotr);
	}

	if (p_enabled)
		return p_avoidloggingotr;
	else
		return OTRL_POLICY_NEVER;
}

PurpleBuddy *
otrg_purple_conversation_get_buddy(PurpleConversation *conv)
{
	if (!PURPLE_IS_IM_CONVERSATION(conv))
		return NULL;

	return purple_blist_find_buddy(
		purple_conversation_get_account(conv),
		purple_conversation_get_name(conv));
}

void
otrg_conversation_set_logging_was_enabled(PurpleConversation *conv,
	gboolean was_enabled)
{
	otrg_conv_set_data(conv, "otr-logging_was_enabled",
		GINT_TO_POINTER(was_enabled));
}

gboolean
otrg_conversation_was_logging_enabled(PurpleConversation *conv)
{
	return GPOINTER_TO_INT(otrg_conv_get_data(conv,
		"otr-logging_was_enabled"));
}

void
otrg_conversation_set_last_msg_event(PurpleConversation *conv,
	OtrlMessageEvent event)
{
	otrg_conv_set_data(conv, "otr-last_msg_event",
		GINT_TO_POINTER(event));
}

OtrlMessageEvent
otrg_conversation_get_last_msg_event(PurpleConversation *conv)
{
	return GPOINTER_TO_INT(otrg_conv_get_data(conv,
		"otr-last_msg_event"));
}

void
otrg_conversation_set_selected_instag(PurpleConversation *conv,
	otrl_instag_t inst)
{
	g_return_if_fail(conv != NULL);

	otrg_conv_set_data(conv, "otr-ui_selected_ctx",
		GINT_TO_POINTER(inst));
}

otrl_instag_t
otrg_conversation_get_selected_instag(PurpleConversation *conv)
{
	g_return_val_if_fail(conv != NULL, 0);

	return GPOINTER_TO_INT(otrg_conv_get_data(conv,
		"otr-ui_selected_ctx"));
}

/* vim: set tabstop=8 softtabstop=8 shiftwidth=8 noexpandtab: */
