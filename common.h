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

#ifndef __OTRG_COMMON_H__
#define __OTRG_COMMON_H__

#include <glib.h>

/* libotr headers */
#include <libotr/instag.h>
#include <libotr/proto.h>
#include <libotr/message.h>

/* purple headers */
#include "conversation.h"

typedef struct _OtrgFingerprintClone OtrgFingerprintClone;
typedef struct _OtrgContextClone OtrgContextClone;

/* Global and per-buddy preferences */
typedef struct {
	OtrlPolicy policy;
	gboolean avoid_logging_otr;
} OtrgUiPrefs; /* TODO: rename it to OtrgPrefs? */

OtrgFingerprintClone *
otrg_fingerprint_clone(Fingerprint *fprint);

Fingerprint *
otrg_fingerprint_get_origin(OtrgFingerprintClone *clone);

void
otrg_fingerprint_clone_free(OtrgFingerprintClone *clone);


OtrgContextClone *
otrg_context_clone(ConnContext *context);

ConnContext *
otrg_context_get_origin(OtrgContextClone *clone);

void
otrg_context_clone_free(OtrgContextClone *clone);

FILE *
otrg_fopen_with_mask(const gchar *file_name, const gchar *mode, guint mask);

gboolean
otrg_fingerprint_is_trusted(Fingerprint *fprint);

GList *
otrg_conversation_get_contexts(PurpleConversation *conv);

void
otrg_conversation_init_vars(PurpleConversation *conv);

void
otrg_conversation_cleanup_vars(PurpleConversation *conv);

gboolean
otrg_conversation_is_otr_enabled(PurpleConversation *conv);

void
otrg_conversation_set_multi_instance(PurpleConversation *conv,
	gboolean is_multi_instance);

gboolean
otrg_conversation_is_multi_instance(PurpleConversation *conv);

void
otrg_conversation_set_warned_instances(PurpleConversation *conv,
	gboolean is_warned);

gboolean
otrg_conversation_is_warned_instances(PurpleConversation *conv);

guint
otrg_context_instance_to_index(PurpleConversation *conv, ConnContext *context);

void
otrg_conversation_set_last_received_instance(PurpleConversation *conv,
	otrl_instag_t instance);

otrl_instag_t
otrg_conversation_get_last_received_instance(PurpleConversation *conv);

void
otrg_prefs_global_load(gboolean *enabledp, gboolean *automaticp,
	gboolean *onlyprivatep, gboolean *avoidloggingotrp);

void
otrg_prefs_global_save(gboolean enabled, gboolean automatic,
	gboolean onlyprivate, gboolean avoidloggingotr);

void
otrg_prefs_buddy_load(PurpleBuddy *buddy, gboolean *usedefaultp,
	gboolean *enabledp, gboolean *automaticp, gboolean *onlyprivatep,
	gboolean *avoidloggingotrp);

void
otrg_prefs_buddy_save(PurpleBuddy *buddy, gboolean usedefault, gboolean enabled,
	gboolean automatic, gboolean onlyprivate, gboolean avoidloggingotr);

void
otrg_buddy_get_prefs(OtrgUiPrefs *prefsp, PurpleAccount *account,
	const char *name);

PurpleBuddy *
otrg_purple_conversation_get_buddy(PurpleConversation *conv);

void
otrg_conversation_set_logging_was_enabled(PurpleConversation *conv,
	gboolean was_enabled);

gboolean
otrg_conversation_was_logging_enabled(PurpleConversation *conv);

void
otrg_conversation_set_last_msg_event(PurpleConversation *conv,
	OtrlMessageEvent event);

OtrlMessageEvent
otrg_conversation_get_last_msg_event(PurpleConversation *conv);

void
otrg_conversation_set_selected_instag(PurpleConversation *conv,
	otrl_instag_t inst);

otrl_instag_t
otrg_conversation_get_selected_instag(PurpleConversation *conv);

#endif

/* vim: set tabstop=8 softtabstop=8 shiftwidth=8 noexpandtab: */
