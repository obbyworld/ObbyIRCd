/*
 *   IRC - Internet Relay Chat, src/modules/isupport.c
 *   (C) 2025 Valware & The UnrealIRCd Team
 *
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* One include for all */
#include "unrealircd.h"

#define CMD_ISUPPORT "ISUPPORT"

/* Forward declarations */
void _send_isupport(Client *client);
void _isupport_check_for_changes(void);

/* Per-local-client moddata: whether _send_isupport has already
 * delivered the full RPL_ISUPPORT list to this client.  Lets the
 * post-welcome auto-send in nick.c be skipped for v0.2 clients that
 * already pulled the data via the pre-registration ISUPPORT command,
 * per the draft/extended-isupport-0.2 "MAY skip" clause. */
static ModDataInfo *isupport_sent_md = NULL;
#define ISUPPORT_SENT(c) \
	((c) && (c)->local && \
	 isupport_sent_md && \
	 moddata_local_client((c), isupport_sent_md).i)
#define SET_ISUPPORT_SENT(c) \
	do \
	{ \
		if ((c) && (c)->local && isupport_sent_md) \
			moddata_local_client((c), isupport_sent_md).i = 1; \
	} while (0)

ModuleHeader MOD_HEADER = {
    "isupport", /* Name of module */
    "5.0", /* Version */
    "Implement ISUPPORT (numeric 005) sending", /* Short description of module */
    "UnrealIRCd Team", /* Author */
    "unrealircd-6", /* Version of UnrealIRCd */
};

MOD_TEST()
{
	MARK_AS_OFFICIAL_MODULE(modinfo);

	EfunctionAddVoid(modinfo->handle, EFUNC_SEND_ISUPPORT, _send_isupport);
	EfunctionAddVoid(modinfo->handle, EFUNC_ISUPPORT_CHECK_FOR_CHANGES, _isupport_check_for_changes);

	return MOD_SUCCESS;
}

MOD_INIT()
{
	ModDataInfo mreq;
	MARK_AS_OFFICIAL_MODULE(modinfo);

	memset(&mreq, 0, sizeof(mreq));
	mreq.name = "isupport_sent";
	mreq.type = MODDATATYPE_LOCAL_CLIENT;
	isupport_sent_md = ModDataAdd(modinfo->handle, mreq);

	return MOD_SUCCESS;
}

MOD_LOAD()
{
	return MOD_SUCCESS;
}

MOD_UNLOAD()
{
	return MOD_SUCCESS;
}

/* Command 'ISUPPORT' (no params)
 * This command is used to send ISUPPORT information to the client.
 * Clients who have the 'draft/extended-isupport' capability will be
 * able to use this command to view ISUPPORT tokens before sending
 * NICK/USER[/PASS].
 * I've left this open to other users as well as it doesn't make sense
 * to gatekeep it beyond what would be considered normal usage anyway.
 * -- Valware
 */
/* Maximum payload bytes available for a single RPL_ISUPPORT line's
 * token list, after we account for the trailing ":are supported..."
 * banner.  Same as the cap used by make_isupportstrings. */
#define ISUPPORT_LINE_PAYLOAD (ISUPPORTLEN)

/* Helper for the v0.2 sender: emit one line (numeric or batched). */
static void isupport_emit_line(Client *client, MessageTag *mtags,
                               const char *batch, const char *line)
{
	if (*batch)
		sendtaggednumericfmt(client, mtags, RPL_ISUPPORT,
		                     "%s :are supported by this server", line);
	else
		sendnumeric(client, RPL_ISUPPORT, line);
}

/* v0.2 sender.  Builds RPL_ISUPPORT lines dynamically from the live
 * ISupports list so a single token whose value exceeds the line
 * payload can be delivered as `KEY=first_chunk` + one or more
 * `KEY+=remainder` lines, per the draft/extended-isupport-0.2 spec.
 * Splitting is byte-wise -- the spec leaves any token-grammar concern
 * (separator placement, escape handling) to the token's own spec, and
 * the server is responsible for emitting required separators inside
 * the appended value (we trust the producer that built `isupport->value`
 * to have done so already). */
static void send_isupport_v02(Client *client, MessageTag *mtags,
                              const char *batch)
{
	ISupport *isupport;
	char line[ISUPPORT_LINE_PAYLOAD + 1];
	int tokcnt = 0;

	line[0] = '\0';

	for (isupport = ISupports; isupport; isupport = isupport->next)
	{
		const char *key = isupport->token;
		const char *value = isupport->value;
		int keylen = (int)strlen(key);

		/* Compose the first-chunk form ("KEY=value" or just "KEY").
		 * If it fits in a fresh line we can pack it alongside other
		 * tokens; otherwise we must split it across multiple
		 * dedicated lines via the `+=` append form. */
		char first[ISUPPORT_LINE_PAYLOAD + 1];
		if (value)
			snprintf(first, sizeof(first), "%s=%s", key, value);
		else
			strlcpy(first, key, sizeof(first));

		/* Long-token path: each chunk lives on its own line.  Reserve
		 * room for the key, the assignment operator (`=` first time,
		 * `+=` for continuations), and a tiny safety margin. */
		int firstlen = (int)strlen(first);
		if (firstlen >= ISUPPORT_LINE_PAYLOAD)
		{
			/* Flush whatever's accumulated so the long token starts
			 * on a clean line. */
			if (*line)
			{
				isupport_emit_line(client, mtags, batch, line);
				line[0] = '\0';
				tokcnt = 0;
			}

			/* Slice the value.  First slice goes out as `KEY=chunk`. */
			int chunk_first_max = ISUPPORT_LINE_PAYLOAD - keylen - 1; /* '=' */
			int chunk_rest_max = ISUPPORT_LINE_PAYLOAD - keylen - 2; /* '+=' */
			int vlen = value ? (int)strlen(value) : 0;
			int pos = 0;
			char chunk_line[ISUPPORT_LINE_PAYLOAD + 1];

			int take = vlen - pos > chunk_first_max ? chunk_first_max : vlen - pos;
			snprintf(chunk_line, sizeof(chunk_line), "%s=%.*s",
			         key, take, value + pos);
			isupport_emit_line(client, mtags, batch, chunk_line);
			pos += take;
			while (pos < vlen)
			{
				int rest = vlen - pos > chunk_rest_max ? chunk_rest_max : vlen - pos;
				snprintf(chunk_line, sizeof(chunk_line), "%s+=%.*s",
				         key, rest, value + pos);
				isupport_emit_line(client, mtags, batch, chunk_line);
				pos += rest;
			}
			continue;
		}

		/* Short-token path: pack alongside neighbours, same 13-token
		 * and ISUPPORTLEN ceilings make_isupportstrings uses. */
		tokcnt++;
		if (*line && ((int)strlen(line) + 1 + firstlen >= ISUPPORT_LINE_PAYLOAD ||
		              tokcnt > 13))
		{
			isupport_emit_line(client, mtags, batch, line);
			line[0] = '\0';
			tokcnt = 1;
		}
		if (*line)
			strlcat(line, " ", sizeof(line));
		strlcat(line, first, sizeof(line));
	}

	if (*line)
		isupport_emit_line(client, mtags, batch, line);
}

/* Whether the client has negotiated the original spec.  Both versions
 * keep the same batch name (draft/isupport) so the wrapper handling is
 * shared between them. */
static int client_wants_isupport_batch(Client *client)
{
	return HasCapability(client, "batch") &&
	       (HasCapability(client, "draft/extended-isupport-0.2") ||
	        HasCapability(client, "draft/extended-isupport"));
}

void _send_isupport(Client *client)
{
	char batch[BATCHLEN + 1];
	int i;
	MessageTag *mtags = NULL, *m;

	/* Spec (draft/extended-isupport-0.2): the server MAY skip the
	 * RPL_ISUPPORT replies usually sent when connection registration
	 * completes if it already sent all information.  When a v0.2
	 * client pulled the full list pre-registration via the ISUPPORT
	 * command, ISUPPORT_SENT has been flipped and the post-welcome
	 * auto-send (nick.c -> send_isupport) is a no-op for them. */
	if (HasCapability(client, "draft/extended-isupport-0.2") &&
	    ISUPPORT_SENT(client))
		return;

	*batch = '\0';

	if (client_wants_isupport_batch(client))
	{
		generate_batch_id(batch);
		new_message(client, NULL, &mtags);
		m = safe_alloc(sizeof(MessageTag));
		safe_strdup(m->name, "batch");
		safe_strdup(m->value, batch);
		AddListItem(m, mtags);
	}

	if (*batch)
		sendto_one(client, NULL, ":%s BATCH +%s draft/isupport", me.name, batch);

	if (HasCapability(client, "draft/extended-isupport-0.2"))
	{
		/* v0.2 path: token-level splitting with the `+=` append form. */
		send_isupport_v02(client, mtags, batch);
	} else
	{
		/* v0.1 / no-cap path: ship the pre-built lines as-is. */
		for (i = 0; ISupportStrings[i]; i++)
		{
			if (*batch)
				sendtaggednumericfmt(client, mtags, RPL_ISUPPORT, "%s :are supported by this server", ISupportStrings[i]);
			else
				sendnumeric(client, RPL_ISUPPORT, ISupportStrings[i]);
		}
	}

	if (*batch)
	{
		sendto_one(client, NULL, ":%s BATCH -%s", me.name, batch);
		safe_free_message_tags(mtags);
	}

	SET_ISUPPORT_SENT(client);
}

ISupport *isupport_find_ex(ISupport *list, const char *name)
{
	for (; list; list = list->next)
		if (!strcmp(list->token, name))
			return list;
	return NULL;
}

void isupport_check_for_changes_send(const char *addstr, char *buf, size_t buflen, char *batch, MessageTag *mtags, int *changes, int *buffered_changes)
{
	Client *acptr;

	if (!*buf)
		return;

	list_for_each_entry(acptr, &lclient_list, lclient_node)
	{
		if (HasCapability(acptr, "draft/extended-isupport") && HasCapability(acptr, "batch"))
		{
			sendtaggednumericfmt(acptr, mtags, RPL_ISUPPORT, "%s :are supported by this server", buf);
		} else
		{
			sendnumeric(acptr, RPL_ISUPPORT, buf);
		}
	}
	*buf = '\0';
	*buffered_changes = 0;
}

void isupport_check_for_changes_one(const char *addstr, char *buf, size_t buflen, char *batch, MessageTag *mtags, int *changes, int *buffered_changes)
{
	Client *acptr;

	if (*changes == 0)
	{
		/* First change, need to start the batch */
		list_for_each_entry(acptr, &lclient_list, lclient_node)
			if (HasCapability(acptr, "draft/extended-isupport") && HasCapability(acptr, "batch"))
				sendto_one(acptr, NULL, ":%s BATCH +%s draft/isupport", me.name, batch);
	}

	*changes = *changes + 1;
	*buffered_changes = *buffered_changes + 1;

	if ((strlen(buf) + strlen(addstr) >= ISUPPORTLEN) || (*buffered_changes == 13))
		isupport_check_for_changes_send(addstr, buf, buflen, batch, mtags, changes, buffered_changes);

	/* Append */
	if (*buf)
		strlcat(buf, " ", buflen);
	strlcat(buf, addstr, buflen);
}

void _isupport_check_for_changes(void)
{
	Client *acptr;
	MessageTag *mtags = NULL;
	char batch[BATCHLEN + 1];
	ISupport *n; // iterator for "new isupports"
	ISupport *o; // iterator for "old isupports"
	char buf[512], addstr[512];
	int changes = 0, bc = 0;

	if (!iConf.send_isupport_updates)
		return;

	buf[0] = '\0';

	generate_batch_id(batch);
	mtags = safe_alloc(sizeof(MessageTag));
	safe_strdup(mtags->name, "batch");
	safe_strdup(mtags->value, batch);

	/* New tokens and changed values */
	for (n = ISupports; n; n = n->next)
	{
		o = isupport_find_ex(ISupports_old, n->token);
		if (!o ||
		    (!o->value && n->value) ||
		    (n->value && !o->value) ||
		    (n->value && o->value && strcmp(n->value, o->value)))
		{
			/* New or changed */
			if (n->value)
			{
				snprintf(addstr, sizeof(addstr), "%s=%s",
				         n->token, n->value);
			} else
			{
				strlcpy(addstr, n->token, sizeof(addstr));
			}
			isupport_check_for_changes_one(addstr, buf, sizeof(buf), batch, mtags, &changes, &bc);
		}
	}

	/* Removed tokens */
	for (o = ISupports_old; o; o = o->next)
	{
		n = isupport_find_ex(ISupports, o->token);
		if (!n)
		{
			/* Removed */
			strlcpy(addstr, "-", sizeof(addstr));
			strlcpy(addstr, o->token, sizeof(addstr));
			isupport_check_for_changes_one(addstr, buf, sizeof(buf), batch, mtags, &changes, &bc);
		}
	}

	isupport_check_for_changes_send(NULL, buf, sizeof(buf), batch, mtags, &changes, &bc);

	if (changes)
	{
		/* End the batch (for those clients who received a batch, that is) */
		list_for_each_entry(acptr, &lclient_list, lclient_node)
			if (HasCapability(acptr, "draft/extended-isupport") && HasCapability(acptr, "batch"))
				sendto_one(acptr, NULL, ":%s BATCH -%s", me.name, batch);
	}

	safe_free_message_tags(mtags);
}
