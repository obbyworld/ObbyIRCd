/*
 * src/modules/memo.c -- MEMO command: send / list / read / delete.
 *
 * Wire format (server -> client):
 *
 *   :server MEMO SENT <recipient> :Memo delivered.
 *   :server MEMO READ <id> :Memo marked as read.
 *   :server MEMO UNREAD <id> :Memo marked unread.
 *   :server MEMO DELETED <id> :Memo deleted.
 *   :server FAIL MEMO NO_SUCH_RECIPIENT|NO_SUCH_MEMO|NOT_LOGGED_IN ...
 *
 *   On MEMO LIST: a verb'd BATCH `obsidianirc/memos`.
 *
 *     :server BATCH +<tag> obsidianirc/memos
 *     @batch=<tag> :server MEMO LIST <id> <sender> <sent_at> <flags> :<body>
 *     @batch=<tag> :server MEMO LIST <id2> <sender2> <sent_at2> <flags2> :<body2>
 *     :server BATCH -<tag>
 *
 * `<flags>` is a comma-separated list of letters: 'r' = read, 'u' = unread,
 *           'M' = system memo (sender == '*'). More can be added later
 *           without breaking parsers.
 *
 * Storage lives in `memos` (created by account-registration.c when it
 * opens obsidian.db). Sender is stored as the canonical account name;
 * the sender's case is preserved.
 *
 * License: GPLv3 or later
 * Copyright (c) 2026 ObbyIRCd Team
 */

#include "unrealircd.h"
#include "obsidian.h"
#include <sqlite3.h>

/* Module-local sqlite handle. UnrealIRCd dlopens each .so with
 * RTLD_LOCAL so we can't share account-registration.c's `memo_db`
 * via extern; we just open our own connection to the same file.
 * sqlite3 supports many concurrent readers + serialised writers in
 * the default mode; the WAL'd traffic from MEMO is tiny so this is
 * fine. */
static sqlite3 *memo_db = NULL;

ModuleHeader MOD_HEADER = {
    "memo",
    "1.0",
    "MEMO command: send and read services-style memos persisted in obsidian.db",
    "ObbyIRCd Team",
    "unrealircd-6",
};

CMD_FUNC(cmd_memo);

MOD_INIT()
{
	MARK_AS_OFFICIAL_MODULE(modinfo);

	if (sqlite3_open(OBSIDIAN_DB, &memo_db) != SQLITE_OK)
	{
		config_error("memo: could not open obsidian.db at %s", OBSIDIAN_DB);
		return MOD_FAILED;
	}
	CommandAdd(modinfo->handle, "MEMO", cmd_memo, MAXPARA, CMD_USER);
	return MOD_SUCCESS;
}

MOD_LOAD()
{
	return MOD_SUCCESS;
}

MOD_UNLOAD()
{
	if (memo_db)
	{
		sqlite3_close(memo_db);
		memo_db = NULL;
	}
	return MOD_SUCCESS;
}

/* ---------------- helpers ---------------- */

static long find_account_id_by_name(const char *name)
{
	const char *sql = "SELECT id FROM accounts WHERE lower(name) = lower(?) LIMIT 1";
	sqlite3_stmt *stmt;
	long id = 0;
	if (sqlite3_prepare_v2(memo_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;
	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_ROW)
		id = (long)sqlite3_column_int64(stmt, 0);
	sqlite3_finalize(stmt);
	return id;
}

static int sender_is_logged_in(Client *c, const char **out_account)
{
	if (!c || !c->user || !*c->user->account || !strcmp(c->user->account, "0"))
		return 0;
	*out_account = c->user->account;
	return 1;
}

static char *make_batch_tag(char *buf, size_t buflen)
{
	static unsigned long counter = 0;
	counter++;
	snprintf(buf, buflen, "M%lu%lx", (unsigned long)TStime(), counter);
	return buf;
}

/* ---------------- subcommands ---------------- */

static void memo_send(Client *client, int parc, const char *parv[])
{
	const char *me_account;
	const char *recipient;
	const char *body;
	long recipient_id;
	sqlite3_stmt *stmt;

	if (!sender_is_logged_in(client, &me_account))
	{
		sendto_one(client, NULL,
		           ":%s FAIL MEMO NOT_LOGGED_IN :You must be logged into an account to send memos.",
		           me.name);
		return;
	}
	if (parc < 4 || BadPtr(parv[2]) || BadPtr(parv[3]))
	{
		sendto_one(client, NULL,
		           ":%s FAIL MEMO INVALID_PARAMS :Syntax: /MEMO SEND <account> :<text>",
		           me.name);
		return;
	}
	recipient = parv[2];
	body = parv[3];

	recipient_id = find_account_id_by_name(recipient);
	if (!recipient_id)
	{
		sendto_one(client, NULL,
		           ":%s FAIL MEMO NO_SUCH_RECIPIENT %s :No registered account by that name.",
		           me.name, recipient);
		return;
	}

	if (sqlite3_prepare_v2(memo_db,
	                       "INSERT INTO memos (recipient_id, sender, body, sent_at) VALUES (?, ?, ?, ?)",
	                       -1, &stmt, NULL) != SQLITE_OK)
	{
		sendto_one(client, NULL,
		           ":%s FAIL MEMO INTERNAL_ERROR :Could not save memo.",
		           me.name);
		return;
	}
	sqlite3_bind_int64(stmt, 1, recipient_id);
	sqlite3_bind_text(stmt, 2, me_account, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, body, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 4, (sqlite3_int64)TStime());
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (rc != SQLITE_DONE)
	{
		sendto_one(client, NULL,
		           ":%s FAIL MEMO INTERNAL_ERROR :Could not save memo.",
		           me.name);
		return;
	}

	sendto_one(client, NULL,
	           ":%s MEMO SENT %s :Memo delivered to %s.",
	           me.name, recipient, recipient);

    /* If the recipient is online, push them a NOTICE so they know to
     * /MEMO LIST. We look at every connected client whose user->account
     * matches the recipient's canonical name (case-insensitive). */
	Client *peer;
	list_for_each_entry(peer, &client_list, client_node)
	{
		if (IsUser(peer) && IsLoggedIn(peer) &&
		    !strcasecmp(peer->user->account, recipient))
		{
			sendto_one(peer, NULL,
			           ":%s NOTICE %s :You have received a memo from %s. Type /MEMO LIST to read it.",
			           me.name, peer->name, me_account);
		}
	}
}

static void memo_list(Client *client, int parc, const char *parv[])
{
	const char *me_account;
	long me_id;
	sqlite3_stmt *stmt;
	int unread_only = 0;
	char batch_tag[32];

	if (!sender_is_logged_in(client, &me_account))
	{
		sendto_one(client, NULL,
		           ":%s FAIL MEMO NOT_LOGGED_IN :You must be logged into an account to view memos.",
		           me.name);
		return;
	}
	me_id = find_account_id_by_name(me_account);
	if (!me_id)
	{
		sendto_one(client, NULL,
		           ":%s FAIL MEMO INTERNAL_ERROR :Account row missing.",
		           me.name);
		return;
	}

	if (parc >= 3 && parv[2] && !strcasecmp(parv[2], "unread"))
		unread_only = 1;

	const char *sql_all =
	    "SELECT id, sender, sent_at, read_at, body FROM memos"
	    " WHERE recipient_id = ? ORDER BY sent_at ASC";
	const char *sql_unread =
	    "SELECT id, sender, sent_at, read_at, body FROM memos"
	    " WHERE recipient_id = ? AND read_at = 0 ORDER BY sent_at ASC";

	if (sqlite3_prepare_v2(memo_db,
	                       unread_only ? sql_unread : sql_all,
	                       -1, &stmt, NULL) != SQLITE_OK)
	{
		sendto_one(client, NULL,
		           ":%s FAIL MEMO INTERNAL_ERROR :Could not query memos.",
		           me.name);
		return;
	}
	sqlite3_bind_int64(stmt, 1, me_id);

	make_batch_tag(batch_tag, sizeof(batch_tag));

    /* Open the verb'd batch. Per IRCv3 BATCH: ":src BATCH +<tag> <type>". */
	sendto_one(client, NULL,
	           ":%s BATCH +%s obsidianirc/memos",
	           me.name, batch_tag);

	int rows = 0;
	while (sqlite3_step(stmt) == SQLITE_ROW)
	{
		long id = (long)sqlite3_column_int64(stmt, 0);
		const unsigned char *sender = sqlite3_column_text(stmt, 1);
		long long sent_at = sqlite3_column_int64(stmt, 2);
		long long read_at = sqlite3_column_int64(stmt, 3);
		const unsigned char *body = sqlite3_column_text(stmt, 4);

		char flags[8];
		char *fp = flags;
		if (read_at > 0)
			*fp++ = 'r';
		else
			*fp++ = 'u';
		if (sender && !strcmp((const char *)sender, "*"))
			*fp++ = 'M';
		*fp = 0;

		sendto_one(client, NULL,
		           "@batch=%s :%s MEMO LIST %ld %s %lld %s :%s",
		           batch_tag, me.name, id,
		           sender ? (const char *)sender : "*",
		           sent_at,
		           *flags ? flags : "*",
		           body ? (const char *)body : "");
		rows++;
	}
	sqlite3_finalize(stmt);

	sendto_one(client, NULL, ":%s BATCH -%s", me.name, batch_tag);

	if (rows == 0)
	{
		sendto_one(client, NULL,
		           ":%s NOTICE %s :%s.",
		           me.name, client->name,
		           unread_only ? "No unread memos" : "No memos");
	}
}

static void memo_read_or_delete(Client *client, int parc, const char *parv[],
                                int is_delete)
{
	const char *me_account;
	long me_id;
	long memo_id;
	sqlite3_stmt *stmt;

	if (!sender_is_logged_in(client, &me_account))
	{
		sendto_one(client, NULL,
		           ":%s FAIL MEMO NOT_LOGGED_IN :You must be logged into an account.",
		           me.name);
		return;
	}
	if (parc < 3 || BadPtr(parv[2]))
	{
		sendto_one(client, NULL,
		           ":%s FAIL MEMO INVALID_PARAMS :Syntax: /MEMO %s <id>",
		           me.name, is_delete ? "DELETE" : "READ");
		return;
	}
	memo_id = strtol(parv[2], NULL, 10);
	if (memo_id <= 0)
	{
		sendto_one(client, NULL,
		           ":%s FAIL MEMO INVALID_PARAMS :Memo id must be a positive integer.",
		           me.name);
		return;
	}
	me_id = find_account_id_by_name(me_account);

    /* Make sure the memo is actually addressed to this user. */
	int matches = 0;
	if (sqlite3_prepare_v2(memo_db,
	                       "SELECT 1 FROM memos WHERE id = ? AND recipient_id = ?",
	                       -1, &stmt, NULL) == SQLITE_OK)
	{
		sqlite3_bind_int64(stmt, 1, memo_id);
		sqlite3_bind_int64(stmt, 2, me_id);
		if (sqlite3_step(stmt) == SQLITE_ROW)
			matches = 1;
		sqlite3_finalize(stmt);
	}
	if (!matches)
	{
		sendto_one(client, NULL,
		           ":%s FAIL MEMO NO_SUCH_MEMO %ld :No memo with that id addressed to you.",
		           me.name, memo_id);
		return;
	}

	const char *sql = is_delete
	                      ? "DELETE FROM memos WHERE id = ? AND recipient_id = ?"
	                      : "UPDATE memos SET read_at = ? WHERE id = ? AND recipient_id = ?";
	if (sqlite3_prepare_v2(memo_db, sql, -1, &stmt, NULL) != SQLITE_OK)
	{
		sendto_one(client, NULL,
		           ":%s FAIL MEMO INTERNAL_ERROR :Could not update memo.",
		           me.name);
		return;
	}
	if (is_delete)
	{
		sqlite3_bind_int64(stmt, 1, memo_id);
		sqlite3_bind_int64(stmt, 2, me_id);
	} else
	{
		sqlite3_bind_int64(stmt, 1, (sqlite3_int64)TStime());
		sqlite3_bind_int64(stmt, 2, memo_id);
		sqlite3_bind_int64(stmt, 3, me_id);
	}
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (rc != SQLITE_DONE)
	{
		sendto_one(client, NULL,
		           ":%s FAIL MEMO INTERNAL_ERROR :Could not update memo.",
		           me.name);
		return;
	}
	sendto_one(client, NULL,
	           ":%s MEMO %s %ld :%s",
	           me.name,
	           is_delete ? "DELETED" : "READ",
	           memo_id,
	           is_delete ? "Memo deleted." : "Memo marked as read.");
}

CMD_FUNC(cmd_memo)
{
	if (!MyUser(client))
		return;
	if (parc < 2 || BadPtr(parv[1]))
	{
		sendto_one(client, NULL,
		           ":%s NOTE MEMO USAGE :MEMO SEND|LIST|READ|DELETE [args]",
		           me.name);
		return;
	}
	if (!strcasecmp(parv[1], "SEND"))
		memo_send(client, parc, parv);
	else if (!strcasecmp(parv[1], "LIST"))
		memo_list(client, parc, parv);
	else if (!strcasecmp(parv[1], "READ"))
		memo_read_or_delete(client, parc, parv, 0);
	else if (!strcasecmp(parv[1], "DELETE"))
		memo_read_or_delete(client, parc, parv, 1);
	else
		sendto_one(client, NULL,
		           ":%s FAIL MEMO INVALID_SUBCOMMAND %s :Unknown subcommand. Try SEND|LIST|READ|DELETE.",
		           me.name, parv[1]);
}
