/* src/modules/dm_history.c - Ergo-style account-keyed DM chathistory.
 *
 * UnrealIRCd's built-in chathistory module hands back an empty BATCH
 * for any non-channel target -- which is fine on the original IRCd
 * but useless on obbyircd, where account-holders have persistent
 * identity and very much expect to scroll their DM backlog after a
 * reconnect.  This module fills that gap, modelled on Ergo:
 *
 *   * Every PRIVMSG/NOTICE/TAGMSG between two account-holders is
 *     persisted to a new `dm_history` table in obsidian.db, keyed by
 *     a sorted (account_a, account_b) pair so either party can query
 *     the same conversation.
 *   * CHATHISTORY is overridden so that a nick target gets routed
 *     through the DM path (resolve nick -> account, query rows
 *     bounded by the standard timestamp= / msgid= filter) and channel
 *     targets fall through to the upstream chathistory.so handler
 *     unchanged.
 *   * The TARGETS subcommand is handled entirely here so we can emit
 *     a single BATCH that lists both channel and DM partners, the way
 *     a sane inbox UI wants.
 *
 * Storage: a single sqlite3 handle opened on PERMDATADIR/obsidian.db
 * (no link-time dep on account-registration.so -- same pattern the
 * invitation / invite-page modules use).
 *
 * What's deliberately out of scope for now: queries against an
 * account name whose owner is offline -- we resolve nick->account
 * via the online client list only.  Add an offline lookup against
 * the registered_accounts table when that becomes a real pain.
 */
#include "unrealircd.h"
#include "obsidian.h"
#include <sqlite3.h>

ModuleHeader MOD_HEADER = {
    "pm_history",
    "0.1",
    "Ergo-style persistent CHATHISTORY for account-holder DMs",
    "obbyircd",
    "unrealircd-6",
};

#define DMH_MAX_LIMIT   100   /* hard cap on any one CHATHISTORY response */
#define DMH_TARGETS_MAX 100  /* hard cap on TARGETS results */

static sqlite3 *pmh_db = NULL;
static CommandOverride *pmh_ovr = NULL;
static CommandOverride *pmh_redact_ovr = NULL;

/* Forward decls */
static int pmh_open_db(void);
static void pmh_close_db(void);
static int pmh_ensure_schema(void);
static int pmh_usermsg(Client *client, Client *to, MessageTag *mtags,
                       const char *text, SendType sendtype);
CMD_OVERRIDE_FUNC(pmh_chathistory_override);
CMD_OVERRIDE_FUNC(pmh_redact_override);

MOD_INIT()
{
	MARK_AS_OFFICIAL_MODULE(modinfo);

	if (pmh_open_db() != 0)
		return MOD_FAILED;
	if (pmh_ensure_schema() != 0)
	{
		pmh_close_db();
		return MOD_FAILED;
	}

	HookAdd(modinfo->handle, HOOKTYPE_USERMSG, 0, pmh_usermsg);

	return MOD_SUCCESS;
}

MOD_LOAD()
{
	/* CommandOverrideAdd must run in MOD_LOAD so the CHATHISTORY
	 * command itself (registered by chathistory.so's MOD_INIT) is
	 * already in the command table. */
	pmh_ovr = CommandOverrideAdd(modinfo->handle, "CHATHISTORY", 0,
	                             pmh_chathistory_override);
	if (!pmh_ovr)
	{
		config_error("dm_history: CommandOverrideAdd(CHATHISTORY) failed -- "
		             "is chathistory.so loaded ahead of dm_history.so?");
		return MOD_FAILED;
	}
	/* REDACT override -- gives draft/message-redaction a DM code path
	 * alongside the channel path the upstream redact.so handles. */
	pmh_redact_ovr = CommandOverrideAdd(modinfo->handle, "REDACT", 0,
	                                    pmh_redact_override);
	if (!pmh_redact_ovr)
	{
		config_error("dm_history: CommandOverrideAdd(REDACT) failed -- "
		             "is redact.so loaded ahead of dm_history.so?");
		return MOD_FAILED;
	}
	return MOD_SUCCESS;
}

MOD_UNLOAD()
{
	pmh_ovr = NULL;
	pmh_redact_ovr = NULL;
	pmh_close_db();
	return MOD_SUCCESS;
}

/* ------------------------------------------------------------------
 * sqlite plumbing
 * ------------------------------------------------------------------ */

static int pmh_open_db(void)
{
	if (sqlite3_open(OBSIDIAN_DB, &pmh_db) != SQLITE_OK)
	{
		config_error("dm_history: could not open %s: %s",
		             OBSIDIAN_DB,
		             pmh_db ? sqlite3_errmsg(pmh_db) : "(open failed)");
		if (pmh_db)
			sqlite3_close(pmh_db);
		pmh_db = NULL;
		return -1;
	}
	/* WAL is what the other obsidian.db consumers use; matching their
	 * journal mode avoids "database is locked" cross-handle. */
	sqlite3_exec(pmh_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
	sqlite3_exec(pmh_db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);
	return 0;
}

static void pmh_close_db(void)
{
	if (pmh_db)
		sqlite3_close(pmh_db);
	pmh_db = NULL;
}

static int pmh_ensure_schema(void)
{
	const char *sql =
	    "CREATE TABLE IF NOT EXISTS dm_history ("
	    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
	    "  account_a TEXT NOT NULL,"
	    "  account_b TEXT NOT NULL,"
	    "  ts_ms INTEGER NOT NULL,"
	    "  msgid TEXT,"
	    "  sender_account TEXT NOT NULL,"
	    "  line TEXT NOT NULL"
	    ");"
	    "CREATE INDEX IF NOT EXISTS dm_history_pair_ts "
	    "  ON dm_history(account_a, account_b, ts_ms);"
	    "CREATE UNIQUE INDEX IF NOT EXISTS dm_history_msgid "
	    "  ON dm_history(msgid) WHERE msgid IS NOT NULL;";
	char *err = NULL;
	if (sqlite3_exec(pmh_db, sql, NULL, NULL, &err) != SQLITE_OK)
	{
		config_error("dm_history: schema init failed: %s",
		             err ? err : "(unknown)");
		if (err)
			sqlite3_free(err);
		return -1;
	}
	return 0;
}

/* ------------------------------------------------------------------
 * Account / pair helpers
 * ------------------------------------------------------------------ */

/* Sort the two account names lexically so both directions of a DM
 * land in the same (a,b) bucket. */
static void pmh_pair(const char *acc1, const char *acc2,
                     const char **out_a, const char **out_b)
{
	if (strcmp(acc1, acc2) <= 0)
	{
		*out_a = acc1;
		*out_b = acc2;
	} else
	{
		*out_a = acc2;
		*out_b = acc1;
	}
}

/* Resolve the account for a CHATHISTORY <target> argument.
 *
 * For now this means: find the online Client whose nick matches and
 * pluck their account.  Returns a heap-dup'd account name on success
 * (caller frees) or NULL when the target isn't online / isn't
 * logged in. */
static char *pmh_account_for_target(const char *target)
{
	Client *c = find_user(target, NULL);
	if (!c || !IsLoggedIn(c))
		return NULL;
	return strdup(c->user->account);
}

/* ------------------------------------------------------------------
 * Persistence hook
 * ------------------------------------------------------------------ */

/* Pull msgid out of mtags if present, else NULL. */
static const char *pmh_find_msgid(MessageTag *mtags)
{
	MessageTag *m;
	for (m = mtags; m; m = m->next)
	{
		if (!strcmp(m->name, "msgid") && m->value && *m->value)
			return m->value;
	}
	return NULL;
}

/* Format the IRC line the recipient would have seen, sans the message
 * tags (those are stored implicitly via msgid / ts and re-emitted on
 * replay by attaching a fresh batch tag). */
static void pmh_format_line(char *buf, size_t n,
                            Client *sender, Client *recipient,
                            const char *cmd, const char *text)
{
	snprintf(buf, n, ":%s!%s@%s %s %s :%s",
	         sender->name,
	         IsUser(sender) ? sender->user->username : "*",
	         IsUser(sender) ? GetHost(sender) : me.name,
	         cmd,
	         recipient->name,
	         text ? text : "");
}

/* Same shape as cmd_privmsg.c uses internally. */
static const char *pmh_cmd_for_sendtype(SendType st)
{
	switch (st)
	{
		case SEND_TYPE_PRIVMSG:
			return "PRIVMSG";
		case SEND_TYPE_NOTICE:
			return "NOTICE";
		case SEND_TYPE_TAGMSG:
			return "TAGMSG";
	}
	return "PRIVMSG";
}

static int pmh_usermsg(Client *client, Client *to, MessageTag *mtags,
                       const char *text, SendType sendtype)
{
	const char *acc_a, *acc_b;
	const char *msgid;
	char line[BUFSIZE];
	sqlite3_stmt *stmt = NULL;
	long long ts_ms;

	/* Persist DMs between two account-holders.  Skip self-DMs to
	 * avoid filling history with a user's own debug `/msg self`
	 * traffic. */
	if (!IsUser(client) || !IsLoggedIn(client))
		return 0;
	if (!IsUser(to) || !IsLoggedIn(to))
		return 0;
	if (!strcasecmp(client->user->account, to->user->account))
		return 0;
	if (!pmh_db)
		return 0;

	pmh_pair(client->user->account, to->user->account, &acc_a, &acc_b);
	msgid = pmh_find_msgid(mtags);
	ts_ms = (long long)(time(NULL)) * 1000;

	/* TAGMSG carries no body; store an empty string so replay still
	 * produces a valid IRC line.  text is normally non-NULL for
	 * PRIVMSG / NOTICE. */
	pmh_format_line(line, sizeof(line),
	                client, to,
	                pmh_cmd_for_sendtype(sendtype),
	                sendtype == SEND_TYPE_TAGMSG ? "" : text);

	const char *sql =
	    "INSERT OR IGNORE INTO dm_history "
	    "  (account_a, account_b, ts_ms, msgid, sender_account, line) "
	    "VALUES (?, ?, ?, ?, ?, ?)";
	if (sqlite3_prepare_v2(pmh_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;
	sqlite3_bind_text(stmt, 1, acc_a, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 2, acc_b, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(stmt, 3, ts_ms);
	if (msgid)
		sqlite3_bind_text(stmt, 4, msgid, -1, SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 4);
	sqlite3_bind_text(stmt, 5, client->user->account, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 6, line, -1, SQLITE_TRANSIENT);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	return 0;
}

/* ------------------------------------------------------------------
 * Query + replay
 * ------------------------------------------------------------------ */

/* Parse "timestamp=YYYY-...." into unix ms.  Returns 1 on success.
 * The IRCv3 timestamp format is ISO-8601 with milliseconds: e.g.
 * "2026-05-19T03:45:12.123Z". */
static int pmh_parse_iso_ms(const char *s, long long *out_ms)
{
	struct tm t;
	int ms = 0;
	memset(&t, 0, sizeof(t));
	if (sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d.%3d",
	           &t.tm_year, &t.tm_mon, &t.tm_mday,
	           &t.tm_hour, &t.tm_min, &t.tm_sec, &ms) < 6)
		return 0;
	t.tm_year -= 1900;
	t.tm_mon -= 1;
	time_t epoch = timegm(&t);
	if (epoch == (time_t)-1)
		return 0;
	*out_ms = (long long)epoch * 1000 + ms;
	return 1;
}

/* Resolve a HistoryFilter timestamp/msgid bound into a ts_ms cutoff.
 * Returns 1 on success.  When the bound is given as msgid, look the
 * row up in dm_history and read its ts_ms; that way our ordering is
 * always a pure ts_ms range query regardless of which form the
 * client used. */
static int pmh_resolve_bound(const char *timestamp, const char *msgid,
                             const char *acc_a, const char *acc_b,
                             long long *out_ms)
{
	if (timestamp && *timestamp)
		return pmh_parse_iso_ms(timestamp, out_ms);
	if (msgid && *msgid)
	{
		sqlite3_stmt *stmt = NULL;
		const char *sql =
		    "SELECT ts_ms FROM dm_history "
		    "WHERE account_a=? AND account_b=? AND msgid=?";
		if (sqlite3_prepare_v2(pmh_db, sql, -1, &stmt, NULL) != SQLITE_OK)
			return 0;
		sqlite3_bind_text(stmt, 1, acc_a, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(stmt, 2, acc_b, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(stmt, 3, msgid, -1, SQLITE_TRANSIENT);
		int rc = sqlite3_step(stmt);
		int found = 0;
		if (rc == SQLITE_ROW)
		{
			*out_ms = sqlite3_column_int64(stmt, 0);
			found = 1;
		}
		sqlite3_finalize(stmt);
		return found;
	}
	return 0;
}

/* Build the mtag list every replayed line needs:
 *   - time=<ISO-8601 ms>: required for the client to surface server-time
 *     instead of "now" against history rows
 *   - msgid=<id>: lets the client dedupe a history row against an in-memory
 *     copy of the same message; without it, the client appends and the user
 *     sees the same line twice
 *   - batch=<id>: links the line to the CHATHISTORY batch we're sending
 * Returns a fresh MessageTag* the caller must free_message_tags(). */
static MessageTag *pmh_build_mtags(const char *msgid, long long ts_ms,
                                   const char *batchid)
{
	MessageTag *head = NULL;

	/* time tag -- ISO-8601 with millisecond precision, UTC. */
	{
		time_t secs = (time_t)(ts_ms / 1000);
		int ms = (int)(ts_ms % 1000);
		struct tm t;
		gmtime_r(&secs, &t);
		char buf[40];
		snprintf(buf, sizeof(buf),
		         "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
		         t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
		         t.tm_hour, t.tm_min, t.tm_sec, ms);
		MessageTag *m = safe_alloc(sizeof(MessageTag));
		safe_strdup(m->name, "time");
		safe_strdup(m->value, buf);
		AddListItem(m, head);
	}

	if (msgid && *msgid)
	{
		MessageTag *m = safe_alloc(sizeof(MessageTag));
		safe_strdup(m->name, "msgid");
		safe_strdup(m->value, msgid);
		AddListItem(m, head);
	}

	if (batchid && *batchid)
	{
		MessageTag *m = safe_alloc(sizeof(MessageTag));
		safe_strdup(m->name, "batch");
		safe_strdup(m->value, batchid);
		AddListItem(m, head);
	}

	return head;
}

/* Send one stored line with reconstructed time/msgid/batch mtags. */
static void pmh_send_line_with_tags(Client *client, const char *line,
                                    const char *msgid, long long ts_ms,
                                    const char *batchid)
{
	MessageTag *mtags = pmh_build_mtags(msgid, ts_ms, batchid);
	sendto_one(client, mtags, "%s", line);
	free_message_tags(mtags);
}

/* Open a chathistory BATCH for the given target and return its id in
 * `out_batch` (must be at least BATCHLEN+1).  Sends nothing on a
 * client without `batch` capability and zeroes out_batch. */
static void pmh_open_batch(Client *client, const char *target, char *out_batch)
{
	out_batch[0] = '\0';
	if (!HasCapability(client, "batch"))
		return;
	generate_batch_id(out_batch);
	sendto_one(client, NULL, ":%s BATCH +%s chathistory %s",
	           me.name, out_batch, target);
}

static void pmh_close_batch(Client *client, const char *batchid)
{
	if (BadPtr(batchid))
		return;
	sendto_one(client, NULL, ":%s BATCH -%s", me.name, batchid);
}

/* Run a CHATHISTORY filter against the DM table and stream the
 * matching lines back inside a BATCH.  `target_nick` is what the
 * client asked for; we use it verbatim in the BATCH target field
 * so the receiving client knows which conversation these messages
 * belong to. */
static void pmh_send_history(Client *client, const char *target_nick,
                             const char *acc_a, const char *acc_b,
                             HistoryFilter *filter)
{
	long long a_ms = 0, b_ms = 0;
	int have_a = 0, have_b = 0;
	char batch[BATCHLEN + 1];
	int limit = filter->limit;
	if (limit <= 0 || limit > DMH_MAX_LIMIT)
		limit = DMH_MAX_LIMIT;

	have_a = pmh_resolve_bound(filter->timestamp_a, filter->msgid_a,
	                           acc_a, acc_b, &a_ms);
	have_b = pmh_resolve_bound(filter->timestamp_b, filter->msgid_b,
	                           acc_a, acc_b, &b_ms);

	/* Build the SQL based on the filter command.  We always select
	 * line + ts_ms and return rows in chronological (ascending)
	 * order to the client; for BEFORE / LATEST we need to do an
	 * inner DESC query to grab the *most recent* N rows, then flip
	 * the result. */
	const char *sql_order_inner = "DESC";
	const char *sql_where = "1=1";
	int use_a_lt = 0, use_a_gt = 0, use_between = 0;

	switch (filter->cmd)
	{
		case HFC_LATEST:
			/* If no anchor, just pull the newest N. */
			if (have_a)
				use_a_gt = 1;
			sql_order_inner = "DESC";
			break;
		case HFC_BEFORE:
			use_a_lt = 1;
			sql_order_inner = "DESC";
			break;
		case HFC_AFTER:
			use_a_gt = 1;
			sql_order_inner = "ASC";
			break;
		case HFC_AROUND:
			/* Around is "half the limit on each side of the anchor".
			 * Easiest: two separate queries (BEFORE + AFTER) merged. */
			break;
		case HFC_BETWEEN:
			use_between = 1;
			sql_order_inner = (a_ms <= b_ms) ? "ASC" : "DESC";
			break;
		case HFC_SIMPLE:
			/* legacy "last N lines / N seconds"; treat as LATEST */
			sql_order_inner = "DESC";
			break;
	}
	(void)sql_where;

	/* AROUND is the odd one -- handled with two queries, then their
	 * results are concatenated.  Implement it inline for clarity. */
	if (filter->cmd == HFC_AROUND)
	{
		if (!have_a)
			goto empty;

		int half = limit / 2;
		if (half < 1)
			half = 1;

		pmh_open_batch(client, target_nick, batch);

		/* Older half (ts < anchor), DESC then we'll flip into ASC. */
		{
			sqlite3_stmt *st = NULL;
			const char *q =
			    "SELECT line, msgid, ts_ms FROM dm_history "
			    "WHERE account_a=? AND account_b=? AND ts_ms<? "
			    "ORDER BY ts_ms DESC LIMIT ?";
			if (sqlite3_prepare_v2(pmh_db, q, -1, &st, NULL) == SQLITE_OK)
			{
				sqlite3_bind_text(st, 1, acc_a, -1, SQLITE_TRANSIENT);
				sqlite3_bind_text(st, 2, acc_b, -1, SQLITE_TRANSIENT);
				sqlite3_bind_int64(st, 3, a_ms);
				sqlite3_bind_int(st, 4, half);
				char *lines[DMH_MAX_LIMIT];
				char *msgids[DMH_MAX_LIMIT];
				long long tss[DMH_MAX_LIMIT];
				int n = 0;
				while (sqlite3_step(st) == SQLITE_ROW && n < DMH_MAX_LIMIT)
				{
					const unsigned char *l = sqlite3_column_text(st, 0);
					const unsigned char *mid = sqlite3_column_text(st, 1);
					lines[n] = strdup((const char *)l);
					msgids[n] = mid ? strdup((const char *)mid) : NULL;
					tss[n] = sqlite3_column_int64(st, 2);
					n++;
				}
				sqlite3_finalize(st);
				for (int i = n - 1; i >= 0; i--)
				{
					pmh_send_line_with_tags(client, lines[i],
					                        msgids[i], tss[i], batch);
					free(lines[i]);
					if (msgids[i])
						free(msgids[i]);
				}
			}
		}
		/* Newer half (ts >= anchor), ASC natively. */
		{
			sqlite3_stmt *st = NULL;
			const char *q =
			    "SELECT line, msgid, ts_ms FROM dm_history "
			    "WHERE account_a=? AND account_b=? AND ts_ms>=? "
			    "ORDER BY ts_ms ASC LIMIT ?";
			if (sqlite3_prepare_v2(pmh_db, q, -1, &st, NULL) == SQLITE_OK)
			{
				sqlite3_bind_text(st, 1, acc_a, -1, SQLITE_TRANSIENT);
				sqlite3_bind_text(st, 2, acc_b, -1, SQLITE_TRANSIENT);
				sqlite3_bind_int64(st, 3, a_ms);
				sqlite3_bind_int(st, 4, limit - half);
				while (sqlite3_step(st) == SQLITE_ROW)
				{
					const unsigned char *l = sqlite3_column_text(st, 0);
					const unsigned char *mid = sqlite3_column_text(st, 1);
					long long ts = sqlite3_column_int64(st, 2);
					pmh_send_line_with_tags(client, (const char *)l,
					                        mid ? (const char *)mid : NULL,
					                        ts, batch);
				}
				sqlite3_finalize(st);
			}
		}
		pmh_close_batch(client, batch);
		return;
	}

	/* LATEST / BEFORE / AFTER / BETWEEN: one query.  Build SQL. */
	char query[512];
	if (use_between)
	{
		long long lo = a_ms < b_ms ? a_ms : b_ms;
		long long hi = a_ms < b_ms ? b_ms : a_ms;
		snprintf(query, sizeof(query),
		         "SELECT line, msgid, ts_ms FROM dm_history "
		         "WHERE account_a=? AND account_b=? "
		         "  AND ts_ms>=%lld AND ts_ms<=%lld "
		         "ORDER BY ts_ms ASC LIMIT %d",
		         lo, hi, limit);
	} else if (use_a_lt)
	{
		snprintf(query, sizeof(query),
		         "SELECT line, msgid, ts_ms FROM dm_history "
		         "WHERE account_a=? AND account_b=? AND ts_ms<%lld "
		         "ORDER BY ts_ms %s LIMIT %d",
		         a_ms, sql_order_inner, limit);
	} else if (use_a_gt) /* LATEST anchored or AFTER */
	{
		snprintf(query, sizeof(query),
		         "SELECT line, msgid, ts_ms FROM dm_history "
		         "WHERE account_a=? AND account_b=? AND ts_ms>%lld "
		         "ORDER BY ts_ms %s LIMIT %d",
		         a_ms, sql_order_inner, limit);
	} else /* LATEST with no anchor -> grab tail */
	{
		snprintf(query, sizeof(query),
		         "SELECT line, msgid, ts_ms FROM dm_history "
		         "WHERE account_a=? AND account_b=? "
		         "ORDER BY ts_ms %s LIMIT %d",
		         sql_order_inner, limit);
	}

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(pmh_db, query, -1, &st, NULL) != SQLITE_OK)
		goto empty;
	sqlite3_bind_text(st, 1, acc_a, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 2, acc_b, -1, SQLITE_TRANSIENT);

	pmh_open_batch(client, target_nick, batch);

	if (!strcmp(sql_order_inner, "DESC") && filter->cmd != HFC_BETWEEN)
	{
		/* We pulled most-recent-N descending; flip to ascending for
		 * the client so messages render top-to-bottom in time order. */
		char *lines[DMH_MAX_LIMIT];
		char *msgids[DMH_MAX_LIMIT];
		long long tss[DMH_MAX_LIMIT];
		int n = 0;
		while (sqlite3_step(st) == SQLITE_ROW && n < DMH_MAX_LIMIT)
		{
			const unsigned char *l = sqlite3_column_text(st, 0);
			const unsigned char *mid = sqlite3_column_text(st, 1);
			lines[n] = strdup((const char *)l);
			msgids[n] = mid ? strdup((const char *)mid) : NULL;
			tss[n] = sqlite3_column_int64(st, 2);
			n++;
		}
		for (int i = n - 1; i >= 0; i--)
		{
			pmh_send_line_with_tags(client, lines[i],
			                        msgids[i], tss[i], batch);
			free(lines[i]);
			if (msgids[i])
				free(msgids[i]);
		}
	} else
	{
		while (sqlite3_step(st) == SQLITE_ROW)
		{
			const unsigned char *l = sqlite3_column_text(st, 0);
			const unsigned char *mid = sqlite3_column_text(st, 1);
			long long ts = sqlite3_column_int64(st, 2);
			pmh_send_line_with_tags(client, (const char *)l,
			                        mid ? (const char *)mid : NULL,
			                        ts, batch);
		}
	}
	sqlite3_finalize(st);
	pmh_close_batch(client, batch);
	return;

empty:
	pmh_open_batch(client, target_nick, batch);
	pmh_close_batch(client, batch);
}

/* TARGETS handler.  Spec is "list of {target, last_ts} that the
 * client has chathistory for, within a timestamp window".  We list
 * channels the client is in (the canonical behaviour) PLUS DM
 * partners from the dm_history table, all in one BATCH. */
static void pmh_send_targets(Client *client, HistoryFilter *filter, int limit)
{
	char batch[BATCHLEN + 1];
	long long a_ms = 0, b_ms = 0;
	int have_a, have_b;
	int sent = 0;

	if (limit <= 0 || limit > DMH_TARGETS_MAX)
		limit = DMH_TARGETS_MAX;

	have_a = filter->timestamp_a &&
	         pmh_parse_iso_ms(filter->timestamp_a, &a_ms);
	have_b = filter->timestamp_b &&
	         pmh_parse_iso_ms(filter->timestamp_b, &b_ms);
	if (!have_a || !have_b)
	{
		/* No window -> use widest possible range. */
		a_ms = LLONG_MIN;
		b_ms = LLONG_MAX;
	}
	long long lo = a_ms < b_ms ? a_ms : b_ms;
	long long hi = a_ms < b_ms ? b_ms : a_ms;

	batch[0] = '\0';
	if (HasCapability(client, "batch"))
	{
		generate_batch_id(batch);
		sendto_one(client, NULL, ":%s BATCH +%s draft/chathistory-targets",
		           me.name, batch);
	}

	/* Channel targets (mirrors the upstream chathistory module).
	 * Inline-walks the client's memberships and pulls the newest
	 * line in each channel's in-memory history for the window. */
	{
		HistoryFilter chf;
		memset(&chf, 0, sizeof(chf));
		chf.cmd = HFC_BEFORE;
		chf.timestamp_a = filter->timestamp_a;
		chf.timestamp_b = filter->timestamp_b;
		chf.limit = 1;

		Membership *mp;
		for (mp = client->user->channel; mp; mp = mp->next)
		{
			Channel *channel = mp->channel;
			HistoryResult *r = history_request(channel->name, &chf);
			if (r && r->log)
			{
				MessageTag *tm = find_mtag(r->log->mtags, "time");
				if (tm && tm->value)
				{
					MessageTag *m = NULL;
					if (*batch)
					{
						m = safe_alloc(sizeof(MessageTag));
						safe_strdup(m->name, "batch");
						safe_strdup(m->value, batch);
					}
					sendto_one(client, m,
					           ":%s CHATHISTORY TARGETS %s %s",
					           me.name, channel->name, tm->value);
					if (m)
						free_message_tags(m);
					if (++sent >= limit)
						break;
				}
			}
			if (r)
				free_history_result(r);
		}
	}

	/* DM partners: for each distinct (account_a, account_b) pair
	 * that contains the requester's account and has at least one
	 * row in the window, emit one CHATHISTORY TARGETS line.
	 * The "target" reported back is the *other* account name --
	 * that's what the client passed to /msg, and what they'll pass
	 * to a follow-up CHATHISTORY LATEST. */
	if (sent < limit && IsLoggedIn(client) && pmh_db)
	{
		const char *q =
		    "SELECT CASE WHEN account_a=?1 THEN account_b ELSE account_a END "
		    "         AS partner, "
		    "       MAX(ts_ms) AS last_ts "
		    "FROM dm_history "
		    "WHERE (account_a=?1 OR account_b=?1) "
		    "  AND ts_ms>=?2 AND ts_ms<=?3 "
		    "GROUP BY partner "
		    "ORDER BY last_ts DESC "
		    "LIMIT ?4";
		sqlite3_stmt *st = NULL;
		if (sqlite3_prepare_v2(pmh_db, q, -1, &st, NULL) == SQLITE_OK)
		{
			sqlite3_bind_text(st, 1, client->user->account, -1, SQLITE_TRANSIENT);
			sqlite3_bind_int64(st, 2, lo);
			sqlite3_bind_int64(st, 3, hi);
			sqlite3_bind_int(st, 4, limit - sent);
			while (sqlite3_step(st) == SQLITE_ROW)
			{
				const unsigned char *partner = sqlite3_column_text(st, 0);
				long long last_ts = sqlite3_column_int64(st, 1);
				/* Format ts_ms as IRCv3 server-time ISO-8601 with ms. */
				time_t secs = last_ts / 1000;
				int ms = last_ts % 1000;
				struct tm t;
				gmtime_r(&secs, &t);
				char ts_buf[40];
				snprintf(ts_buf, sizeof(ts_buf),
				         "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
				         t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
				         t.tm_hour, t.tm_min, t.tm_sec, ms);

				MessageTag *m = NULL;
				if (*batch)
				{
					m = safe_alloc(sizeof(MessageTag));
					safe_strdup(m->name, "batch");
					safe_strdup(m->value, batch);
				}
				sendto_one(client, m,
				           ":%s CHATHISTORY TARGETS %s %s",
				           me.name, partner, ts_buf);
				if (m)
					free_message_tags(m);
				if (++sent >= limit)
					break;
			}
			sqlite3_finalize(st);
		}
	}

	if (*batch)
		sendto_one(client, NULL, ":%s BATCH -%s", me.name, batch);
}

/* ------------------------------------------------------------------
 * CHATHISTORY override
 * ------------------------------------------------------------------ */

/* Minimal token parser matching the upstream chathistory.c style:
 * recognise "name=value" and return a heap-dup of value (NULL on
 * miss).  Used to pluck timestamp= / msgid= out of the argv. */
static char *pmh_token(const char *str, const char *name)
{
	size_t nlen = strlen(name);
	if (strncmp(str, name, nlen) != 0 || str[nlen] != '=')
		return NULL;
	return strdup(str + nlen + 1);
}

static void pmh_filter_free(HistoryFilter *f)
{
	if (!f)
		return;
	safe_free(f->timestamp_a);
	safe_free(f->timestamp_b);
	safe_free(f->msgid_a);
	safe_free(f->msgid_b);
	safe_free(f);
}

CMD_OVERRIDE_FUNC(pmh_chathistory_override)
{
	/* parv[1] = subcommand, parv[2] = target (or filter for TARGETS),
	 * parv[3] = filter, parv[4] = filter/limit, parv[5] = limit (for
	 * BETWEEN). */
	if (!MyUser(client) || parc < 5)
	{
		CALL_NEXT_COMMAND_OVERRIDE();
		return;
	}

	/* TARGETS: handle entirely here so channel + DM listings share a
	 * single batch.  parv[2]/parv[3] are the timestamp window, parv[4]
	 * is the limit. */
	if (!strcasecmp(parv[1], "TARGETS"))
	{
		HistoryFilter *f = safe_alloc(sizeof(HistoryFilter));
		f->timestamp_a = pmh_token(parv[2], "timestamp");
		f->timestamp_b = pmh_token(parv[3], "timestamp");
		if (!f->timestamp_a || !f->timestamp_b)
		{
			/* Malformed -- defer to the upstream handler which
			 * already emits a proper FAIL. */
			pmh_filter_free(f);
			CALL_NEXT_COMMAND_OVERRIDE();
			return;
		}
		int limit = atoi(parv[4]);
		pmh_send_targets(client, f, limit);
		pmh_filter_free(f);
		return;
	}

	/* Channel target -> upstream chathistory.c handles it. */
	const char *target = parv[2];
	if (target && (target[0] == '#' || target[0] == '&' ||
	               target[0] == '^' || target[0] == '$'))
	{
		CALL_NEXT_COMMAND_OVERRIDE();
		return;
	}

	/* Non-channel target.  Requester must be an account-holder. */
	if (!IsLoggedIn(client))
	{
		sendto_one(client, NULL,
		           ":%s FAIL CHATHISTORY INVALID_TARGET %s %s "
		           ":You must be logged in to view DM history",
		           me.name, parv[1], target);
		return;
	}

	char *other_acc = pmh_account_for_target(target);
	if (!other_acc)
	{
		/* Empty batch -- the same shape the upstream module returns
		 * when there's no history.  Better than FAIL for clients
		 * that mass-query an inbox. */
		char batch[BATCHLEN + 1];
		pmh_open_batch(client, target, batch);
		pmh_close_batch(client, batch);
		return;
	}

	const char *acc_a, *acc_b;
	pmh_pair(client->user->account, other_acc, &acc_a, &acc_b);

	HistoryFilter *filter = safe_alloc(sizeof(HistoryFilter));

	if (!strcasecmp(parv[1], "LATEST"))
	{
		filter->cmd = HFC_LATEST;
		if (strcmp(parv[3], "*") != 0)
		{
			filter->timestamp_a = pmh_token(parv[3], "timestamp");
			filter->msgid_a = pmh_token(parv[3], "msgid");
		}
		filter->limit = atoi(parv[4]);
	} else if (!strcasecmp(parv[1], "BEFORE"))
	{
		filter->cmd = HFC_BEFORE;
		filter->timestamp_a = pmh_token(parv[3], "timestamp");
		filter->msgid_a = pmh_token(parv[3], "msgid");
		filter->limit = atoi(parv[4]);
	} else if (!strcasecmp(parv[1], "AFTER"))
	{
		filter->cmd = HFC_AFTER;
		filter->timestamp_a = pmh_token(parv[3], "timestamp");
		filter->msgid_a = pmh_token(parv[3], "msgid");
		filter->limit = atoi(parv[4]);
	} else if (!strcasecmp(parv[1], "AROUND"))
	{
		filter->cmd = HFC_AROUND;
		filter->timestamp_a = pmh_token(parv[3], "timestamp");
		filter->msgid_a = pmh_token(parv[3], "msgid");
		filter->limit = atoi(parv[4]);
	} else if (!strcasecmp(parv[1], "BETWEEN") && parc >= 6)
	{
		filter->cmd = HFC_BETWEEN;
		filter->timestamp_a = pmh_token(parv[3], "timestamp");
		filter->msgid_a = pmh_token(parv[3], "msgid");
		filter->timestamp_b = pmh_token(parv[4], "timestamp");
		filter->msgid_b = pmh_token(parv[4], "msgid");
		filter->limit = atoi(parv[5]);
	} else
	{
		sendto_one(client, NULL,
		           ":%s FAIL CHATHISTORY INVALID_PARAMS %s "
		           ":Invalid subcommand",
		           me.name, parv[1]);
		free(other_acc);
		pmh_filter_free(filter);
		return;
	}

	pmh_send_history(client, target, acc_a, acc_b, filter);

	free(other_acc);
	pmh_filter_free(filter);
}

/* ------------------------------------------------------------------
 * REDACT override -- DM redactions for account-holders
 * ------------------------------------------------------------------ */

/* Send a REDACT line to a single recipient if they have negotiated
 * draft/message-redaction.  If `with_reason` is set, includes the
 * trailing reason. */
static void pmh_send_redact_one(Client *recipient, Client *sender,
                                const char *target_nick,
                                const char *msgid, const char *reason)
{
	if (!recipient || !MyConnect(recipient))
		return;
	if (!HasCapability(recipient, "draft/message-redaction"))
		return;
	if (reason && *reason)
	{
		sendto_prefix_one(recipient, sender, NULL,
		                  ":%s REDACT %s %s :%s",
		                  sender->name, target_nick, msgid, reason);
	} else
	{
		sendto_prefix_one(recipient, sender, NULL,
		                  ":%s REDACT %s %s",
		                  sender->name, target_nick, msgid);
	}
}

/* Send REDACT to every currently-connected client whose account
 * matches `account`.  Used to fan a DM redact out to all of the
 * sender's sessions AND all of the recipient's sessions.  The
 * `sender_client` is the actual originating Client; we still
 * deliver to that one (the user expects to see the redact landed
 * in the conversation they triggered it from). */
static void pmh_fan_redact_to_account(Client *sender_client,
                                      const char *account,
                                      const char *target_nick,
                                      const char *msgid,
                                      const char *reason)
{
	Client *acptr;
	list_for_each_entry(acptr, &lclient_list, lclient_node)
	{
		if (!IsUser(acptr) || !IsLoggedIn(acptr))
			continue;
		if (strcasecmp(acptr->user->account, account))
			continue;
		pmh_send_redact_one(acptr, sender_client, target_nick, msgid, reason);
	}
}

CMD_OVERRIDE_FUNC(pmh_redact_override)
{
	if (!MyUser(client) || parc < 3 || BadPtr(parv[1]) || BadPtr(parv[2]))
	{
		CALL_NEXT_COMMAND_OVERRIDE();
		return;
	}

	/* Channel target -> hand straight off to upstream redact.so. */
	const char *target = parv[1];
	if (target[0] == '#' || target[0] == '&' ||
	    target[0] == '^' || target[0] == '$')
	{
		CALL_NEXT_COMMAND_OVERRIDE();
		return;
	}

	/* Nick target: only account-holders can REDACT a DM, since we
	 * only have history for messages between two account-holders. */
	if (!IsLoggedIn(client))
	{
		sendto_one(client, NULL,
		           ":%s FAIL REDACT REDACT_FORBIDDEN %s %s "
		           ":You must be logged in to redact DMs",
		           me.name, parv[1], parv[2]);
		return;
	}

	char *other_acc = pmh_account_for_target(target);
	if (!other_acc)
	{
		/* Could be offline / unregistered.  Fall back to upstream so
		 * the user gets the existing error path. */
		CALL_NEXT_COMMAND_OVERRIDE();
		return;
	}

	const char *acc_a, *acc_b;
	pmh_pair(client->user->account, other_acc, &acc_a, &acc_b);

	/* Look up the row.  We need sender_account + line so we can both
	 * authorise (sender or oper) and broadcast back the right
	 * source nick on the REDACT line. */
	sqlite3_stmt *st = NULL;
	const char *q =
	    "SELECT sender_account, line FROM dm_history "
	    "WHERE account_a=? AND account_b=? AND msgid=?";
	if (sqlite3_prepare_v2(pmh_db, q, -1, &st, NULL) != SQLITE_OK)
	{
		free(other_acc);
		sendto_one(client, NULL,
		           ":%s FAIL REDACT UNKNOWN_MSGID %s %s "
		           ":Internal error looking up message",
		           me.name, parv[1], parv[2]);
		return;
	}
	sqlite3_bind_text(st, 1, acc_a, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 2, acc_b, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 3, parv[2], -1, SQLITE_TRANSIENT);

	int rc = sqlite3_step(st);
	if (rc != SQLITE_ROW)
	{
		sqlite3_finalize(st);
		free(other_acc);
		sendto_one(client, NULL,
		           ":%s FAIL REDACT UNKNOWN_MSGID %s %s "
		           ":This message does not exist or is too old",
		           me.name, parv[1], parv[2]);
		return;
	}
	const char *sender_account = (const char *)sqlite3_column_text(st, 0);
	const char *line = (const char *)sqlite3_column_text(st, 1);
	char *sender_account_dup = sender_account ? strdup(sender_account) : NULL;
	char *line_dup = line ? strdup(line) : NULL;
	sqlite3_finalize(st);

	/* Authorise: requester is sender, OR has chat:redact oper perm. */
	int is_oper =
	    ValidatePermissionsForPath("chat:redact", client, NULL, NULL, NULL);
	int is_sender = sender_account_dup
	                    ? !strcasecmp(sender_account_dup, client->user->account)
	                    : 0;
	if (!is_sender && !is_oper)
	{
		sendto_one(client, NULL,
		           ":%s FAIL REDACT REDACT_FORBIDDEN %s %s "
		           ":You can only redact your own DMs",
		           me.name, parv[1], parv[2]);
		if (sender_account_dup)
			free(sender_account_dup);
		if (line_dup)
			free(line_dup);
		free(other_acc);
		return;
	}

	/* Delete the row.  We physically remove rather than mark redacted
	 * so a subsequent CHATHISTORY LATEST doesn't replay the redacted
	 * content. */
	{
		sqlite3_stmt *del = NULL;
		const char *dq =
		    "DELETE FROM dm_history "
		    "WHERE account_a=? AND account_b=? AND msgid=?";
		if (sqlite3_prepare_v2(pmh_db, dq, -1, &del, NULL) == SQLITE_OK)
		{
			sqlite3_bind_text(del, 1, acc_a, -1, SQLITE_TRANSIENT);
			sqlite3_bind_text(del, 2, acc_b, -1, SQLITE_TRANSIENT);
			sqlite3_bind_text(del, 3, parv[2], -1, SQLITE_TRANSIENT);
			sqlite3_step(del);
			sqlite3_finalize(del);
		}
	}

	const char *reason = (parc >= 4 && !BadPtr(parv[3])) ? parv[3] : NULL;

	/* Broadcast to every connected session of both parties.  We
	 * deliberately don't limit to MyConnect(client) because the user
	 * almost certainly cares about the redact appearing in their
	 * other sessions (desktop + mobile etc.) -- same UX as the
	 * channel path via sendto_channel.
	 *
	 * The wire line is identical for both sides: source is the
	 * REDACT requester, target is `parv[1]` (the original recipient
	 * nick).  Either party can identify which DM conversation to
	 * apply this to from {source, target} -- one of those two
	 * nicks is themselves; the other is the partner. */
	pmh_fan_redact_to_account(client, client->user->account,
	                          parv[1], parv[2], reason);
	pmh_fan_redact_to_account(client, other_acc,
	                          parv[1], parv[2], reason);

	if (sender_account_dup)
		free(sender_account_dup);
	if (line_dup)
		free(line_dup);
	free(other_acc);
}
