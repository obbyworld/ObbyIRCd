/* src/modules/cmdslist.c
 *
 * obsidianirc/cmdslist: tell connected clients which IRC commands they
 * are allowed to invoke right now.  Used by the obbyworld web client
 * to drive a "/" slash-command suggestion popover.
 *
 * Wire shape:
 *
 *   :server BATCH +<ref> obsidianirc/cmdslist
 *   @batch=<ref> :server CMDSLIST +cmd1 +cmd2 +cmd3 ...
 *   @batch=<ref> :server CMDSLIST +cmd4 +cmd5 ...
 *   :server BATCH -<ref>
 *
 * Each parameter on a CMDSLIST line is "+<cmd>" (add) or "-<cmd>"
 * (remove).  The whole list is wrapped in a draft/batch so the client
 * has a clear end-of-message marker -- the previous one-line-per-cmd
 * shape would just stream forever and the client could never tell when
 * the list was complete.
 *
 * Multiple commands are packed onto each CMDSLIST line until we
 * approach the 512-byte IRC line limit, then we flush and start a new
 * batched line.  The whole batch is the logical "concat" view of the
 * list -- the receiver concatenates all parameters across all lines
 * to get the full set.
 *
 *  LICENSE: GPLv3-or-later
 *  Copyright (c) 2026 Valware and the ObbyIRCd Team
 */

#include "unrealircd.h"

ModuleHeader MOD_HEADER = {
    "cmdslist",
    "1.0",
    "obsidianirc/cmdslist: announce the user's invocable command set",
    "ObbyIRCd Team",
    "unrealircd-6",
};

#define CMDSLIST_CAP "obsidianirc/cmdslist"
#define CMD_CMDSLIST "CMDSLIST"

/* Stay well under 512 bytes after accounting for "@batch=<ref> :<server>
 * CMDSLIST" and the trailing CRLF.  BATCHLEN is small so 470 leaves a
 * comfortable margin even with long server names. */
#define LINE_BUDGET 470

static long CAP_CMDSLIST = 0L;

CMD_FUNC(cmd_cmdslist);

/* ===================================================================
 * Visibility helper -- which commands does this client right now have
 * permission to call?  We mirror UnrealIRCd's CMD_* flags.
 * =================================================================== */
static int user_can_do_command(RealCommand *c, Client *client)
{
	if (!c)
		return 0;
	if (c->flags & CMD_UNREGISTERED && (!IsUser(client) && MyConnect(client)))
		return 1;
	if (c->flags & CMD_USER && IsUser(client))
		return 1;
	if (c->flags & CMD_OPER && IsOper(client))
		return 1;
	return 0;
}

/* ===================================================================
 * Batched send: one BATCH wrapper containing as many CMDSLIST lines as
 * needed to cover `cmds`.  `op` is "+" (add) or "-" (remove); we put
 * one op per line for simplicity (caller picks).
 * =================================================================== */
static void send_cmds_batch(Client *client, const char *op,
                            RealCommand **cmds, int n)
{
	if (!HasCapabilityFast(client, CAP_CMDSLIST) || n == 0)
		return;

	char ref[BATCHLEN + 1];
	gen_random_alnum(ref, BATCHLEN);
	ref[BATCHLEN] = '\0';

	sendto_one(client, NULL, ":%s BATCH +%s " CMDSLIST_CAP, me.name, ref);

    /* Pack as many "<op><cmd>" tokens as fit per CMDSLIST line. */
	char buf[BUFSIZE];
	int pos = 0;
	for (int i = 0; i < n; i++)
	{
		const char *name = cmds[i]->cmd;
		int tok_len = (int)strlen(name) + 1; /* +1 for the op char */
        /* +1 for the leading space we'll prepend */
		if (pos > 0 && pos + 1 + tok_len > LINE_BUDGET)
		{
			buf[pos] = '\0';
			sendto_one(client, NULL,
			           "@batch=%s :%s " CMD_CMDSLIST "%s",
			           ref, me.name, buf);
			pos = 0;
		}
		int rem = (int)sizeof(buf) - pos;
		if (rem <= tok_len + 2)
			break; /* defensive: shouldn't happen */
		pos += snprintf(buf + pos, rem, " %s%s", op, name);
	}
	if (pos > 0)
	{
		buf[pos] = '\0';
		sendto_one(client, NULL,
		           "@batch=%s :%s " CMD_CMDSLIST "%s",
		           ref, me.name, buf);
	}

	sendto_one(client, NULL, ":%s BATCH -%s", me.name, ref);
}

/* Walk the command hash and collect commands matching `filter(client, c)`.
 * Caller frees the returned array; it is NULL-terminated for safety. */
static RealCommand **collect_commands(Client *client,
                                      int (*filter)(Client *, RealCommand *),
                                      int *out_n)
{
	int cap = 64, n = 0;
	RealCommand **arr = safe_alloc(sizeof(*arr) * cap);
	for (int i = 0; i < 256; i++)
	{
		RealCommand *c;
		for (c = CommandHash[i]; c; c = c->next)
		{
			if (!filter(client, c))
				continue;
			if (n + 1 >= cap)
			{
				cap *= 2;
				RealCommand **tmp = realloc(arr, sizeof(*arr) * cap);
				if (!tmp)
					break;
				arr = tmp;
			}
			arr[n++] = c;
		}
	}
	*out_n = n;
	return arr;
}

/* ===================================================================
 * Filters
 * =================================================================== */
static int filter_user_only(Client *client, RealCommand *c)
{
	if (!(c->flags & CMD_USER))
		return 0;
	if (c->flags & CMD_UNREGISTERED)
		return 0;
	return user_can_do_command(c, client);
}

static int filter_unreg_no_longer(Client *_client, RealCommand *c)
{
    /* Unregistered-only commands the now-fully-connected user can no
     * longer invoke. */
	return (c->flags & CMD_UNREGISTERED) && !(c->flags & CMD_USER);
}

static int filter_oper_only(Client *_client, RealCommand *c)
{
	return (c->flags & CMD_OPER) && !(c->flags & CMD_USER);
}

static int filter_all_runnable(Client *client, RealCommand *c)
{
	return user_can_do_command(c, client);
}

/* ===================================================================
 * Hooks: send the command set on connect and on /OPER status change.
 * =================================================================== */
static int hook_local_connect(Client *client)
{
	if (!HasCapabilityFast(client, CAP_CMDSLIST) || !MyUser(client))
		return 0;

	int n_add = 0;
	RealCommand **add_list = collect_commands(client, filter_user_only, &n_add);
	if (n_add)
		send_cmds_batch(client, "+", add_list, n_add);
	safe_free(add_list);

	int n_drop = 0;
	RealCommand **drop_list =
	    collect_commands(client, filter_unreg_no_longer, &n_drop);
	if (n_drop)
		send_cmds_batch(client, "-", drop_list, n_drop);
	safe_free(drop_list);
	return 0;
}

static int hook_local_oper(Client *client, int add,
                           const char *_oper_block, const char *_operclass)
{
	if (!HasCapabilityFast(client, CAP_CMDSLIST))
		return 0;
	int n = 0;
	RealCommand **list = collect_commands(client, filter_oper_only, &n);
	if (n)
		send_cmds_batch(client, add ? "+" : "-", list, n);
	safe_free(list);
	return 0;
}

/* ===================================================================
 * Manual refresh: client sends `CMDSLIST` with no params to ask for
 * the full current set.  Send everything they can do as a single +
 * batch.
 * =================================================================== */
CMD_FUNC(cmd_cmdslist)
{
	if (!HasCapabilityFast(client, CAP_CMDSLIST))
		return;
	add_fake_lag(client, 2000);
	int n = 0;
	RealCommand **list = collect_commands(client, filter_all_runnable, &n);
	if (n)
		send_cmds_batch(client, "+", list, n);
	safe_free(list);
}

/* ===================================================================
 * Module wiring
 * =================================================================== */

MOD_INIT()
{
	ClientCapabilityInfo cap;

	MARK_AS_OFFICIAL_MODULE(modinfo);

	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_CONNECT, 0, hook_local_connect);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_OPER, 0, hook_local_oper);

	memset(&cap, 0, sizeof(cap));
	cap.name = CMDSLIST_CAP;
	if (!ClientCapabilityAdd(modinfo->handle, &cap, &CAP_CMDSLIST))
	{
		config_error("cmdslist: could not add CAP %s", CMDSLIST_CAP);
		return MOD_FAILED;
	}
	return MOD_SUCCESS;
}

MOD_LOAD()
{
	CommandAdd(modinfo->handle, CMD_CMDSLIST, cmd_cmdslist, 0,
	           CMD_USER | CMD_UNREGISTERED);
	return MOD_SUCCESS;
}

MOD_UNLOAD()
{
	return MOD_SUCCESS;
}
