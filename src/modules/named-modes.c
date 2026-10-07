/* IRCv3 draft/named-modes (PROP command) implementation.
 *
 * Spec: https://github.com/progval/ircv3-specifications/blob/
 *       e28f44f8d7b0964c82acd28eea1e35895daf0919/extensions/named-modes.md
 *
 * Wire shape:
 *   Client: PROP #chan +op=alice -topiclock +ban=*!*@spam.example
 *   Server: :alice!~a@host PROP #chan +op=alice -topiclock +ban=*!*@spam.example
 *
 *   Plain (non-cap) clients still receive the legacy MODE form because
 *   src/modules/mode.c filters cap-holders out of its sendto_channel
 *   (clicap | CAP_INVERT). This module then re-emits an equivalent PROP
 *   to cap-holders via the HOOKTYPE_LOCAL_CHANMODE hook.
 *
 *  License: GPLv3-or-later
 *  Copyright (c) 2026 obbyworld Team
 */

#include "unrealircd.h"

ModuleHeader MOD_HEADER = {
    "named-modes",
    "1.0",
    "IRCv3 draft/named-modes -- PROP command + RPL_CHMODELIST etc.",
    "obbyworld Team",
    "unrealircd-6",
};

#define NAMED_MODES_CAP "draft/named-modes"

/* RPL_PROPLIST etc. live in include/numeric.h alongside the rest of
 * the IRC numeric registry. */

static long CAP_NAMED_MODES = 0L;

/* ===================================================================
 * Forward decls
 * =================================================================== */
CMD_FUNC(cmd_prop);
static int named_modes_connect(Client *client, int after_numeric);
static int named_modes_local_chanmode(Client *client, Channel *channel,
                                      MessageTag *mtags, const char *modebuf,
                                      const char *parabuf, time_t sendts,
                                      int samode, int *destroy_channel);

static void send_chmodelist(Client *to);
static void send_umodelist(Client *to);
static int prop_classify_chanmode(Cmode *cm);
static int prop_classify_umode(Umode *um);
static const char *strip_vendor(const char *name);
/* Mode lookup-by-name helpers live in api-channelmode.c /
 * api-usermode.c respectively (find_channel_mode_handler_by_name,
 * find_user_mode_handler_by_name) since they're useful beyond
 * named-modes. */

/* ===================================================================
 * Module wiring
 * =================================================================== */
MOD_INIT()
{
	ClientCapabilityInfo cap;

	MARK_AS_OFFICIAL_MODULE(modinfo);

	memset(&cap, 0, sizeof(cap));
	cap.name = NAMED_MODES_CAP;
	ClientCapabilityAdd(modinfo->handle, &cap, &CAP_NAMED_MODES);

	CommandAdd(modinfo->handle, "PROP", cmd_prop, MAXPARA, CMD_USER);

	HookAdd(modinfo->handle, HOOKTYPE_WELCOME, 0, named_modes_connect);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_CHANMODE, 0,
	        named_modes_local_chanmode);

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

/* ===================================================================
 * Helpers
 * =================================================================== */

/* Mirror the spec's channel-mode type table:
 *   1 list, 2 param-set+unset, 3 param-set, 4 flag, 5 prefix.
 * Returns 0 if the mode shouldn't be advertised. */
static int prop_classify_chanmode(Cmode *cm)
{
	if (!cm || cm->unloaded)
		return 0;
	if (cm->type == CMODE_MEMBER)
		return 5;
	/* List modes (b/e/I) aren't first-class Cmodes in obbyircd --
	 * they're handled separately in cmd_mode.c. We treat any zero-
	 * paracount as flag and any param-mode as type 3 unless it
	 * also requires a param on unset (then 2). */
	if (cm->paracount == 0)
		return 4;
	if (cm->unset_with_param)
		return 2;
	return 3;
}

/* User mode types per spec: 3 param-set, 4 flag.
 * obbyircd user modes are pure flags so this always returns 4. */
static int prop_classify_umode(Umode *um)
{
	if (!um || um->unloaded)
		return 0;
	return 4;
}

/* ban/banex/invex are special: they're list-modes but registered
 * elsewhere. List them by hand for the chmodelist advertisement. */
static const struct {
	int type;
	const char *name;
	char letter;
} extra_chmodes[] = {
    {1, "ban", 'b'},
    {1, "banex", 'e'},
    {1, "invex", 'I'},
    {0, NULL, 0}};

/* For the relay path: when a client sends PROP +foo=bar with a vendor
 * prefix (obsidianirc/foo), we accept either form. strip_vendor returns
 * the unqualified part if the vendor matches our own; else NULL. */
static const char *strip_vendor(const char *name)
{
	const char *slash = strchr(name, '/');
	if (!slash)
		return name;
	if (!strncmp(name, "obsidianirc/", 12))
		return slash + 1;
	return NULL;
}

/* ===================================================================
 * Connect-time advertisement
 *
 * Send RPL_CHMODELIST + RPL_UMODELIST after 005 ISUPPORT but before
 * any user-driven traffic. Cap negotiation may not have completed
 * yet, so we send unconditionally -- non-cap clients ignore unknown
 * numerics.
 * =================================================================== */
static int named_modes_connect(Client *client, int after_numeric)
{
	/* Only fire once per client (after ISUPPORT lands), and only for
	 * cap-holders -- non-cap clients have no idea what 964/965 mean
	 * and the spec says clients MUST negotiate draft/named-modes
	 * before receiving the new numerics. */
	if (after_numeric != 5)
		return 0;
	if (!MyUser(client))
		return 0;
	if (!CAP_NAMED_MODES || !HasCapabilityFast(client, CAP_NAMED_MODES))
		return 0;
	send_chmodelist(client);
	send_umodelist(client);
	return 0;
}

/* Build and send RPL_CHMODELIST 964. Multiple lines if the list is
 * too long for one IRC message; all but the last carry an asterisk
 * placeholder before the mode list, per spec. */
static void send_chmodelist(Client *to)
{
	char buf[BUFSIZE];
	char item[64];
	Cmode *cm;
	int i;
	size_t buf_len = 0;

	buf[0] = '\0';

	/* Hardcoded list-mode entries first (ban/banex/invex). */
	for (i = 0; extra_chmodes[i].name; i++)
	{
		snprintf(item, sizeof(item), "%d:%s=%c",
		         extra_chmodes[i].type,
		         extra_chmodes[i].name,
		         extra_chmodes[i].letter);
		if (buf_len + strlen(item) + 2 > 350)
		{
			sendto_one(to, NULL, ":%s %d %s * :%s",
			           me.name, RPL_CHMODELIST, to->name, buf);
			buf[0] = '\0';
			buf_len = 0;
		}
		if (buf_len)
			buf[buf_len++] = ' ';
		strlcpy(buf + buf_len, item, sizeof(buf) - buf_len);
		buf_len += strlen(item);
	}

	for (cm = channelmodes; cm; cm = cm->next)
	{
		int type = prop_classify_chanmode(cm);
		if (!type || !cm->name)
			continue;
		if (cm->letter)
			snprintf(item, sizeof(item), "%d:%s=%c",
			         type, cm->name, cm->letter);
		else
			snprintf(item, sizeof(item), "%d:%s",
			         type, cm->name);
		if (buf_len + strlen(item) + 2 > 350)
		{
			sendto_one(to, NULL, ":%s %d %s * :%s",
			           me.name, RPL_CHMODELIST, to->name, buf);
			buf[0] = '\0';
			buf_len = 0;
		}
		if (buf_len)
			buf[buf_len++] = ' ';
		strlcpy(buf + buf_len, item, sizeof(buf) - buf_len);
		buf_len += strlen(item);
	}
	if (buf_len)
		sendto_one(to, NULL, ":%s %d %s :%s",
		           me.name, RPL_CHMODELIST, to->name, buf);
}

static void send_umodelist(Client *to)
{
	char buf[BUFSIZE];
	char item[64];
	Umode *um;
	size_t buf_len = 0;

	buf[0] = '\0';

	for (um = usermodes; um; um = um->next)
	{
		int type = prop_classify_umode(um);
		if (!type || !um->name)
			continue;
		if (um->letter)
			snprintf(item, sizeof(item), "%d:%s=%c",
			         type, um->name, um->letter);
		else
			snprintf(item, sizeof(item), "%d:%s",
			         type, um->name);
		if (buf_len + strlen(item) + 2 > 350)
		{
			sendto_one(to, NULL, ":%s %d %s * :%s",
			           me.name, RPL_UMODELIST, to->name, buf);
			buf[0] = '\0';
			buf_len = 0;
		}
		if (buf_len)
			buf[buf_len++] = ' ';
		strlcpy(buf + buf_len, item, sizeof(buf) - buf_len);
		buf_len += strlen(item);
	}
	if (buf_len)
		sendto_one(to, NULL, ":%s %d %s :%s",
		           me.name, RPL_UMODELIST, to->name, buf);
}

/* ===================================================================
 * MODE -> PROP relay
 *
 * Fires after a chanmode change has been processed. mode.c has just
 * sent the legacy MODE to non-cap members (the cap-holders were
 * filtered out via clicap | CAP_INVERT). We translate the same
 * (modebuf, parabuf) into a PROP form and send it to cap-holders.
 *
 * Translation:
 *   "+oo-t alice bob" with modebuf="+oo-t", parabuf="alice bob"
 *     -> "PROP #chan +op=alice +op=bob -topiclock"
 * =================================================================== */
static int named_modes_local_chanmode(Client *client, Channel *channel,
                                      MessageTag *mtags, const char *modebuf,
                                      const char *parabuf, time_t sendts,
                                      int samode, int *destroy_channel)
{
	char propbuf[BUFSIZE];
	const char *params[64];
	int n_params = 0;
	const char *p;
	char tmp[BUFSIZE];
	char *tok;
	char *saveptr;
	char what = '+';
	int param_idx = 0;
	size_t plen = 0;
	int wrote_any = 0;

	if (!CAP_NAMED_MODES || !modebuf)
		return 0;

	/* Split parabuf into tokens up-front. */
	if (parabuf && *parabuf)
	{
		strlcpy(tmp, parabuf, sizeof(tmp));
		for (tok = strtoken(&saveptr, tmp, " "); tok && n_params < 63;
		     tok = strtoken(&saveptr, NULL, " "))
		{
			params[n_params++] = tok;
		}
	}

	propbuf[0] = '\0';

	for (p = modebuf; *p; p++)
	{
		Cmode *cm;
		const char *param = NULL;
		int wants_param = 0;
		int cls;
		char buf[256];
		size_t buflen;

		if (*p == '+' || *p == '-')
		{
			what = *p;
			continue;
		}

		/* Look up the chanmode by letter. */
		for (cm = channelmodes; cm; cm = cm->next)
		{
			if (!cm->unloaded && cm->letter == *p)
				break;
		}

		if (cm && cm->name)
		{
			cls = prop_classify_chanmode(cm);
			/* Type 1/2/5 always param. Type 3 only on +. */
			if (cls == 1 || cls == 2 || cls == 5)
				wants_param = 1;
			else if (cls == 3 && what == '+')
				wants_param = 1;

			if (wants_param && param_idx < n_params)
				param = params[param_idx++];

			if (param)
				snprintf(buf, sizeof(buf), "%c%s=%s",
				         what, cm->name, param);
			else
				snprintf(buf, sizeof(buf), "%c%s",
				         what, cm->name);
		} else if (*p == 'b' || *p == 'e' || *p == 'I')
		{
			/* Hardcoded list-mode bridge. Always one param. */
			const char *name = (*p == 'b')   ? "ban"
			                   : (*p == 'e') ? "banex"
			                                 : "invex";
			if (param_idx < n_params)
				param = params[param_idx++];
			else
				continue;
			snprintf(buf, sizeof(buf), "%c%s=%s",
			         what, name, param);
		} else
		{
			/* Unknown letter -- skip silently rather than
			 * desync the parameter index. */
			continue;
		}

		buflen = strlen(buf);
		if (plen + buflen + 2 >= sizeof(propbuf))
		{
			/* Flush. */
			sendto_channel(channel, client, NULL, 0,
			               CAP_NAMED_MODES, SEND_LOCAL, mtags,
			               ":%s PROP %s %s",
			               client->name, channel->name, propbuf);
			propbuf[0] = '\0';
			plen = 0;
		}
		if (plen)
			propbuf[plen++] = ' ';
		strlcpy(propbuf + plen, buf, sizeof(propbuf) - plen);
		plen += buflen;
		wrote_any = 1;
	}

	if (wrote_any && plen)
	{
		sendto_channel(channel, client, NULL, 0,
		               CAP_NAMED_MODES, SEND_LOCAL, mtags,
		               ":%s PROP %s %s",
		               client->name, channel->name, propbuf);
	}
	return 0;
}

/* ===================================================================
 * cmd_prop
 *
 * Forms:
 *   PROP <target>                       -- list non-list modes (961/960)
 *   PROP <target> <listmode>            -- list one list mode (963/962)
 *   PROP <target> {+|-}<name>[=<param>] -- apply changes (translated
 *                                          to MODE for the underlying
 *                                          machinery)
 * =================================================================== */
CMD_FUNC(cmd_prop)
{
	Channel *channel;
	const char *target;
	int i;

	if (parc < 2 || BadPtr(parv[1]))
	{
		sendnumeric(client, ERR_NEEDMOREPARAMS, "PROP");
		return;
	}
	target = parv[1];
	channel = find_channel(target);
	if (!channel)
	{
		sendnumeric(client, ERR_NOSUCHCHANNEL, target);
		return;
	}

	/* PROP <chan> -- list current mode state. */
	if (parc < 3)
	{
		char buf[BUFSIZE];
		size_t plen = 0;
		Cmode *cm;
		buf[0] = '\0';
		for (cm = channelmodes; cm; cm = cm->next)
		{
			int cls = prop_classify_chanmode(cm);
			char item[256];
			size_t ilen;
			const char *param = NULL;

			if (!cls || cls == 1 || cls == 5 || !cm->name)
				continue;
			if (!(channel->mode.mode & cm->mode))
				continue;
			if (cm->paracount && cm->letter && cm->get_param)
				param = cm->get_param(GETPARASTRUCT(channel, cm->letter));

			if (cls == 4 || !param)
				snprintf(item, sizeof(item), "%s", cm->name);
			else
				snprintf(item, sizeof(item), "%s=%s",
				         cm->name, param);
			ilen = strlen(item);
			if (plen + ilen + 2 >= sizeof(buf))
			{
				sendto_one(client, NULL, ":%s %d %s %s :%s",
				           me.name, RPL_PROPLIST, client->name,
				           channel->name, buf);
				buf[0] = '\0';
				plen = 0;
			}
			if (plen)
				buf[plen++] = ' ';
			strlcpy(buf + plen, item, sizeof(buf) - plen);
			plen += ilen;
		}
		if (plen)
			sendto_one(client, NULL, ":%s %d %s %s :%s",
			           me.name, RPL_PROPLIST, client->name,
			           channel->name, buf);
		sendto_one(client, NULL, ":%s %d %s %s :End of mode list",
		           me.name, RPL_ENDOFPROPLIST, client->name,
		           channel->name);
		return;
	}

	/* PROP <chan> <listmode> -- enumerate the entries of a list-mode.
	 * Table-driven so future vendored list-modes can extend by adding
	 * an entry here (no parser changes needed). */
	if (parv[2][0] != '+' && parv[2][0] != '-')
	{
		static const struct {
			const char *name;
			size_t list_offset;   /* offsetof(Channel, banlist) etc. */
		} listmodes[] = {
		    {"ban", offsetof(Channel, banlist)},
		    {"banex", offsetof(Channel, exlist)},
		    {"invex", offsetof(Channel, invexlist)},
		        /* Future: vendored list-modes register here, e.g.
			 *   { "obsidianirc/timedban", offsetof(...) }, */
		    {NULL, 0}};
		const char *name = parv[2];
		const char *resolved = NULL;
		Ban *b, *list_head = NULL;
		int i;

		if (*name == ':')
			name++;

		/* Accept the unqualified form if the request matches one of
		 * our vendored list-mode names with the prefix stripped. */
		for (i = 0; listmodes[i].name; i++)
		{
			if (!strcmp(name, listmodes[i].name))
			{
				resolved = listmodes[i].name;
				list_head = *(Ban **)((char *)channel +
				                      listmodes[i].list_offset);
				break;
			}
		}
		if (!resolved)
		{
			const char *unq = strip_vendor(name);
			if (unq && unq != name)
			{
				for (i = 0; listmodes[i].name; i++)
				{
					if (!strcmp(unq, listmodes[i].name))
					{
						resolved = listmodes[i].name;
						list_head = *(Ban **)((char *)channel +
						                      listmodes[i].list_offset);
						break;
					}
				}
			}
		}
		if (!resolved)
		{
			sendnumeric(client, ERR_UNKNOWNMODE, *name);
			return;
		}
		for (b = list_head; b; b = b->next)
		{
			sendto_one(client, NULL,
			           ":%s %d %s %s %s %s %s :%lld",
			           me.name, RPL_LISTPROPLIST,
			           client->name, channel->name, resolved,
			           b->banstr,
			           b->who ? b->who : me.name,
			           (long long)b->when);
		}
		sendto_one(client, NULL, ":%s %d %s %s %s :End of list",
		           me.name, RPL_ENDOFLISTPROPLIST,
		           client->name, channel->name, resolved);
		return;
	}

	/* Apply path: translate +foo=bar to a MODE call. v1 limit: one
	 * MODE invocation per PROP (mode.c reassembles internally). */
	{
		char modebuf[64] = "";
		char parabuf[BUFSIZE] = "";
		char what = '+';
		const char *mode_argv[8];
		int mode_argc = 0;
		size_t modelen = 0, paralen = 0;

		mode_argv[mode_argc++] = "MODE";
		mode_argv[mode_argc++] = channel->name;

		for (i = 2; i < parc && parv[i] && mode_argc < 7; i++)
		{
			const char *item = parv[i];
			char sign = '+';
			char namebuf[64];
			const char *eq;
			Cmode *cm;
			const char *unq;

			if (*item == '+' || *item == '-')
			{
				sign = *item;
				item++;
			}
			eq = strchr(item, '=');
			if (eq)
			{
				size_t nlen = (size_t)(eq - item);
				if (nlen >= sizeof(namebuf))
					nlen = sizeof(namebuf) - 1;
				memcpy(namebuf, item, nlen);
				namebuf[nlen] = '\0';
			} else
			{
				strlcpy(namebuf, item, sizeof(namebuf));
			}

			cm = find_channel_mode_handler_by_name(namebuf);
			if (!cm)
			{
				/* Try stripping our vendor prefix. */
				unq = strip_vendor(namebuf);
				if (unq && unq != namebuf)
					cm = find_channel_mode_handler_by_name(unq);
			}
			/* Fallback: hardcoded list-mode names. */
			if (!cm)
			{
				char letter = 0;
				if (!strcmp(namebuf, "ban"))
					letter = 'b';
				else if (!strcmp(namebuf, "banex"))
					letter = 'e';
				else if (!strcmp(namebuf, "invex"))
					letter = 'I';
				if (letter)
				{
					if (sign != what)
					{
						modebuf[modelen++] = sign;
						what = sign;
					}
					if (modelen < sizeof(modebuf) - 2)
						modebuf[modelen++] = letter;
					if (eq && eq[1])
					{
						if (paralen)
							parabuf[paralen++] = ' ';
						strlcpy(parabuf + paralen, eq + 1,
						        sizeof(parabuf) - paralen);
						paralen += strlen(eq + 1);
					}
					continue;
				}
				sendnumeric(client, ERR_UNKNOWNMODE,
				            *namebuf ? *namebuf : '?');
				continue;
			}
			if (!cm->letter)
			{
				/* Name-only mode (no legacy letter). The
				 * cmd_mode dispatcher is letter-keyed so we
				 * can't route through it; instead apply the
				 * change directly here. Only flag (type 4)
				 * modes are handled this way -- list/param
				 * modes still need a letter or a richer
				 * non-letter executor (TODO if/when we
				 * register name-only param modes). */
				int cls = prop_classify_chanmode(cm);
				int mode_change_what =
				    (sign == '+') ? MODE_ADD : MODE_DEL;
				if (cls != 4 || cm->type != CMODE_NORMAL)
				{
					sendnumeric(client, ERR_UNKNOWNMODE, '?');
					continue;
				}
				if (cm->is_ok)
				{
					int access = cm->is_ok(client, channel, 0,
					                       NULL, EXCHK_ACCESS_ERR,
					                       mode_change_what);
					if (access != EX_ALLOW)
						continue;
				}
				/* No-op? */
				if (mode_change_what == MODE_ADD &&
				    (channel->mode.mode & cm->mode))
					continue;
				if (mode_change_what == MODE_DEL &&
				    !(channel->mode.mode & cm->mode))
					continue;
				if (mode_change_what == MODE_ADD)
					channel->mode.mode |= cm->mode;
				else
					channel->mode.mode &= ~cm->mode;
				/* Echo PROP back to all cap-holders directly
				 * (no MODE-letter equivalent exists). */
				{
					MessageTag *mt = NULL;
					new_message(client, recv_mtags, &mt);
					sendto_channel(channel, client, NULL, 0,
					               CAP_NAMED_MODES, SEND_LOCAL,
					               mt,
					               ":%s PROP %s %c%s",
					               client->name, channel->name,
					               sign, cm->name);
					free_message_tags(mt);
				}
				continue;
			}
			if (sign != what)
			{
				if (modelen < sizeof(modebuf) - 2)
					modebuf[modelen++] = sign;
				what = sign;
			}
			if (modelen < sizeof(modebuf) - 2)
				modebuf[modelen++] = cm->letter;
			if (eq && eq[1])
			{
				if (paralen)
					parabuf[paralen++] = ' ';
				strlcpy(parabuf + paralen, eq + 1,
				        sizeof(parabuf) - paralen);
				paralen += strlen(eq + 1);
			}
		}
		modebuf[modelen] = '\0';
		parabuf[paralen] = '\0';

		if (modelen)
		{
			const char *fake_argv[5];
			int fake_argc = 0;
			fake_argv[fake_argc++] = "MODE";
			fake_argv[fake_argc++] = channel->name;
			fake_argv[fake_argc++] = modebuf;
			if (paralen)
				fake_argv[fake_argc++] = parabuf;
			fake_argv[fake_argc] = NULL;
			do_mode(channel, client, recv_mtags,
			        fake_argc - 1, fake_argv + 1, 0, 0);
		}
	}
}
