/*
 *   Unreal Internet Relay Chat Daemon, src/modules/whois.c
 *   (C) 2000-2001 Carsten V. Munk and the UnrealIRCd Team
 *   (C) 2003-2021 Bram Matthys and the UnrealIRCd team
 *   Moved to modules by Fish (Justin Hammond) in 2001
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

#include "unrealircd.h"

/* Structs */
ModuleHeader MOD_HEADER = {
    "whois", /* Name of module */
    "5.0", /* Version */
    "command /whois", /* Short description of module */
    "UnrealIRCd Team",
    "unrealircd-6",
};

typedef enum WhoisConfigUser {
	WHOIS_CONFIG_USER_EVERYONE = 1,
	WHOIS_CONFIG_USER_SELF = 2,
	WHOIS_CONFIG_USER_OPER = 3,
} WhoisConfigUser;
#define HIGHEST_WHOIS_CONFIG_USER_VALUE 3 /* adjust this if you edit the enum above !! */

//this one is in include/struct.h because it needs full API exposure:
//typedef enum WhoisConfigDetails {
//	...
//} WhoisConfigDetails;
//

typedef struct WhoisConfig WhoisConfig;
struct WhoisConfig {
	WhoisConfig *prev, *next;
	char *name;
	WhoisConfigDetails permissions[HIGHEST_WHOIS_CONFIG_USER_VALUE + 1];
};

/* Global variables */
WhoisConfig *whoisconfig = NULL;
static long CAP_OBBY_WHOIS = 0L;

/* Forward declarations */
WhoisConfigDetails _whois_get_policy(Client *client, Client *target, const char *name);
CMD_FUNC(cmd_whois);
static int whois_config_test(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
static int whois_config_run(ConfigFile *cf, ConfigEntry *ce, int type);
static void whois_config_setdefaults(void);

MOD_TEST()
{
	MARK_AS_OFFICIAL_MODULE(modinfo);
	EfunctionAdd(modinfo->handle, EFUNC_WHOIS_GET_POLICY, TO_INTFUNC(_whois_get_policy));
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, whois_config_test);
	return MOD_SUCCESS;
}

MOD_INIT()
{
	ClientCapabilityInfo cap;
	ClientCapability *cap_handle;
	MessageTagHandlerInfo mtag;

	MARK_AS_OFFICIAL_MODULE(modinfo);
	CommandAdd(modinfo->handle, "WHOIS", cmd_whois, MAXPARA, CMD_USER);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, whois_config_run);
	whois_config_setdefaults();

	/* Vendor cap opt-in for obby.world/whois + obby.world/whois-session
	 * batch types.  Without this cap, clients that have only negotiated
	 * the base `batch` cap continue to get legacy unwrapped numerics --
	 * we do NOT emit a vendor batch type they didn't ask for, even
	 * though IRCv3 BATCH requires consumers to tolerate unknown types.
	 * The sub-batch path emits multiple 378/379/671 per WHOIS, which
	 * strict RFC 2812 parsers would discard; gating on this cap makes
	 * the contract explicit.  See doc/specs/whois-batch.md. */
	memset(&cap, 0, sizeof(cap));
	cap.name = "obby.world/whois";
	cap_handle = ClientCapabilityAdd(modinfo->handle, &cap, &CAP_OBBY_WHOIS);

	/* Vendor message tag carrying each session's connect time
	 * (ISO 8601, UTC).  Rides on the obby.world/whois-session
	 * BATCH+ line so clients can render "joined N minutes ago"
	 * without consuming a numeric.  Delivery is gated on the
	 * obby.world/whois cap. */
	memset(&mtag, 0, sizeof(mtag));
	mtag.name = "obby.world/since";
	mtag.clicap_handler = cap_handle;
	MessageTagHandlerAdd(modinfo->handle, &mtag);

	return MOD_SUCCESS;
}

MOD_LOAD()
{
	return MOD_SUCCESS;
}

void free_config(void)
{
	WhoisConfig *w, *w_next;
	for (w = whoisconfig; w; w = w_next)
	{
		w_next = w->next;
		safe_free(w->name);
		safe_free(w);
	}
}

MOD_UNLOAD()
{
	free_config();
	return MOD_SUCCESS;
}

static WhoisConfig *find_whois_config(const char *name)
{
	WhoisConfig *w;
	for (w = whoisconfig; w; w = w->next)
		if (!strcmp(w->name, name))
			return w;
	return NULL;
}

/* Lazy helper for whois_config_setdefaults */
static void whois_config_add(const char *name, WhoisConfigUser user, WhoisConfigDetails details)
{
	WhoisConfig *w = find_whois_config(name);

	if (!w)
	{
		/* New one */
		w = safe_alloc(sizeof(WhoisConfig));
		safe_strdup(w->name, name);
		AddListItem(w, whoisconfig);
	}
	w->permissions[user] = details;
}

static void whois_config_setdefaults(void)
{
	whois_config_add("basic", WHOIS_CONFIG_USER_EVERYONE, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("modes", WHOIS_CONFIG_USER_SELF, WHOIS_CONFIG_DETAILS_FULL);
	whois_config_add("modes", WHOIS_CONFIG_USER_OPER, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("realhost", WHOIS_CONFIG_USER_SELF, WHOIS_CONFIG_DETAILS_FULL);
	whois_config_add("realhost", WHOIS_CONFIG_USER_OPER, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("registered-nick", WHOIS_CONFIG_USER_EVERYONE, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("channels", WHOIS_CONFIG_USER_EVERYONE, WHOIS_CONFIG_DETAILS_LIMITED);
	whois_config_add("channels", WHOIS_CONFIG_USER_SELF, WHOIS_CONFIG_DETAILS_FULL);
	whois_config_add("channels", WHOIS_CONFIG_USER_OPER, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("server", WHOIS_CONFIG_USER_EVERYONE, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("away", WHOIS_CONFIG_USER_EVERYONE, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("oper", WHOIS_CONFIG_USER_EVERYONE, WHOIS_CONFIG_DETAILS_LIMITED);
	whois_config_add("oper", WHOIS_CONFIG_USER_SELF, WHOIS_CONFIG_DETAILS_FULL);
	whois_config_add("oper", WHOIS_CONFIG_USER_OPER, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("secure", WHOIS_CONFIG_USER_EVERYONE, WHOIS_CONFIG_DETAILS_LIMITED);
	whois_config_add("secure", WHOIS_CONFIG_USER_SELF, WHOIS_CONFIG_DETAILS_FULL);
	whois_config_add("secure", WHOIS_CONFIG_USER_OPER, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("bot", WHOIS_CONFIG_USER_EVERYONE, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("services", WHOIS_CONFIG_USER_EVERYONE, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("reputation", WHOIS_CONFIG_USER_OPER, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("security-groups", WHOIS_CONFIG_USER_OPER, WHOIS_CONFIG_DETAILS_FULL);

	/* "Referred by <inviter>" line emitted by the invitation module
	 * via HOOKTYPE_WHOIS.  Default: self + oper see it, everyone
	 * else doesn't.  Leaks social-graph info if broadcast publicly,
	 * but the user themselves should know who vouched for them and
	 * opers want it for moderation context. */
	whois_config_add("referral", WHOIS_CONFIG_USER_SELF, WHOIS_CONFIG_DETAILS_FULL);
	whois_config_add("referral", WHOIS_CONFIG_USER_OPER, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("geo", WHOIS_CONFIG_USER_OPER, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("asn", WHOIS_CONFIG_USER_OPER, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("certfp", WHOIS_CONFIG_USER_EVERYONE, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("shunned", WHOIS_CONFIG_USER_OPER, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("account", WHOIS_CONFIG_USER_EVERYONE, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("swhois", WHOIS_CONFIG_USER_EVERYONE, WHOIS_CONFIG_DETAILS_FULL);

	whois_config_add("idle", WHOIS_CONFIG_USER_EVERYONE, WHOIS_CONFIG_DETAILS_LIMITED);
	whois_config_add("idle", WHOIS_CONFIG_USER_SELF, WHOIS_CONFIG_DETAILS_FULL);
	whois_config_add("idle", WHOIS_CONFIG_USER_OPER, WHOIS_CONFIG_DETAILS_FULL);
}

static void whois_free_config(void)
{
}

static WhoisConfigUser whois_config_user_strtovalue(const char *str)
{
	if (!strcmp(str, "everyone"))
		return WHOIS_CONFIG_USER_EVERYONE;
	if (!strcmp(str, "self"))
		return WHOIS_CONFIG_USER_SELF;
	if (!strcmp(str, "oper"))
		return WHOIS_CONFIG_USER_OPER;
	return 0;
}

static WhoisConfigDetails whois_config_details_strtovalue(const char *str)
{
	if (!strcmp(str, "full"))
		return WHOIS_CONFIG_DETAILS_FULL;
	if (!strcmp(str, "limited"))
		return WHOIS_CONFIG_DETAILS_LIMITED;
	if (!strcmp(str, "none"))
		return WHOIS_CONFIG_DETAILS_NONE;
	return 0;
}

static int whois_config_test(ConfigFile *cf, ConfigEntry *ce, int type, int *errs)
{
	int errors = 0;
	ConfigEntry *cep, *cepp;

	if (type != CONFIG_SET)
		return 0;

	/* We are only interrested in set::whois-details.. */
	if (!ce || strcmp(ce->name, "whois-details"))
		return 0;

	for (cep = ce->items; cep; cep = cep->next)
	{
		if (cep->value)
		{
			config_error("%s:%i: set::whois-details::%s item has a value, which is unexpected. Check your syntax!",
			             cep->file->filename, cep->line_number, cep->name);
			errors++;
			continue;
		}
		for (cepp = cep->items; cepp; cepp = cepp->next)
		{
			if (!whois_config_user_strtovalue(cepp->name))
			{
				config_error("%s:%i: set::whois-details::%s contains unknown user category called '%s', must be one of: everyone, self, ircop",
				             cepp->file->filename, cepp->line_number, cep->name, cepp->name);
				errors++;
				continue;
			} else if (!cepp->value || !whois_config_details_strtovalue(cepp->value))
			{
				config_error("%s:%i: set::whois-details::%s contains unknown details type '%s', must be one of: full, limited, none",
				             cepp->file->filename, cepp->line_number, cep->name, cepp->name);
				errors++;
				continue;
			} /* else it is good */
		}
	}

	*errs = errors;
	return errors ? -1 : 1;
}

static int whois_config_run(ConfigFile *cf, ConfigEntry *ce, int type)
{
	ConfigEntry *cep, *cepp;

	if (type != CONFIG_SET)
		return 0;

	/* We are only interrested in set::whois-details.. */
	if (!ce || strcmp(ce->name, "whois-details"))
		return 0;

	for (cep = ce->items; cep; cep = cep->next)
	{
		WhoisConfig *w = find_whois_config(cep->name);
		if (!w)
		{
			/* New one */
			w = safe_alloc(sizeof(WhoisConfig));
			safe_strdup(w->name, cep->name);
			AddListItem(w, whoisconfig);
		}
		for (cepp = cep->items; cepp; cepp = cepp->next)
		{
			WhoisConfigUser user = whois_config_user_strtovalue(cepp->name);
			WhoisConfigDetails details = whois_config_details_strtovalue(cepp->value);
			w->permissions[user] = details;
		}
	}
	return 1;
}

/** Get set::whois-details policy for an item.
 * @param client		The client doing the /WHOIS
 * @param target		The client being whoised, so the one to show all details for
 * @param name			The name of the whois item (eg "modes")
 */
WhoisConfigDetails _whois_get_policy(Client *client, Client *target, const char *name)
{
	WhoisConfig *w = find_whois_config(name);
	if (!w)
		return WHOIS_CONFIG_DETAILS_DEFAULT;
	if ((client == target) && (w->permissions[WHOIS_CONFIG_USER_SELF] > 0))
		return w->permissions[WHOIS_CONFIG_USER_SELF];
	if (IsOper(client) && (w->permissions[WHOIS_CONFIG_USER_OPER] > 0))
		return w->permissions[WHOIS_CONFIG_USER_OPER];
	if (w->permissions[WHOIS_CONFIG_USER_EVERYONE] > 0)
		return w->permissions[WHOIS_CONFIG_USER_EVERYONE];
	return WHOIS_CONFIG_DETAILS_NONE;
}

/* Per-session WHOIS detail keys. Entries in the nvplist with these
 * names describe a SINGLE connection (its host/IP, TLS state, client
 * cert, geo, ASN, idle clock). When the queried account has multiple
 * live sessions and the querier is allowed to see connection-level
 * detail, we suppress these from the parent batch and re-emit them
 * once per session inside an obby.world/whois-session sub-batch.
 *
 * `modes` (RPL_WHOISMODES 379) is intentionally NOT per-session
 * anymore: the persistence module mirrors canonical's umodes and
 * snomask onto every attached session via HOOKTYPE_UMODE_CHANGE, so
 * all sessions share the same flags by construction. Emitting it
 * once in the parent batch keeps the wire compact and reflects the
 * account-level semantics.  See doc/specs/whois-batch.md. */
static int whois_is_per_session_name(const char *name)
{
	static const char *names[] = {"realhost", "secure", "certfp", "geo", "asn", "idle", NULL};
	int i;
	if (!name)
		return 0;
	for (i = 0; names[i]; i++)
		if (!strcmp(name, names[i]))
			return 1;
	return 0;
}

/* Collect local clients sharing the target's account_canonical (the
 * target's own canonical is included).  Returns total count even if
 * it exceeds 'max' (caller's storage is bounded).  No-op when the
 * persistence module isn't loaded -- the moddata won't exist. */
static int whois_collect_session_clients(Client *target, Client **out, int max)
{
	ModDataInfo *canon_md = findmoddata_byname("account_canonical", MODDATATYPE_CLIENT);
	Client *target_canon, *c;
	int n = 0;

	if (!canon_md)
		return 0;
	target_canon = moddata_client(target, canon_md).ptr;
	if (!target_canon)
		return 0;
	list_for_each_entry(c, &lclient_list, lclient_node)
	{
		if (!IsUser(c))
			continue;
		if (moddata_client(c, canon_md).ptr != target_canon)
			continue;
		if (n < max)
			out[n] = c;
		n++;
	}
	return n;
}

static MessageTag *whois_batch_mtag(const char *batchid)
{
	MessageTag *m = safe_alloc(sizeof(MessageTag));
	safe_strdup(m->name, "batch");
	safe_strdup(m->value, batchid);
	return m;
}

/* Emit per-session WHOIS numerics for one connected session under the
 * queried account.  Each line is tagged @batch=batchid so it lands
 * inside the obby.world/whois-session sub-batch. */
static void whois_emit_session_lines(Client *client, Client *target, Client *sess,
                                     const char *batchid)
{
	MessageTag *mt = whois_batch_mtag(batchid);
	const char *fp;

	sendto_one(client, mt,
	           ":%s %d %s %s :is connecting from %s@%s %s",
	           me.name, RPL_WHOISHOST, client->name, target->name,
	           strcmp(sess->ident, "unknown") ? sess->ident : "*",
	           sess->user ? sess->user->realhost : "",
	           sess->ip ? sess->ip : "");

	/* RPL_WHOISMODES (379) is emitted once in the parent batch by
	 * the unmodified nvplist path; not duplicated here.  Umodes are
	 * synced canonical->sessions via HOOKTYPE_UMODE_CHANGE in
	 * persistence.c, so every session has the same flags. */

	if (sess->umodes & UMODE_SECURE)
	{
		const char *cipher = tls_get_cipher(sess);
		if (cipher)
			sendto_one(client, mt,
			           ":%s %d %s %s :is using a Secure Connection [%s]",
			           me.name, RPL_WHOISSECURE, client->name, target->name, cipher);
		else
			sendto_one(client, mt,
			           ":%s %d %s %s :is using a Secure Connection",
			           me.name, RPL_WHOISSECURE, client->name, target->name);
	}

	fp = moddata_client_get(sess, "certfp");
	if (fp)
		sendto_one(client, mt,
		           ":%s %d %s %s :has client certificate fingerprint %s",
		           me.name, RPL_WHOISCERTFP, client->name, target->name, fp);

	/* Per-session idle clock + signon. Each session has its own
	 * local->idle_since (last activity) and local->creationtime
	 * (when this TCP connection registered). The canonical's
	 * idle in the parent batch is suppressed via the per-session
	 * detail filter; this is the only 317 emitted for this query
	 * when sub-batches are in use. */
	if (sess->local)
	{
		sendto_one(client, mt,
		           ":%s %d %s %s %lld %lld :seconds idle, signon time",
		           me.name, RPL_WHOISIDLE, client->name, target->name,
		           (long long)(TStime() - sess->local->idle_since),
		           (long long)sess->local->creationtime);
	}

	/* Per-session geo / ASN.  Each session connects from one IP,
	 * which may map to a distinct country / ASN from other
	 * sessions of the same account.  Read GeoIP moddata via
	 * findmoddata_byname so whois.c stays decoupled from
	 * geoip_base; if geoip isn't loaded, silently skip. */
	{
		ModDataInfo *geo_md = findmoddata_byname("geoip", MODDATATYPE_CLIENT);
		GeoIPResult *geo = geo_md ? (GeoIPResult *)moddata_client(sess, geo_md).ptr : NULL;
		if (geo)
		{
			if (geo->country_code)
				sendto_one(client, mt,
				           ":%s %d %s %s %s :is connecting from %s",
				           me.name, RPL_WHOISCOUNTRY, client->name, target->name,
				           geo->country_code,
				           geo->country_name ? geo->country_name : "");
			if (geo->asn)
				sendto_one(client, mt,
				           ":%s %d %s %s %u :is connecting from AS%u [%s]",
				           me.name, RPL_WHOISASN, client->name, target->name,
				           geo->asn, geo->asn,
				           geo->asname ? geo->asname : "UNKNOWN");
		}
	}

	free_message_tags(mt);
}

/* WHOIS command.
 * parv[1] = list of nicks (comma separated)
 */
CMD_FUNC(cmd_whois)
{
	Membership *lp;
	Client *target;
	Channel *channel;
	char *nick, *tmp;
	char *p = NULL;
	int len, mlen;
	char querybuf[BUFSIZE];
	char buf[BUFSIZE];
	int ntargets = 0;
	int maxtargets = max_targets_for_command("WHOIS");

	if (parc < 2)
	{
		sendnumeric(client, ERR_NONICKNAMEGIVEN);
		return;
	}

	if (parc > 2)
	{
		if (hunt_server(client, recv_mtags, "WHOIS", 1, parc, parv) != HUNTED_ISME)
			return;
		parv[1] = parv[2];
	}

	strlcpy(querybuf, parv[1], sizeof(querybuf));

	for (tmp = canonize(parv[1]); (nick = strtoken(&p, tmp, ",")); tmp = NULL)
	{
		unsigned char showchannel, wilds, hideoper; /* <- these are all boolean-alike */
		NameValuePrioList *list = NULL;
		int policy; /* for temporary stuff */
		/* Structured security-groups list for the obby.world/whois-
		 * security-groups sub-batch.  Populated alongside the legacy
		 * nvplist entries when the querier has the obby.world/whois
		 * cap; emitted as a separate sub-batch inside the parent
		 * obby.world/whois batch (one line per group, machine-
		 * readable).  Non-cap clients keep getting the legacy
		 * comma-separated single-line 320. */
		struct sg_node {
			char name[64];
			struct sg_node *next;
		} *sg_head = NULL, *sg_tail = NULL;
		int sg_count = 0;
		int want_sg_batch = MyUser(client) &&
		                    HasCapability(client, "obby.world/whois") &&
		                    HasCapability(client, "batch");

		if (MyUser(client) && (++ntargets > maxtargets))
		{
			sendnumeric(client, ERR_TOOMANYTARGETS, nick, maxtargets, "WHOIS");
			break;
		}

		/* We do not support "WHOIS *" */
		wilds = (strchr(nick, '?') || strchr(nick, '*'));
		if (wilds)
			continue;

		target = find_user(nick, NULL);
		if (!target)
		{
			sendnumeric(client, ERR_NOSUCHNICK, nick);
			continue;
		}

		/* Ok, from this point we are going to proceed with the WHOIS.
		 * The idea here is NOT to send any lines, so don't call sendto functions.
		 * Instead, use add_nvplist_numeric() and add_nvplist_numeric_fmt()
		 * to add items to the whois list.
		 * Then at the end of this loop we call modules who can also add/remove
		 * whois lines, and only after that we FINALLY send all the whois lines
		 * in one go.
		 */

		hideoper = 0;
		if (IsHideOper(target) && (target != client) && !IsOper(client))
			hideoper = 1;

		if (whois_get_policy(client, target, "basic") > WHOIS_CONFIG_DETAILS_NONE)
		{
			add_nvplist_numeric(&list, -1000000, "basic", client, RPL_WHOISUSER, target->name,
			                    target->user->username,
			                    IsHidden(target) ? target->user->virthost : target->user->realhost,
			                    target->info);
		}

		if (whois_get_policy(client, target, "modes") > WHOIS_CONFIG_DETAILS_NONE)
		{
			add_nvplist_numeric(&list, -100000, "modes", client, RPL_WHOISMODES, target->name,
			                    get_usermode_string(target), target->user->snomask ? target->user->snomask : "");
		}
		if (whois_get_policy(client, target, "realhost") > WHOIS_CONFIG_DETAILS_NONE)
		{
			add_nvplist_numeric(&list, -90000, "realhost", client, RPL_WHOISHOST, target->name,
			                    (MyConnect(target) && strcmp(target->ident, "unknown")) ? target->ident : "*",
			                    target->user->realhost, target->ip ? target->ip : "");
		}

		if (IsRegNick(target) && (whois_get_policy(client, target, "registered-nick") > WHOIS_CONFIG_DETAILS_NONE))
		{
			add_nvplist_numeric(&list, -80000, "registered-nick", client, RPL_WHOISREGNICK, target->name);
		}

		/* The following code deals with channels */
		policy = whois_get_policy(client, target, "channels");
		if (policy > WHOIS_CONFIG_DETAILS_NONE)
		{
			int channel_whois_lines = 0;
			mlen = strlen(me.name) + strlen(client->name) + 10 + strlen(target->name);
			for (len = 0, *buf = '\0', lp = target->user->channel; lp; lp = lp->next)
			{
				Hook *h;
				int ret = EX_ALLOW;
				int operoverride = 0;

				channel = lp->channel;
				showchannel = 0;

				if (ShowChannel(client, channel))
					showchannel = 1;

				for (h = Hooks[HOOKTYPE_SEE_CHANNEL_IN_WHOIS]; h; h = h->next)
				{
					int n = (*(h->func.intfunc))(client, target, channel);
					/* Hook return values:
					 * EX_ALLOW means 'yes is ok, as far as modules are concerned'
					 * EX_DENY means 'hide this channel, unless oper overriding'
					 * EX_ALWAYS_DENY means 'hide this channel, always'
					 * ... with the exception that we always show the channel if you /WHOIS yourself
					 */
					if (n == EX_DENY)
					{
						ret = EX_DENY;
					} else if (n == EX_ALWAYS_DENY)
					{
						ret = EX_ALWAYS_DENY;
						break;
					}
				}

				if (ret == EX_DENY)
					showchannel = 0;

				/* If the channel is normally hidden, but the user is an IRCOp,
				 * and has the channel:see:whois privilege,
				 * and set::whois-details for 'channels' has 'oper full',
				 * then show it:
				 */
				if (!showchannel && (ValidatePermissionsForPath("channel:see:whois", client, NULL, channel, NULL)) && (policy == WHOIS_CONFIG_DETAILS_FULL))
				{
					showchannel = 1; /* OperOverride */
					operoverride = 1;
				}

				if ((ret == EX_ALWAYS_DENY) && (target != client))
					continue; /* a module asked us to really not expose this channel, so we don't (except target==ourselves). */

				/* This deals with target==client but also for unusual set::whois-details overrides
				 * such as 'everyone full'
				 */
				if (policy == WHOIS_CONFIG_DETAILS_FULL)
					showchannel = 1;

				if (showchannel)
				{
					if (len + strlen(channel->name) > (size_t)BUFSIZE - 4 - mlen)
					{
						add_nvplist_numeric_fmt(&list, -70500 - channel_whois_lines, "channels", client, RPL_WHOISCHANNELS,
						                        "%s :%s", target->name, buf);
						channel_whois_lines++;
						*buf = '\0';
						len = 0;
					}

					if (operoverride)
					{
						/* '?' and '!' both mean we can see the channel in /WHOIS and normally wouldn't,
						 * but there's still a slight difference between the two...
						 */
						if (!PubChannel(channel))
						{
							/* '?' means it's a secret/private channel (too) */
							*(buf + len++) = '?';
						} else
						{
							/* public channel but hidden in WHOIS (umode +p, service bot, etc) */
							*(buf + len++) = '!';
						}
					}

					if (!MyUser(client) || !HasCapability(client, "multi-prefix"))
					{
						/* Standard NAMES reply (single character) */
						char c = mode_to_prefix(*lp->member_modes);
						if (c)
							*(buf + len++) = c;
					} else
					{
						/* NAMES reply with all rights included (multi-prefix / NAMESX) */
						strcpy(buf + len, modes_to_prefix(lp->member_modes));
						len += strlen(buf + len);
					}
					if (len)
						*(buf + len) = '\0';
					strcpy(buf + len, channel->name);
					len += strlen(channel->name);
					strcat(buf + len, " ");
					len++;
				}
			}

			if (buf[0] != '\0')
			{
				add_nvplist_numeric_fmt(&list, -70500 - channel_whois_lines, "channels", client, RPL_WHOISCHANNELS,
				                        "%s :%s", target->name, buf);
				channel_whois_lines++;
			}
		}

		if (!(IsULine(target) && !IsOper(client) && HIDE_ULINES) &&
		    whois_get_policy(client, target, "server") > WHOIS_CONFIG_DETAILS_NONE)
		{
			add_nvplist_numeric(&list, -60000, "server", client, RPL_WHOISSERVER,
			                    target->name, target->user->server, target->uplink->info);
		}

		if (target->user->away && (whois_get_policy(client, target, "away") > WHOIS_CONFIG_DETAILS_NONE))
		{
			add_nvplist_numeric(&list, -50000, "away", client, RPL_AWAY,
			                    target->name, target->user->away);
		}

		if (IsOper(target) && !hideoper)
		{
			policy = whois_get_policy(client, target, "oper");
			if (policy == WHOIS_CONFIG_DETAILS_FULL)
			{
				const char *operlogin = get_operlogin(target);
				const char *operclass = get_operclass(target);

				if (operlogin && operclass)
				{
					add_nvplist_numeric_fmt(&list, -40000, "oper", client, RPL_WHOISOPERATOR,
					                        "%s :is %s (%s) [%s]",
					                        target->name, "an IRC Operator", operlogin, operclass);
				} else if (operlogin)
				{
					add_nvplist_numeric_fmt(&list, -40000, "oper", client, RPL_WHOISOPERATOR,
					                        "%s :is %s (%s)",
					                        target->name, "an IRC Operator", operlogin);
				} else
				{
					add_nvplist_numeric(&list, -40000, "oper", client, RPL_WHOISOPERATOR,
					                    target->name, "an IRC Operator");
				}
			} else if (policy == WHOIS_CONFIG_DETAILS_LIMITED)
			{
				add_nvplist_numeric(&list, -40000, "oper", client, RPL_WHOISOPERATOR,
				                    target->name, "an IRC Operator");
			}
		}

		if (target->umodes & UMODE_SECURE)
		{
			policy = whois_get_policy(client, target, "secure");
			if (policy == WHOIS_CONFIG_DETAILS_LIMITED)
			{
				add_nvplist_numeric(&list, -30000, "secure", client, RPL_WHOISSECURE,
				                    target->name, "is using a Secure Connection");
			} else if (policy == WHOIS_CONFIG_DETAILS_FULL)
			{
				const char *ciphers = tls_get_cipher(target);
				if (ciphers)
				{
					add_nvplist_numeric_fmt(&list, -30000, "secure", client, RPL_WHOISSECURE,
					                        "%s :is using a Secure Connection [%s]",
					                        target->name, ciphers);
				} else
				{
					add_nvplist_numeric(&list, -30000, "secure", client, RPL_WHOISSECURE,
					                    target->name, "is using a Secure Connection");
				}
			}
		}

		/* Collect security-groups the target is in.  Two emission
		 * paths share the same membership computation:
		 *   - Legacy clients (no obby.world/whois cap): one or more
		 *     `:server 320 ... :is in security-groups: a,b,c` lines
		 *     (existing behaviour).
		 *   - obby.world/whois cap clients: a structured
		 *     `obby.world/whois-security-groups` sub-batch with one
		 *     320 line per group (machine-parseable).  The legacy
		 *     nvplist entries are not added in this case so the line
		 *     doesn't appear twice. */
		policy = whois_get_policy(client, target, "security-groups");
		if ((policy > WHOIS_CONFIG_DETAILS_NONE) && !IsULine(target))
		{
			SecurityGroup *s;

			/* "known-users" / "unknown-users" is reported first as a
			 * synthetic group: existing whois output convention.
			 * Evaluated across every session of the account -- if
			 * the account has at least one recognised session
			 * (typically logged-in or matching a known IP) the
			 * whole account is reported as known-users. */
			const char *known_label =
			    user_allowed_by_security_group_account_name(target, "known-users")
			        ? "known-users"
			        : "unknown-users";

			if (want_sg_batch)
			{
				struct sg_node *n = safe_alloc(sizeof(struct sg_node));
				strlcpy(n->name, known_label, sizeof(n->name));
				if (!sg_head)
					sg_head = n;
				else
					sg_tail->next = n;
				sg_tail = n;
				sg_count++;
				for (s = securitygroups; s; s = s->next)
				{
					if (!strcmp(s->name, "known-users"))
						continue;
					if (!user_allowed_by_security_group_account(target, s))
						continue;
					n = safe_alloc(sizeof(struct sg_node));
					strlcpy(n->name, s->name, sizeof(n->name));
					if (!sg_head)
						sg_head = n;
					else
						sg_tail->next = n;
					sg_tail = n;
					sg_count++;
				}
			} else
			{
				int security_groups_whois_lines = 0;

				mlen = strlen(me.name) + strlen(client->name) + 10 +
				       strlen(target->name) + strlen("is in security-groups: ");

				strlcpy(buf, known_label, sizeof(buf));
				strlcat(buf, ",", sizeof(buf));
				len = strlen(buf);

				for (s = securitygroups; s; s = s->next)
				{
					if (len + strlen(s->name) > (size_t)BUFSIZE - 4 - mlen)
					{
						buf[len - 1] = '\0';
						add_nvplist_numeric_fmt(&list, -15000 - security_groups_whois_lines, "security-groups",
						                        target, RPL_WHOISSPECIAL,
						                        "%s :is in security-groups: %s", target->name, buf);
						security_groups_whois_lines++;
						*buf = '\0';
						len = 0;
					}
					if (strcmp(s->name, "known-users") && user_allowed_by_security_group_account(target, s))
					{
						strcpy(buf + len, s->name);
						len += strlen(buf + len);
						strcpy(buf + len, ",");
						len++;
					}
				}

				if (*buf)
				{
					buf[len - 1] = '\0';
					add_nvplist_numeric_fmt(&list, -15000 - security_groups_whois_lines, "security-groups",
					                        client, RPL_WHOISSPECIAL,
					                        "%s :is in security-groups: %s", target->name, buf);
					security_groups_whois_lines++;
				}
			}
		}
		if (MyUser(target) && IsShunned(target) && (whois_get_policy(client, target, "shunned") > WHOIS_CONFIG_DETAILS_NONE))
		{
			add_nvplist_numeric(&list, -20000, "shunned", client, RPL_WHOISSPECIAL,
			                    target->name, "is shunned");
		}

		if (target->user->swhois && (whois_get_policy(client, target, "swhois") > WHOIS_CONFIG_DETAILS_NONE))
		{
			SWhois *s;
			int swhois_lines = 0;

			for (s = target->user->swhois; s; s = s->next)
			{
				if (hideoper && !IsOper(client) && s->setby && !strcmp(s->setby, "oper"))
					continue; /* hide oper-based swhois entries */
				add_nvplist_numeric(&list, 100000 + swhois_lines, "swhois", client, RPL_WHOISSPECIAL,
				                    target->name, s->line);
				swhois_lines++;
			}
		}

		/* TODO: hmm.. this should be a bit more towards the beginning of the whois, no ? */
		if (IsLoggedIn(target) && (whois_get_policy(client, target, "account") > WHOIS_CONFIG_DETAILS_NONE))
		{
			add_nvplist_numeric(&list, 200000, "account", client, RPL_WHOISLOGGEDIN,
			                    target->name, target->user->account);
		}

		if (MyConnect(target))
		{
			policy = whois_get_policy(client, target, "idle");
			/* If the policy is 'full' then show the idle time.
			 * If the policy is 'limited then show the idle time according to the +I rules
			 */
			if ((policy == WHOIS_CONFIG_DETAILS_FULL) ||
			    ((policy == WHOIS_CONFIG_DETAILS_LIMITED) && !hide_idle_time(client, target)))
			{
				add_nvplist_numeric(&list, 500000, "idle", client, RPL_WHOISIDLE,
				                    target->name,
				                    (long long)(TStime() - target->local->idle_since),
				                    (long long)target->local->creationtime);
			}
		}

		RunHook(HOOKTYPE_WHOIS, client, target, &list);

		/* Emission.  Two paths:
		 *   - client has negotiated `batch`: wrap reply in an
		 *     obby.world/whois batch (and obby.world/whois-session
		 *     sub-batches when target has multiple connected sessions
		 *     and the querier is privileged).  RPL_ENDOFWHOIS rides
		 *     inside the parent batch, so the trailing global 318
		 *     emitted after the loop is suppressed.
		 *   - no `batch`: legacy stream of numerics, plus the
		 *     trailing 318 outside the loop. */
		{
			/* Vendor batch types only when the client has opted in
			 * with the obby.world/whois cap (which also requires the
			 * base `batch` cap to be negotiated -- we don't emit
			 * BATCH frames to non-batch clients regardless of the
			 * vendor cap). */
			int use_batch = MyUser(client) &&
			                HasCapability(client, "batch") &&
			                HasCapability(client, "obby.world/whois");
			char parent_batch[BATCHLEN + 1];
			Client *sessions[16];
			int num_sessions = 0;
			int per_session_emit = 0;
			NameValuePrioList *li;

			parent_batch[0] = '\0';
			if (use_batch)
			{
				generate_batch_id(parent_batch);
				sendto_one(client, NULL, ":%s BATCH +%s obby.world/whois %s",
				           me.name, parent_batch, target->name);

				/* Always count sessions when batch is on so we
				 * can emit either per-session sub-batches (for
				 * privileged queriers) or a privacy-preserving
				 * session-count summary (for everyone else). */
				num_sessions = whois_collect_session_clients(target, sessions,
				                                             sizeof(sessions) / sizeof(sessions[0]));
				if (num_sessions >= 2 && (target == client || IsOper(client)))
					per_session_emit = 1;
			}

			for (li = list; li; li = li->next)
			{
				if (per_session_emit && whois_is_per_session_name(li->name))
					continue;
				if (use_batch)
				{
					MessageTag *mt = whois_batch_mtag(parent_batch);
					sendto_one(client, mt, "%s", li->value);
					free_message_tags(mt);
				} else
				{
					sendto_one(client, NULL, "%s", li->value);
				}
			}

			if (per_session_emit)
			{
				int i;
				int total = (num_sessions > (int)(sizeof(sessions) / sizeof(sessions[0])))
				                ? (int)(sizeof(sessions) / sizeof(sessions[0]))
				                : num_sessions;
				for (i = 0; i < total; i++)
				{
					Client *sess = sessions[i];
					char sub_batch[BATCHLEN + 1];
					MessageTag *mt_outer;
					MessageTag *mt_since = NULL;

					generate_batch_id(sub_batch);

					/* Sub-batch open line carries @batch=parent
					 * (to be inside parent batch) AND a vendor
					 * obby.world/since=ISO8601 tag pinning when
					 * this session connected. */
					mt_outer = whois_batch_mtag(parent_batch);
					if (sess->local)
					{
						mt_since = safe_alloc(sizeof(MessageTag));
						safe_strdup(mt_since->name, "obby.world/since");
						safe_strdup(mt_since->value, timestamp_iso8601(sess->local->creationtime));
						AddListItem(mt_since, mt_outer);
					}
					sendto_one(client, mt_outer,
					           ":%s BATCH +%s obby.world/whois-session %d %d",
					           me.name, sub_batch, i + 1, total);
					free_message_tags(mt_outer);

					whois_emit_session_lines(client, target, sess, sub_batch);

					mt_outer = whois_batch_mtag(parent_batch);
					sendto_one(client, mt_outer, ":%s BATCH -%s", me.name, sub_batch);
					free_message_tags(mt_outer);
				}
			} else if (use_batch && num_sessions >= 2)
			{
				/* Querier doesn't get to see per-session detail
				 * (not target, not oper), but the account does
				 * have multiple live sessions.  Give them a
				 * single privacy-preserving line so the client
				 * can render a "multi-session" affordance
				 * without exposing IPs / hosts / TLS.  The line
				 * is a RPL_WHOISSPECIAL (320) so existing
				 * clients render it as ordinary whois text. */
				MessageTag *mt = whois_batch_mtag(parent_batch);
				sendto_one(client, mt,
				           ":%s %d %s %s :is connected from %d sessions",
				           me.name, RPL_WHOISSPECIAL, client->name, target->name,
				           num_sessions);
				free_message_tags(mt);
			}

			/* obby.world/whois-security-groups sub-batch: one 320
			 * line per group as machine-parseable trailing.  Nested
			 * inside the parent obby.world/whois batch via the
			 * @batch tag, same as the session sub-batches.  Only
			 * emitted when use_batch is true; legacy clients got
			 * the comma-separated form earlier as a regular nvplist
			 * entry. */
			if (use_batch && sg_head)
			{
				char sg_batch[BATCHLEN + 1];
				MessageTag *mt_outer;
				MessageTag *mt_inner;
				struct sg_node *n;
				char count_buf[16];

				generate_batch_id(sg_batch);
				snprintf(count_buf, sizeof(count_buf), "%d", sg_count);

				mt_outer = whois_batch_mtag(parent_batch);
				sendto_one(client, mt_outer,
				           ":%s BATCH +%s obby.world/whois-security-groups %s",
				           me.name, sg_batch, count_buf);
				free_message_tags(mt_outer);

				mt_inner = whois_batch_mtag(sg_batch);
				for (n = sg_head; n; n = n->next)
				{
					sendto_one(client, mt_inner,
					           ":%s %d %s %s :%s",
					           me.name, RPL_WHOISSPECIAL, client->name,
					           target->name, n->name);
				}
				free_message_tags(mt_inner);

				mt_outer = whois_batch_mtag(parent_batch);
				sendto_one(client, mt_outer,
				           ":%s BATCH -%s", me.name, sg_batch);
				free_message_tags(mt_outer);
			}

			if (use_batch)
			{
				MessageTag *mt = whois_batch_mtag(parent_batch);
				sendto_one(client, mt,
				           ":%s %d %s %s :End of /WHOIS list.",
				           me.name, RPL_ENDOFWHOIS, client->name, target->name);
				free_message_tags(mt);

				sendto_one(client, NULL, ":%s BATCH -%s", me.name, parent_batch);
			}

			/* Free the structured security-groups list */
			{
				struct sg_node *n, *next;
				for (n = sg_head; n; n = next)
				{
					next = n->next;
					safe_free(n);
				}
			}
		}

		free_nvplist(list);
	}
	/* The trailing global 318 is suppressed only for clients that
	 * actually opted into obby.world/whois -- each parent batch
	 * already contains its own 318.  Clients without the vendor cap
	 * still get the legacy single trailing 318. */
	if (!(MyUser(client) && HasCapability(client, "batch") && HasCapability(client, "obby.world/whois")))
		sendnumeric(client, RPL_ENDOFWHOIS, querybuf);
}
