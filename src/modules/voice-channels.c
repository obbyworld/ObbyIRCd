/* src/modules/voice-channels.c
 *
 * Bridge between obbyworld voice channels (`^`-prefixed) and the
 * hosted-backend's WebRTC SFU + TURN server.
 *
 * Wire shape:
 *
 *   obbyworld client            ObbyIRCd                hosted-backend
 *   ─────────────────             ────────                ──────────────
 *   TAGMSG ^vc                    voice-channels.c        voice.go
 *   @+obsidianirc/rtc=…    ─────► (CAN_SEND_TO_CHANNEL    (Unix-socket
 *                                  hook intercepts        bridge JSON)
 *                                  +obsidianirc/rtc;
 *                                  forwards to bridge,
 *                                  denies broadcast so
 *                                  SDP doesn't leak)
 *
 *   :server.name TAGMSG vc        ◄── bridge frame ───
 *   @+obsidianirc/rtc=…             {"op":"signal",
 *                                    "to":"alice|^vc",
 *                                    "payload":…}
 *
 * The hosted-backend handles all the SFU work; this module just
 * shovels frames between IRC and the Unix-socket bridge.
 *
 *  License: GPLv3-or-later
 *  Copyright (c) 2026 obbyworld Team
 */

#include "unrealircd.h"

#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <jansson.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

ModuleHeader MOD_HEADER = {
    "voice-channels",
    "1.0",
    "Voice/video channels (^prefix) bridged to hosted-backend SFU",
    "obbyworld Team",
    "unrealircd-6",
};

#define VOICE_CHAN_PREFIX  '^'
#define STREAM_CHAN_PREFIX '$'
#define VOICE_RTC_TAG      "+obsidianirc/rtc"
#define VOICE_CAP_NAME     "obsidianirc/voice"
#define VOICE_DEFAULT_SOCK "/tmp/obbyirc-voice.sock"

/* Both prefixes ride the same WebRTC bridge -- the SFU distinguishes
 * streamer vs. viewer roles internally for `$` channels. The IRCd's
 * job here is just to gate JOIN on the cap and shovel signaling. */
static int is_voice_or_stream_channel(const char *name)
{
	return name && (name[0] == VOICE_CHAN_PREFIX ||
	                name[0] == STREAM_CHAN_PREFIX);
}

/* Configurable via env var or set::voice-bridge-socket "<path>"; in obbyircd.conf. */
static char *cfg_bridge_socket = NULL;

/* draft-uberti-behave-turn-rest (coturn use-auth-secret). */
static char **cfg_turn_urls = NULL;
static int cfg_turn_url_count = 0;
static char *cfg_turn_secret = NULL;
static long cfg_turn_ttl = 21600;

/* CAP bit assigned by ClientCapabilityAdd; gates ^channel JOIN. */
static long CAP_OBSIDIANIRC_VOICE = 0L;

static void maybe_rewrite_turn(json_t *payload, const char *to);

/* ===================================================================
 * Bridge connection state
 * =================================================================== */
static int bridge_fd = -1;
static char bridge_inbuf[256 * 1024];
static size_t bridge_inbuf_len = 0;

static void bridge_disconnect(void)
{
	if (bridge_fd >= 0)
	{
		close(bridge_fd);
		bridge_fd = -1;
	}
	bridge_inbuf_len = 0;
}

static int bridge_connect(void)
{
	const char *path = cfg_bridge_socket ? cfg_bridge_socket : VOICE_DEFAULT_SOCK;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, path, sizeof(addr.sun_path));

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		close(fd);
		return -1;
	}
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	bridge_fd = fd;
	bridge_inbuf_len = 0;
	unreal_log(ULOG_INFO, "voice", "BRIDGE_CONNECTED", NULL,
	           "voice-channels: connected to bridge $path",
	           log_data_string("path", path));
	return 0;
}

/* Write a single newline-terminated frame.  Returns 0 on success,
 * -1 on connection failure (caller should reconnect). */
static int bridge_send_frame(json_t *frame)
{
	if (bridge_fd < 0 && bridge_connect() < 0)
		return -1;
	char *encoded = json_dumps(frame, JSON_COMPACT);
	if (!encoded)
		return -1;
	size_t len = strlen(encoded);
	struct iovec iov[2];
	iov[0].iov_base = encoded;
	iov[0].iov_len = len;
	char nl = '\n';
	iov[1].iov_base = &nl;
	iov[1].iov_len = 1;
	ssize_t w = writev(bridge_fd, iov, 2);
	free(encoded);
	if (w < 0)
	{
		bridge_disconnect();
		return -1;
	}
	return 0;
}

/* ===================================================================
 * Send-side: forward client signaling to the bridge.
 *
 * Called from the CAN_SEND_TO_CHANNEL hook when a client TAGMSG with
 * the +obsidianirc/rtc tag lands on a `^channel`.
 * =================================================================== */
static void bridge_forward_signal(Client *client, Channel *channel,
                                  const char *payload_json)
{
	json_error_t je;
	json_t *payload = json_loads(payload_json, 0, &je);
	if (!payload)
	{
		unreal_log(ULOG_DEBUG, "voice", "BAD_PAYLOAD", client,
		           "voice-channels: dropping malformed RTC payload");
		return;
	}
	json_t *frame = json_object();
	json_object_set_new(frame, "op", json_string("signal"));
	json_object_set_new(frame, "from", json_string(client->name));
	json_object_set_new(frame, "channel", json_string(channel->name));
	if (IsLoggedIn(client))
		json_object_set_new(frame, "account",
		                    json_string(client->user->account));
	json_object_set_new(frame, "payload", payload);
	bridge_send_frame(frame);
	json_decref(frame);
}

static void bridge_forward_part(Client *client, const char *channel_name)
{
	json_t *frame = json_object();
	json_object_set_new(frame, "op", json_string("part"));
	json_object_set_new(frame, "from", json_string(client->name));
	json_object_set_new(frame, "channel", json_string(channel_name));
	bridge_send_frame(frame);
	json_decref(frame);
}

static void bridge_forward_quit(Client *client)
{
	json_t *frame = json_object();
	json_object_set_new(frame, "op", json_string("quit"));
	json_object_set_new(frame, "from", json_string(client->name));
	bridge_send_frame(frame);
	json_decref(frame);
}

/* ===================================================================
 * Recv-side: pump the socket and emit TAGMSGs from the server.
 *
 * Called periodically by the EVENT timer.  We do non-blocking read
 * into bridge_inbuf, parse newline-delimited JSON frames, and emit
 * one TAGMSG per frame using me.name as the source.
 * =================================================================== */
/* Resolve persistence's per-client "account_canonical" ModData lazily
 * (persistence may load after us). It maps every multiclient session to its
 * presence's canonical client; the canonical maps to itself. */
static ModDataInfo *account_canonical_md(void)
{
	static ModDataInfo *md = NULL;
	if (!md)
		md = findmoddata_byname("account_canonical", MODDATATYPE_CLIENT);
	return md;
}

static void send_rtc_tagmsg(Client *dest, const char *escaped)
{
	sendto_one(dest, NULL, "@" VOICE_RTC_TAG "=%s :%s TAGMSG %s",
	           escaped, me.name, dest->name);
}

static void emit_outbound_signal(const char *to, const char *payload_json)
{
	if (!to || !*to || !payload_json)
		return;

	/* Tag value escaping per IRCv3 message-tags:
	 *   ;  -> \:
	 *   space -> \s
	 *   \  -> \\
	 *   CR -> \r, LF -> \n
	 * The JSON is unlikely to contain CR/LF (single-line) but
	 * spaces are very likely.
	 */
	size_t plen = strlen(payload_json);
	char *escaped = safe_alloc(plen * 2 + 1);
	size_t ei = 0;
	for (size_t i = 0; i < plen; i++)
	{
		char c = payload_json[i];
		switch (c)
		{
			case ';':
				escaped[ei++] = '\\';
				escaped[ei++] = ':';
				break;
			case ' ':
				escaped[ei++] = '\\';
				escaped[ei++] = 's';
				break;
			case '\\':
				escaped[ei++] = '\\';
				escaped[ei++] = '\\';
				break;
			case '\r':
				escaped[ei++] = '\\';
				escaped[ei++] = 'r';
				break;
			case '\n':
				escaped[ei++] = '\\';
				escaped[ei++] = 'n';
				break;
			default:
				escaped[ei++] = c;
				break;
		}
	}
	escaped[ei] = '\0';

	if (is_voice_or_stream_channel(to) || to[0] == '#')
	{
		/* Channel target: server-sourced TAGMSG to every member. */
		Channel *channel = find_channel(to);
		if (!channel)
		{
			safe_free(escaped);
			return;
		}
		Member *m;
		for (m = channel->members; m; m = m->next)
		{
			if (!MyUser(m->client))
				continue;
			sendto_one(m->client, NULL,
			           "@" VOICE_RTC_TAG "=%s :%s TAGMSG %s",
			           escaped, me.name, channel->name);
		}
	} else
	{
		/* Direct to a specific user. find_user returns the canonical;
		 * multiclient session clients are out of the nick hash. Deliver to
		 * the canonical AND every attached session of the presence, so
		 * whichever client is actually viewing the channel receives the
		 * signaling -- clients not viewing simply ignore the rtc tag. */
		Client *target = find_user(to, NULL);
		if (target && MyUser(target))
			send_rtc_tagmsg(target, escaped);
		ModDataInfo *md = account_canonical_md();
		if (target && md)
		{
			Client *c;
			list_for_each_entry(c, &lclient_list, lclient_node)
			{
				if (c == target || !MyUser(c))
					continue;
				if (moddata_client(c, md).ptr == target)
					send_rtc_tagmsg(c, escaped);
			}
		}
	}
	safe_free(escaped);
}

static void process_bridge_frame(const char *line, size_t len)
{
	json_error_t je;
	json_t *frame = json_loadb(line, len, 0, &je);
	if (!frame)
	{
		unreal_log(ULOG_DEBUG, "voice", "BRIDGE_BAD_FRAME", NULL,
		           "voice-channels: bad bridge frame: $err",
		           log_data_string("err", je.text));
		return;
	}
	json_t *op = json_object_get(frame, "op");
	if (!op || strcmp(json_string_value(op), "signal") != 0)
	{
		json_decref(frame);
		return;
	}
	json_t *to = json_object_get(frame, "to");
	json_t *payload = json_object_get(frame, "payload");
	if (!to || !payload)
	{
		json_decref(frame);
		return;
	}
	maybe_rewrite_turn(payload, json_is_string(to) ? json_string_value(to) : NULL);
	char *payload_json = json_dumps(payload, JSON_COMPACT);
	if (payload_json)
	{
		emit_outbound_signal(json_string_value(to), payload_json);
		free(payload_json);
	}
	json_decref(frame);
}

EVENT(bridge_pump_event)
{
	if (bridge_fd < 0)
	{
		/* Try to (re)connect every tick. */
		bridge_connect();
		return;
	}
	for (;;)
	{
		size_t avail = sizeof(bridge_inbuf) - bridge_inbuf_len - 1;
		if (avail == 0)
		{
			/* Buffer overflow: scrap and reconnect. */
			bridge_disconnect();
			return;
		}
		ssize_t n = read(bridge_fd, bridge_inbuf + bridge_inbuf_len, avail);
		if (n == 0)
		{
			bridge_disconnect();
			return;
		}
		if (n < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			bridge_disconnect();
			return;
		}
		bridge_inbuf_len += n;
	}

	/* Parse complete lines. */
	size_t consumed = 0;
	while (consumed < bridge_inbuf_len)
	{
		char *nl = memchr(bridge_inbuf + consumed, '\n',
		                  bridge_inbuf_len - consumed);
		if (!nl)
			break;
		size_t line_len = (size_t)(nl - (bridge_inbuf + consumed));
		process_bridge_frame(bridge_inbuf + consumed, line_len);
		consumed += line_len + 1; /* skip the \n */
	}
	if (consumed > 0)
	{
		memmove(bridge_inbuf, bridge_inbuf + consumed,
		        bridge_inbuf_len - consumed);
		bridge_inbuf_len -= consumed;
	}
}

/* ===================================================================
 * Hooks
 * =================================================================== */
/* PRE_CHANMSG fires before the channel TAGMSG is broadcast.  We
 * inspect the outgoing mtag list, forward the +obsidianirc/rtc payload
 * to the bridge, and *delete* the tag from the list -- the empty
 * resulting TAGMSG is dropped automatically by message.c's
 * has_client_mtags() guard, so the SDP never reaches other channel
 * members. */
static int voice_pre_chanmsg(Client *client, Channel *channel,
                             MessageTag **mtags,
                             const char *_text, SendType sendtype)
{
	if (!MyUser(client))
		return 0;
	if (!is_voice_or_stream_channel(channel->name))
		return 0;
	if (sendtype != SEND_TYPE_TAGMSG)
		return 0;


	MessageTag *prev = NULL;
	for (MessageTag *m = *mtags; m; m = m->next)
	{
		if (m->name && !strcmp(m->name, VOICE_RTC_TAG) && m->value)
		{
			bridge_forward_signal(client, channel, m->value);
			/* Detach `m` from the list -- has_client_mtags() in
			 * message.c will then see an empty list and drop the
			 * TAGMSG before it broadcasts. */
			if (prev)
				prev->next = m->next;
			else
				*mtags = m->next;
			m->next = NULL;
			free_message_tags(m);
			return 0;
		}
		prev = m;
	}
	return 0;
}

static int voice_local_part(Client *client, Channel *channel,
                            MessageTag *_mtags, const char *_comment)
{
	if (is_voice_or_stream_channel(channel->name))
		bridge_forward_part(client, channel->name);
	return 0;
}

static int voice_local_quit(Client *client, MessageTag *_mtags,
                            const char *_comment)
{
	if (!IsUser(client))
		return 0;
	bridge_forward_quit(client);
	return 0;
}

/* Permit "+obsidianirc/rtc" from anyone -- clients send it, the
 * server module relays it back, and other servers may forward it. */
static int voice_rtc_mtag_is_ok(Client *_client, const char *_name,
                                const char *_value)
{
	return 1;
}

/* HOOKTYPE_CAN_JOIN: only clients that negotiated the obsidianirc/voice
 * capability are allowed into ^ (voice) or $ (stream) channels.  Plain
 * IRC clients (HexChat, irssi, etc.) hitting these channels would just
 * see an unintelligible stream of voice signaling traffic, so we hide
 * them entirely. */
static int voice_can_join(Client *client, Channel *channel,
                          const char *_key, char **errmsg)
{
	static char fmt[160];

	if (!is_voice_or_stream_channel(channel->name))
		return 0;
	if (!MyUser(client))
		return 0; /* trust remote servers for federated joins */
	if (HasCapabilityFast(client, CAP_OBSIDIANIRC_VOICE))
		return 0;
	if (IsUser(client) && has_user_mode(client, 'B'))
		return 0; /* bot ghosts (pushbot, etc.) don't negotiate caps */

	snprintf(fmt, sizeof(fmt),
	         "%%s :Voice channels require the " VOICE_CAP_NAME
	         " client capability");
	*errmsg = fmt;
	return ERR_NOSUCHCHANNEL;
}

/* HOOKTYPE_NEW_MESSAGE: copy "+obsidianirc/rtc" from the parsed recv
 * tag list onto the outgoing tag list so PRE_CHANMSG can see it.
 * Without this the tag is parsed and accepted but never propagated
 * past new_message(). */
static void voice_rtc_new_message(Client *_client, MessageTag *recv_mtags,
                                  MessageTag **mtag_list,
                                  const char *_signature)
{
	MessageTag *m = find_mtag(recv_mtags, VOICE_RTC_TAG);
	if (m)
	{
		m = duplicate_mtag(m);
		AddListItem(m, *mtag_list);
	}
}

static void free_turn_cfg(void)
{
	if (cfg_turn_urls)
	{
		for (int i = 0; i < cfg_turn_url_count; i++)
			safe_free(cfg_turn_urls[i]);
		safe_free(cfg_turn_urls);
		cfg_turn_urls = NULL;
		cfg_turn_url_count = 0;
	}
	safe_free_sensitive(cfg_turn_secret);
	cfg_turn_ttl = 21600;
}

static json_t *mint_turn_creds(const char *account)
{
	if (!cfg_turn_secret || !account || !*account)
		return NULL;

	long expiry = (long)time(NULL) + cfg_turn_ttl;
	char username[256];
	snprintf(username, sizeof(username), "%ld:%s", expiry, account);

	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned int mac_len = 0;
	if (!HMAC(EVP_sha1(), cfg_turn_secret, (int)strlen(cfg_turn_secret),
	          (const unsigned char *)username, strlen(username),
	          mac, &mac_len))
		return NULL;

	char b64[128];
	if (b64_encode(mac, mac_len, b64, sizeof(b64)) <= 0)
		return NULL;

	json_t *t = json_object();
	json_t *urls = json_array();
	for (int i = 0; i < cfg_turn_url_count; i++)
		json_array_append_new(urls, json_string(cfg_turn_urls[i]));
	json_object_set_new(t, "urls", urls);
	json_object_set_new(t, "username", json_string(username));
	json_object_set_new(t, "password", json_string(b64));
	json_object_set_new(t, "ttl", json_integer(cfg_turn_ttl));
	return t;
}

static void maybe_rewrite_turn(json_t *payload, const char *to)
{
	if (!cfg_turn_secret)
		return;
	if (!payload || !json_is_object(payload))
		return;
	if (!json_object_get(payload, "turn"))
		return;

	const char *account = NULL;
	json_t *acct_j = json_object_get(payload, "account");
	if (acct_j && json_is_string(acct_j))
		account = json_string_value(acct_j);
	if ((!account || !*account) && to)
		account = to;

	json_t *fresh = account && *account ? mint_turn_creds(account) : NULL;
	if (fresh)
	{
		json_object_set_new(payload, "turn", fresh);
		return;
	}

	/* Fail closed: external TURN configured but couldn't mint creds.
	 * Strip the field so embedded-TURN creds from the SFU don't leak. */
	unreal_log(ULOG_WARNING, "voice", "TURN_REWRITE_FAILED", NULL,
	           "voice-channels: external TURN configured but mint failed; "
	           "stripping placeholder TURN from envelope");
	json_object_del(payload, "turn");
}

/* ===================================================================
 * Config
 * =================================================================== */
static int voice_turn_configtest(ConfigEntry *turn_ce, int *errs)
{
	int errors = 0;
	int urls_seen = 0, secret_seen = 0;
	for (ConfigEntry *cep = turn_ce->items; cep; cep = cep->next)
	{
		if (!cep->name)
		{
			config_error("%s:%i: voice::turn: blank directive",
			             cep->file->filename, cep->line_number);
			errors++;
			continue;
		}
		if (!strcmp(cep->name, "url"))
		{
			if (!cep->value || !*cep->value)
			{
				config_error("%s:%i: voice::turn::url requires a value",
				             cep->file->filename, cep->line_number);
				errors++;
			} else
			{
				urls_seen++;
			}
		} else if (!strcmp(cep->name, "shared-secret"))
		{
			if (!cep->value || !*cep->value)
			{
				config_error("%s:%i: voice::turn::shared-secret requires a value",
				             cep->file->filename, cep->line_number);
				errors++;
			} else
			{
				secret_seen++;
			}
		} else if (!strcmp(cep->name, "ttl"))
		{
			long v = cep->value ? atol(cep->value) : 0;
			if (v < 60 || v > 86400)
			{
				config_error("%s:%i: voice::turn::ttl must be in range 60-86400",
				             cep->file->filename, cep->line_number);
				errors++;
			}
		} else
		{
			config_error("%s:%i: unknown directive voice::turn::%s",
			             cep->file->filename, cep->line_number, cep->name);
			errors++;
		}
	}
	if (!urls_seen)
	{
		config_error("%s:%i: voice::turn: at least one url is required",
		             turn_ce->file->filename, turn_ce->line_number);
		errors++;
	}
	if (!secret_seen)
	{
		config_error("%s:%i: voice::turn: shared-secret is required",
		             turn_ce->file->filename, turn_ce->line_number);
		errors++;
	}
	*errs += errors;
	return errors ? -1 : 1;
}

static int voice_configtest(ConfigFile *_cf, ConfigEntry *ce, int type,
                            int *errs)
{
	if (type == CONFIG_SET)
	{
		if (!ce->name || strcmp(ce->name, "voice-bridge-socket"))
			return 0;
		return 1;
	}
	if (type == CONFIG_MAIN)
	{
		if (!ce->name || strcmp(ce->name, "voice"))
			return 0;
		int errors = 0;
		for (ConfigEntry *cep = ce->items; cep; cep = cep->next)
		{
			if (!cep->name)
				continue;
			if (!strcmp(cep->name, "turn"))
			{
				int rc = voice_turn_configtest(cep, &errors);
				if (rc < 0)
				{
					if (errs)
						*errs = errors;
					return -1;
				}
			} else
			{
				config_error("%s:%i: unknown directive voice::%s",
				             cep->file->filename, cep->line_number, cep->name);
				errors++;
			}
		}
		if (errs)
			*errs = errors;
		return errors ? -1 : 1;
	}
	return 0;
}

static int voice_configrun(ConfigFile *_cf, ConfigEntry *ce, int type)
{
	if (type == CONFIG_SET)
	{
		if (!ce->name || strcmp(ce->name, "voice-bridge-socket"))
			return 0;
		safe_free(cfg_bridge_socket);
		safe_strdup(cfg_bridge_socket, ce->value);
		return 1;
	}
	if (type == CONFIG_MAIN)
	{
		if (!ce->name || strcmp(ce->name, "voice"))
			return 0;
		for (ConfigEntry *cep = ce->items; cep; cep = cep->next)
		{
			if (!cep->name)
				continue;
			if (strcmp(cep->name, "turn"))
				continue;

			free_turn_cfg();
			int n = 0;
			for (ConfigEntry *t = cep->items; t; t = t->next)
				if (t->name && !strcmp(t->name, "url"))
					n++;
			cfg_turn_urls = safe_alloc((n + 1) * sizeof(char *));
			cfg_turn_url_count = n;
			int i = 0;
			for (ConfigEntry *t = cep->items; t; t = t->next)
			{
				if (!t->name)
					continue;
				if (!strcmp(t->name, "url"))
				{
					safe_strdup(cfg_turn_urls[i], t->value);
					i++;
				} else if (!strcmp(t->name, "shared-secret"))
					safe_strdup_sensitive(cfg_turn_secret, t->value);
				else if (!strcmp(t->name, "ttl"))
					cfg_turn_ttl = atol(t->value);
			}
			cfg_turn_urls[n] = NULL;
		}
		return 1;
	}
	return 0;
}

/* Reset TURN config to defaults before each rehash so that removing the
 * voice::turn block (or the whole voice block) actually disables external
 * TURN rewriting; configrun repopulates it when the block is still present. */
static int voice_rehash(void)
{
	free_turn_cfg();
	return 0;
}

/* ===================================================================
 * Module wiring
 * =================================================================== */
MOD_TEST()
{
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, voice_configtest);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, voice_configrun);
	return MOD_SUCCESS;
}

MOD_INIT()
{
	MARK_AS_OFFICIAL_MODULE(modinfo);

	const char *env = getenv("VOICE_BRIDGE_SOCKET");
	if (env && *env && !cfg_bridge_socket)
		safe_strdup(cfg_bridge_socket, env);

	/* Advertise the obsidianirc/voice client capability.  Clients that
	 * support voice/video signaling REQ this in their CAP exchange; the
	 * CAN_JOIN hook below uses it as the gate for ^channel access. */
	ClientCapabilityInfo cap;
	memset(&cap, 0, sizeof(cap));
	cap.name = VOICE_CAP_NAME;
	ClientCapabilityAdd(modinfo->handle, &cap, &CAP_OBSIDIANIRC_VOICE);

	/* Without registering a MessageTagHandler the parser silently
	 * drops "+obsidianirc/rtc" from incoming TAGMSGs (message_tag_ok()
	 * rejects unknown tags from local clients), and PRE_CHANMSG sees
	 * an empty mtag list. */
	MessageTagHandlerInfo mtag;
	memset(&mtag, 0, sizeof(mtag));
	mtag.name = VOICE_RTC_TAG;
	mtag.is_ok = voice_rtc_mtag_is_ok;
	mtag.flags = MTAG_HANDLER_FLAGS_NO_CAP_NEEDED;
	MessageTagHandlerAdd(modinfo->handle, &mtag);

	HookAddVoid(modinfo->handle, HOOKTYPE_NEW_MESSAGE, 0, voice_rtc_new_message);
	HookAdd(modinfo->handle, HOOKTYPE_PRE_CHANMSG, 0, voice_pre_chanmsg);
	HookAdd(modinfo->handle, HOOKTYPE_CAN_JOIN, 0, voice_can_join);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_PART, 0, voice_local_part);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_QUIT, 0, voice_local_quit);
	HookAdd(modinfo->handle, HOOKTYPE_REHASH, 0, voice_rehash);

	/* Pump the bridge socket on a 100ms cadence -- low enough that
	 * signaling RTT feels instant, high enough that idle CPU is
	 * negligible. */
	EventAdd(modinfo->handle, "voice_bridge_pump", bridge_pump_event,
	         NULL, 100, 0);

	/* CHANTYPES already advertises `#^` from src/api-isupport.c
	 * (see the patch alongside this module). */

	return MOD_SUCCESS;
}

MOD_LOAD()
{
	bridge_connect(); /* best-effort; pump event will retry */
	return MOD_SUCCESS;
}

MOD_UNLOAD()
{
	bridge_disconnect();
	safe_free(cfg_bridge_socket);
	free_turn_cfg();
	return MOD_SUCCESS;
}
