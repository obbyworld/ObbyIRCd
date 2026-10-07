/* sentinel.c -- in-process behavioural detector for obbyircd.
 *
 * Blocks malicious messages BEFORE delivery via CAN_SEND_TO_CHANNEL,
 * CAN_SEND_TO_USER and CAN_JOIN hooks. Per-client sliding-window state
 * is attached as ModData and freed automatically on disconnect.
 *
 * Also emits behavioural events as newline-delimited JSON to a local
 * Unix socket (default /run/obby/sentry.sock). Best-effort: if no
 * consumer is listening the emit fails silently and the IRCd is
 * unaffected. The training side reads those events to keep its
 * baselines warm but never makes moderation decisions.
 */

#include "unrealircd.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

ModuleHeader MOD_HEADER = {
    "sentinel",
    "0.1",
    "emit behavioural events to local sentry pipeline",
    "obbyircd",
    "unrealircd-6",
};

#define SENTINEL_DEFAULT_SOCK "/run/obby/sentry.sock"

static int sentinel_fd = -1;
static char *cfg_sock_path = NULL;
static time_t last_connect_attempt = 0;

/* ===================================================================
 * Unix-socket bridge -- mirror voice-channels.c's pattern.
 * =================================================================== */

static void sentinel_disconnect(void)
{
	if (sentinel_fd >= 0)
	{
		close(sentinel_fd);
		sentinel_fd = -1;
	}
}

static int sentinel_connect(void)
{
	time_t now = TStime();
	/* Backoff: don't re-attempt more than once per 5 seconds. */
	if (now - last_connect_attempt < 5)
		return -1;
	last_connect_attempt = now;

	const char *path = cfg_sock_path ? cfg_sock_path : SENTINEL_DEFAULT_SOCK;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, path, sizeof(addr.sun_path));

	int flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	/* Non-blocking connect; EINPROGRESS is fine (later writev EAGAINs
	 * silently until the socket comes up). */
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 && errno != EINPROGRESS)
	{
		close(fd);
		return -1;
	}
	sentinel_fd = fd;
	return 0;
}

/* Write one newline-terminated JSON frame. Silent on failure -- the
 * detection pipeline is a debugging aid, not a critical path. */
static void sentinel_emit(json_t *frame)
{
	if (!frame)
		return;
	if (sentinel_fd < 0 && sentinel_connect() < 0)
	{
		json_decref(frame);
		return;
	}
	/* Always stamp the time field so sentry can reason about real
	 * cadence even if its consumption is bursty. */
	json_object_set_new(frame, "t", json_integer((json_int_t)TStime() * 1000));

	char *encoded = json_dumps(frame, JSON_COMPACT);
	json_decref(frame);
	if (!encoded)
		return;

	struct iovec iov[2];
	iov[0].iov_base = encoded;
	iov[0].iov_len = strlen(encoded);
	char nl = '\n';
	iov[1].iov_base = &nl;
	iov[1].iov_len = 1;
	ssize_t w = writev(sentinel_fd, iov, 2);
	free(encoded);
	if (w < 0)
	{
		/* EAGAIN under load just drops the event; serious errors
		 * tear the socket down so the next emit reconnects. */
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			sentinel_disconnect();
	}
}

/* Stamp the common per-client identity fields into the frame. */
static void put_subject(json_t *frame, Client *c)
{
	if (!c)
		return;
	if (*c->name)
		json_object_set_new(frame, "nick", json_string(c->name));
	if (*c->id)
		json_object_set_new(frame, "uid", json_string(c->id));
	if (c->user)
	{
		if (*c->user->username)
			json_object_set_new(frame, "ident", json_string(c->user->username));
		if (*c->user->realhost)
			json_object_set_new(frame, "host", json_string(c->user->realhost));
		if (*c->user->account)
			json_object_set_new(frame, "account", json_string(c->user->account));
	}
	if (c->ip && *c->ip)
		json_object_set_new(frame, "ip", json_string(c->ip));
	if (IsSecure(c))
		json_object_set_new(frame, "tls", json_true());
}

/* ===================================================================
 * Hook handlers
 * =================================================================== */

static int sentinel_connect_hook(Client *client)
{
	json_t *f = json_object();
	json_object_set_new(f, "kind", json_string("connect"));
	put_subject(f, client);
	sentinel_emit(f);
	return 0;
}

static int sentinel_register_hook(Client *client, int after_numeric)
{
	/* HOOKTYPE_WELCOME fires once per RPL_*; emit only on the final
	 * (after_numeric == 376 / RPL_ENDOFMOTD) so we count each
	 * client exactly once. */
	if (after_numeric != 376)
		return 0;
	json_t *f = json_object();
	json_object_set_new(f, "kind", json_string("register"));
	put_subject(f, client);
	sentinel_emit(f);
	return 0;
}

static int sentinel_quit_hook(Client *client, MessageTag *_mtags, const char *comment)
{
	if (!IsUser(client))
		return 0;

	/* A QUIT comment of "Killed by <oper> (<reason>)" identifies an
	 * oper-driven kill regardless of code path (IRC /KILL command,
	 * /SAKILL, the RPC user.kill method, ...). Excluding our own
	 * "Killed by Orca" stamp avoids learning from sentinel's own
	 * decisions. */
	const char *kind = "quit";
	const char *oper_name = NULL;
	char oper_buf[64] = {0};
	char *kill_reason = NULL;
	if (comment && !strncmp(comment, "Killed by ", 10) &&
	    strncmp(comment, "Killed by Orca", 14))
	{
		kind = "oper_kill";
		const char *p = comment + 10;
		const char *paren = strchr(p, ' ');
		if (paren)
		{
			size_t n = (size_t)(paren - p);
			if (n >= sizeof(oper_buf))
				n = sizeof(oper_buf) - 1;
			memcpy(oper_buf, p, n);
			oper_buf[n] = 0;
			oper_name = oper_buf;
			const char *open_paren = strchr(paren, '(');
			if (open_paren)
			{
				kill_reason = strdup(open_paren + 1);
				size_t kl = strlen(kill_reason);
				if (kl > 0 && kill_reason[kl - 1] == ')')
					kill_reason[kl - 1] = 0;
			}
		}
	}

	json_t *f = json_object();
	json_object_set_new(f, "kind", json_string(kind));
	put_subject(f, client);
	if (comment && *comment)
		json_object_set_new(f, "reason", json_string(kill_reason ? kill_reason : comment));
	if (oper_name)
		json_object_set_new(f, "oper", json_string(oper_name));
	sentinel_emit(f);
	safe_free(kill_reason);
	return 0;
}

static int sentinel_join_hook(Client *client, Channel *channel, MessageTag *_mtags)
{
	json_t *f = json_object();
	json_object_set_new(f, "kind", json_string("join"));
	put_subject(f, client);
	json_object_set_new(f, "channel", json_string(channel->name));
	sentinel_emit(f);
	return 0;
}

static int sentinel_part_hook(Client *client, Channel *channel, MessageTag *_mtags, const char *comment)
{
	json_t *f = json_object();
	json_object_set_new(f, "kind", json_string("part"));
	put_subject(f, client);
	json_object_set_new(f, "channel", json_string(channel->name));
	if (comment && *comment)
		json_object_set_new(f, "reason", json_string(comment));
	sentinel_emit(f);
	return 0;
}

static int sentinel_kick_hook(Client *client, Client *victim, Channel *channel,
                              MessageTag *_mtags, const char *comment)
{
	json_t *f = json_object();
	json_object_set_new(f, "kind", json_string("kick"));
	/* `subject` is the victim. The actor (kicker) goes in oper/target
	 * fields so the L3 trainer can use it as a positive label when an
	 * oper kicks. */
	if (victim)
		put_subject(f, victim);
	json_object_set_new(f, "channel", json_string(channel->name));
	if (client && *client->name)
		json_object_set_new(f, "oper", json_string(client->name));
	if (comment && *comment)
		json_object_set_new(f, "reason", json_string(comment));
	/* Distinguish oper-driven kicks for label generation. */
	if (client && IsOper(client))
		json_object_set_new(f, "kind", json_string("oper_kick"));
	sentinel_emit(f);
	return 0;
}

static int sentinel_nickchange_hook(Client *client, MessageTag *_mtags, const char *newnick)
{
	json_t *f = json_object();
	json_object_set_new(f, "kind", json_string("nick"));
	put_subject(f, client);
	if (newnick && *newnick)
		json_object_set_new(f, "target", json_string(newnick));
	sentinel_emit(f);
	return 0;
}

/* CTCP detection: PRIVMSG body starts with 0x01.  This catches both
 * channel and user CTCP traffic via the same predicate. */
static int is_ctcp(const char *text)
{
	return text && text[0] == 0x01;
}

static int sentinel_chanmsg_hook(Client *client, Channel *channel, int sendflags,
                                 const char *member_modes, const char *target,
                                 MessageTag *_mtags, const char *text, SendType sendtype)
{
	(void)sendflags;
	(void)member_modes;
	(void)target;
	if (!channel || !text)
		return 0;
	const char *kind = "chanmsg";
	if (sendtype == SEND_TYPE_NOTICE)
		kind = "channotice";
	else if (sendtype == SEND_TYPE_TAGMSG)
		return 0; /* TAGMSGs are pure metadata; skip for now. */
	if (is_ctcp(text))
		kind = "ctcp";

	json_t *f = json_object();
	json_object_set_new(f, "kind", json_string(kind));
	put_subject(f, client);
	json_object_set_new(f, "channel", json_string(channel->name));
	if (text && *text)
		json_object_set_new(f, "text", json_string(text));
	sentinel_emit(f);
	return 0;
}

static int sentinel_usermsg_hook(Client *client, Client *to,
                                 MessageTag *_mtags, const char *text, SendType sendtype)
{
	const char *kind = (sendtype == SEND_TYPE_NOTICE) ? "usernotice" : "usermsg";
	if (sendtype == SEND_TYPE_TAGMSG)
		return 0;
	if (is_ctcp(text))
		kind = "ctcp";

	json_t *f = json_object();
	json_object_set_new(f, "kind", json_string(kind));
	put_subject(f, client);
	if (to && *to->name)
		json_object_set_new(f, "target", json_string(to->name));
	if (text && *text)
		json_object_set_new(f, "text", json_string(text));
	sentinel_emit(f);
	return 0;
}

static int sentinel_kill_hook(Client *killedby, Client *killed, const char *reason)
{
	if (!killed)
		return 0;
	json_t *f = json_object();
	json_object_set_new(f, "kind", json_string("oper_kill"));
	put_subject(f, killed);
	if (killedby && *killedby->name)
		json_object_set_new(f, "oper", json_string(killedby->name));
	if (reason && *reason)
		json_object_set_new(f, "reason", json_string(reason));
	sentinel_emit(f);
	return 0;
}

/* Oper added a TKL (K/G/Z-line, shun, namedban, ...). Emit so the
 * training side can use it as a positive label for any currently-
 * tracked user whose user@host matches. */
static int sentinel_tkl_add_hook(Client *client, TKL *tkl)
{
	if (!tkl || !client || !IsOper(client))
		return 0;
	const char *btype = NULL;
	if (TKLIsServerBan(tkl))
	{
		if (tkl->type & TKL_KILL)
			btype = (tkl->type & TKL_GLOBAL) ? "gline" : "kline";
		else if (tkl->type & TKL_ZAP)
			btype = (tkl->type & TKL_GLOBAL) ? "gzline" : "zline";
		else if (tkl->type & TKL_SHUN)
			btype = "shun";
	}
	if (!btype)
		return 0;

	json_t *f = json_object();
	json_object_set_new(f, "kind", json_string("oper_kline"));
	json_object_set_new(f, "oper", json_string(client->name));
	if (tkl->ptr.serverban)
	{
		if (tkl->ptr.serverban->usermask)
			json_object_set_new(f, "target_ident", json_string(tkl->ptr.serverban->usermask));
		if (tkl->ptr.serverban->hostmask)
			json_object_set_new(f, "target_host", json_string(tkl->ptr.serverban->hostmask));
	}
	json_object_set_new(f, "ban_type", json_string(btype));
	if (tkl->set_by)
		json_object_set_new(f, "reason", json_string(tkl->set_by));
	sentinel_emit(f);
	return 0;
}

/* Detector: per-client sliding-window state, rule evaluators, and the
 * CAN_SEND / CAN_JOIN hook handlers that block + kill on a rule hit. */

#define SENTINEL_WINDOW_SEC     60
#define SENTINEL_MAX_URL_TS     64
#define SENTINEL_MAX_PM_HIST    64
#define SENTINEL_MAX_MENTION_TS 64
#define SENTINEL_MAX_MSG        32
#define SENTINEL_MAX_JOIN       16
#define SENTINEL_MAX_NICK       16
#define SENTINEL_MAX_HOP        64

#define SENTINEL_LINK_SPAM_AGE   30   /* URL in <= N seconds from connect */
#define SENTINEL_MENTION_STORM_R 3    /* >= N mention-bomb msgs in 60s */
#define SENTINEL_PM_SHOTGUN_K    5    /* >= K distinct PM targets in 60s */
#define SENTINEL_FLOOD_RATE      30   /* msgs/min */
#define SENTINEL_REPEAT_DUPS     4    /* duplicate hash hits in window */
#define SENTINEL_MASS_JOIN       10   /* joins/min */
#define SENTINEL_CTCP_STORM      6    /* CTCPs in window */
#define SENTINEL_SHOUT_MIN_MSG   4    /* msgs before shouting can fire */
#define SENTINEL_SHOUT_RATIO     85   /* upper-ratio % */
#define SENTINEL_NICK_FLIP       5    /* nick changes/min */
#define SENTINEL_HOP_FLOOD       8    /* (join+part)/min */
#define SENTINEL_PM_FLOOD        12   /* PMs/min */
#define SENTINEL_IDLE_AGE        600  /* user must be on net >=N sec */
#define SENTINEL_IDLE_GAP        300  /* prior idle gap >=N sec */
#define SENTINEL_IDLE_RATE       10   /* burst rate to fire idle_burst */

typedef struct {
	time_t at;
	char *target;
} PMRecord;

typedef struct {
	time_t at;
	uint64_t hash;     /* FNV-64a of the lowercased+normalised text */
	int upper_pc; /* uppercase percentage 0..100 */
} MsgRecord;

typedef struct {
	time_t first_seen;
	time_t blocked_at;
	time_t last_msg_at;
	time_t burst_start_idle_gap;

	time_t url_ts[SENTINEL_MAX_URL_TS];
	int url_n;

	time_t mention_ts[SENTINEL_MAX_MENTION_TS];
	int mention_n;

	PMRecord pm_hist[SENTINEL_MAX_PM_HIST];
	int pm_n;

	MsgRecord msgs[SENTINEL_MAX_MSG];
	int msg_n;

	time_t join_ts[SENTINEL_MAX_JOIN];
	int join_n;

	time_t nick_ts[SENTINEL_MAX_NICK];
	int nick_n;

	time_t hop_ts[SENTINEL_MAX_HOP];  /* joins + parts together */
	int hop_n;

	int ctcp_count;     /* CTCPs in 60s window (decayed lazily) */
	time_t last_ctcp_at;
} SentinelState;

static ModDataInfo *sentinel_md = NULL;

#define SENT_MD(c) (moddata_local_client((c), sentinel_md).ptr)

static SentinelState *sentinel_state_ensure(Client *c)
{
	SentinelState *s = SENT_MD(c);
	if (!s)
	{
		s = safe_alloc(sizeof(SentinelState));
		s->first_seen = TStime();
		moddata_local_client(c, sentinel_md).ptr = s;
	}
	return s;
}

static void sentinel_state_free(ModData *md)
{
	SentinelState *s = md->ptr;
	if (!s)
		return;
	for (int i = 0; i < s->pm_n; i++)
		safe_free(s->pm_hist[i].target);
	safe_free(s);
	md->ptr = NULL;
}

/* ---- content scanners ---------------------------------------------- */

static int sentinel_count_urls(const char *text)
{
	if (!text)
		return 0;
	int n = 0;
	for (const char *p = text; (p = strstr(p, "://")); p++)
	{
		if (p - text >= 4 &&
		    (!strncasecmp(p - 4, "http", 4) || !strncasecmp(p - 5, "https", 5)))
			n++;
	}
	for (const char *p = text; (p = strstr(p, "www.")); p += 4)
		n++;
	return n;
}

/* ---- URL maliciousness scorer -------------------------------------
 *
 * Shape-only scoring: no external lookups. Each signal contributes a
 * weight; the rule layer compares the maximum URL score in a message
 * against SENTINEL_URL_BLOCK_SCORE.
 *
 * The thresholds here are tuned so:
 *   - "https://github.com/foo/bar" scores 0
 *   - "https://bit.ly/x" scores ~5 (shortener alone -> block)
 *   - "http://192.168.1.1/x" scores ~6 (IP host alone -> block)
 *   - "https://win-9382.tk/promo" scores ~10 (burner TLD + spam path)
 */

#define SENTINEL_URL_BLOCK_SCORE 5

static int has_suffix_ci(const char *host, int host_len, const char *suf)
{
	int sl = (int)strlen(suf);
	if (host_len < sl)
		return 0;
	return !strncasecmp(host + host_len - sl, suf, sl);
}

static int host_starts_with_ipv4(const char *h, int n)
{
	int dots = 0, digits = 0, run = 0;
	for (int i = 0; i < n; i++)
	{
		char c = h[i];
		if (c >= '0' && c <= '9')
		{
			digits++;
			run++;
			if (run > 3)
				return 0;
		} else if (c == '.')
		{
			if (run == 0)
				return 0;
			run = 0;
			dots++;
		} else
		{
			break;
		}
	}
	return dots == 3 && digits >= 4 && digits <= 12;
}

static int subdomain_is_digit_heavy(const char *host, int host_len)
{
	int first_dot = -1;
	for (int i = 0; i < host_len; i++)
		if (host[i] == '.')
		{
			first_dot = i;
			break;
		}
	if (first_dot < 4)
		return 0;
	int digits = 0;
	for (int i = 0; i < first_dot; i++)
		if (host[i] >= '0' && host[i] <= '9')
			digits++;
	return (digits * 100) / first_dot >= 40;
}

static int count_dots(const char *host, int host_len)
{
	int n = 0;
	for (int i = 0; i < host_len; i++)
		if (host[i] == '.')
			n++;
	return n;
}

static int has_punycode_label(const char *host, int host_len)
{
	for (int i = 0; i < host_len - 4; i++)
	{
		if ((i == 0 || host[i - 1] == '.') &&
		    !strncasecmp(host + i, "xn--", 4))
			return 1;
	}
	return 0;
}

/* score a single URL substring (from start to end-exclusive). */
static int sentinel_url_score(const char *url, int url_len)
{
	const char *host_start = url;
	while (host_start < url + url_len && *host_start != ':' && *host_start != '/')
		host_start++;
	if (host_start + 3 > url + url_len || strncmp(host_start, "://", 3) != 0)
		return 0;
	host_start += 3;

	const char *p = host_start;
	while (p < url + url_len && *p != '/' && *p != '?' && *p != '#' && *p != ' ')
		p++;
	int host_len = (int)(p - host_start);
	if (host_len <= 0)
		return 0;

	const char *path_start = p;
	int path_len = (int)(url + url_len - path_start);

	int score = 0;

	/* Suspicious TLDs. Sources: Spamhaus Domain Reputation Oct 2024
	 * - Mar 2025, Interisle Phishing Landscape 2024, Cloudflare
	 * Email Security TLD report, APWG Q2 2025. Ordering reflects
	 * current-era reality: Freenom set is declining, BinkyMoon
	 * ultra-cheap new-gTLDs dominate, .top is the volume leader. */
	static const char *bad_tlds[] = {
	        /* Highest normalized phishing rate (Interisle 2024) */
	    ".lol", ".bond", ".support", ".top", ".sbs",
	        /* >99% mail malicious (Cloudflare) */
	    ".bar", ".rest", ".uno", ".academy", ".directory", ".beauty",
	        /* Spamhaus top-20 worst, toll-road scam vectors */
	    ".xin", ".cyou", ".cfd", ".buzz", ".monster",
	        /* Cheap new-gTLD burner pool */
	    ".xyz", ".icu", ".click", ".work", ".link", ".live",
	    ".country", ".pw", ".review", ".download", ".stream", ".gdn",
	        /* Google confusable-with-filename TLDs */
	    ".zip", ".mov",
	        /* Freenom-era (declining but present) */
	    ".tk", ".ml", ".ga", ".cf", ".gq",
	        /* ccTLD with >85% malicious mail share (Cloudflare) */
	    ".zw",
	    NULL};
	for (int i = 0; bad_tlds[i]; i++)
	{
		if (has_suffix_ci(host_start, host_len, bad_tlds[i]))
		{
			score += 5;
			break;
		}
	}

	/* Known shortener domains -- exact host match. */
	static const char *shorteners[] = {
	    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
	    "buff.ly", "cutt.ly", "tiny.cc", "rebrand.ly", "shorturl.at",
	    "lnkd.in", "v.gd", "s.id", "ift.tt", "clck.ru", "tr.im",
	    "shorte.st", "adf.ly", "linktr.ee",
	    NULL};
	for (int i = 0; shorteners[i]; i++)
	{
		int n = (int)strlen(shorteners[i]);
		if (host_len == n && !strncasecmp(host_start, shorteners[i], n))
		{
			score += 4;
			break;
		}
	}

	if (host_starts_with_ipv4(host_start, host_len))
		score += 6;

	if (has_punycode_label(host_start, host_len))
		score += 5;

	if (subdomain_is_digit_heavy(host_start, host_len))
		score += 3;

	/* Excessive subdomain depth: a.b.c.d.example.com = 4 dots+ */
	if (count_dots(host_start, host_len) >= 4)
		score += 2;

	/* Excessive host length: rare on legitimate domains. */
	if (host_len >= 40)
		score += 2;

	/* Common spam path tokens. Compare against path lowercased on the fly. */
	if (path_len > 0)
	{
		char low[128];
		int copy = path_len < (int)sizeof(low) - 1 ? path_len : (int)sizeof(low) - 1;
		for (int i = 0; i < copy; i++)
		{
			char c = path_start[i];
			low[i] = (c >= 'A' && c <= 'Z') ? (c | 0x20) : c;
		}
		low[copy] = 0;
		static const char *spam_tokens[] = {
		    "/promo", "/claim", "/win", "/verify", "/signup", "/ref",
		    "/track", "/click", "/go?", "/free", "/bonus", "/redeem",
		    "?ref=", "?promo=", NULL};
		for (int i = 0; spam_tokens[i]; i++)
			if (strstr(low, spam_tokens[i]))
			{
				score += 2;
				break;
			}
	}
	return score;
}

/* Returns the MAX score across every URL in the message. */
static int sentinel_max_url_score(const char *text)
{
	if (!text)
		return 0;
	int max = 0;
	for (const char *p = text; *p;)
	{
		const char *colon = strstr(p, "://");
		if (!colon)
			break;
		const char *url_start = colon;
		while (url_start > text && url_start[-1] != ' ' && url_start[-1] != '\t' &&
		       url_start[-1] != '<' && url_start[-1] != '(')
			url_start--;
		if (strncasecmp(url_start, "http", 4) && strncasecmp(url_start, "https", 5))
		{
			p = colon + 3;
			continue;
		}
		const char *url_end = colon + 3;
		while (*url_end && *url_end != ' ' && *url_end != '\t' &&
		       *url_end != '>' && *url_end != ')' && *url_end != '\n' &&
		       *url_end != '\r')
			url_end++;
		int s = sentinel_url_score(url_start, (int)(url_end - url_start));
		if (s > max)
			max = s;
		p = url_end;
	}
	return max;
}

/* count distinct @nick-style or "nick:" tokens. */
static int sentinel_count_mentions(const char *text)
{
	if (!text)
		return 0;
	int n = 0;
	const char *p = text;
	while (*p)
	{
		while (*p && (*p == ' ' || *p == '\t'))
			p++;
		if (!*p)
			break;
		if (*p == '@' && p[1] && p[1] != ' ')
		{
			n++;
		} else
		{
			/* "nick:" leading-address style: check for trailing ':' */
			const char *q = p;
			while (*q && *q != ' ' && *q != ':')
				q++;
			if (*q == ':' && q != p)
				n++;
		}
		while (*p && *p != ' ' && *p != '\t')
			p++;
	}
	return n;
}

/* case-insensitive substring contains-any. lowercases up to 1023
 * chars of input to a stack buffer to keep the hot path stack-only.
 */
static int sentinel_has_nickserv_spoof(const char *text)
{
	if (!text)
		return 0;
	char low[1024];
	int i;
	for (i = 0; i < (int)sizeof(low) - 1 && text[i]; i++)
	{
		char c = text[i];
		low[i] = (c >= 'A' && c <= 'Z') ? (c | 0x20) : c;
	}
	low[i] = 0;
	static const char *needles[] = {
	    "nickserv identify", "/msg nickserv", "msg nickserv id",
	    "identify your password", "verify your password",
	    "to confirm your account", "type /msg",
	    "your account has been compromised", "re-authenticate",
	    NULL};
	for (int j = 0; needles[j]; j++)
		if (strstr(low, needles[j]))
			return 1;
	return 0;
}

/* Recognise IRCBot-family C&C verbs sent as PRIVMSG/CTCP payload.
 * Sources: Perdisci/Vigna 2014 C&C-signature paper, Stratosphere Labs
 * 2019 botnet capture, evilxyz/IRC-Bot reference implementation,
 * jgamblin/Mirai-Source-Code. Verbs are dot- or bang-prefixed short
 * tokens at the start of a line. */
static int sentinel_has_cnc_verb(const char *text)
{
	if (!text || (text[0] != '.' && text[0] != '!'))
		return 0;
	char tok[24];
	int i = 1;
	while (i < (int)sizeof(tok) - 1 && text[i] &&
	       text[i] != ' ' && text[i] != '\t' && text[i] != '\r' &&
	       text[i] != '\n')
	{
		char c = text[i];
		tok[i - 1] = (c >= 'A' && c <= 'Z') ? (c | 0x20) : c;
		i++;
	}
	tok[i - 1] = 0;
	if (i < 3)
		return 0;
	static const char *verbs[] = {
	    "scan", "ddos", "udp", "tcp", "syn", "ack",
	    "download", "visit", "exec", "shell", "kill",
	    "login", "logout", "auth", "join", "part",
	    "flood", "spam", "raid", "attack",
	    "update", "upgrade", "reload", "restart",
	    "mirai", "kaiten", "sdbot", "rbot",
	    NULL};
	for (int j = 0; verbs[j]; j++)
		if (!strcmp(tok, verbs[j]))
			return 1;
	return 0;
}

static uint64_t sentinel_hash_text(const char *text)
{
	if (!text)
		return 0;
	uint64_t h = 14695981039346656037ULL;
	int prev_space = 1;
	for (const char *p = text; *p; p++)
	{
		char c = *p;
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
		{
			if (prev_space)
				continue;
			c = ' ';
			prev_space = 1;
		} else
		{
			prev_space = 0;
			if (c >= 'A' && c <= 'Z')
				c |= 0x20;
		}
		h ^= (uint64_t)(unsigned char)c;
		h *= 1099511628211ULL;
	}
	return h;
}

/* Uppercase-letter percentage 0..100 over alphabetic chars. */
static int sentinel_upper_pct(const char *text)
{
	if (!text)
		return 0;
	int up = 0, alpha = 0;
	for (const char *p = text; *p; p++)
	{
		if (*p >= 'A' && *p <= 'Z')
		{
			up++;
			alpha++;
		} else if (*p >= 'a' && *p <= 'z')
		{
			alpha++;
		}
	}
	if (alpha == 0)
		return 0;
	return (up * 100) / alpha;
}

/* ---- sliding-window helpers ---------------------------------------- */

static int sentinel_sw_compact(time_t *ts, int *n, time_t now, int window_sec)
{
	int kept = 0;
	for (int i = 0; i < *n; i++)
	{
		if (now - ts[i] <= window_sec)
			ts[kept++] = ts[i];
	}
	*n = kept;
	return kept;
}

static void sentinel_sw_push(time_t *ts, int *n, int max, time_t now)
{
	if (*n >= max)
	{
		memmove(ts, ts + 1, sizeof(time_t) * (max - 1));
		*n = max - 1;
	}
	ts[(*n)++] = now;
}

/* ---- rule evaluators ----------------------------------------------- */

/* Record one channel message into the per-user state. Called BEFORE
 * the block-rules run so they see the current msg. */
static void sentinel_record_chanmsg(SentinelState *s, const char *text, time_t now)
{
	/* Burst-gap bookkeeping: was the user silent before this msg? */
	if (s->last_msg_at != 0)
	{
		time_t gap = now - s->last_msg_at;
		if (gap >= SENTINEL_IDLE_GAP)
			s->burst_start_idle_gap = gap;
		else if (s->burst_start_idle_gap > 0 && gap > SENTINEL_WINDOW_SEC)
			s->burst_start_idle_gap = 0;
	}
	s->last_msg_at = now;

	/* Append to message history (capacity SENTINEL_MAX_MSG). */
	MsgRecord rec = {
	    .at = now,
	    .hash = sentinel_hash_text(text),
	    .upper_pc = sentinel_upper_pct(text),
	};
	if (s->msg_n >= SENTINEL_MAX_MSG)
	{
		memmove(s->msgs, s->msgs + 1,
		        sizeof(MsgRecord) * (SENTINEL_MAX_MSG - 1));
		s->msg_n = SENTINEL_MAX_MSG - 1;
	}
	s->msgs[s->msg_n++] = rec;
}

/* Decay CTCP count if the last CTCP was more than a window ago. */
static void sentinel_decay_ctcp(SentinelState *s, time_t now)
{
	if (s->ctcp_count == 0)
		return;
	if (now - s->last_ctcp_at > SENTINEL_WINDOW_SEC)
	{
		s->ctcp_count = 0;
	}
}

/* Returns 1 if the chanmsg should be blocked. Updates state. */
static int sentinel_block_chanmsg(Client *client, const char *text,
                                  SendType sendtype, const char **reason_out)
{
	SentinelState *s = sentinel_state_ensure(client);
	time_t now = TStime();

	/* CTCP detection: PRIVMSG body wrapped in 0x01. */
	int is_ctcp = (text && text[0] == 0x01 && sendtype == SEND_TYPE_PRIVMSG);
	if (is_ctcp)
	{
		sentinel_decay_ctcp(s, now);
		s->ctcp_count++;
		s->last_ctcp_at = now;
		if (s->ctcp_count >= SENTINEL_CTCP_STORM)
		{
			*reason_out = "ctcp_storm";
			return 1;
		}
		/* Don't run text-based rules on CTCP bodies. */
		return 0;
	}

	/* Record the message for downstream rules. */
	sentinel_record_chanmsg(s, text, now);

	/* botnet C&C verb: ".scan", "!login", etc. */
	if (sentinel_has_cnc_verb(text))
	{
		*reason_out = "botnet_cnc";
		return 1;
	}

	/* link_spam: score URL shape, not just timing.
	 * Fresh users (< SENTINEL_LINK_SPAM_AGE on net) get a bonus so a
	 * marginal URL still trips for drive-by spammers, but a normal
	 * github.com URL from a new user no longer fires. */
	int urls = sentinel_count_urls(text);
	if (urls > 0)
	{
		for (int i = 0; i < urls; i++)
			sentinel_sw_push(s->url_ts, &s->url_n,
			                 SENTINEL_MAX_URL_TS, now);
		sentinel_sw_compact(s->url_ts, &s->url_n, now, SENTINEL_WINDOW_SEC);

		int score = sentinel_max_url_score(text);
		if (now - s->first_seen <= SENTINEL_LINK_SPAM_AGE)
			score += 2;
		if (score >= SENTINEL_URL_BLOCK_SCORE)
		{
			*reason_out = "link_spam";
			return 1;
		}
	}

	/* mention_storm. */
	int men = sentinel_count_mentions(text);
	if (men >= 3)
	{
		sentinel_sw_push(s->mention_ts, &s->mention_n,
		                 SENTINEL_MAX_MENTION_TS, now);
		sentinel_sw_compact(s->mention_ts, &s->mention_n, now,
		                    SENTINEL_WINDOW_SEC);
		if (s->mention_n >= SENTINEL_MENTION_STORM_R)
		{
			*reason_out = "mention_storm";
			return 1;
		}
	}

	/* Compact msg history to the 60s window. */
	int kept = 0;
	for (int i = 0; i < s->msg_n; i++)
	{
		if (now - s->msgs[i].at <= SENTINEL_WINDOW_SEC)
			s->msgs[kept++] = s->msgs[i];
	}
	s->msg_n = kept;

	/* flood: msgs/min over the window. */
	if (s->msg_n >= SENTINEL_FLOOD_RATE)
	{
		*reason_out = "flood";
		return 1;
	}

	/* repeat: same hash hits >= threshold (excluding the original). */
	for (int i = 0; i < s->msg_n; i++)
	{
		int dups = 0;
		for (int j = 0; j < s->msg_n; j++)
			if (i != j && s->msgs[i].hash == s->msgs[j].hash)
				dups++;
		if (dups >= SENTINEL_REPEAT_DUPS)
		{
			*reason_out = "repeat";
			return 1;
		}
	}

	/* shouting: sustained high uppercase ratio. */
	if (s->msg_n >= SENTINEL_SHOUT_MIN_MSG)
	{
		int sum = 0;
		for (int i = 0; i < s->msg_n; i++)
			sum += s->msgs[i].upper_pc;
		int mean = sum / s->msg_n;
		if (mean >= SENTINEL_SHOUT_RATIO)
		{
			*reason_out = "shouting";
			return 1;
		}
	}

	/* idle_burst: age > 10min + prior idle >= 5min + recent rate >= 10/min. */
	if (now - s->first_seen >= SENTINEL_IDLE_AGE &&
	    s->burst_start_idle_gap >= SENTINEL_IDLE_GAP &&
	    s->msg_n >= SENTINEL_IDLE_RATE)
	{
		*reason_out = "idle_burst";
		return 1;
	}

	return 0;
}

static int sentinel_block_usermsg(Client *client, Client *target,
                                  const char *text, SendType sendtype,
                                  const char **reason_out)
{
	SentinelState *s = sentinel_state_ensure(client);
	time_t now = TStime();

	/* CTCP in PM counts toward ctcp_storm. */
	int is_ctcp = (text && text[0] == 0x01 && sendtype == SEND_TYPE_PRIVMSG);
	if (is_ctcp)
	{
		sentinel_decay_ctcp(s, now);
		s->ctcp_count++;
		s->last_ctcp_at = now;
		if (s->ctcp_count >= SENTINEL_CTCP_STORM)
		{
			*reason_out = "ctcp_storm";
			return 1;
		}
		return 0;
	}

	if (sentinel_has_nickserv_spoof(text))
	{
		*reason_out = "nickserv_spoof";
		return 1;
	}

	if (sentinel_has_cnc_verb(text))
	{
		*reason_out = "botnet_cnc";
		return 1;
	}

	/* Prune expired PM history. */
	int kept = 0;
	for (int i = 0; i < s->pm_n; i++)
	{
		if (now - s->pm_hist[i].at <= SENTINEL_WINDOW_SEC)
		{
			s->pm_hist[kept++] = s->pm_hist[i];
		} else
		{
			safe_free(s->pm_hist[i].target);
		}
	}
	s->pm_n = kept;

	/* Push this PM. */
	if (target && target->name[0])
	{
		if (s->pm_n >= SENTINEL_MAX_PM_HIST)
		{
			safe_free(s->pm_hist[0].target);
			memmove(s->pm_hist, s->pm_hist + 1,
			        sizeof(PMRecord) * (SENTINEL_MAX_PM_HIST - 1));
			s->pm_n = SENTINEL_MAX_PM_HIST - 1;
		}
		s->pm_hist[s->pm_n].at = now;
		s->pm_hist[s->pm_n].target = strdup(target->name);
		s->pm_n++;
	}

	/* pm_flood: outbound PMs/min over window. */
	if (s->pm_n >= SENTINEL_PM_FLOOD)
	{
		*reason_out = "pm_flood";
		return 1;
	}

	/* pm_shotgun: distinct PM targets in window. */
	int distinct = 0;
	for (int i = 0; i < s->pm_n; i++)
	{
		int dup = 0;
		for (int j = 0; j < i; j++)
			if (!strcasecmp(s->pm_hist[i].target, s->pm_hist[j].target))
			{
				dup = 1;
				break;
			}
		if (!dup)
			distinct++;
	}
	if (distinct >= SENTINEL_PM_SHOTGUN_K)
	{
		*reason_out = "pm_shotgun";
		return 1;
	}
	return 0;
}

/* ---- the actual hooks ---------------------------------------------- */

static int sentinel_can_send_chan(Client *client, Channel *channel,
                                  Membership *member, const char **text, const char **errmsg,
                                  SendType sendtype, ClientContext *clictx)
{
	if (!MyUser(client))
		return HOOK_CONTINUE;
	if (IsOper(client) || IsULine(client))
		return HOOK_CONTINUE;
	if (sendtype != SEND_TYPE_PRIVMSG && sendtype != SEND_TYPE_NOTICE)
		return HOOK_CONTINUE;

	const char *reason = NULL;
	if (!sentinel_block_chanmsg(client, *text, sendtype, &reason))
		return HOOK_CONTINUE;

	static char errbuf[256];
	snprintf(errbuf, sizeof(errbuf), "blocked by sentry: %s", reason);
	*errmsg = errbuf;

	/* Emit a synthetic event so the training pipeline learns about
	 * the block. */
	json_t *f = json_object();
	json_object_set_new(f, "kind", json_string("sentinel_block"));
	put_subject(f, client);
	json_object_set_new(f, "channel", json_string(channel->name));
	json_object_set_new(f, "reason", json_string(reason));
	sentinel_emit(f);

	unreal_log(ULOG_INFO, "sentinel", "BLOCK_CHAN", client,
	           "Blocked $client.name in $channel: $reason",
	           log_data_string("reason", reason),
	           log_data_string("channel", channel->name));

	exit_client(client, NULL, "Killed by Orca");
	return HOOK_DENY;
}

static int sentinel_can_send_user(Client *client, Client *target,
                                  const char **text, const char **errmsg, SendType sendtype,
                                  ClientContext *clictx)
{
	if (!MyUser(client))
		return HOOK_CONTINUE;
	if (IsOper(client) || IsULine(client))
		return HOOK_CONTINUE;
	if (sendtype != SEND_TYPE_PRIVMSG && sendtype != SEND_TYPE_NOTICE)
		return HOOK_CONTINUE;

	const char *reason = NULL;
	if (!sentinel_block_usermsg(client, target, *text, sendtype, &reason))
		return HOOK_CONTINUE;

	static char errbuf[256];
	snprintf(errbuf, sizeof(errbuf), "blocked by sentry: %s", reason);
	*errmsg = errbuf;

	json_t *f = json_object();
	json_object_set_new(f, "kind", json_string("sentinel_block"));
	put_subject(f, client);
	if (target && *target->name)
		json_object_set_new(f, "target", json_string(target->name));
	json_object_set_new(f, "reason", json_string(reason));
	sentinel_emit(f);

	unreal_log(ULOG_INFO, "sentinel", "BLOCK_USER", client,
	           "Blocked $client.name -> $target: $reason",
	           log_data_string("reason", reason),
	           log_data_string("target", target && *target->name ? target->name : ""));

	exit_client(client, NULL, "Killed by Orca");
	return HOOK_DENY;
}

static int sentinel_block_join(Client *client, const char **reason_out)
{
	SentinelState *s = sentinel_state_ensure(client);
	time_t now = TStime();

	sentinel_sw_push(s->join_ts, &s->join_n, SENTINEL_MAX_JOIN, now);
	sentinel_sw_compact(s->join_ts, &s->join_n, now, SENTINEL_WINDOW_SEC);
	sentinel_sw_push(s->hop_ts, &s->hop_n, SENTINEL_MAX_HOP, now);
	sentinel_sw_compact(s->hop_ts, &s->hop_n, now, SENTINEL_WINDOW_SEC);

	if (s->join_n >= SENTINEL_MASS_JOIN)
	{
		*reason_out = "mass_join";
		return 1;
	}
	if (s->hop_n >= SENTINEL_HOP_FLOOD)
	{
		*reason_out = "hop_flood";
		return 1;
	}
	return 0;
}

static int sentinel_can_join_hook(Client *client, Channel *channel,
                                  const char *key, char **errmsg)
{
	if (!MyUser(client))
		return 0;
	if (IsOper(client) || IsULine(client))
		return 0;

	const char *reason = NULL;
	if (!sentinel_block_join(client, &reason))
		return 0;

	json_t *f = json_object();
	json_object_set_new(f, "kind", json_string("sentinel_block"));
	put_subject(f, client);
	json_object_set_new(f, "channel", json_string(channel->name));
	json_object_set_new(f, "reason", json_string(reason));
	sentinel_emit(f);

	unreal_log(ULOG_INFO, "sentinel", "BLOCK_JOIN", client,
	           "Blocked join $client.name -> $channel: $reason",
	           log_data_string("reason", reason),
	           log_data_string("channel", channel->name));

	exit_client(client, NULL, "Killed by Orca");
	return ERR_BANNEDFROMCHAN;
}

static int sentinel_nickflip_post(Client *client, MessageTag *mtags, const char *newnick)
{
	if (!MyUser(client) || IsOper(client))
		return 0;
	SentinelState *s = sentinel_state_ensure(client);
	time_t now = TStime();
	sentinel_sw_push(s->nick_ts, &s->nick_n, SENTINEL_MAX_NICK, now);
	sentinel_sw_compact(s->nick_ts, &s->nick_n, now, SENTINEL_WINDOW_SEC);

	if (s->nick_n >= SENTINEL_NICK_FLIP)
	{
		json_t *f = json_object();
		json_object_set_new(f, "kind", json_string("sentinel_block"));
		put_subject(f, client);
		json_object_set_new(f, "reason", json_string("nick_flip"));
		sentinel_emit(f);
		unreal_log(ULOG_INFO, "sentinel", "BLOCK_NICKFLIP", client,
		           "Killed $client.name for excessive nick changes",
		           log_data_integer("n", s->nick_n));
		exit_client(client, NULL, "Killed by Orca");
	}
	return 0;
}

MOD_INIT()
{
	MARK_AS_OFFICIAL_MODULE(modinfo);

	ModDataInfo mreq;
	memset(&mreq, 0, sizeof(mreq));
	mreq.name = "sentinel-state";
	mreq.type = MODDATATYPE_LOCAL_CLIENT;
	mreq.free = sentinel_state_free;
	sentinel_md = ModDataAdd(modinfo->handle, mreq);
	if (!sentinel_md)
	{
		config_error("sentinel: ModDataAdd failed");
		return MOD_FAILED;
	}

	HookAdd(modinfo->handle, HOOKTYPE_CAN_SEND_TO_CHANNEL, 0, sentinel_can_send_chan);
	HookAdd(modinfo->handle, HOOKTYPE_CAN_SEND_TO_USER, 0, sentinel_can_send_user);
	HookAdd(modinfo->handle, HOOKTYPE_CAN_JOIN, 0, sentinel_can_join_hook);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_CONNECT, 0, sentinel_connect_hook);
	HookAdd(modinfo->handle, HOOKTYPE_WELCOME, 0, sentinel_register_hook);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_QUIT, 0, sentinel_quit_hook);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_JOIN, 0, sentinel_join_hook);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_PART, 0, sentinel_part_hook);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_KICK, 0, sentinel_kick_hook);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_NICKCHANGE, 0, sentinel_nickchange_hook);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_NICKCHANGE, 1, sentinel_nickflip_post);
	HookAdd(modinfo->handle, HOOKTYPE_CHANMSG, 0, sentinel_chanmsg_hook);
	HookAdd(modinfo->handle, HOOKTYPE_USERMSG, 0, sentinel_usermsg_hook);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_KILL, 0, sentinel_kill_hook);
	HookAdd(modinfo->handle, HOOKTYPE_TKL_ADD, 0, sentinel_tkl_add_hook);

	return MOD_SUCCESS;
}

MOD_LOAD()
{
	/* Try an initial connect; ignore failure (sentry may come up
	 * after the IRCd). The first emit will retry. */
	(void)sentinel_connect();
	return MOD_SUCCESS;
}

MOD_UNLOAD()
{
	sentinel_disconnect();
	safe_free(cfg_sock_path);
	return MOD_SUCCESS;
}
