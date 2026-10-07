/*
  Licence: GPLv3 or later
  Copyright Ⓒ 2022 Valerie Pond
  draft/react

  React to a message.

  obbyircd note: adapted from val's unrealircd-contrib react.c
  (https://github.com/ValwareIRC/valware-unrealircd-mods/tree/main/react)
  to live in src/modules/ as a built-in (the upstream version was a
  Module-Manager third/ install). The +draft/react mtag handler is
  preserved verbatim; a text-only CTCP ACTION fallback was added so
  that channel members who haven't negotiated message-tags still see
  reactions as a /me line like:
      Valware reacted with ❤️ to "alice Hey did you see this..."

  The fallback needs to quote the original message body. We don't rely
  on the history backend for that (it requires chanmode +H, which isn't
  guaranteed) -- instead we keep a tiny in-memory LRU mapping
  msgid -> (nick, body) populated from PRE_CHANMSG for PRIVMSGs. 256
  entries server-wide is plenty for the reaction-within-seconds use
  case and bounds memory tightly.
*/

#include "unrealircd.h"

ModuleHeader MOD_HEADER = {
    "react",
    "0.4",
    "+draft/react (IRCv3) + text-only fallback for clients without message-tags",
    "Valware",
    "unrealircd-6",
};

/* Set in MOD_LOAD by querying ClientCapabilityBit("message-tags"). 0
 * means message-tags isn't loaded -- the fallback then fires for every
 * recipient (which is fine: nobody has the cap, so nobody would have
 * seen the +draft/react TAGMSG at all). */
static long CAP_MESSAGE_TAGS_FOR_REACT = 0L;

/* How many characters of the original message we quote in the fallback
 * line before truncating with "...". Keep it small enough that even a
 * worst-case (40-char nick prefix + escaped 4-byte UTF-8 emoji + this
 * preview) stays well under the 510-byte IRC line limit. */
#define REACT_PREVIEW_CHARS 60

/* Capacity of the msgid->message cache. Reactions land seconds after
 * the original message in practice; even a busy channel won't push
 * recent messages out of a 256-deep LRU before a user reacts. */
#define REACT_CACHE_MAX 256

typedef struct ReactCacheEntry {
	struct ReactCacheEntry *next, *prev;
	char *channel;   /* channel name as-stored; compared case-insensitively */
	char *msgid;
	char *nick;
	char *text;      /* original body, CTCP-stripped */
} ReactCacheEntry;

static ReactCacheEntry *react_cache_head = NULL;
static ReactCacheEntry *react_cache_tail = NULL;
static int react_cache_size = 0;

int i3react_mtag_is_ok(Client *client, const char *name, const char *value);
void mtag_add_i3react(Client *client, MessageTag *recv_mtags, MessageTag **mtag_list, const char *signature);
static int react_pre_chanmsg(Client *client, Channel *channel, MessageTag **mtags, const char *text, SendType sendtype);

MOD_INIT()
{
	MessageTagHandlerInfo mtag;

	MARK_AS_OFFICIAL_MODULE(modinfo);

	memset(&mtag, 0, sizeof(mtag));
	mtag.is_ok = i3react_mtag_is_ok;
	mtag.flags = MTAG_HANDLER_FLAGS_NO_CAP_NEEDED;
	mtag.name = "+draft/react";
	MessageTagHandlerAdd(modinfo->handle, &mtag);

	HookAddVoid(modinfo->handle, HOOKTYPE_NEW_MESSAGE, 0, mtag_add_i3react);

	/* Records PRIVMSGs into the cache AND synthesises /me fallbacks
	 * for non-cap recipients on TAGMSGs carrying +draft/react.
	 * PRE_CHANMSG fires for both, after new_message() has populated
	 * mtags with msgid, but before broadcast -- perfect for both
	 * read and write. */
	HookAdd(modinfo->handle, HOOKTYPE_PRE_CHANMSG, 0, react_pre_chanmsg);

	return MOD_SUCCESS;
}

MOD_LOAD()
{
	CAP_MESSAGE_TAGS_FOR_REACT = ClientCapabilityBit("message-tags");
	return MOD_SUCCESS;
}

static void react_cache_free_entry(ReactCacheEntry *e)
{
	safe_free(e->channel);
	safe_free(e->msgid);
	safe_free(e->nick);
	safe_free(e->text);
	safe_free(e);
}

static void react_cache_clear(void)
{
	ReactCacheEntry *e, *next;
	for (e = react_cache_head; e; e = next)
	{
		next = e->next;
		react_cache_free_entry(e);
	}
	react_cache_head = react_cache_tail = NULL;
	react_cache_size = 0;
}

MOD_UNLOAD()
{
	react_cache_clear();
	return MOD_SUCCESS;
}

int i3react_mtag_is_ok(Client *client, const char *name, const char *value)
{
	if (BadPtr(value) || !strlen(value) || strlen(value) > 10)
		return 0;

	return 1;
}

void mtag_add_i3react(Client *client, MessageTag *recv_mtags, MessageTag **mtag_list, const char *signature)
{
	MessageTag *m;

	if (IsUser(client))
	{
		m = find_mtag(recv_mtags, "+draft/react");
		if (m)
		{
			m = duplicate_mtag(m);
			AddListItem(m, *mtag_list);
		}
	}
}

/* Walk a UTF-8 string for up to `chars` codepoints (or to the first
 * stripped trailing CTCP-end / CR / LF), copy the matching byte range
 * into `out`, and append "..." if we cut short. Bytewise truncation is
 * unsafe for emoji / multibyte text in chan content. */
static void utf8_truncate(const char *src, size_t srclen, size_t chars,
                          char *out, size_t outsz)
{
	if (!outsz)
		return;
	size_t i = 0, codepoints = 0;
	/* Trim trailing CTCP-end / NL */
	while (srclen && (src[srclen - 1] == '\1' || src[srclen - 1] == '\r' || src[srclen - 1] == '\n'))
		srclen--;
	while (i < srclen && codepoints < chars)
	{
		unsigned char b = (unsigned char)src[i];
		int extra;
		if (b < 0x80)
			extra = 0;
		else if ((b & 0xE0) == 0xC0)
			extra = 1;
		else if ((b & 0xF0) == 0xE0)
			extra = 2;
		else if ((b & 0xF8) == 0xF0)
			extra = 3;
		else
			extra = 0; /* invalid byte, treat as single */
		size_t step = 1 + (size_t)extra;
		if (i + step > srclen)
			break;
		i += step;
		codepoints++;
	}
	int truncated = (i < srclen);
	size_t copy = i;
	const char *suffix = truncated ? "..." : "";
	if (copy + strlen(suffix) >= outsz)
		copy = outsz - strlen(suffix) - 1;
	memcpy(out, src, copy);
	strcpy(out + copy, suffix);
}

/* Strip "\1ACTION ... [\1]" wrapper from a PRIVMSG body so reactions
 * to /me lines read naturally inside the quote. Returns the stripped
 * portion of `text` (possibly == text) and writes the effective length
 * to *out_len. */
static const char *strip_ctcp_action(const char *text, size_t *out_len)
{
	size_t len = strlen(text);
	if (len >= 8 && text[0] == '\1' && !strncmp(text + 1, "ACTION ", 7))
	{
		text += 8;
		len -= 8;
	}
	while (len && (text[len - 1] == '\1' || text[len - 1] == '\r' || text[len - 1] == '\n'))
		len--;
	*out_len = len;
	return text;
}

static void react_cache_remember(const char *channel, const char *msgid,
                                 const char *nick, const char *text)
{
	ReactCacheEntry *e;
	size_t text_len;
	const char *body;

	if (!channel || !msgid || !nick || !text)
		return;

	body = strip_ctcp_action(text, &text_len);

	e = safe_alloc(sizeof(ReactCacheEntry));
	safe_strdup(e->channel, channel);
	safe_strdup(e->msgid, msgid);
	safe_strdup(e->nick, nick);
	e->text = safe_alloc(text_len + 1);
	memcpy(e->text, body, text_len);
	e->text[text_len] = '\0';

	e->next = react_cache_head;
	e->prev = NULL;
	if (react_cache_head)
		react_cache_head->prev = e;
	react_cache_head = e;
	if (!react_cache_tail)
		react_cache_tail = e;
	react_cache_size++;

	while (react_cache_size > REACT_CACHE_MAX && react_cache_tail)
	{
		ReactCacheEntry *victim = react_cache_tail;
		react_cache_tail = victim->prev;
		if (react_cache_tail)
			react_cache_tail->next = NULL;
		else
			react_cache_head = NULL;
		react_cache_free_entry(victim);
		react_cache_size--;
	}
}

static ReactCacheEntry *react_cache_find(const char *channel, const char *msgid)
{
	ReactCacheEntry *e;
	if (!channel || !msgid)
		return NULL;
	for (e = react_cache_head; e; e = e->next)
	{
		if (!strcasecmp(e->channel, channel) && !strcmp(e->msgid, msgid))
			return e;
	}
	return NULL;
}

static int react_pre_chanmsg(Client *client, Channel *channel, MessageTag **mtags,
                             const char *text, SendType sendtype)
{
	MessageTag *m_react, *m_reply, *m_msgid;
	Member *mem;
	const char *emoji;
	char origin_nick[NICKLEN + 1] = "";
	char origin_preview[256] = "";
	char actionbuf[400];
	char usermask_user[USERLEN + 1] = "*";
	char usermask_host[HOSTLEN + 1] = "*";

	if (!IsUser(client))
		return 0;
	if (!mtags || !*mtags)
		return 0;

	/* On PRIVMSG: record (channel, msgid) -> (nick, body) for later
	 * react lookup. The msgid lives in mtags after new_message(). */
	if (sendtype == SEND_TYPE_PRIVMSG)
	{
		m_msgid = find_mtag(*mtags, "msgid");
		if (m_msgid && !BadPtr(m_msgid->value) && text && *text)
			react_cache_remember(channel->name, m_msgid->value,
			                     client->name, text);
		return 0;
	}

	if (sendtype != SEND_TYPE_TAGMSG)
		return 0;

	m_react = find_mtag(*mtags, "+draft/react");
	if (!m_react || BadPtr(m_react->value))
		return 0;

	emoji = m_react->value;

	/* Look up the original message via +reply (ratified) or
	 * +draft/reply (legacy). Lookup failure is non-fatal -- we still
	 * emit a fallback without a quoted preview. */
	m_reply = find_mtag(*mtags, "+reply");
	if (!m_reply)
		m_reply = find_mtag(*mtags, "+draft/reply");

	if (m_reply && !BadPtr(m_reply->value))
	{
		ReactCacheEntry *entry = react_cache_find(channel->name, m_reply->value);
		if (entry)
		{
			strlcpy(origin_nick, entry->nick, sizeof(origin_nick));
			utf8_truncate(entry->text, strlen(entry->text),
			              REACT_PREVIEW_CHARS,
			              origin_preview, sizeof(origin_preview));
		}
	}

	/* Build the synthesised /me text once. */
	if (*origin_nick && *origin_preview)
		snprintf(actionbuf, sizeof(actionbuf),
		         "\1ACTION reacted with %s to \"%s %s\"\1",
		         emoji, origin_nick, origin_preview);
	else if (*origin_nick)
		snprintf(actionbuf, sizeof(actionbuf),
		         "\1ACTION reacted with %s to %s's message\1",
		         emoji, origin_nick);
	else
		snprintf(actionbuf, sizeof(actionbuf),
		         "\1ACTION reacted with %s\1", emoji);

	if (client->user)
	{
		strlcpy(usermask_user, client->user->username, sizeof(usermask_user));
		strlcpy(usermask_host, GetHost(client), sizeof(usermask_host));
	}

	for (mem = channel->members; mem; mem = mem->next)
	{
		Client *target = mem->client;
		if (!MyUser(target))
			continue; /* remote: the other server's react module is
			           * responsible for fanning out fallbacks to its
			           * own local non-cap members. */
		if (target == client)
			continue; /* don't echo the user's own reaction back as
			           * a /me; their client renders the reaction
			           * inline already. */
		if (CAP_MESSAGE_TAGS_FOR_REACT && HasCapabilityFast(target, CAP_MESSAGE_TAGS_FOR_REACT))
			continue; /* cap-aware: the normal TAGMSG broadcast
			           * delivers the real reaction tag. */

		sendto_one(target, NULL,
		           ":%s!%s@%s PRIVMSG %s :%s",
		           client->name, usermask_user, usermask_host,
		           channel->name, actionbuf);
	}

	return 0;
}
