/* src/modules/webpush.c - IRCv3 draft/webpush (and soju.im/webpush).
 *
 * Implements the IRC-protocol half of Web Push (RFC 8030/8291/8292):
 *
 *   * advertises the `draft/webpush` and `soju.im/webpush` capabilities
 *     once a backend is configured
 *   * advertises `VAPID=<base64url-public-key>` in ISUPPORT, taken from
 *     set::webpush::vapid-key or fetched from the backend
 *   * handles `WEBPUSH REGISTER <endpoint> <keys>` and
 *     `WEBPUSH UNREGISTER <endpoint>` (keys = message-tag form:
 *     `p256dh=...;auth=...`), storing subscriptions per account in
 *     obsidian.db
 *   * on a DM to an account-holder that has push subscriptions, POSTs
 *     a small JSON blob (subscription + the plaintext IRC line) to the
 *     hosted-backend's /push/send, which owns the VAPID private key and
 *     does the actual RFC 8291 encryption + delivery.
 *
 * We deliberately don't encrypt here: obbyircd's outbound HTTP body is
 * strlen-bounded and would truncate aes128gcm ciphertext at its first
 * NUL.  The obbyircd->backend hop is plain JSON (text), so that path is
 * fine; the binary ciphertext only ever exists inside the Go backend.
 *
 * Config:
 *   set {
 *     webpush {
 *       backend-url 'https://api.example.com';  // hosted-backend base, https
 *       backend-key "<IRC_SERVER_KEY>";        // X-ObsidianIRC-Key
 *       vapid-key "<base64url public key>";    // optional, else /push/vapid-key
 *       ttl 86400;                             // optional, push TTL secs
 *     }
 *   }
 */
#include "unrealircd.h"
#include "obsidian.h"
#include <sqlite3.h>

ModuleHeader MOD_HEADER = {
    "webpush",
    "0.1",
    "IRCv3 soju.im/webpush: per-account Web Push subscriptions",
    "obbyircd",
    "unrealircd-6",
};

#define WEBPUSH_DEFAULT_TTL 86400

struct cfgstruct {
	char *backend_url;
	char *backend_key;
	char *vapid_key;
	int ttl;
};
static struct cfgstruct cfg;

#define WEBPUSH_ENDPOINT_MAX 1024

static sqlite3 *wp_db = NULL;
static Module *wp_module = NULL;
static char *vapid_public = NULL;
static long CAP_WEBPUSH = 0L;
static long CAP_SOJU_WEBPUSH = 0L;

/* Forward decls */
static int wp_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
static int wp_configrun(ConfigFile *cf, ConfigEntry *ce, int type);
static int wp_open_db(void);
static void wp_create_tables(void);
static int wp_usermsg(Client *client, Client *to, MessageTag *mtags,
                      const char *text, SendType sendtype);
static int wp_chanmsg(Client *client, Channel *channel, int sendflags,
                      const char *member_modes, const char *target,
                      MessageTag *mtags, const char *text, SendType sendtype);
CMD_FUNC(cmd_webpush);
static void wp_fetch_vapid_key(void);
EVENT(wp_vapid_key_retry);
static int wp_capability_visible(Client *client);
static void wp_delete_subscription(const char *account, const char *endpoint);
static void wp_vapid_key_cb(OutgoingWebRequest *request, OutgoingWebResponse *response);
static void wp_push_result_cb(OutgoingWebRequest *request, OutgoingWebResponse *response);
static void wp_generic_free(ModData *m);

MOD_TEST()
{
	memset(&cfg, 0, sizeof(cfg));
	cfg.ttl = WEBPUSH_DEFAULT_TTL;
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, wp_configtest);
	return MOD_SUCCESS;
}

MOD_INIT()
{
	ClientCapabilityInfo c;

	MARK_AS_OFFICIAL_MODULE(modinfo);
	wp_module = modinfo->handle;
	LoadPersistentPointer(modinfo, vapid_public, wp_generic_free);

	if (wp_open_db() != 0)
		return MOD_FAILED;
	wp_create_tables();

	memset(&c, 0, sizeof(c));
	c.name = "draft/webpush";
	c.visible = wp_capability_visible;
	ClientCapabilityAdd(modinfo->handle, &c, &CAP_WEBPUSH);
	c.name = "soju.im/webpush";
	ClientCapabilityAdd(modinfo->handle, &c, &CAP_SOJU_WEBPUSH);

	CommandAdd(modinfo->handle, "WEBPUSH", cmd_webpush, MAXPARA, CMD_USER);
	RegisterApiCallbackWebResponse(modinfo->handle, "webpush_vapid_key", wp_vapid_key_cb);
	RegisterApiCallbackWebResponse(modinfo->handle, "webpush_push_result", wp_push_result_cb);

	HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, wp_configrun);
	HookAdd(modinfo->handle, HOOKTYPE_USERMSG, 0, wp_usermsg);
	HookAdd(modinfo->handle, HOOKTYPE_CHANMSG, 0, wp_chanmsg);

	return MOD_SUCCESS;
}

/* Clients only see push once we can deliver it: a backend to send through
 * and a VAPID key for them to subscribe against. */
static int wp_capability_visible(Client *client)
{
	return cfg.backend_url && cfg.backend_key && vapid_public;
}

static int wp_wants_fetched_key(void)
{
	return cfg.backend_url && cfg.backend_key && !(cfg.vapid_key && *cfg.vapid_key);
}

static void wp_generic_free(ModData *m)
{
	safe_free(m->ptr);
}

/* We announce the key to clients already connected so they can subscribe without reconnecting. */
static void wp_announce_vapid_key(void)
{
	Client *client;
	char token[300];

	send_cap_notify(1, "draft/webpush");
	send_cap_notify(1, "soju.im/webpush");
	snprintf(token, sizeof(token), "VAPID=%s", vapid_public);
	list_for_each_entry(client, &lclient_list, lclient_node)
		if (IsUser(client))
			sendnumeric(client, RPL_ISUPPORT, token);
}

static void wp_set_vapid_key(const char *key)
{
	int changed = !vapid_public || strcmp(vapid_public, key);

	safe_strdup(vapid_public, key);
	ISupportSetFmt(wp_module, "VAPID", "%s", key);
	if (changed)
		wp_announce_vapid_key();
}

MOD_LOAD()
{
	if (cfg.vapid_key && *cfg.vapid_key)
		wp_set_vapid_key(cfg.vapid_key);
	else if (cfg.backend_url && cfg.backend_key)
	{
		if (vapid_public)
			ISupportSetFmt(wp_module, "VAPID", "%s", vapid_public);
		wp_fetch_vapid_key();
	}
	return MOD_SUCCESS;
}

MOD_UNLOAD()
{
	if (wp_db)
		sqlite3_close(wp_db);
	wp_db = NULL;
	safe_free(cfg.backend_url);
	safe_free(cfg.backend_key);
	safe_free(cfg.vapid_key);
	SavePersistentPointer(modinfo, vapid_public);
	return MOD_SUCCESS;
}

/* ------------------------------------------------------------------
 * Config
 * ------------------------------------------------------------------ */

static int wp_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs)
{
	ConfigEntry *cep;
	int errors = 0;

	if (type != CONFIG_SET)
		return 0;
	if (!ce || !ce->name || strcmp(ce->name, "webpush"))
		return 0;

	for (cep = ce->items; cep; cep = cep->next)
	{
		if (!cep->name)
			continue;
		if (!strcmp(cep->name, "backend-url") ||
		    !strcmp(cep->name, "backend-key") ||
		    !strcmp(cep->name, "vapid-key"))
		{
			if (!cep->value || !*cep->value)
			{
				config_error("%s:%i: set::webpush::%s requires a value",
				             cep->file->filename, cep->line_number, cep->name);
				errors++;
			} else if (!strcmp(cep->name, "backend-url") && strncmp(cep->value, "https://", 8))
			{
				config_error("%s:%i: set::webpush::backend-url must be an https:// URL",
				             cep->file->filename, cep->line_number);
				errors++;
			}
		} else if (!strcmp(cep->name, "ttl"))
		{
			int n = cep->value ? atoi(cep->value) : -1;
			if (n < 0 || n > 2592000)
			{
				config_error("%s:%i: set::webpush::ttl must be 0..2592000",
				             cep->file->filename, cep->line_number);
				errors++;
			}
		} else
		{
			config_error("%s:%i: unknown directive set::webpush::%s",
			             cep->file->filename, cep->line_number, cep->name);
			errors++;
		}
	}

	*errs = errors;
	return errors ? -1 : 1;
}

static int wp_configrun(ConfigFile *cf, ConfigEntry *ce, int type)
{
	ConfigEntry *cep;
	if (type != CONFIG_SET)
		return 0;
	if (!ce || !ce->name || strcmp(ce->name, "webpush"))
		return 0;

	for (cep = ce->items; cep; cep = cep->next)
	{
		if (!cep->name || !cep->value)
			continue;
		if (!strcmp(cep->name, "backend-url"))
			safe_strdup(cfg.backend_url, cep->value);
		else if (!strcmp(cep->name, "backend-key"))
			safe_strdup(cfg.backend_key, cep->value);
		else if (!strcmp(cep->name, "vapid-key"))
			safe_strdup(cfg.vapid_key, cep->value);
		else if (!strcmp(cep->name, "ttl"))
			cfg.ttl = atoi(cep->value);
	}
	return 1;
}

/* ------------------------------------------------------------------
 * Storage
 * ------------------------------------------------------------------ */

static int wp_open_db(void)
{
	if (sqlite3_open(OBSIDIAN_DB, &wp_db) != SQLITE_OK)
	{
		config_error("webpush: could not open %s: %s", OBSIDIAN_DB,
		             wp_db ? sqlite3_errmsg(wp_db) : "(open failed)");
		if (wp_db)
			sqlite3_close(wp_db);
		wp_db = NULL;
		return -1;
	}
	sqlite3_exec(wp_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
	sqlite3_exec(wp_db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);
	return 0;
}

static void wp_create_tables(void)
{
	const char *sql =
	    "CREATE TABLE IF NOT EXISTS webpush_subscriptions ("
	    "  account TEXT NOT NULL,"
	    "  endpoint TEXT NOT NULL,"
	    "  p256dh TEXT NOT NULL,"
	    "  auth TEXT NOT NULL,"
	    "  created_at INTEGER NOT NULL,"
	    "  PRIMARY KEY (account, endpoint)"
	    ");"
	    "CREATE INDEX IF NOT EXISTS webpush_subs_account "
	    "  ON webpush_subscriptions(account);";
	char *err = NULL;
	if (sqlite3_exec(wp_db, sql, NULL, NULL, &err) != SQLITE_OK)
	{
		config_error("webpush: schema create failed: %s", err ? err : "(unknown)");
		if (err)
			sqlite3_free(err);
	}
}

/* ------------------------------------------------------------------
 * WEBPUSH command
 * ------------------------------------------------------------------ */

/* Parse a message-tag-form keys string ("p256dh=AAA;auth=BBB") into
 * its p256dh / auth components.  Writes heap-dup'd values to *p256dh
 * and *auth (caller frees) or leaves them NULL.  Returns 1 if both
 * required keys were found. */
static int wp_parse_keys(const char *keys, char **p256dh, char **auth)
{
	char buf[2048];
	char *tok, *save = NULL;

	*p256dh = NULL;
	*auth = NULL;
	strlcpy(buf, keys, sizeof(buf));

	for (tok = strtoken(&save, buf, ";"); tok; tok = strtoken(&save, NULL, ";"))
	{
		char *eq = strchr(tok, '=');
		if (!eq)
			continue;
		*eq = '\0';
		const char *val = eq + 1;
		if (!strcmp(tok, "p256dh") && *val && !*p256dh)
			*p256dh = strdup(val);
		else if (!strcmp(tok, "auth") && *val && !*auth)
			*auth = strdup(val);
	}
	return (*p256dh && *auth) ? 1 : 0;
}

CMD_FUNC(cmd_webpush)
{
	if (!MyUser(client))
		return;

	if (parc < 3 || BadPtr(parv[1]) || BadPtr(parv[2]))
	{
		sendto_one(client, NULL, ":%s FAIL WEBPUSH INVALID_PARAMS :Insufficient parameters", me.name);
		return;
	}

	/* Only account-holders can register: subscriptions are keyed by
	 * account so a push survives reconnects and nick changes. */
	if (!IsLoggedIn(client))
	{
		sendto_one(client, NULL,
		           ":%s FAIL WEBPUSH INVALID_PARAMS :You must be logged in to manage push subscriptions",
		           me.name);
		return;
	}

	if (!strcasecmp(parv[1], "REGISTER"))
	{
		const char *endpoint = parv[2];
		char *p256dh = NULL, *errk_auth = NULL;

		/* Push services are public HTTPS endpoints; the backend refuses
		 * anything else, so we turn it away here with a clear error. */
		if (strncmp(endpoint, "https://", 8) || strlen(endpoint) > WEBPUSH_ENDPOINT_MAX)
		{
			sendto_one(client, NULL,
			           ":%s FAIL WEBPUSH INVALID_PARAMS REGISTER :Invalid endpoint",
			           me.name);
			return;
		}

		if (BadPtr(parv[3]) || !wp_parse_keys(parv[3], &p256dh, &errk_auth))
		{
			sendto_one(client, NULL,
			           ":%s FAIL WEBPUSH INVALID_PARAMS REGISTER :keys must include p256dh and auth",
			           me.name);
			if (p256dh)
				free(p256dh);
			if (errk_auth)
				free(errk_auth);
			return;
		}

		sqlite3_stmt *st = NULL;
		const char *sql =
		    "INSERT INTO webpush_subscriptions (account, endpoint, p256dh, auth, created_at) "
		    "VALUES (?, ?, ?, ?, ?) "
		    "ON CONFLICT(account, endpoint) DO UPDATE SET "
		    "  p256dh=excluded.p256dh, auth=excluded.auth, created_at=excluded.created_at";
		if (wp_db && sqlite3_prepare_v2(wp_db, sql, -1, &st, NULL) == SQLITE_OK)
		{
			sqlite3_bind_text(st, 1, client->user->account, -1, SQLITE_TRANSIENT);
			sqlite3_bind_text(st, 2, endpoint, -1, SQLITE_TRANSIENT);
			sqlite3_bind_text(st, 3, p256dh, -1, SQLITE_TRANSIENT);
			sqlite3_bind_text(st, 4, errk_auth, -1, SQLITE_TRANSIENT);
			sqlite3_bind_int64(st, 5, (long long)TStime());
			int rc = sqlite3_step(st);
			sqlite3_finalize(st);
			if (rc == SQLITE_DONE)
			{
				sendto_one(client, NULL, ":%s WEBPUSH REGISTER %s",
				           me.name, endpoint);
			} else
			{
				sendto_one(client, NULL,
				           ":%s FAIL WEBPUSH INTERNAL_ERROR REGISTER :Could not store subscription",
				           me.name);
			}
		} else
		{
			sendto_one(client, NULL,
			           ":%s FAIL WEBPUSH INTERNAL_ERROR REGISTER :Database unavailable",
			           me.name);
		}

		free(p256dh);
		free(errk_auth);
		return;
	}

	if (!strcasecmp(parv[1], "UNREGISTER"))
	{
		const char *endpoint = parv[2];
		wp_delete_subscription(client->user->account, endpoint);
		/* Echo success unconditionally -- UNREGISTER is idempotent. */
		sendto_one(client, NULL, ":%s WEBPUSH UNREGISTER %s", me.name, endpoint);
		return;
	}

	sendto_one(client, NULL,
	           ":%s FAIL WEBPUSH INVALID_PARAMS %s :Unknown subcommand",
	           me.name, parv[1]);
}

/* ------------------------------------------------------------------
 * Push trigger (DM to account-holder)
 * ------------------------------------------------------------------ */

/* Append `src` to `dst` as a JSON string value (with surrounding
 * quotes), escaping per RFC 8259.  Truncates safely at the buffer
 * limit.  `dstsize` is the total size of dst. */
static void json_append_string(char *dst, size_t dstsize, const char *src)
{
	size_t len = strlen(dst);
	if (len + 1 >= dstsize)
		return;
	dst[len++] = '"';
	for (const char *p = src; *p && len + 8 < dstsize; p++)
	{
		unsigned char ch = (unsigned char)*p;
		switch (ch)
		{
			case '"':
				dst[len++] = '\\';
				dst[len++] = '"';
				break;
			case '\\':
				dst[len++] = '\\';
				dst[len++] = '\\';
				break;
			case '\n':
				dst[len++] = '\\';
				dst[len++] = 'n';
				break;
			case '\r':
				dst[len++] = '\\';
				dst[len++] = 'r';
				break;
			case '\t':
				dst[len++] = '\\';
				dst[len++] = 't';
				break;
			default:
				if (ch < 0x20)
				{
					int n = snprintf(dst + len, dstsize - len, "\\u%04x", ch);
					if (n > 0)
						len += n;
				} else
				{
					dst[len++] = (char)ch;
				}
		}
	}
	if (len + 1 < dstsize)
		dst[len++] = '"';
	dst[len] = '\0';
}

static void wp_delete_subscription(const char *account, const char *endpoint)
{
	sqlite3_stmt *st = NULL;
	const char *sql =
	    "DELETE FROM webpush_subscriptions WHERE account=? AND endpoint=?";
	if (!wp_db || sqlite3_prepare_v2(wp_db, sql, -1, &st, NULL) != SQLITE_OK)
		return;
	sqlite3_bind_text(st, 1, account, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 2, endpoint, -1, SQLITE_TRANSIENT);
	sqlite3_step(st);
	sqlite3_finalize(st);
}

static char *wp_subscription_ref(const char *account, const char *endpoint)
{
	size_t n = strlen(account) + strlen(endpoint) + 2;
	char *ref = safe_alloc(n);
	snprintf(ref, n, "%s %s", account, endpoint);
	return ref;
}

/* Result callback: surfaces transport failures, and drops a subscription
 * the push service reports as gone (404/410, relayed by the backend), so
 * we stop pushing to a browser that unsubscribed. */
static void wp_push_result_cb(OutgoingWebRequest *request,
                              OutgoingWebResponse *response)
{
	char *ref = response->ptr;
	char *endpoint = ref ? strchr(ref, ' ') : NULL;
	json_t *result;
	json_error_t jerr;
	int status;

	if (response->errorbuf)
		unreal_log(ULOG_WARNING, "webpush", "WP_SEND_FAILED", NULL,
		           "push POST to backend failed: $err",
		           log_data_string("err", response->errorbuf));
	else if (endpoint && response->memory &&
	         (result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr)))
	{
		status = json_object_get_integer(result, "status", 0);
		if (status == 404 || status == 410)
		{
			*endpoint++ = '\0';
			wp_delete_subscription(ref, endpoint);
		}
		json_decref(result);
	}
	safe_free(ref);
}

static void wp_vapid_key_cb(OutgoingWebRequest *request,
                            OutgoingWebResponse *response)
{
	json_t *result = NULL;
	json_error_t jerr;
	const char *key = NULL;

	if (!wp_wants_fetched_key())
		return;
	if (!response->errorbuf && response->memory)
		result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (result)
		key = json_object_get_string(result, "publicKey");
	if (key && *key && strlen(key) < 256)
		wp_set_vapid_key(key);
	else
	{
		unreal_log(ULOG_WARNING, "webpush", "WP_VAPID_FAILED", NULL,
		           "could not fetch the VAPID key from the backend, retrying in 30s: $err",
		           log_data_string("err", response->errorbuf ? response->errorbuf : "no publicKey in the reply"));
		/* The backend often starts after us, so we ask again until it answers. */
		if (!EventFind("webpush_vapid_key_retry"))
			EventAdd(wp_module, "webpush_vapid_key_retry", wp_vapid_key_retry, NULL, 30000, 1);
	}
	if (result)
		json_decref(result);
}

EVENT(wp_vapid_key_retry)
{
	wp_fetch_vapid_key();
}

static void wp_fetch_vapid_key(void)
{
	OutgoingWebRequest *req;
	char url[512];

	if (!wp_wants_fetched_key())
		return;
	req = safe_alloc(sizeof(OutgoingWebRequest));
	snprintf(url, sizeof(url), "%s/push/vapid-key", cfg.backend_url);
	safe_strdup(req->url, url);
	req->http_method = HTTP_METHOD_GET;
	safe_strdup(req->apicallback, "webpush_vapid_key");
	req->max_redirects = 0;
	req->connect_timeout = 5;
	req->transfer_timeout = 10;
	url_start_async(req);
}

static void wp_send_push(const char *account, const char *endpoint,
                         const char *p256dh, const char *auth,
                         const char *payload)
{
	OutgoingWebRequest *req;
	char url[512];
	/* We size for every byte escaping to a six-byte \u sequence so the JSON always closes. */
	char body[6 * (WEBPUSH_ENDPOINT_MAX + 2 * BUFSIZE) + 256];
	NameValuePrioList *headers = NULL;

	if (!cfg.backend_url || !cfg.backend_key)
		return;

	snprintf(url, sizeof(url), "%s/push/send", cfg.backend_url);

	/* Build the JSON body.  endpoint/p256dh/auth are base64url (safe
	 * chars) but we escape them anyway for robustness; payload is an
	 * arbitrary IRC line and definitely needs escaping. */
	strlcpy(body, "{\"endpoint\":", sizeof(body));
	json_append_string(body, sizeof(body), endpoint);
	strlcat(body, ",\"p256dh\":", sizeof(body));
	json_append_string(body, sizeof(body), p256dh);
	strlcat(body, ",\"auth\":", sizeof(body));
	json_append_string(body, sizeof(body), auth);
	strlcat(body, ",\"payload\":", sizeof(body));
	json_append_string(body, sizeof(body), payload);
	{
		char ttlbuf[64];
		snprintf(ttlbuf, sizeof(ttlbuf), ",\"ttl\":%d}", cfg.ttl);
		strlcat(body, ttlbuf, sizeof(body));
	}

	add_nvplist(&headers, 0, "Content-Type", "application/json");
	add_nvplist(&headers, 1, "X-ObsidianIRC-Key", cfg.backend_key);

	req = safe_alloc(sizeof(OutgoingWebRequest));
	safe_strdup(req->url, url);
	req->http_method = HTTP_METHOD_POST;
	safe_strdup(req->body, body);
	req->headers = headers;
	safe_strdup(req->apicallback, "webpush_push_result");
	req->callback_data = wp_subscription_ref(account, endpoint);
	req->max_redirects = 0;
	req->connect_timeout = 5;
	req->transfer_timeout = 10;
	url_start_async(req);
}

/* Build the push payload: one IRC message, no trailing CRLF, message
 * tags dropped except msgid and time, which let the client open the chat at
 * that message.  Shape:
 *   [@msgid=<id>;time=<ts> ]:<nick>!<user>@<host> <CMD> <target> :<text>
 * `target` is the recipient nick (DM) or the channel name (highlight).
 */
static void wp_build_payload(char *buf, size_t n, Client *sender,
                             const char *target, MessageTag *mtags,
                             const char *cmd, const char *text)
{
	MessageTag *mid = find_mtag(mtags, "msgid");
	MessageTag *sent = find_mtag(mtags, "time");
	const char *src_user = IsUser(sender) ? sender->user->username : "*";
	const char *src_host = IsUser(sender) ? GetHost(sender) : me.name;
	char tags[256] = "";

	if (mid && mid->value)
		snprintf(tags, sizeof(tags), "msgid=%s", mid->value);
	if (sent && sent->value)
	{
		if (*tags)
			strlcat(tags, ";", sizeof(tags));
		strlcat(tags, "time=", sizeof(tags));
		strlcat(tags, sent->value, sizeof(tags));
	}

	if (*tags)
		snprintf(buf, n, "@%s :%s!%s@%s %s %s :%s",
		         tags, sender->name, src_user, src_host,
		         cmd, target, text ? text : "");
	else
		snprintf(buf, n, ":%s!%s@%s %s %s :%s",
		         sender->name, src_user, src_host,
		         cmd, target, text ? text : "");
}

/* Push `payload` to every stored subscription for `account`. */
static void wp_push_to_account(const char *account, const char *payload)
{
	sqlite3_stmt *st = NULL;
	const char *sql =
	    "SELECT endpoint, p256dh, auth FROM webpush_subscriptions WHERE account=?";
	if (!wp_db || sqlite3_prepare_v2(wp_db, sql, -1, &st, NULL) != SQLITE_OK)
		return;
	sqlite3_bind_text(st, 1, account, -1, SQLITE_TRANSIENT);
	while (sqlite3_step(st) == SQLITE_ROW)
	{
		const char *endpoint = (const char *)sqlite3_column_text(st, 0);
		const char *p256dh = (const char *)sqlite3_column_text(st, 1);
		const char *auth = (const char *)sqlite3_column_text(st, 2);
		if (endpoint && p256dh && auth)
			wp_send_push(account, endpoint, p256dh, auth, payload);
	}
	sqlite3_finalize(st);
}

static int wp_usermsg(Client *client, Client *to, MessageTag *mtags,
                      const char *text, SendType sendtype)
{
	char payload[BUFSIZE];

	/* DMs to an account-holder only.  TAGMSG carries no body worth
	 * pushing; skip it.  Self-messages don't warrant a push. */
	if (!IsUser(to) || !IsLoggedIn(to))
		return 0;
	if (sendtype == SEND_TYPE_TAGMSG)
		return 0;
	if (IsUser(client) && IsLoggedIn(client) &&
	    !strcasecmp(client->user->account, to->user->account))
		return 0;
	if (!wp_db || !cfg.backend_url)
		return 0;

	const char *cmd = (sendtype == SEND_TYPE_NOTICE) ? "NOTICE" : "PRIVMSG";
	wp_build_payload(payload, sizeof(payload), client, to->name, mtags, cmd, text);
	wp_push_to_account(to->user->account, payload);
	return 0;
}

/* True if `nick` appears in `text` delimited by non-nick characters --
 * a "highlight".  Case-insensitive.  Avoids false hits where the nick
 * is a substring of a longer word (e.g. "sam" inside "same"). */
static int wp_text_highlights_nick(const char *text, const char *nick)
{
	size_t nlen = strlen(nick);
	if (nlen == 0)
		return 0;
	const char *p = text;
	while ((p = our_strcasestr(p, nick)))
	{
		char before = (p == text) ? '\0' : p[-1];
		char after = p[nlen];
		/* Treat alphanumerics as word chars; anything else (space,
		 * punctuation, start/end of string) is a boundary. */
		int before_word = before && isalnum((unsigned char)before);
		int after_word = after && isalnum((unsigned char)after);
		if (!before_word && !after_word)
			return 1;
		p += 1;
	}
	return 0;
}

/* Channel highlight push: when a channel message mentions an
 * account-holder member by nick, push it to that account's devices.
 * The SW suppresses the notification if a window is focused, so this
 * is safe to fire even for users actively in the channel. */
static int wp_chanmsg(Client *client, Channel *channel, int sendflags,
                      const char *member_modes, const char *target,
                      MessageTag *mtags, const char *text, SendType sendtype)
{
	Member *m;
	char payload[BUFSIZE];

	if (sendtype == SEND_TYPE_TAGMSG || !text || !*text)
		return 0;
	if (!wp_db || !cfg.backend_url || !channel)
		return 0;

	const char *cmd = (sendtype == SEND_TYPE_NOTICE) ? "NOTICE" : "PRIVMSG";

	for (m = channel->members; m; m = m->next)
	{
		Client *acptr = m->client;
		if (!acptr || !IsUser(acptr) || !IsLoggedIn(acptr))
			continue;
		if (acptr == client)
			continue; /* don't push the sender their own mention */
		/* Skip if the sender shares this account (own multi-session). */
		if (IsUser(client) && IsLoggedIn(client) &&
		    !strcasecmp(client->user->account, acptr->user->account))
			continue;
		if (!wp_text_highlights_nick(text, acptr->name))
			continue;
		wp_build_payload(payload, sizeof(payload), client, channel->name,
		                 mtags, cmd, text);
		wp_push_to_account(acptr->user->account, payload);
	}
	return 0;
}
