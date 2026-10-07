/*
 * pushbot -- Discord-style out-of-process bot framework for obbyircd.
 *
 * Phase 1: skeleton + config-defined bots + ghost clients + the
 * /PUSHBOT command with LIST and INFO subcommands.
 *
 * No event routing, no REST API, no gateway WebSocket yet -- those
 * land in subsequent phases.  Once Phase 1 is in, bots defined in
 * obbyircd.conf show up in /NAMES, /WHO, and /WHOIS but don't
 * actually do anything.  The point of this phase is to nail the
 * lifecycle: bot configured in conf -> persisted to SQLite ->
 * ghost client materialised at module load -> shows up in channels
 * -> survives /REHASH.
 *
 * Storage: pushbot.db (SQLite) in PERMDATADIR.  Schema covers all
 * the data the later phases will need (commands, channels, requests,
 * dead-letter queue) so we don't have to do a migration every time
 * we land a phase.
 *
 * Spec: doc/specs/pushbot-spec.md and doc/specs/pushbot-architecture.md.
 *
 * (C) 2026 Valerie / ObbyIRCd Team
 * License: GPLv3 or later
 */

#include "unrealircd.h"
#include <sqlite3.h>
#include <jansson.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdint.h>

#define MYCONF "pushbot"
#define DEFAULT_DB "pushbot.db"

/* Gateway URL path. */
#define PB_GATEWAY_PATH "/pushbot/v1/gateway"

/* WS close codes (Discord-style). */
#define PB_CLOSE_GOING_AWAY 1001 /* RFC 6455: endpoint is going away */
#define PB_CLOSE_AUTH_FAILED 4004
#define PB_CLOSE_INVALID_SESSION 4006
#define PB_CLOSE_TIMEOUT 4009
#define PB_CLOSE_QUEUE_OVERFLOW 4011

/* Default heartbeat interval (ms). */
#define PB_HEARTBEAT_INTERVAL_MS 30000
/* Two missed heartbeats -> session timeout. */
#define PB_HEARTBEAT_GRACE_MS (PB_HEARTBEAT_INTERVAL_MS * 2 + 5000)

/* Opcodes per spec §4.3. */
#define PB_OP_DISPATCH       0
#define PB_OP_HEARTBEAT      1
#define PB_OP_IDENTIFY       2
#define PB_OP_RESUME         6
#define PB_OP_RECONNECT      7
#define PB_OP_INVALID_SESSION 9
#define PB_OP_HELLO          10
#define PB_OP_HEARTBEAT_ACK  11
/* Phase 5: slash-command opcodes. */
#define PB_OP_COMMAND_REGISTER     20  /* bot -> server */
#define PB_OP_INTERACTION_RESPONSE 21  /* bot -> server */
#define PB_OP_INTERACTION_DEFER    22  /* bot -> server (extend window) */
#define PB_OP_WORKFLOW_EVENT       30  /* bot -> server (emit workflow/step) */
#define PB_OP_SEND_MESSAGE         31  /* bot -> server: spontaneous PRIVMSG/NOTICE */
#define PB_OP_SEND_TAGMSG          32  /* bot -> server: TAGMSG with client-only tags */

#define PB_WORKFLOW_TTL_SEC          3600
#define PB_WORKFLOW_GC_INTERVAL_MS   60000
#define PB_WORKFLOW_JSON_BUDGET      3000

#define PB_INTERACTION_TIMEOUT_SEC 3
#define PB_INTERACTION_DEFER_SEC   15
/* When the bot acks an interaction with a workflow:start, or emits a
 * step event, the interaction's expires_at is bumped by this much. The
 * window slides forward on every step so a long-running workflow that
 * keeps reporting progress never expires. 30 minutes leaves enough
 * head-room for a stall to be obvious but isn't so long that a crashed
 * bot leaves a stuck "in flight" interaction forever. */
#define PB_INTERACTION_WORKFLOW_SEC (30 * 60)

ModuleHeader MOD_HEADER = {
	"pushbot",
	"0.2",
	"Discord-style out-of-process bots (phase 1+2: skeleton + gateway)",
	"ObbyIRCd Team",
	"unrealircd-6"
};

/* ===================================================================
 * Internal state
 * =================================================================== */

typedef enum {
	PB_SCOPE_CHANNEL = 0,
	PB_SCOPE_SERVER  = 1,
} PbScope;

typedef enum {
	PB_TRANSPORT_GATEWAY = 0,
	PB_TRANSPORT_WEBHOOK = 1,
	PB_TRANSPORT_BOTH    = 2,
} PbTransport;

typedef enum {
	PB_STATUS_PENDING   = 0,
	PB_STATUS_ACTIVE    = 1,
	PB_STATUS_SUSPENDED = 2,
	PB_STATUS_DELETED   = 3,
} PbStatus;

struct PbSession;
typedef struct PbSession PbSession;

/* One serialized event waiting in a bot's outbound queue.  Kept in
 * memory for 60s (resume TTL); replayed on a successful RESUME. */
typedef struct PbQueuedEvent PbQueuedEvent;
struct PbQueuedEvent {
	PbQueuedEvent *prev, *next;
	long long seq;
	char *json;          /* serialized DISPATCH frame ready to send */
	time_t expires_at;   /* drop after this time */
};

/* Maximum queue depth per bot.  Exceeding this disconnects the slow
 * bot with PB_CLOSE_QUEUE_OVERFLOW; RESUME-fresh-IDENTIFY catches up
 * from the live state. */
#define PB_QUEUE_MAX 1024
/* Queued events outlive a disconnected session for this long. */
#define PB_RESUME_TTL_SEC 60

/* In-memory record for a bot.  Mirrors the SQLite row but with
 * resolved pointers and the live ghost client. */
typedef struct PbBot PbBot;
struct PbBot {
	PbBot *prev, *next;
	char *bot_id;          /* opaque id; matches SQLite row */
	char *nick;
	char *account;
	char *realname;
	PbScope scope;
	PbTransport transport;
	PbStatus status;
	char *webhook_url;     /* may be NULL */
	char *webhook_secret;  /* HMAC-SHA256 signing key; may be NULL */
	int   webhook_failures; /* consecutive non-2xx; reset on success */
	int   webhook_suspended; /* 1 = stop firing webhooks until /REHASH */
	char *config_token;    /* plaintext token from config; NULL for self-reg */
	NameList *auto_join;   /* channels to auto-join after ghost creation */
	int from_config;       /* 1 = defined in obbyircd.conf this run */
	Client *ghost;         /* the virtual client, NULL when not materialised */
	PbSession *session;    /* current gateway session, NULL if not connected */

	/* Outbound event queue (for backpressure + RESUME). */
	PbQueuedEvent *queue_head, *queue_tail;
	int queue_count;
	long long next_seq;       /* next sequence number to assign */
	long long last_acked_seq; /* highest seq the bot has acked */
	char *resume_session_id;  /* id valid for RESUME (matches IDENTIFY result) */
	time_t resume_expires_at; /* when the resume window closes (0 = active) */

	/* Phase 5: slash commands the bot has registered. */
	json_t *commands;         /* JSON array; each entry a draft/bot-cmds command */
	char *prefix;             /* legacy text prefix (e.g. "!") for draft/bot-cmds
	                           * compatibility translation; NULL = not bridged */
};

/* Outstanding interactions waiting for INTERACTION_RESPONSE. */
typedef struct PbInteraction PbInteraction;
struct PbInteraction {
	PbInteraction *prev, *next;
	char *id;                 /* server-generated; echoed in COMMAND_INVOKE.d.id */
	char *invoker_nick;       /* who ran the slash command */
	char *channel;            /* channel context (NULL = DM with bot) */
	char *invoker_msgid;      /* msgid of the TAGMSG (for +reply) */
	char *invoker_cmd_b64;    /* base64-JSON of {nick, name, options}; sent
	                           * back as +draft/invoked-by on the bot's
	                           * reply so the client can render a quote
	                           * attribution without local state. */
	int invoked_public;       /* 1 = invoked publicly in-channel; 0 = private/pm.
	                           * A non-public invocation must never reply to the
	                           * channel, regardless of the visibility the bot
	                           * returns -- otherwise a private command leaks. */
	PbBot *bot;
	time_t expires_at;        /* hard timeout: 3s default, 15s after defer */
	int deferred;
	char *workflow_id;        /* if the bot acked with workflow:start, the wid
	                           * that's keeping this interaction alive -- every
	                           * step event on this wid slides expires_at
	                           * forward, so a long-running workflow that keeps
	                           * reporting progress never times out. */
};
static PbInteraction *interactions = NULL;

/* Tracks one live draft/bot-tools workflow so inbound action TAGMSGs
 * (whose target is a wid or sid, not a bot nick) can be routed back to
 * the owning bot. */
typedef struct PbWorkflow PbWorkflow;
struct PbWorkflow {
	PbWorkflow *prev, *next;
	char *wid;
	PbBot *bot;
	char *target;          /* channel name or user nick (last seen) */
	NameList *sids;        /* step sids seen on this workflow */
	time_t expires_at;
	int terminal;          /* 1 = state was complete/failed/cancelled */
};
static PbWorkflow *workflows = NULL;

/* One gateway connection.  Created on WS upgrade, hung off the
 * connecting client via moddata.  Becomes "bound" to a PbBot once
 * IDENTIFY succeeds.  Sequence numbers + queue live on the bot,
 * not here, so they survive reconnects within the resume window. */
struct PbSession {
	Client *client;        /* the websocket-bearing client */
	PbBot *bot;            /* NULL until IDENTIFY succeeds */
	int identified;
	Event *heartbeat_ev;
	time_t last_heartbeat;
};

/* Pending config: collected during configrun, applied at MOD_LOAD. */
typedef struct PbConfigBot PbConfigBot;
struct PbConfigBot {
	PbConfigBot *prev, *next;
	char *nick;
	char *realname;
	char *token;
	char *webhook_url;
	char *webhook_secret;
	char *prefix;          /* legacy text prefix for bot-cmds compat */
	PbScope scope;
	PbTransport transport;
	NameList *auto_join;
};

typedef struct {
	char *database_path;
	char *registration_mode;     /* "admin" | "approval" | "open" */
	char *registration_secret;   /* shared secret for POST /bots; NULL = disabled */
	int webhook_failure_suspend_after;
	PbConfigBot *pending_bots;   /* head of list */
} PbCfg;

static PbCfg cfg;
static sqlite3 *db = NULL;
static PbBot *bots = NULL;
static ModuleInfo *modinfo_ref = NULL;

/* obby.world/channel-bots client capability -- when negotiated, the
 * server sends an initial bot list burst on welcome and pushes
 * per-bot lifecycle updates ('add' / 'update' / 'remove') as they
 * happen. */
#define PB_CAP_NAME "obby.world/channel-bots"
static long CAP_CHANBOTS = 0L;
/* draft/bot-cmds capability bit -- lets us tell capable clients from legacy
 * ones for the compatibility translation. */
static long CAP_BOT_CMDS = 0L;
static long pb_cap_away_notify = 0L;

/* Broadcast a bot ghost's away state change to channel members who have
 * the away-notify cap.  Mirrors away.c cmd_away's broadcast pattern: if
 * the ghost is now away, send `:nick AWAY :reason`; if not, send the
 * bare `:nick AWAY`.  Also fires HOOKTYPE_AWAY so other modules (like
 * server-to-server propagation) can observe the change. */
static void pb_broadcast_away(Client *ghost)
{
	MessageTag *mtags = NULL;
	if (!ghost || !ghost->user) return;
	new_message(ghost, NULL, &mtags);
	if (ghost->user->away)
		sendto_local_common_channels(ghost, ghost, pb_cap_away_notify, mtags,
		                             ":%s AWAY :%s",
		                             ghost->name, ghost->user->away);
	else
		sendto_local_common_channels(ghost, ghost, pb_cap_away_notify, mtags,
		                             ":%s AWAY", ghost->name);
	RunHook(HOOKTYPE_AWAY, ghost, mtags, ghost->user->away, 0);
	free_message_tags(mtags);
}
#define PB_BOT_INFO_TAG "obby.world/bot-info"

/* Gateway moddata: per-client session pointer. */
static ModDataInfo *pb_session_md = NULL;
/* websocket_common's moddata, for inheriting WSU(). */
static ModDataInfo *pb_websocket_md = NULL;
/* webserver's moddata, for accessing WebRequest from client. */
static ModDataInfo *pb_webserver_md = NULL;

#define PB_SESS(c) ((PbSession *)moddata_local_client(c, pb_session_md).ptr)
#define PB_WEB(c)  ((WebRequest *)moddata_local_client(c, pb_webserver_md).ptr)

/* ===================================================================
 * Forward declarations
 * =================================================================== */

static int pb_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
static int pb_configrun(ConfigFile *cf, ConfigEntry *ce, int type);
static int pb_open_db(void);
static int pb_init_schema(void);
static int pb_apply_pending_bots(void);
static int pb_on_rehash_complete(void);
static int pb_upsert_bot_row(const char *bot_id, PbConfigBot *b);
static int pb_load_active_bots_from_db(void);
static PbBot *pb_find_bot_by_nick(const char *nick);
static void pb_free_bot(PbBot *b);
static void pb_free_config(void);
static void pb_free_pending_bot(PbConfigBot *b);
static Client *pb_spawn_ghost(PbBot *b);
static void pb_destroy_ghost(PbBot *b, const char *reason);
static int pb_autojoin(PbBot *b);
static const char *pb_scope_str(PbScope s);
static const char *pb_transport_str(PbTransport t);
static const char *pb_status_str(PbStatus s);
static PbScope pb_parse_scope(const char *s);
static PbTransport pb_parse_transport(const char *s);
static void pb_generate_id(char *out, size_t outlen);

CMD_FUNC(cmd_pushbot);

/* Event-dispatch -- forward decls (Phase 3) */
static int pb_hook_chanmsg(Client *client, Channel *channel, int sendflags,
                           const char *member_modes, const char *target,
                           MessageTag *mtags, const char *text, SendType sendtype);
static int pb_hook_local_join(Client *client, Channel *channel, MessageTag *mtags);
static int pb_hook_local_part(Client *client, Channel *channel, MessageTag *mtags,
                              const char *comment);
static int pb_hook_local_kick(Client *client, Client *victim, Channel *channel,
                              MessageTag *mtags, const char *comment);
static int pb_hook_usermsg(Client *client, Client *to, MessageTag *mtags,
                           const char *text, SendType sendtype);
static json_t *pb_json_client(Client *c);
static json_t *pb_json_channel(Channel *ch);
static int pb_bot_is_in_channel(PbBot *b, Channel *ch);

/* REST API -- forward decls (Phase 4) */
static int pb_handle_rest(Client *client, WebRequest *web, PbBot *b);
static void pb_rest_send_json(Client *client, int status, json_t *body);
static void pb_rest_send_error(Client *client, int status, const char *msg);
static void pb_rest_channel_message(Client *client, WebRequest *web, PbBot *b,
                                    const char *channel);
static void pb_rest_user_message(Client *client, WebRequest *web, PbBot *b,
                                 const char *nick);
static void pb_rest_react(Client *client, WebRequest *web, PbBot *b,
                          const char *channel, const char *msgid, int remove,
                          const char *emoji);
static void pb_rest_redact(Client *client, WebRequest *web, PbBot *b,
                           const char *channel, const char *msgid);
static void pb_rest_channel_join(Client *client, WebRequest *web, PbBot *b,
                                 const char *channel);
static void pb_rest_channel_part(Client *client, WebRequest *web, PbBot *b,
                                 const char *channel);
static void pb_rest_get_bot(Client *client, WebRequest *web, PbBot *b);
static void pb_rest_get_channels(Client *client, WebRequest *web, PbBot *b);
static void pb_rest_get_members(Client *client, WebRequest *web, PbBot *b,
                                const char *channel);

/* Shared cores: behaviours called by gateway op handlers, REST handlers,
 * AND webhook inline-action dispatch. */
typedef enum {
	PB_CORE_OK,
	PB_CORE_BAD_REQUEST,
	PB_CORE_NOT_FOUND,
	PB_CORE_FORBIDDEN,
} PbCoreResult;
static MessageTag *pb_build_tags(json_t *tagj);
static PbCoreResult pb_core_register_commands(PbBot *b, json_t *cmds_array);
static PbCoreResult pb_core_interaction_respond(PbBot *b, const char *iid,
                                                const char *content,
                                                const char *visibility,
                                                int ephemeral,
                                                MessageTag *extra_tags);
static PbCoreResult pb_core_interaction_defer(PbBot *b, const char *iid,
                                              int seconds);
static PbCoreResult pb_core_workflow_event(PbBot *b, const char *target,
                                           json_t *payload);
static void pb_rest_register_commands(Client *client, WebRequest *web, PbBot *b);
static void pb_rest_interaction_respond(Client *client, WebRequest *web,
                                        PbBot *b, const char *iid);
static void pb_rest_interaction_defer(Client *client, WebRequest *web,
                                      PbBot *b, const char *iid);
static void pb_rest_workflow_event(Client *client, WebRequest *web,
                                   PbBot *b, const char *wid_in_path);
static void pb_webhook_dispatch_inline_action(PbBot *b, const char *iid,
                                              json_t *action);

/* Gateway -- forward decls */
static int pb_config_test_listen(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
static int pb_config_run_ex_listen(ConfigFile *cf, ConfigEntry *ce, int type, void *ptr);
static int pb_config_listener(ConfigItem_listen *l);
static void pb_client_handshake(Client *client);
static int pb_pre_handshake_timeout(Client *client, const char **comment);
static int pb_handle_webrequest(Client *client, WebRequest *web);
static int pb_handle_webrequest_data(Client *client, WebRequest *web, const char *buf, int len);
static int pb_ws_handshake_send(Client *client);
static int pb_packet_in_websocket(Client *client, char *buf, int len);
static int pb_handle_body_websocket(Client *client, WebRequest *web, const char *buf, int len);
static void pb_handle_ws_message(Client *client, char *msg, int len);
static void pb_send_op(Client *client, json_t *frame);
static void pb_send_hello(Client *client);
static void pb_send_dispatch(Client *client, const char *event_name, json_t *data);
static void pb_handle_identify(Client *client, json_t *frame);
static void pb_handle_resume(Client *client, json_t *frame);
static void pb_handle_heartbeat(Client *client, json_t *frame);
static void pb_close_ws(Client *client, int code, const char *reason);
static void pb_session_free(PbSession *s);
static void pb_moddata_session_free(ModData *md);
EVENT(pb_heartbeat_check);

/* Phase 6: outgoing webhook delivery */
static void pb_webhook_dispatch(PbBot *b, const char *event_name, const char *body_json);
static void pb_webhook_response(OutgoingWebRequest *req, OutgoingWebResponse *resp);

/* Phase 8: self-registration REST endpoints */
static void pb_rest_register_bot(Client *client, WebRequest *web);
static void pb_rest_list_bots(Client *client, WebRequest *web);

/* Phase 9: JSON-RPC parity */
RPC_CALL_FUNC(pb_rpc_list);
RPC_CALL_FUNC(pb_rpc_get);
RPC_CALL_FUNC(pb_rpc_register);
RPC_CALL_FUNC(pb_rpc_approve);
RPC_CALL_FUNC(pb_rpc_suspend);
RPC_CALL_FUNC(pb_rpc_unsuspend);
RPC_CALL_FUNC(pb_rpc_delete);

/* obby.world/channel-bots cap helpers */
static int  pb_mtag_bot_info_is_ok(Client *c, const char *n, const char *v);
static int  pb_mtag_invoked_by_is_ok(Client *c, const char *n, const char *v);
static int  pb_hook_welcome_burst(Client *client);
static int  pb_hook_oper_change(Client *client, int add,
                                const char *oper_block, const char *operclass);
static void pb_send_bot_burst(Client *client);
static void pb_broadcast_bot_event(PbBot *b, const char *event);
static int  pb_bot_visible_to(PbBot *b, Client *client);
static json_t *pb_bot_to_burst_json(PbBot *b, int for_oper, const char *event);

/* Phase 5: slash commands */
static int  pb_mtag_botcmd_is_ok(Client *c, const char *n, const char *v);
static int  pb_mtag_botcmds_query_is_ok(Client *c, const char *n, const char *v);
static int  pb_mtag_botcmds_is_ok(Client *c, const char *n, const char *v);
static int  pb_mtag_botcmds_changed_is_ok(Client *c, const char *n, const char *v);
static void pb_send_botcmds_to(Client *client, PbBot *b);
static void pb_mtag_forward(Client *sender, MessageTag *recv_mtags,
                            MessageTag **mtag_list, const char *signature);
CMD_OVERRIDE_FUNC(pb_override_batch);
static void pb_handle_command_register(Client *client, json_t *frame);
static void pb_handle_interaction_response(Client *client, json_t *frame);
static void pb_handle_interaction_defer(Client *client, json_t *frame);
static void pb_handle_workflow_event(Client *client, json_t *frame);
static void pb_handle_send_message(Client *client, json_t *frame);
static void pb_handle_send_tagmsg(Client *client, json_t *frame);
static PbWorkflow *pb_workflow_find(const char *wid);
static PbWorkflow *pb_workflow_find_by_sid(const char *sid);
static PbWorkflow *pb_workflow_touch(PbBot *bot, const char *wid, const char *target);
static void pb_workflow_remember_sid(PbWorkflow *w, const char *sid);
static void pb_workflow_terminate(PbWorkflow *w);
static void pb_workflow_free(PbWorkflow *w);
static void pb_workflow_drop_for_bot(PbBot *bot);
static int pb_route_bottools_action(Client *invoker, Client *target_user,
                                    Channel *target_chan, const char *bot_tools_b64);
EVENT(pb_workflow_gc);
static int  pb_route_botcmd_channel(Client *invoker, Channel *channel,
                                    MessageTag *mtags, const char *botcmd_b64);
static int  pb_route_botcmd_user(Client *invoker, Client *to, MessageTag *mtags,
                                 const char *botcmd_b64, const char *channel_context);
static PbInteraction *pb_interaction_new(PbBot *bot, Client *invoker,
                                         const char *channel, const char *msgid,
                                         int invoked_public);
static PbInteraction *pb_interaction_find(const char *id);
static void pb_interaction_free(PbInteraction *it);
EVENT(pb_interaction_timeout_check);

/* ===================================================================
 * Module lifecycle
 * =================================================================== */

MOD_TEST()
{
	memset(&cfg, 0, sizeof(cfg));
	safe_strdup(cfg.database_path, DEFAULT_DB);
	safe_strdup(cfg.registration_mode, "admin");
	cfg.webhook_failure_suspend_after = 86400;
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, pb_configtest);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, pb_config_test_listen);
	return MOD_SUCCESS;
}

MOD_INIT()
{
	ModDataInfo mreq;

	modinfo_ref = modinfo;
	MARK_AS_OFFICIAL_MODULE(modinfo);
	/* Stay loaded across /REHASH so gateway WS sessions survive --
	 * the alternative was tearing down every bot's WebSocket on every
	 * rehash and waiting for the client-side reconnect loop.  PERM
	 * skips Unload_all_loaded_modules; conf changes to the
	 * pushbot {} block now arrive via HOOKTYPE_REHASH (pb_on_rehash). */
	ModuleSetOptions(modinfo->handle, MOD_OPT_PERM, 1);

	/* Register our per-client session moddata. */
	memset(&mreq, 0, sizeof(mreq));
	mreq.name = "pushbot_session";
	mreq.type = MODDATATYPE_LOCAL_CLIENT;
	mreq.free = pb_moddata_session_free;
	pb_session_md = ModDataAdd(modinfo->handle, mreq);
	if (!pb_session_md) {
		config_error("[pushbot] ModDataAdd(pushbot_session) failed: %s",
		             ModuleGetErrorStr(modinfo->handle));
		return MOD_FAILED;
	}

	/* Borrow websocket_common's moddata for WSU(). */
	pb_websocket_md = findmoddata_byname("websocket", MODDATATYPE_CLIENT);
	pb_webserver_md = findmoddata_byname("web", MODDATATYPE_LOCAL_CLIENT);

	HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, pb_configrun);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN_EX, 0, pb_config_run_ex_listen);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIG_LISTENER, 0, pb_config_listener);
	HookAdd(modinfo->handle, HOOKTYPE_PRE_LOCAL_HANDSHAKE_TIMEOUT, 0,
	        pb_pre_handshake_timeout);
	/* Apply conf-block edits live on /REHASH.  cfg.pending_bots was
	 * just rebuilt by pb_configrun; pb_apply_pending_bots is
	 * idempotent (add + update on existing nicks).  Removed-from-conf
	 * bots and database_path changes still need a full restart. */
	HookAdd(modinfo->handle, HOOKTYPE_REHASH_COMPLETE, 0, pb_on_rehash_complete);

	/* obby.world/channel-bots cap: clients that negotiate this get a
	 * bot-list burst at the end of registration and incremental
	 * updates as bots come/go/change.  The burst rides over TAGMSGs
	 * carrying an obby.world/bot-info server-tag (base64 JSON). */
	{
		ClientCapabilityInfo cap;
		memset(&cap, 0, sizeof(cap));
		cap.name = PB_CAP_NAME;
		if (!ClientCapabilityAdd(modinfo->handle, &cap, &CAP_CHANBOTS)) {
			config_error("[pushbot] ClientCapabilityAdd(%s) failed", PB_CAP_NAME);
			return MOD_FAILED;
		}

		/* draft/bot-cmds: the slash-command capability itself.  Valueless;
		 * negotiating it marks a client as "capable" so the compatibility
		 * layer knows who still needs the legacy text rendering. */
		ClientCapabilityInfo cmdcap;
		memset(&cmdcap, 0, sizeof(cmdcap));
		cmdcap.name = "draft/bot-cmds";
		if (!ClientCapabilityAdd(modinfo->handle, &cmdcap, &CAP_BOT_CMDS)) {
			config_error("[pushbot] ClientCapabilityAdd(draft/bot-cmds) failed");
			return MOD_FAILED;
		}
		MessageTagHandlerInfo m;
		memset(&m, 0, sizeof(m));
		m.name = PB_BOT_INFO_TAG;
		m.is_ok = pb_mtag_bot_info_is_ok;
		m.flags = MTAG_HANDLER_FLAGS_NO_CAP_NEEDED;
		MessageTagHandlerAdd(modinfo->handle, &m);

		/* +draft/invoked-by carries a base64 JSON describing the
		 * original slash-command invocation; emitted on the bot's
		 * channel reply so the client can render an attribution quote
		 * without tracking outgoing msgids itself. */
		memset(&m, 0, sizeof(m));
		m.name = "+draft/invoked-by";
		m.is_ok = pb_mtag_invoked_by_is_ok;
		m.flags = MTAG_HANDLER_FLAGS_NO_CAP_NEEDED;
		MessageTagHandlerAdd(modinfo->handle, &m);
	}
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_CONNECT, 0, pb_hook_welcome_burst);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_OPER, 0, pb_hook_oper_change);

	/* Phase 5: register the client-prefixed message tags used by
	 * slash-command discovery + invocation.  Without these, the
	 * ircd silently drops them on the parser side. */
	{
		MessageTagHandlerInfo m;
		memset(&m, 0, sizeof(m));
		m.is_ok = pb_mtag_botcmd_is_ok;
		m.flags = MTAG_HANDLER_FLAGS_NO_CAP_NEEDED;
		m.name = "+draft/bot-cmd";
		MessageTagHandlerAdd(modinfo->handle, &m);
		m.is_ok = pb_mtag_botcmds_query_is_ok;
		m.name = "+draft/bot-cmds-query";
		MessageTagHandlerAdd(modinfo->handle, &m);
		m.is_ok = pb_mtag_botcmds_is_ok;
		m.name = "+draft/bot-cmds";
		MessageTagHandlerAdd(modinfo->handle, &m);
		m.is_ok = pb_mtag_botcmds_changed_is_ok;
		m.name = "+draft/bot-cmds-changed";
		MessageTagHandlerAdd(modinfo->handle, &m);
		m.is_ok = pb_mtag_botcmd_is_ok;
		m.name = "+draft/bot-cmd-error";
		MessageTagHandlerAdd(modinfo->handle, &m);
	}
	/* Forward client-prefixed bot-cmd tags from recv_mtags into the
	 * outbound mtag set so HOOKTYPE_CHANMSG / USERMSG can see them. */
	HookAddVoid(modinfo->handle, HOOKTYPE_NEW_MESSAGE, 0, pb_mtag_forward);

	/* Phase 6: register webhook response callback so url_start_async()
	 * can call us back when delivery completes. */
	RegisterApiCallbackWebResponse(modinfo->handle, "pb_webhook_response",
	                               pb_webhook_response);

	/* Phase 3: dispatch events to bots whose channels they're in. */
	HookAdd(modinfo->handle, HOOKTYPE_CHANMSG, 0, pb_hook_chanmsg);
	HookAdd(modinfo->handle, HOOKTYPE_USERMSG, 0, pb_hook_usermsg);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_JOIN, 0, pb_hook_local_join);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_PART, 0, pb_hook_local_part);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_KICK, 0, pb_hook_local_kick);
	CommandAdd(modinfo->handle, "PUSHBOT", cmd_pushbot, MAXPARA, CMD_USER);

	/* Phase 9: JSON-RPC parity */
	{
		RPCHandlerInfo r;
		memset(&r, 0, sizeof(r));
		r.loglevel = ULOG_DEBUG;
		r.method = "pushbot.list";    r.call = pb_rpc_list;       RPCHandlerAdd(modinfo->handle, &r);
		r.method = "pushbot.get";     r.call = pb_rpc_get;        RPCHandlerAdd(modinfo->handle, &r);
		r.method = "pushbot.register";r.call = pb_rpc_register;   RPCHandlerAdd(modinfo->handle, &r);
		r.method = "pushbot.approve"; r.call = pb_rpc_approve;    RPCHandlerAdd(modinfo->handle, &r);
		r.method = "pushbot.suspend"; r.call = pb_rpc_suspend;    RPCHandlerAdd(modinfo->handle, &r);
		r.method = "pushbot.unsuspend"; r.call = pb_rpc_unsuspend;RPCHandlerAdd(modinfo->handle, &r);
		r.method = "pushbot.delete";  r.call = pb_rpc_delete;     RPCHandlerAdd(modinfo->handle, &r);
	}

	/* Cache the away-notify cap bit so we can broadcast bot
	 * online/offline transitions to channel members who negotiated it. */
	pb_cap_away_notify = ClientCapabilityBit("away-notify");

	/* Heartbeat watchdog: every 5s, kick sessions that missed too many. */
	EventAdd(modinfo->handle, "pb_heartbeat_check", pb_heartbeat_check, NULL, 5000, 0);
	/* Phase 5: expire stale interactions every second. */
	EventAdd(modinfo->handle, "pb_interaction_timeout_check",
	         pb_interaction_timeout_check, NULL, 1000, 0);
	EventAdd(modinfo->handle, "pb_workflow_gc",
	         pb_workflow_gc, NULL, PB_WORKFLOW_GC_INTERVAL_MS, 0);
	return MOD_SUCCESS;
}

static int pb_on_rehash_complete(void)
{
	/* Reapply config-block bot definitions.  pb_configrun already
	 * rebuilt cfg.pending_bots from the new config; this turns those
	 * into live bots (add or update existing nicks).  Removed-from-
	 * conf bots stay live until restart -- handling that delta cleanly
	 * needs an explicit destroy path and is a phase-2 enhancement. */
	pb_apply_pending_bots();
	return 0;
}

MOD_LOAD()
{
	CommandOverrideAdd(modinfo->handle, "BATCH", 0, pb_override_batch);

	if (pb_open_db() < 0) {
		config_error("[pushbot] cannot open database at %s", cfg.database_path);
		return MOD_FAILED;
	}
	if (pb_init_schema() < 0) {
		config_error("[pushbot] schema init failed");
		return MOD_FAILED;
	}

	/* Pull previously-active bots back into memory.  Self-registered
	 * bots (phase 8) come from this path; config-defined bots come
	 * from the pending list below. */
	pb_load_active_bots_from_db();

	/* Re-apply config-defined bots: upsert their row, materialise
	 * their ghost if status=active. */
	pb_apply_pending_bots();

	unreal_log(ULOG_INFO, "pushbot", "PUSHBOT_LOADED", NULL,
	           "pushbot module loaded (mode=$mode, db=$db)",
	           log_data_string("mode", cfg.registration_mode),
	           log_data_string("db", cfg.database_path));
	return MOD_SUCCESS;
}

MOD_UNLOAD()
{
	PbBot *b, *n;
	/* Send a clean WebSocket Close to every live gateway session
	 * before tearing anything down.  Without this the bot client's
	 * TCP socket lingers after /REHASH -- the bot thinks it's still
	 * connected, the freshly-loaded pushbot module has no record of
	 * the session, and the bot becomes a silent zombie until its
	 * systemd unit gets bounced.  Sending a Close frame here forces
	 * the bot's read loop to disconnect and reconnect cleanly. */
	for (b = bots; b; b = b->next) {
		if (b->session && b->session->client && !IsDead(b->session->client))
			pb_close_ws(b->session->client, PB_CLOSE_GOING_AWAY,
			            "pushbot module reloading");
	}
	/* Sever session<->bot back-pointers before we free any bot.
	 * After MOD_UNLOAD returns, UnrealIRCd sweeps every client with
	 * our pushbot_session moddata and fires pb_moddata_session_free;
	 * that calls pb_session_free which dereferences s->bot.  If we
	 * leave the back-pointer pointing at freed memory we crash
	 * during the framework's teardown, not in our code -- which is
	 * exactly what the 17:55 /REHASH SEGV looked like. */
	for (b = bots; b; b = b->next) {
		if (b->session) {
			b->session->bot = NULL;
			b->session = NULL;
		}
	}
	for (b = bots; b; b = n) {
		n = b->next;
		pb_destroy_ghost(b, "pushbot module unloaded");
		pb_free_bot(b);
	}
	bots = NULL;

	while (workflows)
		pb_workflow_free(workflows);

	if (db) {
		sqlite3_close(db);
		db = NULL;
	}
	pb_free_config();
	return MOD_SUCCESS;
}

/* ===================================================================
 * Config parsing
 * =================================================================== */

static int pb_test_bot_block(ConfigFile *cf, ConfigEntry *bot_ce, int *errs)
{
	int errors = 0;
	int has_token = 0;
	if (!bot_ce->value || !*bot_ce->value) {
		config_error("%s:%d: pushbot::bot block needs a nick",
		             bot_ce->file->filename, bot_ce->line_number);
		errors++;
	}
	for (ConfigEntry *cep = bot_ce->items; cep; cep = cep->next) {
		if (!cep->name) continue;
		if (!strcmp(cep->name, "token")) {
			if (!cep->value || !*cep->value) {
				config_error("%s:%d: pushbot::bot::token must have a value",
				             cep->file->filename, cep->line_number);
				errors++;
			} else has_token = 1;
		} else if (!strcmp(cep->name, "realname")
		        || !strcmp(cep->name, "scope")
		        || !strcmp(cep->name, "transport")
		        || !strcmp(cep->name, "webhook-url")
		        || !strcmp(cep->name, "webhook-secret")) {
			if (!cep->value) {
				config_error("%s:%d: pushbot::bot::%s needs a value",
				             cep->file->filename, cep->line_number, cep->name);
				errors++;
			}
		} else if (!strcmp(cep->name, "auto-join")) {
			/* Block of channel names; values inside are channels. */
			for (ConfigEntry *ch = cep->items; ch; ch = ch->next) {
				if (!ch->name ||
				    (ch->name[0] != '#' && ch->name[0] != '&' &&
				     ch->name[0] != '^' && ch->name[0] != '$')) {
					config_error("%s:%d: pushbot::bot::auto-join entries must be channel names",
					             ch->file->filename, ch->line_number);
					errors++;
				}
			}
		} else if (!strcmp(cep->name, "permissions")
		        || !strcmp(cep->name, "triggers")) {
			/* Reserved for later phases; quietly accept structure. */
		} else {
			config_error("%s:%d: unknown directive pushbot::bot::%s",
			             cep->file->filename, cep->line_number, cep->name);
			errors++;
		}
	}
	if (!has_token) {
		config_error("%s:%d: pushbot::bot %s missing token",
		             bot_ce->file->filename, bot_ce->line_number,
		             bot_ce->value ? bot_ce->value : "");
		errors++;
	}
	*errs += errors;
	return errors;
}

static int pb_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs)
{
	int errors = 0;
	if (type != CONFIG_MAIN) return 0;
	if (!ce || !ce->name || strcmp(ce->name, MYCONF)) return 0;

	for (ConfigEntry *cep = ce->items; cep; cep = cep->next) {
		if (!cep->name) continue;
		if (!strcmp(cep->name, "mode")) {
			if (!cep->value
			    || (strcmp(cep->value, "admin")
			        && strcmp(cep->value, "approval")
			        && strcmp(cep->value, "open"))) {
				config_error("%s:%d: pushbot::mode must be admin|approval|open",
				             cep->file->filename, cep->line_number);
				errors++;
			}
		} else if (!strcmp(cep->name, "database")) {
			if (!cep->value) {
				config_error("%s:%d: pushbot::database needs a value",
				             cep->file->filename, cep->line_number);
				errors++;
			}
		} else if (!strcmp(cep->name, "webhook-failure-suspend-after")) {
			if (!cep->value || atoi(cep->value) <= 0) {
				config_error("%s:%d: pushbot::webhook-failure-suspend-after needs positive seconds",
				             cep->file->filename, cep->line_number);
				errors++;
			}
		} else if (!strcmp(cep->name, "default-permissions")) {
			/* Reserved for later phases. */
		} else if (!strcmp(cep->name, "registration-secret")) {
			if (!cep->value || !*cep->value) {
				config_error("%s:%d: pushbot::registration-secret cannot be empty",
				             cep->file->filename, cep->line_number);
				errors++;
			} else if (strlen(cep->value) < 16) {
				config_warn("%s:%d: pushbot::registration-secret is shorter than 16 chars; use a longer secret",
				             cep->file->filename, cep->line_number);
			}
		} else if (!strcmp(cep->name, "bot")) {
			pb_test_bot_block(cf, cep, &errors);
		} else {
			config_error("%s:%d: unknown directive pushbot::%s",
			             cep->file->filename, cep->line_number, cep->name);
			errors++;
		}
	}
	*errs = errors;
	return errors ? -1 : 1;
}

static void pb_parse_bot_block(ConfigEntry *bot_ce)
{
	PbConfigBot *b = safe_alloc(sizeof(*b));
	safe_strdup(b->nick, bot_ce->value);
	b->scope = PB_SCOPE_CHANNEL;
	b->transport = PB_TRANSPORT_GATEWAY;
	for (ConfigEntry *cep = bot_ce->items; cep; cep = cep->next) {
		if (!cep->name) continue;
		if (!strcmp(cep->name, "token")) safe_strdup(b->token, cep->value);
		else if (!strcmp(cep->name, "realname")) safe_strdup(b->realname, cep->value);
		else if (!strcmp(cep->name, "scope")) b->scope = pb_parse_scope(cep->value);
		else if (!strcmp(cep->name, "transport")) b->transport = pb_parse_transport(cep->value);
		else if (!strcmp(cep->name, "webhook-url")) safe_strdup(b->webhook_url, cep->value);
		else if (!strcmp(cep->name, "webhook-secret")) safe_strdup(b->webhook_secret, cep->value);
		else if (!strcmp(cep->name, "prefix")) safe_strdup(b->prefix, cep->value);
		else if (!strcmp(cep->name, "auto-join")) {
			for (ConfigEntry *ch = cep->items; ch; ch = ch->next) {
				if (ch->name &&
				    (ch->name[0] == '#' || ch->name[0] == '&' ||
				     ch->name[0] == '^' || ch->name[0] == '$'))
					add_name_list(b->auto_join, ch->name);
			}
		}
	}
	if (!b->realname) safe_strdup(b->realname, b->nick);
	b->next = cfg.pending_bots;
	if (cfg.pending_bots) cfg.pending_bots->prev = b;
	cfg.pending_bots = b;
}

static int pb_configrun(ConfigFile *cf, ConfigEntry *ce, int type)
{
	if (type != CONFIG_MAIN) return 0;
	if (!ce || !ce->name || strcmp(ce->name, MYCONF)) return 0;

	/* On /REHASH this may be called again; drop any previously-collected
	 * pending bots so we re-derive the set from the new config. */
	while (cfg.pending_bots) {
		PbConfigBot *next = cfg.pending_bots->next;
		pb_free_pending_bot(cfg.pending_bots);
		cfg.pending_bots = next;
	}

	for (ConfigEntry *cep = ce->items; cep; cep = cep->next) {
		if (!cep->name) continue;
		if (!strcmp(cep->name, "mode")) {
			safe_strdup(cfg.registration_mode, cep->value);
		} else if (!strcmp(cep->name, "database")) {
			safe_strdup(cfg.database_path, cep->value);
		} else if (!strcmp(cep->name, "webhook-failure-suspend-after")) {
			cfg.webhook_failure_suspend_after = atoi(cep->value);
		} else if (!strcmp(cep->name, "registration-secret")) {
			safe_strdup(cfg.registration_secret, cep->value);
		} else if (!strcmp(cep->name, "bot")) {
			pb_parse_bot_block(cep);
		}
	}
	return 1;
}

static void pb_free_pending_bot(PbConfigBot *b)
{
	if (!b) return;
	safe_free(b->nick);
	safe_free(b->realname);
	safe_free(b->token);
	safe_free(b->webhook_url);
	safe_free(b->webhook_secret);
	safe_free(b->prefix);
	free_entire_name_list(b->auto_join);
	safe_free(b);
}

static void pb_free_config(void)
{
	while (cfg.pending_bots) {
		PbConfigBot *next = cfg.pending_bots->next;
		pb_free_pending_bot(cfg.pending_bots);
		cfg.pending_bots = next;
	}
	safe_free(cfg.database_path);
	safe_free(cfg.registration_mode);
}

/* ===================================================================
 * SQLite
 * =================================================================== */

static int pb_open_db(void)
{
	char *abspath = NULL;
	safe_strdup(abspath, cfg.database_path);
	convert_to_absolute_path(&abspath, PERMDATADIR);
	int rv = sqlite3_open(abspath, &db);
	if (rv != SQLITE_OK) {
		unreal_log(ULOG_ERROR, "pushbot", "DB_OPEN", NULL,
		           "Could not open pushbot DB at $path: $err",
		           log_data_string("path", abspath),
		           log_data_string("err", db ? sqlite3_errmsg(db) : "(no handle)"));
		if (db) { sqlite3_close(db); db = NULL; }
		safe_free(abspath);
		return -1;
	}
	safe_free(abspath);
	sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);
	return 0;
}

static int pb_init_schema(void)
{
	static const char *schema =
		"CREATE TABLE IF NOT EXISTS pushbots ("
		"  bot_id TEXT PRIMARY KEY, nick TEXT UNIQUE NOT NULL,"
		"  account TEXT UNIQUE NOT NULL, realname TEXT NOT NULL,"
		"  scope TEXT NOT NULL CHECK(scope IN ('channel','server')),"
		"  token_hash TEXT NOT NULL, webhook_url TEXT, webhook_secret_hash TEXT,"
		"  transport TEXT NOT NULL CHECK(transport IN ('gateway','webhook','both')),"
		"  status TEXT NOT NULL CHECK(status IN ('pending','active','suspended','deleted')),"
		"  triggers TEXT NOT NULL DEFAULT '{}',"
		"  permissions TEXT NOT NULL DEFAULT '{}',"
		"  created_at INTEGER NOT NULL,"
		"  created_by TEXT NOT NULL,"
		"  approved_by TEXT, approved_at INTEGER, last_seen INTEGER"
		");"
		"CREATE TABLE IF NOT EXISTS pushbot_channels ("
		"  bot_id TEXT NOT NULL REFERENCES pushbots(bot_id) ON DELETE CASCADE,"
		"  channel TEXT NOT NULL, PRIMARY KEY(bot_id, channel)"
		");"
		"CREATE TABLE IF NOT EXISTS pushbot_commands ("
		"  bot_id TEXT NOT NULL REFERENCES pushbots(bot_id) ON DELETE CASCADE,"
		"  name TEXT NOT NULL, description TEXT NOT NULL,"
		"  visibility TEXT NOT NULL CHECK(visibility IN ('public','private')),"
		"  scopes TEXT NOT NULL, options TEXT NOT NULL,"
		"  requires TEXT, version INTEGER NOT NULL DEFAULT 1,"
		"  PRIMARY KEY(bot_id, name)"
		");"
		"CREATE TABLE IF NOT EXISTS pushbot_requests ("
		"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"  bot_id TEXT NOT NULL REFERENCES pushbots(bot_id) ON DELETE CASCADE,"
		"  channel TEXT NOT NULL, requested_by TEXT NOT NULL,"
		"  message TEXT,"
		"  status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','expired')),"
		"  resolved_by TEXT, resolved_at INTEGER, deny_reason TEXT,"
		"  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL"
		");"
		"CREATE TABLE IF NOT EXISTS pushbot_dead_letters ("
		"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"  bot_id TEXT NOT NULL REFERENCES pushbots(bot_id) ON DELETE CASCADE,"
		"  event_type TEXT NOT NULL, payload TEXT NOT NULL,"
		"  error TEXT, failed_at INTEGER NOT NULL"
		");";
	char *err = NULL;
	int rv = sqlite3_exec(db, schema, NULL, NULL, &err);
	if (rv != SQLITE_OK) {
		unreal_log(ULOG_ERROR, "pushbot", "DB_SCHEMA", NULL,
		           "Schema init failed: $err",
		           log_data_string("err", err ? err : "?"));
		sqlite3_free(err);
		return -1;
	}
	return 0;
}

/* Trivial hash that's safe-enough for "did the config token change?"
 * we just store a SHA-256 hex digest.  We use the IRCd's built-in
 * sha2 functions where available.  For phase 1 we deliberately stash
 * the *plaintext* in memory for config-defined bots (`config_token`)
 * because the gateway needs to verify it on connect; the DB stores
 * the hash and we'd reject any external supplied token by comparing
 * its hash too.  Phase 2 will replace the plaintext-in-memory bit
 * with a constant-time bearer-comparison. */
static void pb_token_hash(const char *plaintext, char *out, size_t outlen)
{
	if (outlen < 65) { if (outlen) out[0] = '\0'; return; }
	unsigned char digest[32];
	sha256hash_binary((char *)digest, (char *)plaintext, strlen(plaintext));
	static const char *hex = "0123456789abcdef";
	for (int i = 0; i < 32; i++) {
		out[i * 2]     = hex[(digest[i] >> 4) & 0xf];
		out[i * 2 + 1] = hex[digest[i] & 0xf];
	}
	out[64] = '\0';
}

static int pb_upsert_bot_row(const char *bot_id, PbConfigBot *b)
{
	const char *sql =
		"INSERT INTO pushbots ("
		"  bot_id, nick, account, realname, scope, token_hash,"
		"  webhook_url, transport, status, created_at, created_by"
		") VALUES (?,?,?,?,?,?,?,?,'active',?,?)"
		" ON CONFLICT(bot_id) DO UPDATE SET"
		"  nick=excluded.nick, realname=excluded.realname,"
		"  scope=excluded.scope, token_hash=excluded.token_hash,"
		"  webhook_url=excluded.webhook_url,"
		"  transport=excluded.transport,"
		"  status=CASE WHEN pushbots.status='suspended' THEN 'suspended' ELSE 'active' END";

	char hash[65];
	pb_token_hash(b->token, hash, sizeof(hash));

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_text(st, 1, bot_id, -1, SQLITE_STATIC);
	sqlite3_bind_text(st, 2, b->nick, -1, SQLITE_STATIC);
	sqlite3_bind_text(st, 3, b->nick, -1, SQLITE_STATIC); /* account == nick */
	sqlite3_bind_text(st, 4, b->realname ? b->realname : b->nick, -1, SQLITE_STATIC);
	sqlite3_bind_text(st, 5, pb_scope_str(b->scope), -1, SQLITE_STATIC);
	sqlite3_bind_text(st, 6, hash, -1, SQLITE_STATIC);
	sqlite3_bind_text(st, 7, b->webhook_url, -1, SQLITE_STATIC);
	sqlite3_bind_text(st, 8, pb_transport_str(b->transport), -1, SQLITE_STATIC);
	sqlite3_bind_int64(st, 9, (long long)TStime());
	sqlite3_bind_text(st, 10, "config", -1, SQLITE_STATIC);

	int rv = sqlite3_step(st);
	sqlite3_finalize(st);
	return (rv == SQLITE_DONE) ? 0 : -1;
}

static int pb_load_active_bots_from_db(void)
{
	const char *sql =
		"SELECT bot_id, nick, account, realname, scope, transport,"
		"       status, webhook_url"
		"  FROM pushbots WHERE status IN ('active','suspended')";
	sqlite3_stmt *st;
	if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
		return -1;
	int loaded = 0;
	while (sqlite3_step(st) == SQLITE_ROW) {
		const char *bot_id   = (const char *)sqlite3_column_text(st, 0);
		const char *nick     = (const char *)sqlite3_column_text(st, 1);
		const char *account  = (const char *)sqlite3_column_text(st, 2);
		const char *realname = (const char *)sqlite3_column_text(st, 3);
		const char *scope    = (const char *)sqlite3_column_text(st, 4);
		const char *transp   = (const char *)sqlite3_column_text(st, 5);
		const char *status   = (const char *)sqlite3_column_text(st, 6);
		const char *whurl    = (const char *)sqlite3_column_text(st, 7);
		if (!bot_id || !nick) continue;
		if (pb_find_bot_by_nick(nick)) continue;

		PbBot *b = safe_alloc(sizeof(*b));
		safe_strdup(b->bot_id, bot_id);
		safe_strdup(b->nick, nick);
		safe_strdup(b->account, account);
		safe_strdup(b->realname, realname);
		b->scope = pb_parse_scope(scope);
		b->transport = pb_parse_transport(transp);
		b->status = !strcmp(status, "suspended") ? PB_STATUS_SUSPENDED : PB_STATUS_ACTIVE;
		if (whurl) safe_strdup(b->webhook_url, whurl);
		AddListItem(b, bots);
		loaded++;
	}
	sqlite3_finalize(st);
	if (loaded)
		unreal_log(ULOG_INFO, "pushbot", "DB_LOAD", NULL,
		           "Loaded $count bot row(s) from database",
		           log_data_integer("count", loaded));
	return 0;
}

static int pb_apply_pending_bots(void)
{
	for (PbConfigBot *pc = cfg.pending_bots; pc; pc = pc->next) {
		char bot_id[16];
		PbBot *existing = pb_find_bot_by_nick(pc->nick);
		if (existing) {
			strlcpy(bot_id, existing->bot_id, sizeof(bot_id));
		} else {
			pb_generate_id(bot_id, sizeof(bot_id));
		}

		if (pb_upsert_bot_row(bot_id, pc) < 0) {
			unreal_log(ULOG_ERROR, "pushbot", "DB_UPSERT", NULL,
			           "Failed to upsert bot $nick",
			           log_data_string("nick", pc->nick));
			continue;
		}

		PbBot *b = existing;
		if (!b) {
			b = safe_alloc(sizeof(*b));
			safe_strdup(b->bot_id, bot_id);
			safe_strdup(b->nick, pc->nick);
			safe_strdup(b->account, pc->nick);
			safe_strdup(b->realname, pc->realname ? pc->realname : pc->nick);
			b->scope = pc->scope;
			b->transport = pc->transport;
			b->status = PB_STATUS_ACTIVE;
			if (pc->webhook_url) safe_strdup(b->webhook_url, pc->webhook_url);
			if (pc->webhook_secret) safe_strdup(b->webhook_secret, pc->webhook_secret);
			if (pc->prefix) safe_strdup(b->prefix, pc->prefix);
			AddListItem(b, bots);
		} else {
			/* Update mutable fields from new config */
			safe_strdup(b->realname, pc->realname ? pc->realname : pc->nick);
			b->scope = pc->scope;
			b->transport = pc->transport;
			safe_free(b->webhook_url);
			if (pc->webhook_url) safe_strdup(b->webhook_url, pc->webhook_url);
			safe_free(b->webhook_secret);
			if (pc->webhook_secret) safe_strdup(b->webhook_secret, pc->webhook_secret);
			safe_free(b->prefix);
			if (pc->prefix) safe_strdup(b->prefix, pc->prefix);
			b->webhook_suspended = 0;  /* /REHASH clears suspension */
			b->webhook_failures = 0;
		}
		safe_strdup(b->config_token, pc->token);
		b->from_config = 1;

		/* Materialise ghost if not already up. */
		if (b->status == PB_STATUS_ACTIVE && !b->ghost)
			pb_spawn_ghost(b);

		/* Auto-join channels listed in config. */
		free_entire_name_list(b->auto_join);
		b->auto_join = NULL;
		for (NameList *n = pc->auto_join; n; n = n->next)
			add_name_list(b->auto_join, n->name);
		pb_autojoin(b);
	}
	return 0;
}

/* ===================================================================
 * Ghost client lifecycle
 * =================================================================== */

static Client *pb_spawn_ghost(PbBot *b)
{
	if (!b || b->ghost) return b ? b->ghost : NULL;

	/* If a real user already holds the nick we can't proceed. */
	if (find_user(b->nick, NULL)) {
		unreal_log(ULOG_WARNING, "pushbot", "NICK_TAKEN", NULL,
		           "Cannot materialise bot $nick: nick is in use by a real user",
		           log_data_string("nick", b->nick));
		return NULL;
	}

	Client *ghost = make_client(NULL, &me);
	ghost->local->fd = -2;
	/* Mirror persistence.c's spawn order exactly.  Various periodic
	 * IRCd paths (ping check, /STATS sweep, idle scan) walk client
	 * lists; missing ip / sockhost / away strings can NULL-deref
	 * them. */
	strlcpy(ghost->name, b->nick, sizeof(ghost->name));
	safe_strdup(ghost->ip, "127.0.0.1");
	strlcpy(ghost->local->sockhost, "bot.obby.world", sizeof(ghost->local->sockhost));

	make_user(ghost);
	/* user->server is the source-server name for the user record.
	 * For local users, src/modules/user.c sets it to me_hash (the
	 * pooled string for our own server name).  Persistence's
	 * ghost-revival code happens to dodge crashes because the field
	 * is overwritten when the real user reconnects, but for a ghost
	 * that NEVER becomes real (PushBot), leaving this NULL crashes
	 * /WHO * 0 (RPL_WHOREPLY formats acptr->user->server unchecked). */
	ghost->user->server = me_hash;
	strlcpy(ghost->ident, b->nick, sizeof(ghost->ident));
	strlcpy(ghost->info, b->realname, sizeof(ghost->info));
	strlcpy(ghost->user->username, b->nick, sizeof(ghost->user->username));
	strlcpy(ghost->user->realhost, "bot.obby.world", sizeof(ghost->user->realhost));
	strlcpy(ghost->user->cloakedhost, "bot.obby.world", sizeof(ghost->user->cloakedhost));
	safe_free(ghost->user->virthost);
	safe_strdup(ghost->user->virthost, "bot.obby.world");
	strlcpy(ghost->user->account, b->account, sizeof(ghost->user->account));

	long bot_bit = find_user_mode('B');
	long invis_bit = find_user_mode('i');
	if (bot_bit) ghost->umodes |= bot_bit;
	if (invis_bit) ghost->umodes |= invis_bit;
	if (b->scope == PB_SCOPE_SERVER) {
		long service_bit = find_user_mode('S');
		if (service_bit) ghost->umodes |= service_bit;
	}
	SetUser(ghost);

	/* Mark away BEFORE adding to lists (matches persistence.c
	 * ordering, so no walker sees us mid-init without an away
	 * string). */
	safe_strdup(ghost->user->away, "bot offline");
	ghost->user->away_since = TStime();

	add_to_client_hash_table(ghost->name, ghost);
	add_client_to_list(ghost);
	irccounts.clients++;
	irccounts.me_clients++;
	if (IsInvisible(ghost))
		irccounts.invisible++;
	if (ghost->uplink && ghost->uplink->server)
		ghost->uplink->server->users++;

	b->ghost = ghost;
	unreal_log(ULOG_INFO, "pushbot", "GHOST_UP", ghost,
	           "Bot $nick materialised",
	           log_data_string("nick", b->nick));
	pb_broadcast_bot_event(b, "add");
	return ghost;
}

static void pb_destroy_ghost(PbBot *b, const char *reason)
{
	if (!b || !b->ghost) return;
	Client *ghost = b->ghost;
	b->ghost = NULL;

	Membership *mp;
	while ((mp = ghost->user->channel))
		remove_user_from_channel_withmb(ghost, mp->channel, mp, 1);

	moddata_free_client(ghost);
	if (*ghost->id) {
		del_from_id_hash_table(ghost->id, ghost);
		*ghost->id = '\0';
	}
	if (*ghost->name)
		del_from_client_hash_table(ghost->name, ghost);
	remove_client_from_list(ghost);
	irccounts.clients--;
	irccounts.me_clients--;
	if (IsInvisible(ghost))
		irccounts.invisible--;
	if (me.server)
		me.server->users--;
	free_client(ghost);

	if (reason)
		unreal_log(ULOG_INFO, "pushbot", "GHOST_DOWN", NULL,
		           "Bot $nick ghost destroyed: $reason",
		           log_data_string("nick", b->nick),
		           log_data_string("reason", reason));
}

static int pb_autojoin(PbBot *b)
{
	if (!b || !b->ghost) return 0;
	int joined = 0;
	for (NameList *n = b->auto_join; n; n = n->next) {
		Channel *ch = find_channel(n->name);
		if (!ch) ch = make_channel(n->name);
		if (!ch) continue;
		Membership *m;
		int already = 0;
		for (m = b->ghost->user->channel; m; m = m->next)
			if (m->channel == ch) { already = 1; break; }
		if (already) continue;
		add_user_to_channel(ch, b->ghost, "");
		joined++;
	}
	return joined;
}

/* ===================================================================
 * Helpers
 * =================================================================== */

static PbBot *pb_find_bot_by_nick(const char *nick)
{
	for (PbBot *b = bots; b; b = b->next)
		if (!strcasecmp(b->nick, nick)) return b;
	return NULL;
}

static void pb_free_bot(PbBot *b)
{
	if (!b) return;
	pb_workflow_drop_for_bot(b);
	while (b->queue_head) {
		PbQueuedEvent *e = b->queue_head;
		safe_free(e->json);
		DelListItem(e, b->queue_head);
		safe_free(e);
	}
	safe_free(b->resume_session_id);
	safe_free(b->bot_id);
	safe_free(b->nick);
	safe_free(b->account);
	safe_free(b->realname);
	safe_free(b->webhook_url);
	safe_free(b->webhook_secret);
	safe_free(b->config_token);
	safe_free(b->prefix);
	if (b->commands) json_decref(b->commands);
	free_entire_name_list(b->auto_join);
	DelListItem(b, bots);
	safe_free(b);
}

static const char *pb_scope_str(PbScope s)
{
	return s == PB_SCOPE_SERVER ? "server" : "channel";
}

static PbScope pb_parse_scope(const char *s)
{
	return (s && !strcasecmp(s, "server")) ? PB_SCOPE_SERVER : PB_SCOPE_CHANNEL;
}

static const char *pb_transport_str(PbTransport t)
{
	switch (t) {
	case PB_TRANSPORT_WEBHOOK: return "webhook";
	case PB_TRANSPORT_BOTH:    return "both";
	default:                   return "gateway";
	}
}

static PbTransport pb_parse_transport(const char *s)
{
	if (!s) return PB_TRANSPORT_GATEWAY;
	if (!strcasecmp(s, "webhook")) return PB_TRANSPORT_WEBHOOK;
	if (!strcasecmp(s, "both"))    return PB_TRANSPORT_BOTH;
	return PB_TRANSPORT_GATEWAY;
}

static const char *pb_status_str(PbStatus s)
{
	switch (s) {
	case PB_STATUS_PENDING:   return "pending";
	case PB_STATUS_SUSPENDED: return "suspended";
	case PB_STATUS_DELETED:   return "deleted";
	default:                  return "active";
	}
}

static void pb_generate_id(char *out, size_t outlen)
{
	static unsigned long counter = 0;
	counter++;
	snprintf(out, outlen, "pb%lx%lx",
	         (unsigned long)TStime(),
	         counter ^ (unsigned long)getpid());
}

/* ===================================================================
 * /PUSHBOT command  (IRCop-only in this phase)
 * =================================================================== */

static void cmd_pushbot_list(Client *client)
{
	int count = 0;
	for (PbBot *b = bots; b; b = b->next) {
		sendnotice(client, "%-16s  %-8s  %-9s  %-10s  ghost:%s",
		           b->nick,
		           pb_scope_str(b->scope),
		           pb_transport_str(b->transport),
		           pb_status_str(b->status),
		           b->ghost ? "up" : "down");
		count++;
	}
	sendnotice(client, "--- %d bot(s)", count);
}

static void cmd_pushbot_info(Client *client, const char *nick)
{
	PbBot *b = pb_find_bot_by_nick(nick);
	if (!b) {
		sendnotice(client, "No such bot: %s", nick);
		return;
	}
	sendnotice(client, "Bot:        %s", b->nick);
	sendnotice(client, "  id:       %s", b->bot_id);
	sendnotice(client, "  account:  %s", b->account);
	sendnotice(client, "  realname: %s", b->realname);
	sendnotice(client, "  scope:    %s", pb_scope_str(b->scope));
	sendnotice(client, "  trans:    %s", pb_transport_str(b->transport));
	sendnotice(client, "  status:   %s", pb_status_str(b->status));
	sendnotice(client, "  source:   %s", b->from_config ? "config" : "self/db");
	if (b->webhook_url)
		sendnotice(client, "  webhook:  %s", b->webhook_url);
	if (b->ghost) {
		int chs = 0;
		for (Membership *m = b->ghost->user->channel; m; m = m->next) chs++;
		sendnotice(client, "  ghost:    up, %d channel(s)", chs);
		for (Membership *m = b->ghost->user->channel; m; m = m->next)
			sendnotice(client, "    - %s", m->channel->name);
	} else {
		sendnotice(client, "  ghost:    down");
	}
}

static void cmd_pushbot_setstatus(Client *client, const char *nick, PbStatus new_status, const char *verb)
{
	PbBot *b = pb_find_bot_by_nick(nick);
	if (!b) { sendnotice(client, "No such bot: %s", nick); return; }
	if (b->from_config) {
		sendnotice(client, "Bot %s is config-defined; edit obbyircd.conf + /REHASH", nick);
		return;
	}
	if (b->status == new_status) {
		sendnotice(client, "Bot %s is already %s", nick, verb);
		return;
	}
	PbStatus old = b->status;
	b->status = new_status;

	if (new_status == PB_STATUS_ACTIVE && !b->ghost) {
		pb_spawn_ghost(b);
	}
	if (new_status != PB_STATUS_ACTIVE && b->ghost) {
		Client *g = b->ghost;
		b->ghost = NULL;
		exit_client(g, NULL, "Bot deactivated by operator");
	}
	if (new_status == PB_STATUS_DELETED) {
		sqlite3_stmt *st = NULL;
		if (sqlite3_prepare_v2(db, "UPDATE pushbots SET status='deleted' WHERE bot_id=?", -1, &st, NULL) == SQLITE_OK) {
			sqlite3_bind_text(st, 1, b->bot_id, -1, SQLITE_STATIC);
			sqlite3_step(st);
			sqlite3_finalize(st);
		}
	} else {
		const char *str = new_status == PB_STATUS_ACTIVE ? "active" :
		                  new_status == PB_STATUS_SUSPENDED ? "suspended" : "pending";
		sqlite3_stmt *st = NULL;
		if (sqlite3_prepare_v2(db, "UPDATE pushbots SET status=? WHERE bot_id=?", -1, &st, NULL) == SQLITE_OK) {
			sqlite3_bind_text(st, 1, str, -1, SQLITE_STATIC);
			sqlite3_bind_text(st, 2, b->bot_id, -1, SQLITE_STATIC);
			sqlite3_step(st);
			sqlite3_finalize(st);
		}
	}
	sendnotice(client, "Bot %s status: %s -> %s", nick,
	           old == PB_STATUS_ACTIVE ? "active" : old == PB_STATUS_PENDING ? "pending" : old == PB_STATUS_SUSPENDED ? "suspended" : "deleted",
	           verb);
	unreal_log(ULOG_INFO, "pushbot", "ADMIN", client,
	           "Operator $opnick: $verb bot $bot",
	           log_data_string("opnick", client->name),
	           log_data_string("verb", verb),
	           log_data_string("bot", nick));
	pb_broadcast_bot_event(b, new_status == PB_STATUS_DELETED ? "remove" : "update");
}

CMD_FUNC(cmd_pushbot)
{
	if (!MyConnect(client) || !IsUser(client)) return;

	if (!ValidatePermissionsForPath("server:pushbot", client, NULL, NULL, NULL)) {
		sendnumeric(client, ERR_NOPRIVILEGES);
		return;
	}
	if (parc < 2) {
		sendnotice(client, "Usage: PUSHBOT LIST | INFO <nick> | APPROVE <nick> | SUSPEND <nick> | UNSUSPEND <nick> | DELETE <nick>");
		return;
	}

	const char *sub = parv[1];
	if (!strcasecmp(sub, "LIST")) {
		cmd_pushbot_list(client);
		return;
	}
	if (!strcasecmp(sub, "INFO")) {
		if (parc < 3) {
			sendnotice(client, "Usage: PUSHBOT INFO <nick>");
			return;
		}
		cmd_pushbot_info(client, parv[2]);
		return;
	}
	if (!strcasecmp(sub, "APPROVE")) {
		if (parc < 3) { sendnotice(client, "Usage: PUSHBOT APPROVE <nick>"); return; }
		cmd_pushbot_setstatus(client, parv[2], PB_STATUS_ACTIVE, "active");
		return;
	}
	if (!strcasecmp(sub, "SUSPEND")) {
		if (parc < 3) { sendnotice(client, "Usage: PUSHBOT SUSPEND <nick>"); return; }
		cmd_pushbot_setstatus(client, parv[2], PB_STATUS_SUSPENDED, "suspended");
		return;
	}
	if (!strcasecmp(sub, "UNSUSPEND")) {
		if (parc < 3) { sendnotice(client, "Usage: PUSHBOT UNSUSPEND <nick>"); return; }
		cmd_pushbot_setstatus(client, parv[2], PB_STATUS_ACTIVE, "active");
		return;
	}
	if (!strcasecmp(sub, "DELETE")) {
		if (parc < 3) { sendnotice(client, "Usage: PUSHBOT DELETE <nick>"); return; }
		cmd_pushbot_setstatus(client, parv[2], PB_STATUS_DELETED, "deleted");
		return;
	}
	sendnotice(client, "Unknown PUSHBOT subcommand: %s", sub);
}

/* ===================================================================
 * Gateway -- Phase 2
 *
 * Listener registration:  listen { options { pushbot; }; } turns the
 * listener into a webserver-mode endpoint with our handlers attached.
 *
 * Path routing inside pb_handle_webrequest:
 *   GET /pushbot/v1/gateway  -> WebSocket upgrade (this phase)
 *   anything else            -> 404 for now (REST API: phase 4)
 *
 * On WS upgrade we:
 *   - require an Authorization: Bearer <token> header
 *   - allocate a PbSession and attach it to moddata
 *   - send op=10 HELLO with the heartbeat interval
 *
 * After upgrade the bot sends:
 *   - op=2 IDENTIFY  -> we look up the bot, attach session, send READY
 *   - op=1 HEARTBEAT -> we ack with op=11
 * =================================================================== */

static int pb_config_test_listen(ConfigFile *cf, ConfigEntry *ce, int type, int *errs)
{
	if (type != CONFIG_LISTEN_OPTIONS)
		return 0;
	if (!ce || !ce->name || strcmp(ce->name, "pushbot"))
		return 0;
	/* No sub-keys yet; this just claims the directive so the parser
	 * doesn't warn about an unknown listen option. */
	return 1;
}

static int pb_config_run_ex_listen(ConfigFile *cf, ConfigEntry *ce, int type, void *ptr)
{
	ConfigItem_listen *l;
	if (type != CONFIG_LISTEN_OPTIONS) return 0;
	if (!ce || !ce->name || strcmp(ce->name, "pushbot")) return 0;
	l = (ConfigItem_listen *)ptr;
	l->options |= LISTENER_NO_CHECK_CONNECT_FLOOD;
	l->options |= LISTENER_NO_CHECK_ZLINED;
	/* Stash via reusing rpc_options? We can't -- it's RPC-specific.
	 * We'll detect in pb_config_listener by walking listen->config. */
	l->rpc_options = 0; /* unrelated; ensures we don't accidentally flip rpc */
	/* We need a distinguishing flag. Hijack a spare bit in listener
	 * options for pushbot. */
	l->options |= 0x800000; /* PUSHBOT marker -- unused upstream bit */
	return 1;
}

static int pb_is_pushbot_listener(ConfigItem_listen *l)
{
	return (l && (l->options & 0x800000)) ? 1 : 0;
}

static int pb_config_listener(ConfigItem_listen *l)
{
	if (!pb_is_pushbot_listener(l)) return 0;
	if (l->socket_type == SOCKET_TYPE_UNIX) {
		/* Not supported -- pushbot wants real TCP+TLS for external bots. */
		config_warn("[pushbot] Unix-socket pushbot listeners are not supported (yet).");
		return 0;
	}
	l->options |= LISTENER_TLS;
	/* Need a custom start_handshake so the default doesn't spam
	 * "*** Looking up your hostname..." NOTICEs into the connection
	 * BEFORE we discover it's an HTTP/WS request -- those bytes
	 * corrupt the WS upgrade response. */
	l->start_handshake = pb_client_handshake;
	l->webserver = safe_alloc(sizeof(WebServer));
	l->webserver->handle_request = pb_handle_webrequest;
	l->webserver->handle_body = pb_handle_webrequest_data;
	return 1;
}

/* Called on accept().  Replaces the default IRC handshake (which
 * would send "*** Looking up your hostname..." NOTICEs that
 * corrupt the WS handshake response).  We still need the bare
 * minimum: reset client status post-TLS and run HOOKTYPE_HANDSHAKE
 * so other modules (TLS cipher info, etc.) get notified.  Skip the
 * DNS lookup -- bots authenticate by Bearer, not by hostmask. */
static void pb_client_handshake(Client *client)
{
	client->status = CLIENT_STATUS_UNKNOWN;
	RunHook(HOOKTYPE_HANDSHAKE, client);
	if (!IsDead(client))
		fd_setselect(client->local->fd, FD_SELECT_READ, read_packet, client);
}

/* Pushbot connections never send NICK/USER, so the default IRC
 * registration-timeout would kill them after ~60 s.  Take over that
 * decision: once the WS handshake has completed, the connection is
 * "registered" as far as we're concerned and only the heartbeat
 * watchdog (pb_heartbeat_check) is allowed to kill it. */
static int pb_pre_handshake_timeout(Client *client, const char **comment)
{
	if (!client || !client->local || !client->local->listener) return HOOK_CONTINUE;
	if (!pb_is_pushbot_listener(client->local->listener)) return HOOK_CONTINUE;
	WebSocketUser *wsu = pb_websocket_md
	    ? (WebSocketUser *)moddata_client(client, pb_websocket_md).ptr
	    : NULL;
	if (wsu && wsu->handshake_completed)
		return HOOK_ALLOW;  /* WS bot is alive; don't time it out */
	return HOOK_CONTINUE;
}

static int pb_check_bearer(const char *auth, char *token_out, size_t tlen)
{
	if (!auth) return 0;
	while (*auth == ' ') auth++;
	if (strncasecmp(auth, "Bearer ", 7)) return 0;
	auth += 7;
	while (*auth == ' ') auth++;
	strlcpy(token_out, auth, tlen);
	/* Strip trailing whitespace just in case. */
	size_t n = strlen(token_out);
	while (n > 0 && (token_out[n-1] == ' ' || token_out[n-1] == '\r' || token_out[n-1] == '\t'))
		token_out[--n] = '\0';
	return token_out[0] ? 1 : 0;
}

/* Look up a bot by plaintext bearer.  Returns NULL on no-match.
 * Phase 1 stashed config-tokens in PbBot->config_token; that's what
 * we compare here.  Self-registered bots will get hashed tokens; we'll
 * compare via the hash in a later phase. */
static PbBot *pb_find_bot_by_token(const char *token)
{
	if (!token || !*token) return NULL;
	for (PbBot *b = bots; b; b = b->next) {
		if (b->status != PB_STATUS_ACTIVE) continue;
		if (!b->config_token) continue;
		if (!strcmp(b->config_token, token))
			return b;
	}
	return NULL;
}

static int pb_handle_webrequest(Client *client, WebRequest *web)
{
	const char *auth = get_nvplist(web->headers, "Authorization");
	char token[512];
	if (!pb_check_bearer(auth, token, sizeof(token))) {
		webserver_send_response(client, 401, "Bearer token required\n");
		return 0;
	}

	/* Phase 8: self-registration endpoint -- doesn't auth as a bot,
	 * but against the configured registration-secret.  Both POST
	 * (register) and GET (list pending requests, ircop-only via the
	 * registration-secret) defer to the body handler. */
	if (web->uri && !strcmp(web->uri, "/pushbot/v1/bots")) {
		/* For POST we MUST read the body even on auth failure --
		 * sending a response + close while the client is still
		 * streaming POST data triggers TCP RST and clients see
		 * "Remote end closed connection without response".
		 * Defer to handle_body so the kernel buffers the body
		 * first.  For GET (no body), reply now. */
		if (web->method == HTTP_METHOD_POST)
			return 1;  /* wait for body, then validate + respond */
		if (!cfg.registration_secret) {
			webserver_send_response(client, 403, "self-registration disabled\n");
			return 0;
		}
		if (strcmp(token, cfg.registration_secret)) {
			webserver_send_response(client, 401, "invalid registration secret\n");
			return 0;
		}
		if (web->method == HTTP_METHOD_GET) {
			pb_rest_list_bots(client, web);
			return 0;
		}
		webserver_send_response(client, 405, "method not allowed\n");
		return 0;
	}

	/* Need to keep token around until the upgrade is complete so we
	 * can hand it to the session.  Stash on the WebSocketUser-equiv
	 * for now (we'll create our session below). */

	if (!strcmp(web->uri, PB_GATEWAY_PATH) &&
	    get_nvplist(web->headers, "Sec-WebSocket-Key")) {
		/* WebSocket upgrade path. */
		if (!pb_websocket_md) {
			webserver_send_response(client, 405,
			    "WebSocket support not loaded (websocket_common module missing).\n");
			return 0;
		}
		/* Look up bot by token BEFORE upgrading -- saves us a roundtrip
		 * on bad creds. */
		PbBot *b = pb_find_bot_by_token(token);
		if (!b) {
			webserver_send_response(client, 401, "Invalid bearer token\n");
			return 0;
		}

		/* Allocate WebSocketUser so websocket_common's frame parser
		 * picks up our connection. */
		moddata_client(client, pb_websocket_md).ptr = safe_alloc(sizeof(WebSocketUser));
		((WebSocketUser *)moddata_client(client, pb_websocket_md).ptr)->type = WEBSOCKET_TYPE_TEXT;

		const char *ws_key = get_nvplist(web->headers, "Sec-WebSocket-Key");
		if (strchr(ws_key, ':')) {
			webserver_send_response(client, 400, "Invalid Sec-WebSocket-Key\n");
			return 0;
		}
		safe_strdup(((WebSocketUser *)moddata_client(client, pb_websocket_md).ptr)->handshake_key, ws_key);

		/* Allocate our session, link to the bot. */
		PbSession *s = safe_alloc(sizeof(PbSession));
		s->client = client;
		s->bot = NULL; /* attached on IDENTIFY, not here */
		s->last_heartbeat = TStime();
		moddata_local_client(client, pb_session_md).ptr = s;

		/* Stash the bot we resolved so IDENTIFY can verify the token
		 * matches what was sent. We do this by storing bot_id in the
		 * client's local extended info -- simplest: set the session's
		 * `bot` field tentatively, but mark identified=0 so dispatch
		 * doesn't fire yet. */
		s->bot = b;

		pb_ws_handshake_send(client);
		pb_send_hello(client);
		return 1; /* accept */
	}

	/* REST routes -- bot already resolved via Bearer token. */
	PbBot *rest_bot = pb_find_bot_by_token(token);
	if (!rest_bot) {
		webserver_send_response(client, 401, "Invalid bearer token\n");
		return 0;
	}
	/* For methods that carry a body (POST), defer until the body has
	 * arrived: webserver will keep calling pb_handle_webrequest_data
	 * with chunks, and we dispatch to pb_handle_rest once complete. */
	if (web->method == HTTP_METHOD_POST || web->method == HTTP_METHOD_PUT) {
		return 1;
	}
	return pb_handle_rest(client, web, rest_bot);
}

static int pb_ws_handshake_send(Client *client)
{
	char buf[512], hashbuf[64], sha1out[20];
	WebSocketUser *wsu = moddata_client(client, pb_websocket_md).ptr;
	wsu->handshake_completed = 1;
	snprintf(buf, sizeof(buf), "%s%s", wsu->handshake_key, WEBSOCKET_MAGIC_KEY);
	sha1hash_binary(sha1out, buf, strlen(buf));
	b64_encode(sha1out, sizeof(sha1out), hashbuf, sizeof(hashbuf));
	snprintf(buf, sizeof(buf),
	         "HTTP/1.1 101 Switching Protocols\r\n"
	         "Upgrade: websocket\r\n"
	         "Connection: Upgrade\r\n"
	         "Sec-WebSocket-Accept: %s\r\n\r\n",
	         hashbuf);
	dbuf_put(&client->local->sendQ, buf, strlen(buf));
	send_queued(client);
	return 0;
}

static int pb_handle_webrequest_data(Client *client, WebRequest *web, const char *buf, int len)
{
	WebSocketUser *wsu = pb_websocket_md ? moddata_client(client, pb_websocket_md).ptr : NULL;
	if (wsu)
		return pb_handle_body_websocket(client, web, buf, len);

	/* REST body (POST): accumulate via webserver_handle_body, then
	 * once complete, the existing pb_handle_rest path doesn't run
	 * again (we already returned 1 from handle_request).  Web body
	 * data comes through here for POST endpoints. */
	if (!webserver_handle_body(client, web, buf, len)) {
		webserver_send_response(client, 400, "Error reading body\n");
		return 0;
	}
	if (web->request_body_complete) {
		/* re-resolve bot by token (cheap; ensures we don't trust
		 * stale state across requests on the same connection) */
		const char *auth = get_nvplist(web->headers, "Authorization");
		char token[512];
		if (!pb_check_bearer(auth, token, sizeof(token))) {
			webserver_send_response(client, 401, "Bearer required\n");
			return 0;
		}
		/* Phase 8: self-registration uses the registration-secret,
		 * not a bot bearer token. */
		if (web->uri && !strcmp(web->uri, "/pushbot/v1/bots") &&
		    web->method == HTTP_METHOD_POST) {
			if (!cfg.registration_secret ||
			    strcmp(token, cfg.registration_secret)) {
				webserver_send_response(client, 401, "invalid registration secret\n");
				return 0;
			}
			pb_rest_register_bot(client, web);
			return 1;
		}
		PbBot *b = pb_find_bot_by_token(token);
		if (!b) {
			webserver_send_response(client, 401, "Invalid token\n");
			return 0;
		}
		pb_handle_rest(client, web, b);
	}
	return 1;
}

static int pb_handle_body_websocket(Client *client, WebRequest *web, const char *buf, int len)
{
	WebSocketUser *wsu = moddata_client(client, pb_websocket_md).ptr;
	if (!wsu || !wsu->handshake_completed)
		return 0;
	return websocket_handle_websocket(client, web, buf, len, pb_packet_in_websocket);
}

static int pb_packet_in_websocket(Client *client, char *buf, int len)
{
	/* Each call is one fully-reassembled WS frame.  We expect text
	 * frames carrying a single JSON object per spec §4.2. */
	if (len <= 0) return 0;
	pb_handle_ws_message(client, buf, len);
	return 0;
}

static void pb_send_op(Client *client, json_t *frame)
{
	char *body = json_dumps(frame, JSON_COMPACT);
	if (!body) return;
	int len = strlen(body);
	char *out = body;
	if (websocket_create_packet(WSOP_TEXT, &out, &len) < 0) {
		free(body);
		return;
	}
	dbuf_put(&client->local->sendQ, out, len);
	send_queued(client);
	free(body);
}

static void pb_send_hello(Client *client)
{
	json_t *frame = json_object();
	json_t *d = json_object();
	json_object_set_new(d, "heartbeat_interval", json_integer(PB_HEARTBEAT_INTERVAL_MS));
	json_object_set_new(frame, "op", json_integer(PB_OP_HELLO));
	json_object_set_new(frame, "d", d);
	pb_send_op(client, frame);
	json_decref(frame);
}

/* Drop everything in the queue with seq <= ack. */
static void pb_queue_ack(PbBot *b, long long ack)
{
	if (!b) return;
	PbQueuedEvent *e = b->queue_head;
	while (e && e->seq <= ack) {
		PbQueuedEvent *next = e->next;
		safe_free(e->json);
		DelListItem(e, b->queue_head);
		if (e == b->queue_tail) b->queue_tail = NULL;
		safe_free(e);
		b->queue_count--;
		e = next;
	}
	if (ack > b->last_acked_seq) b->last_acked_seq = ack;
}

/* Walk the queue and drop entries past their TTL. */
static void pb_queue_expire(PbBot *b)
{
	if (!b) return;
	time_t now = TStime();
	PbQueuedEvent *e = b->queue_head;
	while (e) {
		PbQueuedEvent *next = e->next;
		if (e->expires_at && e->expires_at < now) {
			safe_free(e->json);
			DelListItem(e, b->queue_head);
			if (e == b->queue_tail) b->queue_tail = NULL;
			safe_free(e);
			b->queue_count--;
		}
		e = next;
	}
}

/* Stash a serialized DISPATCH frame in the bot's queue with the given
 * seq.  Used both for new events and for resumption replay (which
 * already has the JSON). */
static int pb_queue_push(PbBot *b, long long seq, const char *json)
{
	if (!b || !json) return -1;
	if (b->queue_count >= PB_QUEUE_MAX) {
		unreal_log(ULOG_WARNING, "pushbot", "QUEUE_OVERFLOW", NULL,
		           "Bot $nick queue overflowed; disconnecting",
		           log_data_string("nick", b->nick));
		if (b->session && b->session->client)
			pb_close_ws(b->session->client, PB_CLOSE_QUEUE_OVERFLOW,
			            "Outbound queue overflowed");
		return -1;
	}
	PbQueuedEvent *e = safe_alloc(sizeof(*e));
	e->seq = seq;
	e->json = strdup(json);
	e->expires_at = TStime() + PB_RESUME_TTL_SEC;
	AppendListItem(e, b->queue_head);
	b->queue_tail = e;
	b->queue_count++;
	return 0;
}

/* Send a DISPATCH frame to the bot's current session AND record it
 * in the per-bot queue for resume.  Called by event-routing code in
 * later phases (CHANMSG handler, slash-command dispatch, etc.). */
static void pb_dispatch_event(PbBot *b, const char *event_name, json_t *data)
{
	if (!b) { if (data) json_decref(data); return; }

	long long seq = ++b->next_seq;
	json_t *frame = json_object();
	json_object_set_new(frame, "op", json_integer(PB_OP_DISPATCH));
	json_object_set_new(frame, "t", json_string(event_name));
	json_object_set_new(frame, "s", json_integer(seq));
	json_object_set_new(frame, "d", data ? data : json_object());

	char *body = json_dumps(frame, JSON_COMPACT);
	json_decref(frame);
	if (!body) return;

	pb_queue_push(b, seq, body);

	/* Gateway leg: deliver if the bot has an active session. */
	if (b->session && b->session->client &&
	    !IsDead(b->session->client) && b->session->client->local &&
	    b->session->identified &&
	    (b->transport == PB_TRANSPORT_GATEWAY || b->transport == PB_TRANSPORT_BOTH)) {
		int len = strlen(body);
		char *out = body;
		if (websocket_create_packet(WSOP_TEXT, &out, &len) >= 0) {
			dbuf_put(&b->session->client->local->sendQ, out, len);
			send_queued(b->session->client);
		}
	}

	/* Webhook leg: fire HTTP POST if configured. */
	if ((b->transport == PB_TRANSPORT_WEBHOOK || b->transport == PB_TRANSPORT_BOTH) &&
	    b->webhook_url && !b->webhook_suspended)
		pb_webhook_dispatch(b, event_name, body);

	free(body);
}

/* Compat shim while older code paths still call the old per-session
 * sender.  Internally just defers to pb_dispatch_event. */
static void pb_send_dispatch(Client *client, const char *event_name, json_t *data)
{
	PbSession *s = PB_SESS(client);
	if (!s || !s->bot) { if (data) json_decref(data); return; }
	pb_dispatch_event(s->bot, event_name, data);
}

static void pb_handle_ws_message(Client *client, char *msg, int len)
{
	json_error_t err;
	json_t *frame = json_loadb(msg, len, 0, &err);
	if (!frame || !json_is_object(frame)) {
		pb_close_ws(client, PB_CLOSE_INVALID_SESSION, "Frame is not a JSON object");
		if (frame) json_decref(frame);
		return;
	}
	json_t *opj = json_object_get(frame, "op");
	if (!json_is_integer(opj)) {
		pb_close_ws(client, PB_CLOSE_INVALID_SESSION, "Frame missing op");
		json_decref(frame);
		return;
	}
	int op = (int)json_integer_value(opj);
	switch (op) {
	case PB_OP_IDENTIFY:   pb_handle_identify(client, frame); break;
	case PB_OP_HEARTBEAT:  pb_handle_heartbeat(client, frame); break;
	case PB_OP_RESUME:   pb_handle_resume(client, frame); break;
	case PB_OP_COMMAND_REGISTER:     pb_handle_command_register(client, frame); break;
	case PB_OP_INTERACTION_RESPONSE: pb_handle_interaction_response(client, frame); break;
	case PB_OP_INTERACTION_DEFER:    pb_handle_interaction_defer(client, frame); break;
	case PB_OP_WORKFLOW_EVENT:       pb_handle_workflow_event(client, frame); break;
	case PB_OP_SEND_MESSAGE:         pb_handle_send_message(client, frame); break;
	case PB_OP_SEND_TAGMSG:          pb_handle_send_tagmsg(client, frame); break;
	default:
		unreal_log(ULOG_DEBUG, "pushbot", "WS_UNKNOWN_OP", client,
		           "Received unknown opcode $op",
		           log_data_integer("op", op));
		break;
	}
	json_decref(frame);
}

static void pb_handle_identify(Client *client, json_t *frame)
{
	PbSession *s = PB_SESS(client);
	if (!s || !s->bot) {
		pb_close_ws(client, PB_CLOSE_AUTH_FAILED, "No session context");
		return;
	}

	json_t *d = json_object_get(frame, "d");
	if (!json_is_object(d)) {
		pb_close_ws(client, PB_CLOSE_AUTH_FAILED, "IDENTIFY.d must be an object");
		return;
	}
	/* Verify token in IDENTIFY matches what authenticated the upgrade. */
	json_t *tokj = json_object_get(d, "token");
	if (!json_is_string(tokj) ||
	    !s->bot->config_token ||
	    strcmp(json_string_value(tokj), s->bot->config_token)) {
		pb_close_ws(client, PB_CLOSE_AUTH_FAILED,
		            "IDENTIFY token mismatch");
		return;
	}

	/* If another session is already attached to this bot, evict it --
	 * IDENTIFY semantics are "I'm taking over".  Without this the old
	 * connection sits there orphaned but with its commands/state still
	 * registered, leading to flapping schemas if the displacing client
	 * registers a different set. */
	if (s->bot->session && s->bot->session != s &&
	    s->bot->session->client && !IsDead(s->bot->session->client))
	{
		unreal_log(ULOG_INFO, "pushbot", "BOT_SESSION_EVICTED", NULL,
		           "Bot $nick: evicting previous session in favour of fresh IDENTIFY",
		           log_data_string("nick", s->bot->nick));
		pb_close_ws(s->bot->session->client, PB_CLOSE_AUTH_FAILED,
		            "Session displaced by new IDENTIFY");
	}
	/* Also drop any previously-registered command schema so a fresh
	 * IDENTIFY isn't serving the old session's commands until the new
	 * session sends its own COMMAND_REGISTER. */
	if (s->bot->commands) {
		json_decref(s->bot->commands);
		s->bot->commands = NULL;
	}

	/* IDENTIFY (vs RESUME) explicitly starts a fresh session.  Any
	 * previous resume window is closed and queued events tossed. */
	while (s->bot->queue_head) {
		PbQueuedEvent *e = s->bot->queue_head;
		safe_free(e->json);
		DelListItem(e, s->bot->queue_head);
		safe_free(e);
		s->bot->queue_count--;
	}
	s->bot->queue_tail = NULL;
	s->bot->next_seq = 0;
	s->bot->last_acked_seq = 0;
	s->bot->resume_expires_at = 0;

	/* Mint a fresh resume session id. */
	char rid[64];
	snprintf(rid, sizeof(rid), "%s.%lx.%lx",
	         s->bot->bot_id, (unsigned long)TStime(), (unsigned long)getpid());
	safe_strdup(s->bot->resume_session_id, rid);

	s->identified = 1;
	s->bot->session = s;
	s->last_heartbeat = TStime();

	/* Update the ghost's away to "online" (drop the away flag) and
	 * broadcast the change so away-notify clients see the bot return. */
	if (s->bot->ghost && s->bot->ghost->user->away) {
		safe_free(s->bot->ghost->user->away);
		s->bot->ghost->user->away = NULL;
		pb_broadcast_away(s->bot->ghost);
	}

	/* READY dispatch. */
	json_t *ready_d = json_object();
	json_object_set_new(ready_d, "session_id", json_string(s->bot->resume_session_id));
	json_object_set_new(ready_d, "bot_nick", json_string(s->bot->nick));
	json_object_set_new(ready_d, "scope", json_string(pb_scope_str(s->bot->scope)));
	json_t *channels = json_array();
	if (s->bot->ghost) {
		for (Membership *m = s->bot->ghost->user->channel; m; m = m->next)
			json_array_append_new(channels, json_string(m->channel->name));
	}
	json_object_set_new(ready_d, "channels", channels);
	pb_send_dispatch(client, "READY", ready_d);

	unreal_log(ULOG_INFO, "pushbot", "BOT_ONLINE", NULL,
	           "Bot $nick is now online on gateway",
	           log_data_string("nick", s->bot->nick));
	pb_broadcast_bot_event(s->bot, "update");
}

static void pb_handle_heartbeat(Client *client, json_t *frame)
{
	PbSession *s = PB_SESS(client);
	if (!s) return;
	/* d carries the last seq the bot has seen; we use it to release
	 * everything in the queue at or below that watermark. */
	json_t *d = json_object_get(frame, "d");
	if (json_is_integer(d) && s->bot)
		pb_queue_ack(s->bot, json_integer_value(d));
	s->last_heartbeat = TStime();
	json_t *ack = json_object();
	json_object_set_new(ack, "op", json_integer(PB_OP_HEARTBEAT_ACK));
	pb_send_op(client, ack);
	json_decref(ack);
}

/* RESUME: bot reconnected within the TTL window and wants to replay
 * missed events. */
static void pb_handle_resume(Client *client, json_t *frame)
{
	PbSession *s = PB_SESS(client);
	if (!s || !s->bot) {
		pb_close_ws(client, PB_CLOSE_INVALID_SESSION, "No session context for resume");
		return;
	}
	PbBot *b = s->bot;

	json_t *d = json_object_get(frame, "d");
	if (!json_is_object(d)) {
		pb_close_ws(client, PB_CLOSE_INVALID_SESSION, "RESUME.d must be object");
		return;
	}
	json_t *sidj = json_object_get(d, "session_id");
	json_t *seqj = json_object_get(d, "seq");
	json_t *tokj = json_object_get(d, "token");
	if (!json_is_string(sidj) || !json_is_integer(seqj) || !json_is_string(tokj)) {
		pb_close_ws(client, PB_CLOSE_INVALID_SESSION,
		            "RESUME requires session_id, seq, token");
		return;
	}
	const char *sid = json_string_value(sidj);
	long long seq = (long long)json_integer_value(seqj);
	const char *tok = json_string_value(tokj);

	/* Validate everything before touching state. */
	if (!b->config_token || strcmp(tok, b->config_token)) {
		pb_close_ws(client, PB_CLOSE_AUTH_FAILED, "RESUME token mismatch");
		return;
	}
	if (!b->resume_session_id || strcmp(sid, b->resume_session_id)) {
		pb_close_ws(client, PB_CLOSE_INVALID_SESSION, "Unknown session_id");
		return;
	}
	pb_queue_expire(b);
	/* If the queue is empty AND seq < next_seq, we lost events that
	 * fell off the TTL window.  Reject; bot must IDENTIFY fresh. */
	if (b->queue_count == 0 && seq < b->next_seq) {
		pb_close_ws(client, PB_CLOSE_INVALID_SESSION,
		            "Resume window expired -- IDENTIFY fresh");
		return;
	}
	if (seq > b->next_seq) {
		pb_close_ws(client, PB_CLOSE_INVALID_SESSION,
		            "seq ahead of server -- IDENTIFY fresh");
		return;
	}

	/* Attach to the bot.  Acknowledge what they have and replay
	 * everything beyond it.  We don't INCREMENT next_seq while
	 * replaying -- the seqs are already baked into each event. */
	pb_queue_ack(b, seq);
	b->session = s;
	b->resume_expires_at = 0;
	s->identified = 1;
	s->last_heartbeat = TStime();

	for (PbQueuedEvent *e = b->queue_head; e; e = e->next) {
		int len = strlen(e->json);
		char *out = e->json;
		if (websocket_create_packet(WSOP_TEXT, &out, &len) >= 0) {
			dbuf_put(&client->local->sendQ, out, len);
		}
	}
	send_queued(client);

	/* Final RESUMED dispatch so the bot knows the replay is done. */
	json_t *resumed_d = json_object();
	json_object_set_new(resumed_d, "replayed",
	                    json_integer(b->queue_count));
	pb_dispatch_event(b, "RESUMED", resumed_d);

	unreal_log(ULOG_INFO, "pushbot", "BOT_RESUMED", NULL,
	           "Bot $nick resumed session, replayed $count event(s)",
	           log_data_string("nick", b->nick),
	           log_data_integer("count", b->queue_count));
}

static void pb_close_ws(Client *client, int code, const char *reason)
{
	/* Send a WebSocket Close frame (opcode 0x08), then mark the
	 * connection dead.  Frame body is a 2-byte close code in network
	 * byte order optionally followed by a UTF-8 reason. */
	char buf[256];
	int rlen = reason ? strlen(reason) : 0;
	if (rlen > 250) rlen = 250;
	buf[0] = (code >> 8) & 0xff;
	buf[1] = code & 0xff;
	if (rlen) memcpy(buf + 2, reason, rlen);
	char *payload = buf;
	int total = 2 + rlen;
	if (websocket_create_packet(0x08 /* WSOP_CLOSE */, &payload, &total) >= 0) {
		dbuf_put(&client->local->sendQ, payload, total);
		send_queued(client);
	}
	dead_socket(client, reason ? reason : "Gateway closed");
}

static void pb_session_free(PbSession *s)
{
	if (!s) return;
	PbBot *online_bot = NULL;
	if (s->bot && s->bot->session == s) {
		PbBot *b = s->bot;
		online_bot = b;
		b->session = NULL;
		/* Open a resume window: keep queued events + session id
		 * around for PB_RESUME_TTL_SEC.  pb_heartbeat_check garbage-
		 * collects expired windows. */
		b->resume_expires_at = TStime() + PB_RESUME_TTL_SEC;
		if (b->ghost && !b->ghost->user->away) {
			safe_strdup(b->ghost->user->away, "bot offline");
			b->ghost->user->away_since = TStime();
			pb_broadcast_away(b->ghost);
		}
	}
	if (s->heartbeat_ev) { EventDel(s->heartbeat_ev); s->heartbeat_ev = NULL; }
	safe_free(s);
	if (online_bot) pb_broadcast_bot_event(online_bot, "update");
}

static void pb_moddata_session_free(ModData *md)
{
	if (!md || !md->ptr) return;
	pb_session_free((PbSession *)md->ptr);
	md->ptr = NULL;
}

EVENT(pb_heartbeat_check)
{
	time_t now = TStime();
	for (PbBot *b = bots; b; b = b->next) {
		/* Live session: check heartbeat.  Guard against half-dead
		 * clients -- moddata free may not have run yet between
		 * dead_socket() and the actual teardown, so b->session can
		 * still point to an IsDead client that we MUST NOT touch. */
		PbSession *s = b->session;
		if (s && s->client && !IsDead(s->client) && s->client->local && s->identified) {
			if ((now - s->last_heartbeat) * 1000 > PB_HEARTBEAT_GRACE_MS) {
				unreal_log(ULOG_INFO, "pushbot", "HEARTBEAT_TIMEOUT", NULL,
				           "Bot $nick gateway timed out, closing",
				           log_data_string("nick", b->nick));
				pb_close_ws(s->client, PB_CLOSE_TIMEOUT, "Heartbeat missed");
			}
		}

		/* Detached resume window: expire queue + clear session id
		 * if the bot didn't come back in time. */
		if (!b->session && b->resume_expires_at && b->resume_expires_at < now) {
			pb_queue_expire(b);
			/* If everything's gone or expired, drop the resume id
			 * so the next IDENTIFY is treated as fresh. */
			if (b->queue_count == 0) {
				safe_free(b->resume_session_id);
				b->resume_session_id = NULL;
				b->next_seq = 0;
				b->last_acked_seq = 0;
				b->resume_expires_at = 0;
			}
		} else if (!b->session && b->queue_head) {
			/* Still inside the window -- just expire individual
			 * entries that timed out. */
			pb_queue_expire(b);
		}
	}
}

/* ===================================================================
 * Phase 5 -- slash commands
 * =================================================================== */

/* Tag validators.  All four are client-prefixed (`+draft/`) tags that
 * carry base64-JSON values; we only sanity-check size + base64-ish
 * character set.  Per-context validation (does the bot exist? does
 * the JSON parse?) happens later in pb_route_botcmd_*. */
static int pb_mtag_botcmd_is_ok(Client *c, const char *n, const char *v)
{
	if (!v || !*v) return 0;
	int len = strlen(v);
	if (len > 4096) return 0;
	for (int i = 0; i < len; i++) {
		char ch = v[i];
		if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
		      (ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=' ||
		      ch == '-' || ch == '_'))
			return 0;
	}
	return 1;
}
static int pb_mtag_botcmds_query_is_ok(Client *c, const char *n, const char *v)
{
	return 1; /* spec-defined valueless tag */
}
static int pb_mtag_botcmds_is_ok(Client *c, const char *n, const char *v)
{
	return pb_mtag_botcmd_is_ok(c, n, v);
}
static int pb_mtag_botcmds_changed_is_ok(Client *c, const char *n, const char *v)
{
	return 1;
}

/* Normalise one registered command to the draft/bot-cmds wire schema.
 * Bots may register either the new shape (a `contexts` array of
 * public/private/pm) or the older obby shape (`visibility` public|private +
 * `scopes` channel|dm); either way we emit `contexts`.  name/description/
 * options/requires pass through unchanged. */
static json_t *pb_command_to_spec(json_t *cmd)
{
	json_t *out = json_object();
	const char *pass[] = { "name", "description", "options", "requires", NULL };
	for (int i = 0; pass[i]; i++) {
		json_t *v = json_object_get(cmd, pass[i]);
		if (v) json_object_set(out, pass[i], v);
	}

	json_t *ctx = json_object_get(cmd, "contexts");
	if (json_is_array(ctx)) {
		json_object_set(out, "contexts", ctx);
		return out;
	}

	/* Derive contexts from the legacy visibility + scopes pair. */
	const char *vis = "public";
	json_t *vj = json_object_get(cmd, "visibility");
	if (json_is_string(vj)) vis = json_string_value(vj);
	int priv = !strcasecmp(vis, "private");

	int has_channel = 0, has_dm = 0;
	json_t *scopes = json_object_get(cmd, "scopes");
	if (json_is_array(scopes)) {
		size_t i; json_t *s;
		json_array_foreach(scopes, i, s) {
			if (!json_is_string(s)) continue;
			if (!strcasecmp(json_string_value(s), "channel")) has_channel = 1;
			else if (!strcasecmp(json_string_value(s), "dm")) has_dm = 1;
		}
	} else {
		has_channel = 1;  /* no scopes => channel by default */
	}

	json_t *contexts = json_array();
	if (has_channel)
		json_array_append_new(contexts, json_string(priv ? "private" : "public"));
	if (has_dm)
		json_array_append_new(contexts, json_string("pm"));
	if (json_array_size(contexts) == 0)
		json_array_append_new(contexts, json_string(priv ? "private" : "public"));
	json_object_set_new(out, "contexts", contexts);
	return out;
}

/* Map a bot's registered command array to the draft/bot-cmds wire schema
 * (contexts rather than the stored visibility/scopes).  Returns a new array.
 * Used everywhere commands go on the wire so clients always see `contexts`. */
static json_t *pb_commands_to_spec_array(json_t *commands)
{
	json_t *out = json_array();
	if (commands) {
		size_t i; json_t *c;
		json_array_foreach(commands, i, c)
			json_array_append_new(out, pb_command_to_spec(c));
	}
	return out;
}

/* Reply to a +draft/bot-cmds-query TAGMSG with the bot's command
 * schema, base64-encoded, addressed back to the querying client. */
static void pb_send_botcmds_to(Client *client, PbBot *b)
{
	if (!client || !b || !b->ghost) return;
	json_t *body = json_object();
	if (b->prefix)
		json_object_set_new(body, "prefix", json_string(b->prefix));
	json_object_set_new(body, "commands", pb_commands_to_spec_array(b->commands));
	char *json_str = json_dumps(body, JSON_COMPACT);
	json_decref(body);
	if (!json_str) return;
	int jlen = strlen(json_str);
	int b64_max = ((jlen + 2) / 3) * 4 + 1;
	char *b64 = safe_alloc(b64_max);
	b64_encode(json_str, jlen, b64, b64_max);
	free(json_str);

	MessageTag *tag = safe_alloc(sizeof(*tag));
	safe_strdup(tag->name, "+draft/bot-cmds");
	safe_strdup(tag->value, b64);
	sendto_one(client, tag, ":%s TAGMSG %s",
	           b->ghost->name, client->name);
	free_message_tags(tag);
	safe_free(b64);
}

/* ===================================================================
 * draft/bot-tools workflow streaming
 * =================================================================== */

static PbWorkflow *pb_workflow_find(const char *wid)
{
	if (!wid || !*wid) return NULL;
	for (PbWorkflow *w = workflows; w; w = w->next)
		if (w->wid && !strcmp(w->wid, wid))
			return w;
	return NULL;
}

static PbWorkflow *pb_workflow_find_by_sid(const char *sid)
{
	if (!sid || !*sid) return NULL;
	for (PbWorkflow *w = workflows; w; w = w->next) {
		for (NameList *n = w->sids; n; n = n->next)
			if (!strcmp(n->name, sid)) return w;
	}
	return NULL;
}

static PbWorkflow *pb_workflow_touch(PbBot *bot, const char *wid, const char *target)
{
	if (!bot || !wid || !*wid) return NULL;
	PbWorkflow *w = pb_workflow_find(wid);
	if (w) {
		if (w->bot != bot) return NULL;   /* foreign wid -- refuse */
		w->expires_at = TStime() + PB_WORKFLOW_TTL_SEC;
		if (target && (!w->target || strcmp(w->target, target)))
			safe_strdup(w->target, target);
		w->terminal = 0;
		return w;
	}
	w = safe_alloc(sizeof(*w));
	safe_strdup(w->wid, wid);
	w->bot = bot;
	if (target && *target) safe_strdup(w->target, target);
	w->expires_at = TStime() + PB_WORKFLOW_TTL_SEC;
	AddListItem(w, workflows);
	return w;
}

static void pb_workflow_remember_sid(PbWorkflow *w, const char *sid)
{
	if (!w || !sid || !*sid) return;
	if (find_name_list(w->sids, sid)) return;
	add_name_list(w->sids, sid);
}

static void pb_workflow_terminate(PbWorkflow *w)
{
	if (!w) return;
	/* Keep the entry alive for a short grace window so any in-flight
	 * action TAGMSG still resolves; the GC takes it from there. */
	w->terminal = 1;
	w->expires_at = TStime() + 60;
}

static void pb_workflow_free(PbWorkflow *w)
{
	if (!w) return;
	DelListItem(w, workflows);
	safe_free(w->wid);
	safe_free(w->target);
	free_entire_name_list(w->sids);
	safe_free(w);
}

static void pb_workflow_drop_for_bot(PbBot *bot)
{
	PbWorkflow *w = workflows;
	while (w) {
		PbWorkflow *next = w->next;
		if (w->bot == bot) pb_workflow_free(w);
		w = next;
	}
}

EVENT(pb_workflow_gc)
{
	time_t now = TStime();
	PbWorkflow *w = workflows;
	while (w) {
		PbWorkflow *next = w->next;
		if (w->expires_at && now > w->expires_at)
			pb_workflow_free(w);
		w = next;
	}
}

/* Construct and send a +draft/bot-tools TAGMSG from a bot's ghost to a
 * channel or user. payload_obj is owned by caller (we json_dumps it,
 * possibly mutate `content` for truncation, and don't free). */
static int pb_workflow_send_tag(PbBot *bot, const char *target,
                                json_t *payload_obj)
{
	if (!bot || !bot->ghost || !target || !*target || !payload_obj)
		return 0;

	/* If the payload won't fit under the tag limit, try truncating
	 * `content` (per draft/bot-tools §value-encoding). */
	char *json_str = json_dumps(payload_obj, JSON_COMPACT);
	if (!json_str) return 0;
	if ((int)strlen(json_str) > PB_WORKFLOW_JSON_BUDGET) {
		json_t *content = json_object_get(payload_obj, "content");
		if (content && json_is_string(content)) {
			const char *s = json_string_value(content);
			int overshoot = strlen(json_str) - PB_WORKFLOW_JSON_BUDGET;
			int slen = strlen(s);
			int keep = slen - overshoot - 32;
			if (keep < 0) keep = 0;
			char *truncated = safe_alloc(keep + 2);
			memcpy(truncated, s, keep);
			truncated[keep] = '\0';
			json_object_set_new(payload_obj, "content", json_string(truncated));
			json_object_set_new(payload_obj, "truncated", json_true());
			safe_free(truncated);
			free(json_str);
			json_str = json_dumps(payload_obj, JSON_COMPACT);
			if (!json_str) return 0;
		}
		/* If it's still too big (or content wasn't a string), give up
		 * gracefully: log and emit nothing rather than a broken tag. */
		if ((int)strlen(json_str) > PB_WORKFLOW_JSON_BUDGET) {
			unreal_log(ULOG_WARNING, "pushbot", "WF_OVERSIZE", NULL,
			           "Bot $nick workflow payload too big to send "
			           "(size=$size, budget=$budget); drop",
			           log_data_string("nick", bot->nick ? bot->nick : "?"),
			           log_data_integer("size", (int)strlen(json_str)),
			           log_data_integer("budget", PB_WORKFLOW_JSON_BUDGET));
			free(json_str);
			return 0;
		}
	}

	int jlen = strlen(json_str);
	int b64_max = ((jlen + 2) / 3) * 4 + 1;
	char *b64 = safe_alloc(b64_max);
	b64_encode((unsigned char *)json_str, jlen, b64, b64_max);
	free(json_str);

	MessageTag *tag = safe_alloc(sizeof(*tag));
	safe_strdup(tag->name, "+draft/bot-tools");
	safe_strdup(tag->value, b64);

	Channel *ch = (*target == '#' || *target == '&' || *target == '^') ?
	              find_channel(target) : NULL;
	if (ch) {
		sendto_channel(ch, bot->ghost, NULL, NULL, 0, SEND_ALL, tag,
		               ":%s TAGMSG %s", bot->ghost->name, ch->name);
	} else {
		Client *to = find_user(target, NULL);
		if (to)
			sendto_one(to, tag, ":%s TAGMSG %s",
			           bot->ghost->name, to->name);
	}

	free_message_tags(tag);
	safe_free(b64);
	return 1;
}

/* PB_OP_WORKFLOW_EVENT handler:
 *   {op:30, d:{target:"#chan"|"nick", payload:{...draft/bot-tools obj...}}}
 *
 * Updates the workflow ownership table from the payload (wid/sid/state),
 * then constructs and sends a +draft/bot-tools TAGMSG to `target`.
 */
static void pb_handle_workflow_event(Client *client, json_t *frame)
{
	PbSession *s = PB_SESS(client);
	if (!s || !s->bot || !s->identified) {
		pb_close_ws(client, PB_CLOSE_AUTH_FAILED, "Not authenticated");
		return;
	}
	json_t *d = json_object_get(frame, "d");
	if (!json_is_object(d)) return;

	json_t *targetj = json_object_get(d, "target");
	json_t *payload = json_object_get(d, "payload");
	if (!json_is_string(targetj) || !json_is_object(payload)) return;

	pb_core_workflow_event(s->bot, json_string_value(targetj), payload);
}

/* Inbound action routing.
 *
 * A user sends a TAGMSG carrying +draft/bot-tools whose decoded value
 * has msg="action". Per spec the target is a workflow id (cancel,
 * input) or a step sid (approve, reject). We look it up, find the
 * owning bot, and dispatch a WORKFLOW_ACTION event to that bot. */
static int pb_route_bottools_action(Client *invoker, Client *target_user,
                                    Channel *target_chan, const char *bot_tools_b64)
{
	if (!invoker || !bot_tools_b64 || !*bot_tools_b64) return 0;

	int blen = strlen(bot_tools_b64);
	int max_decoded = (blen / 4) * 3 + 4;
	unsigned char *decoded = safe_alloc(max_decoded);
	int dlen = b64_decode(bot_tools_b64, decoded, max_decoded);
	if (dlen <= 0) { safe_free(decoded); return 0; }

	json_error_t je;
	json_t *obj = json_loadb((const char *)decoded, dlen, 0, &je);
	safe_free(decoded);
	if (!obj || !json_is_object(obj)) {
		if (obj) json_decref(obj);
		return 0;
	}

	json_t *msgj = json_object_get(obj, "msg");
	if (!json_is_string(msgj) || strcmp(json_string_value(msgj), "action")) {
		json_decref(obj);
		return 0;
	}

	json_t *actionj = json_object_get(obj, "action");
	json_t *targetj = json_object_get(obj, "target");
	if (!json_is_string(actionj) || !json_is_string(targetj)) {
		json_decref(obj);
		return 0;
	}
	const char *action = json_string_value(actionj);
	const char *target = json_string_value(targetj);

	/* Resolve target -> workflow. cancel/input identify the workflow
	 * directly by wid; approve/reject use a step sid. */
	PbWorkflow *w = NULL;
	if (!strcmp(action, "approve") || !strcmp(action, "reject"))
		w = pb_workflow_find_by_sid(target);
	if (!w) w = pb_workflow_find(target);
	if (!w || !w->bot) {
		json_decref(obj);
		return 0;
	}

	/* If the TAGMSG was sent to a channel (rare for actions; the spec
	 * says actions go to the bot's nick), make sure the bot is at
	 * least in that channel before forwarding the signal. */
	if (target_chan && !pb_bot_is_in_channel(w->bot, target_chan)) {
		json_decref(obj);
		return 0;
	}
	(void)target_user;

	json_t *d = json_object();
	json_object_set_new(d, "wid", json_string(w->wid ? w->wid : ""));
	json_object_set_new(d, "action", json_string(action));
	json_object_set_new(d, "target", json_string(target));
	json_t *contentj = json_object_get(obj, "content");
	if (contentj) json_object_set(d, "content", contentj);
	json_object_set_new(d, "from", pb_json_client(invoker));

	pb_dispatch_event(w->bot, "WORKFLOW_ACTION", d);
	json_decref(obj);
	return 1;
}

/* Copy our client-prefixed tags from the incoming message into the
 * outgoing tag list, so HOOKTYPE_CHANMSG/USERMSG can see them. */
static void pb_mtag_forward(Client *sender, MessageTag *recv_mtags,
                            MessageTag **mtag_list, const char *signature)
{
	if (!IsUser(sender)) return;
	static const char *names[] = {
		"+draft/bot-cmd", "+draft/bot-cmds-query",
		"+draft/bot-cmds", "+draft/bot-cmds-changed",
		"+draft/invoked-by",
		"batch",
		NULL
	};
	for (int i = 0; names[i]; i++) {
		MessageTag *m = find_mtag(recv_mtags, names[i]);
		if (!m) continue;
		MessageTag *dup = duplicate_mtag(m);
		AddListItem(dup, *mtag_list);
	}
}

typedef struct PbBotCmdsBatch {
	struct PbBotCmdsBatch *prev, *next;
	Client *opener;
	char ref[64];
	char target_nick[NICKLEN + 1];
} PbBotCmdsBatch;

static PbBotCmdsBatch *pb_botcmds_batches = NULL;

static PbBotCmdsBatch *pb_botcmds_batch_find(Client *c, const char *ref)
{
	for (PbBotCmdsBatch *b = pb_botcmds_batches; b; b = b->next)
		if (b->opener == c && !strcmp(b->ref, ref))
			return b;
	return NULL;
}

static void pb_botcmds_batch_remove(PbBotCmdsBatch *b)
{
	DelListItem(b, pb_botcmds_batches);
	safe_free(b);
}

/* Deliver a bot-cmds BATCH frame to `target` and every persistence session
 * attached to the same account.  A nick-targeted batch otherwise reaches only
 * the canonical connection, so a multi-session user never sees the bot-cmds
 * reply on their other clients.  Sessions are discovered through the
 * account_canonical moddata persistence exposes (the canonical points at
 * itself, each session at its canonical); with persistence absent the frame
 * goes to the single target exactly as before. */
static void pb_botcmds_batch_frame(Client *from, Client *target, const char *batcharg)
{
	ModDataInfo *canon = findmoddata_byname("account_canonical", MODDATATYPE_CLIENT);
	Client *anchor = canon ? moddata_client(target, canon).ptr : NULL;
	int sent = 0;

	if (anchor)
	{
		Client *c;
		list_for_each_entry(c, &lclient_list, lclient_node)
		{
			if (!MyUser(c) || !IsUser(c))
				continue;
			if (moddata_client(c, canon).ptr != anchor)
				continue;
			if (!HasCapability(c, "batch") || !HasCapability(c, "message-tags"))
				continue;
			sendto_prefix_one(c, from, NULL, ":%s BATCH %s", from->name, batcharg);
			sent = 1;
		}
	}

	if (!sent && MyUser(target) &&
	    HasCapability(target, "batch") && HasCapability(target, "message-tags"))
		sendto_prefix_one(target, from, NULL, ":%s BATCH %s", from->name, batcharg);
}

/* BATCH override: claim draft/bot-cmds so cmd_batch doesn't reject it
 * as UNKNOWN_TYPE. Syntax: BATCH +ref draft/bot-cmds <target>. */
CMD_OVERRIDE_FUNC(pb_override_batch)
{
	if (!MyUser(client) || parc < 2 || BadPtr(parv[1]))
	{
		CALL_NEXT_COMMAND_OVERRIDE();
		return;
	}

	if (parv[1][0] == '+')
	{
		if (parc < 3 || BadPtr(parv[2]) || strcmp(parv[2], "draft/bot-cmds"))
		{
			CALL_NEXT_COMMAND_OVERRIDE();
			return;
		}
		if (!valid_batch_reference_tag(parv[1] + 1))
		{
			sendto_one(client, NULL, ":%s FAIL BATCH INVALID_REFTAG %s :Invalid batch reference tag",
			           me.name, parv[1] + 1);
			return;
		}
		if (parc < 4 || BadPtr(parv[3]))
		{
			sendto_one(client, NULL, ":%s FAIL BATCH BOT_CMDS_INVALID :draft/bot-cmds requires target nick",
			           me.name);
			return;
		}

		Client *target = find_user(parv[3], NULL);
		if (!target)
		{
			sendnumeric(client, ERR_NOSUCHNICK, parv[3]);
			return;
		}

		PbBotCmdsBatch *b = safe_alloc(sizeof(*b));
		strlcpy(b->ref, parv[1] + 1, sizeof(b->ref));
		strlcpy(b->target_nick, target->name, sizeof(b->target_nick));
		b->opener = client;
		AddListItem(b, pb_botcmds_batches);

		{
			char batcharg[128];
			ircsnprintf(batcharg, sizeof(batcharg), "%s draft/bot-cmds", parv[1]);
			pb_botcmds_batch_frame(client, target, batcharg);
		}
		return;
	}

	if (parv[1][0] == '-')
	{
		PbBotCmdsBatch *b = pb_botcmds_batch_find(client, parv[1] + 1);
		if (!b)
		{
			CALL_NEXT_COMMAND_OVERRIDE();
			return;
		}
		Client *target = find_user(b->target_nick, NULL);
		if (target)
			pb_botcmds_batch_frame(client, target, parv[1]);
		pb_botcmds_batch_remove(b);
		return;
	}

	CALL_NEXT_COMMAND_OVERRIDE();
}

static PbInteraction *pb_interaction_find(const char *id)
{
	if (!id) return NULL;
	for (PbInteraction *it = interactions; it; it = it->next)
		if (it->id && !strcmp(it->id, id))
			return it;
	return NULL;
}

static PbInteraction *pb_interaction_new(PbBot *bot, Client *invoker,
                                         const char *channel, const char *msgid,
                                         int invoked_public)
{
	PbInteraction *it = safe_alloc(sizeof(*it));
	it->invoked_public = invoked_public;
	char idbuf[64];
	snprintf(idbuf, sizeof(idbuf), "iact.%lx.%lx",
	         (unsigned long)TStime(), (unsigned long)rand());
	safe_strdup(it->id, idbuf);
	if (invoker && invoker->name[0]) safe_strdup(it->invoker_nick, invoker->name);
	if (channel) safe_strdup(it->channel, channel);
	if (msgid) safe_strdup(it->invoker_msgid, msgid);
	it->bot = bot;
	it->expires_at = TStime() + PB_INTERACTION_TIMEOUT_SEC;
	AddListItem(it, interactions);
	return it;
}

static void pb_interaction_free(PbInteraction *it)
{
	if (!it) return;
	DelListItem(it, interactions);
	safe_free(it->id);
	safe_free(it->invoker_nick);
	safe_free(it->channel);
	safe_free(it->invoker_msgid);
	safe_free(it->invoker_cmd_b64);
	safe_free(it->workflow_id);
	safe_free(it);
}

/* Build a NameValuePrioList holding +reply / +draft/channel-context
 * / +draft/invoked-by for use with sendto_one() etc.  Caller
 * must free_message_tags(). */
static MessageTag *pb_make_reply_tags(const char *reply_msgid,
                                      const char *channel_ctx,
                                      const char *invoked_by_b64)
{
	MessageTag *head = NULL, *tail = NULL;
	if (reply_msgid && *reply_msgid) {
		/* Only +draft/reply, NOT also +reply: obsidian client treats
		 * each as a separate reply annotation and renders the message
		 * twice when both are present. Matches fluffilloo. */
		MessageTag *m = safe_alloc(sizeof(*m));
		safe_strdup(m->name, "+draft/reply");
		safe_strdup(m->value, reply_msgid);
		AddListItem(m, head);
		if (!tail) tail = m;
	}
	if (channel_ctx && *channel_ctx) {
		MessageTag *m = safe_alloc(sizeof(*m));
		safe_strdup(m->name, "+draft/channel-context");
		safe_strdup(m->value, channel_ctx);
		AddListItem(m, head);
	}
	if (invoked_by_b64 && *invoked_by_b64) {
		MessageTag *m = safe_alloc(sizeof(*m));
		safe_strdup(m->name, "+draft/invoked-by");
		safe_strdup(m->value, invoked_by_b64);
		AddListItem(m, head);
	}
	return head;
}

/* Decode base64 -- tolerate missing '=' padding (IRCv3 tag-values
 * frequently strip it to save bytes; unrealircd's b64_decode is
 * strict and would reject them otherwise). */
static char *pb_b64_decode_alloc(const char *b64, int *outlen)
{
	if (!b64) return NULL;
	int n = strlen(b64);
	int pad = (4 - (n % 4)) % 4;
	char *padded = safe_alloc(n + pad + 1);
	memcpy(padded, b64, n);
	for (int i = 0; i < pad; i++) padded[n + i] = '=';
	padded[n + pad] = '\0';
	char *buf = safe_alloc(n + pad + 1);
	int got = b64_decode(padded, (unsigned char *)buf, n + pad + 1);
	safe_free(padded);
	if (got <= 0) {
		safe_free(buf);
		return NULL;
	}
	if (outlen) *outlen = got;
	return buf;
}

/* draft/bot-cmds §Reporting an error: a NOTICE to the invoker carrying
 * +draft/bot-cmd-error=<CODE>, correlated with +reply, whispered against the
 * channel for a private invocation.  `from` is the bot ghost name, or the
 * server name when no bot/command resolved. */
static void pb_send_botcmd_error(Client *invoker, const char *from,
                                 const char *channel, const char *msgid,
                                 const char *code, const char *human)
{
	if (!invoker || !from || !code) return;
	MessageTag *tags = NULL, *m;
	if (msgid && *msgid) {
		m = safe_alloc(sizeof(*m));
		safe_strdup(m->name, "+reply");
		safe_strdup(m->value, msgid);
		AddListItem(m, tags);
	}
	if (channel && *channel) {
		m = safe_alloc(sizeof(*m));
		safe_strdup(m->name, "+draft/channel-context");
		safe_strdup(m->value, channel);
		AddListItem(m, tags);
	}
	m = safe_alloc(sizeof(*m));
	safe_strdup(m->name, "+draft/bot-cmd-error");
	safe_strdup(m->value, code);
	AddListItem(m, tags);
	sendto_one(invoker, tags, ":%s NOTICE %s :%s",
	           from, invoker->name, human ? human : code);
	free_message_tags(tags);
}

/* Find a registered command definition by name (case-insensitive). */
static json_t *pb_find_command_def(PbBot *b, const char *name)
{
	if (!b || !b->commands || !name) return NULL;
	size_t i; json_t *c;
	json_array_foreach(b->commands, i, c) {
		json_t *n = json_object_get(c, "name");
		if (json_is_string(n) && !strcasecmp(json_string_value(n), name))
			return c;
	}
	return NULL;
}

/* draft/bot-cmds min-channel-rank ladder: voice=1 .. owner=5. */
static int pb_rank_level(const char *name)
{
	if (!name) return 0;
	if (!strcasecmp(name, "voice"))  return 1;
	if (!strcasecmp(name, "halfop")) return 2;
	if (!strcasecmp(name, "op"))     return 3;
	if (!strcasecmp(name, "admin"))  return 4;
	if (!strcasecmp(name, "owner"))  return 5;
	return 0;
}
static int pb_member_rank(Client *cli, Channel *ch)
{
	if (!cli || !cli->user || !ch) return 0;
	Membership *mb = find_membership_link(cli->user->channel, ch);
	if (!mb) return 0;
	int r = 0;
	if (strchr(mb->member_modes, 'v')) r = 1;
	if (strchr(mb->member_modes, 'h')) r = 2;
	if (strchr(mb->member_modes, 'o')) r = 3;
	if (strchr(mb->member_modes, 'a')) r = 4;
	if (strchr(mb->member_modes, 'q')) r = 5;
	return r;
}

/* Validate an invocation against the advertised schema + gating.  Returns a
 * draft/bot-cmds error code (and sets *human) on failure, or NULL if OK. */
static const char *pb_validate_invocation(PbBot *bot, const char *cmd_name,
                                          json_t *options, Client *invoker,
                                          Channel *ch, const char **human)
{
	static char buf[160];
	json_t *def = pb_find_command_def(bot, cmd_name);
	if (!def) { *human = "No such command."; return "INVALID_COMMAND"; }

	json_t *opts = json_object_get(def, "options");
	if (json_is_array(opts)) {
		size_t i; json_t *o;
		json_array_foreach(opts, i, o) {
			json_t *nmj = json_object_get(o, "name");
			if (!json_is_string(nmj)) continue;
			const char *oname = json_string_value(nmj);
			json_t *val = options ? json_object_get(options, oname) : NULL;
			if (json_is_true(json_object_get(o, "required")) && !val) {
				snprintf(buf, sizeof buf, "Missing required option: %s", oname);
				*human = buf; return "INVALID_OPTIONS";
			}
			json_t *choices = json_object_get(o, "choices");
			if (val && json_is_array(choices) && json_array_size(choices) > 0) {
				const char *vs = json_is_string(val) ? json_string_value(val) : NULL;
				int ok = 0; size_t k; json_t *cj;
				json_array_foreach(choices, k, cj)
					if (json_is_string(cj) && vs &&
					    !strcmp(json_string_value(cj), vs)) { ok = 1; break; }
				if (!ok) {
					snprintf(buf, sizeof buf, "Invalid value for option: %s", oname);
					*human = buf; return "INVALID_OPTIONS";
				}
			}
		}
	}

	json_t *req = json_object_get(def, "requires");
	if (json_is_object(req)) {
		if (json_is_true(json_object_get(req, "tls")) && !IsSecure(invoker)) {
			*human = "This command requires a secure (TLS) connection.";
			return "NOT_PERMITTED";
		}
		if (json_is_true(json_object_get(req, "account")) && !IsLoggedIn(invoker)) {
			*human = "This command requires you to be logged in to an account.";
			return "NOT_PERMITTED";
		}
		json_t *mr = json_object_get(req, "min-channel-rank");
		if (json_is_string(mr) && ch) {
			int need = pb_rank_level(json_string_value(mr));
			if (need && pb_member_rank(invoker, ch) < need) {
				snprintf(buf, sizeof buf,
				         "This command requires channel rank: %s",
				         json_string_value(mr));
				*human = buf; return "NOT_PERMITTED";
			}
		}
	}
	return NULL;
}

/* Common dispatch path once the bot, invoker, and command JSON
 * are known.  Generates an interaction id, fires COMMAND_INVOKE. */
static void pb_dispatch_command(PbBot *bot, Client *invoker,
                                const char *channel, const char *invoker_msgid,
                                int invoked_public, json_t *cmd_json)
{
	if (!bot || !invoker || !cmd_json) {
		if (cmd_json) json_decref(cmd_json);
		return;
	}

	/* Validate against the advertised schema + gating before dispatching;
	 * report failures via +draft/bot-cmd-error rather than acting. */
	{
		const char *vname = NULL;
		json_t *vnm = json_object_get(cmd_json, "name");
		if (json_is_string(vnm)) vname = json_string_value(vnm);
		json_t *vopts = json_object_get(cmd_json, "options");
		Channel *vch = channel ? find_channel(channel) : NULL;
		const char *human = NULL;
		const char *code = pb_validate_invocation(bot, vname ? vname : "",
		                                          vopts, invoker, vch, &human);
		if (code) {
			pb_send_botcmd_error(invoker,
			                     bot->ghost ? bot->ghost->name : me.name,
			                     channel, invoker_msgid, code, human);
			json_decref(cmd_json);
			return;
		}
	}

	if (!bot->session || !bot->session->identified ||
	    !bot->session->client || IsDead(bot->session->client)) {
		sendto_one(invoker, NULL, ":%s FAIL BOTCMD BOT_OFFLINE %s :Bot is offline",
		           me.name, bot->nick ? bot->nick : "?");
		json_decref(cmd_json);
		return;
	}
	PbInteraction *it = pb_interaction_new(bot, invoker, channel, invoker_msgid,
	                                       invoked_public);

	json_t *d = json_object();
	json_object_set_new(d, "id", json_string(it->id));
	json_object_set_new(d, "invoker", pb_json_client(invoker));
	if (channel) json_object_set_new(d, "channel", json_string(channel));
	else         json_object_set_new(d, "channel", json_null());
	if (invoker_msgid)
		json_object_set_new(d, "invoker_msgid", json_string(invoker_msgid));
	/* cmd_json is { "name": ..., "options": {...} } */
	const char *cmd_name = NULL;
	json_t *nm = json_object_get(cmd_json, "name");
	if (json_is_string(nm)) cmd_name = json_string_value(nm);
	json_object_set_new(d, "name", json_string(cmd_name ? cmd_name : ""));
	json_t *opts = json_object_get(cmd_json, "options");
	json_object_set_new(d, "options", opts ? json_incref(opts) : json_object());

	/* Snapshot the invocation for the eventual reply tag.  We base64
	 * a JSON object {nick, name, options} so the receiving client
	 * doesn't have to track outgoing msgids itself to know what the
	 * user originally typed -- the reply carries the context inline. */
	{
		json_t *snap = json_object();
		json_object_set_new(snap, "nick",
		    json_string(invoker && invoker->name[0] ? invoker->name : ""));
		json_object_set_new(snap, "name", json_string(cmd_name ? cmd_name : ""));
		json_object_set_new(snap, "options",
		    opts ? json_incref(opts) : json_object());
		char *snap_str = json_dumps(snap, JSON_COMPACT);
		json_decref(snap);
		if (snap_str) {
			int slen = strlen(snap_str);
			int b64_max = ((slen + 2) / 3) * 4 + 1;
			char *b64 = safe_alloc(b64_max);
			b64_encode(snap_str, slen, b64, b64_max);
			free(snap_str);
			it->invoker_cmd_b64 = b64; /* safe_alloc'd, freed in pb_interaction_free */
		}
	}

	pb_dispatch_event(bot, "COMMAND_INVOKE", d);
	json_decref(cmd_json);
}

/* ── draft/bot-cmds legacy compatibility ──────────────────────────────────── */

/* Append one option value to a legacy text rendering buffer. */
static int pb_append_value(char *buf, int n, size_t cap, json_t *v)
{
	char vbuf[160];
	if (json_is_string(v))
		strlcpy(vbuf, json_string_value(v), sizeof vbuf);
	else if (json_is_integer(v))
		snprintf(vbuf, sizeof vbuf, "%lld", (long long)json_integer_value(v));
	else if (json_is_real(v))
		snprintf(vbuf, sizeof vbuf, "%g", json_real_value(v));
	else if (json_is_true(v)) strlcpy(vbuf, "true", sizeof vbuf);
	else if (json_is_false(v)) strlcpy(vbuf, "false", sizeof vbuf);
	else return n;
	if (n < (int)cap)
		n += snprintf(buf + n, cap - n, " %s", vbuf);
	return n;
}

/* §Downgrading a structured invocation: render the invocation in the bot's
 * legacy "<prefix><name> v1 v2 ..." form (values in schema order) and send it,
 * as a PRIVMSG from the invoker, only to channel members that have NOT
 * negotiated draft/bot-cmds and are not bots -- so legacy users see what ran.
 * No-op unless the bot has a configured prefix. */
static void pb_downgrade_invocation(Client *invoker, Channel *channel,
                                    PbBot *bot, json_t *cmd)
{
	if (!bot->prefix || !invoker || !invoker->user || !channel) return;
	const char *name = NULL;
	json_t *nmj = json_object_get(cmd, "name");
	if (json_is_string(nmj)) name = json_string_value(nmj);
	if (!name) return;
	json_t *options = json_object_get(cmd, "options");

	char text[512];
	int n = snprintf(text, sizeof text, "%s%s", bot->prefix, name);
	json_t *def = pb_find_command_def(bot, name);
	json_t *opts = def ? json_object_get(def, "options") : NULL;
	if (json_is_array(opts) && json_is_object(options)) {
		size_t i; json_t *o;
		json_array_foreach(opts, i, o) {
			json_t *onm = json_object_get(o, "name");
			if (!json_is_string(onm)) continue;
			json_t *v = json_object_get(options, json_string_value(onm));
			if (v) n = pb_append_value(text, n, sizeof text, v);
		}
	}

	const char *umask_user = invoker->user->username;
	const char *umask_host = GetHost(invoker);
	for (Member *mem = channel->members; mem; mem = mem->next) {
		Client *t = mem->client;
		if (!MyUser(t)) continue;
		if (t == invoker) continue;
		if (CAP_BOT_CMDS && HasCapabilityFast(t, CAP_BOT_CMDS)) continue;
		if (has_user_mode(t, 'B')) continue;
		sendto_one(t, NULL, ":%s!%s@%s PRIVMSG %s :%s",
		           invoker->name, umask_user, umask_host, channel->name, text);
	}
}

/* §Upgrading a legacy invocation: if `text` is a "<prefix><name> args" line for
 * a command this bot publishes, build a structured invocation (mapping
 * whitespace-separated args onto options in schema order) and dispatch it.
 * Returns 1 if handled (caller should not also fire MESSAGE_CREATE for this
 * bot), 0 otherwise.  No-op unless the bot has a configured prefix. */
static int pb_try_upgrade_legacy(PbBot *bot, Client *invoker,
                                 const char *channel, const char *msgid,
                                 const char *text)
{
	if (!bot->prefix || !text) return 0;
	size_t plen = strlen(bot->prefix);
	if (strncmp(text, bot->prefix, plen) != 0) return 0;
	const char *rest = text + plen;
	while (*rest == ' ') rest++;
	if (!*rest) return 0;

	char name[64];
	size_t i = 0;
	while (rest[i] && rest[i] != ' ' && i < sizeof(name) - 1) { name[i] = rest[i]; i++; }
	name[i] = '\0';
	json_t *def = pb_find_command_def(bot, name);
	if (!def) return 0;

	const char *args = rest + i;
	while (*args == ' ') args++;

	json_t *options = json_object();
	json_t *opts = json_object_get(def, "options");
	if (json_is_array(opts) && *args) {
		size_t nopts = json_array_size(opts);
		const char *p = args;
		for (size_t k = 0; k < nopts && *p; k++) {
			json_t *o = json_array_get(opts, k);
			json_t *onm = json_object_get(o, "name");
			if (!json_is_string(onm)) continue;
			const char *oname = json_string_value(onm);
			char val[256];
			if (k == nopts - 1) {           /* last option soaks up the rest */
				strlcpy(val, p, sizeof val);
				p += strlen(p);
			} else {
				size_t j = 0;
				while (*p && *p != ' ' && j < sizeof(val) - 1) val[j++] = *p++;
				val[j] = '\0';
				while (*p == ' ') p++;
			}
			json_t *otype = json_object_get(o, "type");
			const char *ty = json_is_string(otype) ? json_string_value(otype) : "string";
			if (!strcmp(ty, "int"))
				json_object_set_new(options, oname, json_integer(atoll(val)));
			else if (!strcmp(ty, "bool"))
				json_object_set_new(options, oname,
				    (!strcmp(val, "true") || !strcmp(val, "1") ||
				     !strcmp(val, "yes")) ? json_true() : json_false());
			else
				json_object_set_new(options, oname, json_string(val));
		}
	}

	json_t *cmd = json_object();
	json_object_set_new(cmd, "name", json_string(name));
	json_object_set_new(cmd, "options", options);
	/* A legacy "<prefix><cmd>" typed in a channel is a public invocation; in a
	 * DM it is pm. */
	pb_dispatch_command(bot, invoker, channel, msgid, channel ? 1 : 0, cmd);
	return 1;
}

/* Resolve the target bot from a TAGMSG sent to a channel.  Strategy:
 *   1. If the +draft/bot-cmd JSON has "target": "<nick>", use that.
 *   2. Otherwise pick the first PushBot in the channel that has a
 *      command with the matching name registered.
 *   3. If multiple match, prefer channel-scope over server-scope. */
/* Look for a command by name in the bot's registered schema. */
static int pb_bot_has_command(PbBot *b, const char *name)
{
	if (!b || !b->commands || !name) return 0;
	size_t i; json_t *c;
	json_array_foreach(b->commands, i, c) {
		json_t *cn = json_object_get(c, "name");
		if (json_is_string(cn) && !strcmp(json_string_value(cn), name))
			return 1;
	}
	return 0;
}

/* Resolve a slash-command invocation in a channel.  Spec §3.3:
 *   1) explicit target via /cmd@botnick wins;
 *   2) channel-scope bots in this channel that publish the command;
 *   3) fall through to server-wide bots that publish the command.
 * A user can always reach a server-wide bot from any channel by name. */
static PbBot *pb_resolve_channel_botcmd(Channel *ch, json_t *cmd,
                                        const char *target_nick)
{
	if (target_nick && *target_nick) {
		/* A named (disambiguated) bot must still be reachable from THIS channel:
		 * server-scope bots are reachable everywhere, channel-scope bots only in
		 * channels they are actually in.  Without this check a channel-scope bot
		 * could be invoked from any channel just by naming it. */
		PbBot *b = pb_find_bot_by_nick(target_nick);
		if (!b || b->status != PB_STATUS_ACTIVE)
			return NULL;
		if (b->scope == PB_SCOPE_SERVER || pb_bot_is_in_channel(b, ch))
			return b;
		return NULL;
	}
	const char *name = NULL;
	json_t *nmj = json_object_get(cmd, "name");
	if (json_is_string(nmj)) name = json_string_value(nmj);
	if (!name) return NULL;
	/* Pass 1: channel-scope bot in this channel. */
	for (PbBot *b = bots; b; b = b->next) {
		if (b->status != PB_STATUS_ACTIVE) continue;
		if (b->scope != PB_SCOPE_CHANNEL) continue;
		if (!pb_bot_is_in_channel(b, ch)) continue;
		if (pb_bot_has_command(b, name)) return b;
	}
	/* Pass 2: server-wide bot (no channel-membership requirement). */
	for (PbBot *b = bots; b; b = b->next) {
		if (b->status != PB_STATUS_ACTIVE) continue;
		if (b->scope != PB_SCOPE_SERVER) continue;
		if (pb_bot_has_command(b, name)) return b;
	}
	return NULL;
}

static int pb_route_botcmd_channel(Client *invoker, Channel *channel,
                                   MessageTag *mtags, const char *botcmd_b64)
{
	int plen = 0;
	char *json_buf = pb_b64_decode_alloc(botcmd_b64, &plen);
	if (!json_buf) {
		sendto_one(invoker, NULL, ":%s FAIL BOTCMD INVALID :bot-cmd: bad base64", me.name);
		return 0;
	}
	json_error_t err;
	json_t *cmd = json_loadb(json_buf, plen, 0, &err);
	safe_free(json_buf);
	if (!cmd || !json_is_object(cmd)) {
		if (cmd) json_decref(cmd);
		sendto_one(invoker, NULL, ":%s FAIL BOTCMD INVALID :bot-cmd: invalid JSON", me.name);
		return 0;
	}
	const char *target_nick = NULL;
	json_t *tj = json_object_get(cmd, "bot");       /* draft/bot-cmds disambiguation */
	if (!json_is_string(tj)) tj = json_object_get(cmd, "target"); /* legacy fallback */
	if (json_is_string(tj)) target_nick = json_string_value(tj);

	const char *msgid = NULL;
	for (MessageTag *m = mtags; m; m = m->next)
		if (m->name && !strcmp(m->name, "msgid")) { msgid = m->value; break; }

	PbBot *bot = pb_resolve_channel_botcmd(channel, cmd, target_nick);
	if (!bot) {
		/* Not a pushbot-registered bot; let the TAGMSG flow to the
		 * channel so a spec-compliant bot in it (draft/bot-cmds via
		 * its own TAGMSG handler) can answer. */
		json_decref(cmd);
		return 0;
	}

	pb_downgrade_invocation(invoker, channel, bot, cmd);
	pb_dispatch_command(bot, invoker, channel->name, msgid, 1, cmd);  /* public */
	return 0;
}

static int pb_route_botcmd_user(Client *invoker, Client *to, MessageTag *mtags,
                                const char *botcmd_b64, const char *channel_context)
{
	PbBot *bot = NULL;
	for (PbBot *b = bots; b; b = b->next)
		if (b->ghost == to) { bot = b; break; }
	if (!bot) return 0;  /* not a pushbot, leave for other handlers */

	int plen = 0;
	char *json_buf = pb_b64_decode_alloc(botcmd_b64, &plen);
	if (!json_buf) {
		sendto_one(invoker, NULL, ":%s FAIL BOTCMD INVALID :bot-cmd: bad base64", me.name);
		return 0;
	}
	json_error_t err;
	json_t *cmd = json_loadb(json_buf, plen, 0, &err);
	safe_free(json_buf);
	if (!cmd || !json_is_object(cmd)) {
		if (cmd) json_decref(cmd);
		sendto_one(invoker, NULL, ":%s FAIL BOTCMD INVALID :bot-cmd: invalid JSON", me.name);
		return 0;
	}

	/* New spec: a private-context invocation carries the channel it relates to
	 * in the payload (+draft/channel-context is not valid on TAGMSG).  Prefer
	 * that over the legacy channel-context tag. */
	json_t *chj = json_object_get(cmd, "channel");
	if (json_is_string(chj) && *json_string_value(chj))
		channel_context = json_string_value(chj);

	/* Validate channel_context: the invoker must be in the channel.
	 * For channel-scope bots the bot ghost must also be a member;
	 * server-scope bots (helpbot, dicebot) are reachable from any
	 * channel and never auto-join, so skip the bot-in-channel check
	 * for them. */
	if (channel_context && *channel_context) {
		Channel *ch = find_channel(channel_context);
		int bot_ok = (bot->scope == PB_SCOPE_SERVER) ||
		             (ch && pb_bot_is_in_channel(bot, ch));
		if (!ch || !find_membership_link(invoker->user->channel, ch) || !bot_ok) {
			sendto_one(invoker, NULL,
			           ":%s FAIL BOTCMD INVALID_CHANNEL_CONTEXT %s :bot-cmd: invalid channel context",
			           me.name, channel_context);
			json_decref(cmd);
			return 0;
		}
	}

	const char *msgid = NULL;
	for (MessageTag *m = mtags; m; m = m->next)
		if (m->name && !strcmp(m->name, "msgid")) { msgid = m->value; break; }

	pb_dispatch_command(bot, invoker, channel_context, msgid, 0, cmd);  /* private/pm */
	return 0;
}

static void pb_handle_command_register(Client *client, json_t *frame)
{
	PbSession *s = PB_SESS(client);
	if (!s || !s->bot || !s->identified) {
		pb_close_ws(client, PB_CLOSE_AUTH_FAILED, "Not authenticated");
		return;
	}
	json_t *d = json_object_get(frame, "d");
	if (!json_is_object(d)) {
		pb_close_ws(client, PB_CLOSE_INVALID_SESSION, "COMMAND_REGISTER.d must be object");
		return;
	}
	json_t *cmds = json_object_get(d, "commands");
	if (pb_core_register_commands(s->bot, cmds) != PB_CORE_OK)
		pb_close_ws(client, PB_CLOSE_INVALID_SESSION, "commands must be array");
}

static void pb_append_tags(MessageTag **head, MessageTag *extra)
{
	for (MessageTag *m = extra; m; m = m->next) {
		MessageTag *cp = safe_alloc(sizeof(*cp));
		safe_strdup(cp->name, m->name);
		if (m->value) safe_strdup(cp->value, m->value);
		AddListItem(cp, *head);
	}
}

/* Split content on \n into up to 128 trimmed lines (returned as
 * pointers into the caller-supplied `dup` buffer, which the caller
 * must safe_free after use). Returns line count. */
static int pb_split_lines(char *dup, char *lines[128])
{
	int n = strlen(dup);
	while (n > 0 && (dup[n-1] == '\n' || dup[n-1] == '\r'))
		dup[--n] = '\0';
	int count = 0;
	char *p = dup;
	while (p && count < 128) {
		char *nl = strchr(p, '\n');
		if (nl) *nl = '\0';
		int len = strlen(p);
		if (len > 0 && p[len-1] == '\r') p[len-1] = '\0';
		lines[count++] = p;
		if (!nl) break;
		p = nl + 1;
	}
	return count;
}

/* Send a (possibly multi-line) reply to a channel OR a single user
 * as an IRCv3 draft/multiline batch when >1 line, or a single
 * PRIVMSG/NOTICE when 1 line. outer_tags are attached to the batch
 * open (multi-line) or the single message (one-line); inside the
 * batch each line carries only the inherited @batch tag. */
static void pb_send_multiline(Channel *ch, Client *target, Client *ghost,
                              const char *verb, MessageTag *outer_tags,
                              const char *content)
{
	if (!ghost || !content) return;

	char *dup = raw_strdup(content);
	char *lines[128];
	int n = pb_split_lines(dup, lines);

	if (n <= 1) {
		const char *one = (n == 1) ? lines[0] : "";
		/* new_message() injects msgid/time/account so the obsidian
		 * client can dedupe; without msgid it renders the same
		 * PRIVMSG twice (once via +draft/reply as a reply tile,
		 * once as a generic channel line). */
		MessageTag *mtags = NULL;
		new_message(ghost, NULL, &mtags);
		pb_append_tags(&mtags, outer_tags);
		if (ch) {
			sendto_channel(ch, ghost, NULL, NULL, 0, SEND_ALL, mtags,
			               ":%s %s %s :%s",
			               ghost->name, verb, ch->name, one);
		} else if (target) {
			sendto_one(target, mtags, ":%s %s %s :%s",
			           ghost->name, verb, target->name, one);
		}
		free_message_tags(mtags);
		safe_free(dup);
		return;
	}

	char batch_id[BATCHLEN+1];
	generate_batch_id(batch_id);
	const char *object = ch ? ch->name : (target ? target->name : "*");

	MessageTag *open_mtags = NULL;
	new_message(ghost, NULL, &open_mtags);
	pb_append_tags(&open_mtags, outer_tags);
	if (ch) {
		sendto_channel(ch, ghost, NULL, NULL, 0, SEND_ALL, open_mtags,
		               ":%s BATCH +%s draft/multiline %s",
		               ghost->name, batch_id, object);
	} else {
		sendto_one(target, open_mtags, ":%s BATCH +%s draft/multiline %s",
		           ghost->name, batch_id, object);
	}
	free_message_tags(open_mtags);

	for (int i = 0; i < n; i++) {
		MessageTag *line_mtags = NULL;
		new_message(ghost, NULL, &line_mtags);
		MessageTag *bt = safe_alloc(sizeof(*bt));
		safe_strdup(bt->name, "batch");
		safe_strdup(bt->value, batch_id);
		AddListItem(bt, line_mtags);
		if (ch) {
			sendto_channel(ch, ghost, NULL, NULL, 0, SEND_ALL, line_mtags,
			               ":%s %s %s :%s",
			               ghost->name, verb, ch->name, lines[i]);
		} else {
			sendto_one(target, line_mtags, ":%s %s %s :%s",
			           ghost->name, verb, target->name, lines[i]);
		}
		free_message_tags(line_mtags);
	}

	MessageTag *close_mtags = NULL;
	new_message(ghost, NULL, &close_mtags);
	if (ch) {
		sendto_channel(ch, ghost, NULL, NULL, 0, SEND_ALL, close_mtags,
		               ":%s BATCH -%s", ghost->name, batch_id);
	} else {
		sendto_one(target, close_mtags, ":%s BATCH -%s",
		           ghost->name, batch_id);
	}
	free_message_tags(close_mtags);

	safe_free(dup);
}

static void pb_send_interaction_reply(PbInteraction *it, const char *content,
                                      const char *visibility, int ephemeral,
                                      MessageTag *extra_tags)
{
	if (!it || !content) return;
	Client *target = find_user(it->invoker_nick, NULL);
	if (!target) return;
	if (!it->bot || !it->bot->ghost) return;

	int as_notice = ephemeral ? 1 : 0;
	/* Privacy: only a publicly-invoked command may reply into the channel. A
	 * private/pm invocation is always whispered, whatever visibility the bot
	 * asked for -- this stops a "private" command leaking to the channel when a
	 * bot omits (or mis-sets) the response visibility. */
	int public_visible = it->invoked_public &&
	                     (visibility && !strcasecmp(visibility, "public"));

	if (it->channel && public_visible) {
		Channel *ch = find_channel(it->channel);
		if (!ch) return;
		MessageTag *tags = pb_make_reply_tags(it->invoker_msgid, NULL,
		                                      it->invoker_cmd_b64);
		pb_append_tags(&tags, extra_tags);
		pb_send_multiline(ch, NULL, it->bot->ghost, "PRIVMSG", tags, content);
		free_message_tags(tags);
		return;
	}

	MessageTag *tags = pb_make_reply_tags(it->invoker_msgid, it->channel,
	                                      it->invoker_cmd_b64);
	pb_append_tags(&tags, extra_tags);
	pb_send_multiline(NULL, target, it->bot->ghost,
	                  as_notice ? "NOTICE" : "PRIVMSG", tags, content);
	free_message_tags(tags);
}

static void pb_handle_interaction_response(Client *client, json_t *frame)
{
	PbSession *s = PB_SESS(client);
	if (!s || !s->bot || !s->identified) {
		pb_close_ws(client, PB_CLOSE_AUTH_FAILED, "Not authenticated");
		return;
	}
	json_t *d = json_object_get(frame, "d");
	if (!json_is_object(d)) return;
	json_t *idj = json_object_get(d, "id");
	if (!json_is_string(idj)) return;

	const char *content = "";
	const char *vis = "public";
	int ephemeral = 0;
	json_t *cj = json_object_get(d, "content");
	if (json_is_string(cj)) content = json_string_value(cj);
	json_t *vj = json_object_get(d, "visibility");
	if (json_is_string(vj)) vis = json_string_value(vj);
	json_t *ej = json_object_get(d, "ephemeral");
	if (json_is_boolean(ej)) ephemeral = json_is_true(ej) ? 1 : 0;

	MessageTag *extra = pb_build_tags(json_object_get(d, "tags"));
	PbCoreResult r = pb_core_interaction_respond(s->bot,
	                                             json_string_value(idj),
	                                             content, vis, ephemeral,
	                                             extra);
	free_message_tags(extra);
	if (r == PB_CORE_NOT_FOUND)
		unreal_log(ULOG_INFO, "pushbot", "INT_LATE", NULL,
		           "Bot $nick responded to unknown/expired interaction $id",
		           log_data_string("nick", s->bot->nick),
		           log_data_string("id", json_string_value(idj)));
}

static void pb_handle_interaction_defer(Client *client, json_t *frame)
{
	PbSession *s = PB_SESS(client);
	if (!s || !s->bot || !s->identified) return;
	json_t *d = json_object_get(frame, "d");
	if (!json_is_object(d)) return;
	json_t *idj = json_object_get(d, "id");
	if (!json_is_string(idj)) return;
	pb_core_interaction_defer(s->bot, json_string_value(idj), 0);
}

/* PB_OP_SEND_MESSAGE: bot sends a spontaneous PRIVMSG/NOTICE from its
 * ghost. d = { target, content, [is_notice] }. Target may be a
 * channel (#/^/&/$) or a nick. Not tied to any interaction -- used by
 * e.g. Orca voice subsystem to mirror transcripts into the text side
 * of a voice channel without piggybacking on a user invocation. */
static void pb_handle_send_message(Client *client, json_t *frame)
{
	PbSession *s = PB_SESS(client);
	if (!s || !s->bot || !s->identified) {
		pb_close_ws(client, PB_CLOSE_AUTH_FAILED, "Not authenticated");
		return;
	}
	if (!s->bot->ghost) return;

	json_t *d = json_object_get(frame, "d");
	if (!json_is_object(d)) return;

	json_t *tj = json_object_get(d, "target");
	json_t *cj = json_object_get(d, "content");
	if (!json_is_string(tj) || !json_is_string(cj)) return;
	const char *target = json_string_value(tj);
	const char *content = json_string_value(cj);
	if (!target || !*target || !content) return;

	int as_notice = 0;
	json_t *nj = json_object_get(d, "is_notice");
	if (json_is_true(nj)) as_notice = 1;

	const char *verb = as_notice ? "NOTICE" : "PRIVMSG";

	/* Optional client-only tags to attach to the outgoing message. */
	MessageTag *tags = NULL;
	json_t *tagj = json_object_get(d, "tags");
	if (json_is_object(tagj)) {
		const char *key;
		json_t *val;
		json_object_foreach(tagj, key, val) {
			if (!key || key[0] != '+') continue;
			if (!json_is_string(val)) continue;
			MessageTag *m = safe_alloc(sizeof(*m));
			safe_strdup(m->name, key);
			safe_strdup(m->value, json_string_value(val));
			AddListItem(m, tags);
		}
	}

	if (target[0] == '#' || target[0] == '&' ||
	    target[0] == '^' || target[0] == '$') {
		Channel *ch = find_channel(target);
		if (!ch) { free_message_tags(tags); return; }
		pb_send_multiline(ch, NULL, s->bot->ghost, verb, tags, content);
	} else {
		Client *to = find_user(target, NULL);
		if (!to) { free_message_tags(tags); return; }
		pb_send_multiline(NULL, to, s->bot->ghost, verb, tags, content);
	}
	free_message_tags(tags);
}

/* d = { target, tags: { "+name": "value", ... } } */
static void pb_handle_send_tagmsg(Client *client, json_t *frame)
{
	PbSession *s = PB_SESS(client);
	if (!s || !s->bot || !s->identified) {
		pb_close_ws(client, PB_CLOSE_AUTH_FAILED, "Not authenticated");
		return;
	}
	if (!s->bot->ghost) return;

	json_t *d = json_object_get(frame, "d");
	if (!json_is_object(d)) return;

	json_t *tj = json_object_get(d, "target");
	json_t *tagj = json_object_get(d, "tags");
	if (!json_is_string(tj) || !json_is_object(tagj)) return;
	const char *target = json_string_value(tj);
	if (!target || !*target) return;

	MessageTag *head = NULL;
	const char *key;
	json_t *val;
	json_object_foreach(tagj, key, val) {
		if (!key || key[0] != '+') continue;
		if (!json_is_string(val)) continue;
		MessageTag *m = safe_alloc(sizeof(*m));
		safe_strdup(m->name, key);
		safe_strdup(m->value, json_string_value(val));
		AddListItem(m, head);
	}
	if (!head) return;

	MessageTag *mtags = NULL;
	new_message(s->bot->ghost, NULL, &mtags);
	pb_append_tags(&mtags, head);
	free_message_tags(head);

	if (target[0] == '#' || target[0] == '&' ||
	    target[0] == '^' || target[0] == '$') {
		Channel *ch = find_channel(target);
		if (!ch) { free_message_tags(mtags); return; }
		sendto_channel(ch, s->bot->ghost, NULL, NULL, 0, SEND_ALL, mtags,
		               ":%s TAGMSG %s",
		               s->bot->ghost->name, ch->name);
	} else {
		Client *to = find_user(target, NULL);
		if (!to) { free_message_tags(mtags); return; }
		sendto_one(to, mtags, ":%s TAGMSG %s",
		           s->bot->ghost->name, to->name);
	}
	free_message_tags(mtags);
}

EVENT(pb_interaction_timeout_check)
{
	time_t now = TStime();
	PbInteraction *next;
	for (PbInteraction *it = interactions; it; it = next) {
		next = it->next;
		if (it->expires_at >= now) continue;
		/* Time out: send a FAIL standard-reply to invoker. */
		Client *target = find_user(it->invoker_nick, NULL);
		if (target) {
			sendto_one(target, NULL, ":%s FAIL BOTCMD TIMEOUT %s :bot timed out",
			           me.name, it->bot && it->bot->nick ? it->bot->nick : "?");
		}
		pb_interaction_free(it);
	}
}

/* ===================================================================
 * obby.world/channel-bots client cap -- bot list + push updates
 * =================================================================== */

static int pb_mtag_bot_info_is_ok(Client *c, const char *n, const char *v)
{
	/* Server-emitted tag.  Reject if a client tries to send one. */
	return IsServer(c) ? 1 : 0;
}

static int pb_mtag_invoked_by_is_ok(Client *c, const char *n, const char *v)
{
	/* Bots emit this on their channel replies to attribute the
	 * triggering slash invocation. Accept from any registered
	 * client; payload shape is validated downstream by clients. */
	if (IsServer(c)) return 1;
	if (!has_user_mode(c, 'B')) return 0;
	if (!v || !*v) return 0;
	return 1;
}

/* Decide whether `client` is allowed to see `bot` in burst/push events.
 * Non-opers only see ACTIVE bots; opers see everything (pending /
 * suspended / deleted-but-not-yet-purged) so the management UI is
 * useful. */
static int pb_bot_visible_to(PbBot *b, Client *client)
{
	if (!b) return 0;
	if (b->status == PB_STATUS_DELETED) return IsOper(client);
	if (b->status == PB_STATUS_ACTIVE) return 1;
	/* PENDING and SUSPENDED -> oper-only */
	return IsOper(client);
}

/* Build the JSON payload for one bot.  `for_oper` controls whether the
 * sensitive fields (webhook_url, raw token presence flags) are included.
 * If `event` is non-NULL, set d.event to it ("add" / "update" / "remove"). */
static json_t *pb_bot_to_burst_json(PbBot *b, int for_oper, const char *event)
{
	json_t *j = json_object();
	if (event) json_object_set_new(j, "event", json_string(event));
	json_object_set_new(j, "bot_id", json_string(b->bot_id ? b->bot_id : ""));
	json_object_set_new(j, "nick", json_string(b->nick ? b->nick : ""));
	json_object_set_new(j, "realname", json_string(b->realname ? b->realname : ""));
	json_object_set_new(j, "scope", json_string(pb_scope_str(b->scope)));
	json_object_set_new(j, "transport", json_string(pb_transport_str(b->transport)));
	const char *status_str =
	    b->status == PB_STATUS_ACTIVE ? "active" :
	    b->status == PB_STATUS_PENDING ? "pending" :
	    b->status == PB_STATUS_SUSPENDED ? "suspended" : "deleted";
	json_object_set_new(j, "status", json_string(status_str));
	json_object_set_new(j, "online",
	    json_boolean(b->session && b->session->identified));
	json_object_set_new(j, "from_config", json_boolean(b->from_config));

	json_t *chans = json_array();
	if (b->ghost) {
		for (Membership *m = b->ghost->user->channel; m; m = m->next) {
			if (m->channel && m->channel->name[0])
				json_array_append_new(chans, json_string(m->channel->name));
		}
	}
	json_object_set_new(j, "channels", chans);

	/* Emit the spec schema (contexts), not the raw stored visibility/scopes, so
	 * a client that populates its command list from the directory routes a
	 * private command privately instead of broadcasting it to the channel. */
	json_object_set_new(j, "commands", pb_commands_to_spec_array(b->commands));

	if (for_oper) {
		json_object_set_new(j, "webhook_url",
		    json_string(b->webhook_url ? b->webhook_url : ""));
		json_object_set_new(j, "webhook_suspended", json_boolean(b->webhook_suspended));
		json_object_set_new(j, "webhook_failures", json_integer(b->webhook_failures));
	}
	return j;
}

/* Emit one TAGMSG line with the bot-info tag set, base64-encoded. */
static void pb_send_bot_info(Client *client, const char *batch_ref,
                             json_t *body)
{
	char *json_str = json_dumps(body, JSON_COMPACT);
	if (!json_str) return;
	int jlen = strlen(json_str);
	int b64_max = ((jlen + 2) / 3) * 4 + 1;
	char *b64 = safe_alloc(b64_max);
	b64_encode(json_str, jlen, b64, b64_max);
	free(json_str);

	if (batch_ref) {
		sendto_one(client, NULL,
		           "@batch=%s;" PB_BOT_INFO_TAG "=%s :%s TAGMSG %s",
		           batch_ref, b64, me.name, client->name);
	} else {
		sendto_one(client, NULL,
		           "@" PB_BOT_INFO_TAG "=%s :%s TAGMSG %s",
		           b64, me.name, client->name);
	}
	safe_free(b64);
}

/* Send the full bot-list burst to one client, BATCH-wrapped. */
/* On connect, send server-scope bots only -- they're always reachable
 * regardless of channel membership.  Channel-scope bots are revealed
 * to the client on a per-channel basis from pb_hook_local_join when
 * the user joins a channel they're a member of.  Keeps the directory
 * the client cares about scoped to "what can I actually invoke right
 * now".  Opers see every bot in the burst since they may need to
 * manage bots in channels they haven't joined. */
static void pb_send_bot_burst(Client *client)
{
	if (!HasCapabilityFast(client, CAP_CHANBOTS)) return;
	if (!MyUser(client) || !client->name[0] || !*client->name) return;

	char ref[BATCHLEN + 1];
	gen_random_alnum(ref, BATCHLEN);
	ref[BATCHLEN] = '\0';
	int for_oper = IsOper(client) ? 1 : 0;

	int n = 0;
	for (PbBot *b = bots; b; b = b->next) {
		if (!pb_bot_visible_to(b, client)) continue;
		if (!for_oper && b->scope != PB_SCOPE_SERVER) continue;
		n++;
	}
	if (n == 0) return;  /* nothing to send */

	sendto_one(client, NULL, ":%s BATCH +%s " PB_CAP_NAME, me.name, ref);
	for (PbBot *b = bots; b; b = b->next) {
		if (!pb_bot_visible_to(b, client)) continue;
		if (!for_oper && b->scope != PB_SCOPE_SERVER) continue;
		json_t *body = pb_bot_to_burst_json(b, for_oper, "add");
		pb_send_bot_info(client, ref, body);
		json_decref(body);
	}
	sendto_one(client, NULL, ":%s BATCH -%s", me.name, ref);
}

/* Announce channel-scope bots present in a channel the user just
 * joined.  Sent as individual obby.world/bot-info TAGMSGs (no batch
 * wrapper since the count is typically 0..2). */
static void pb_announce_channel_bots(Client *client, Channel *ch)
{
	if (!client || !ch) return;
	if (!HasCapabilityFast(client, CAP_CHANBOTS)) return;
	int for_oper = IsOper(client) ? 1 : 0;
	for (PbBot *b = bots; b; b = b->next) {
		if (b->scope != PB_SCOPE_CHANNEL) continue;
		if (!pb_bot_visible_to(b, client)) continue;
		if (!pb_bot_is_in_channel(b, ch)) continue;
		json_t *body = pb_bot_to_burst_json(b, for_oper, "add");
		pb_send_bot_info(client, NULL, body);
		json_decref(body);
	}
}

/* Push a single bot event to every cap-aware local client that can see
 * the bot.  Used on add / online-status-change / commands-updated /
 * remove. */
static void pb_broadcast_bot_event(PbBot *b, const char *event)
{
	if (!b || !event) return;
	Client *c;
	list_for_each_entry(c, &lclient_list, lclient_node) {
		if (!HasCapabilityFast(c, CAP_CHANBOTS)) continue;
		if (!MyUser(c) || !IsUser(c)) continue;
		if (!c->name[0] || !*c->name) continue;
		if (strcmp(event, "remove") != 0 && !pb_bot_visible_to(b, c)) continue;
		json_t *body = pb_bot_to_burst_json(b, IsOper(c), event);
		pb_send_bot_info(c, NULL, body);
		json_decref(body);
	}
}

static int pb_hook_welcome_burst(Client *client)
{
	pb_send_bot_burst(client);
	return 0;
}

static int pb_hook_oper_change(Client *client, int add,
                               const char *oper_block, const char *operclass)
{
	/* Re-send the burst: opers see suspended/pending bots that
	 * non-opers don't, and unoper means they should stop seeing them. */
	(void)oper_block; (void)operclass; (void)add;
	pb_send_bot_burst(client);
	return 0;
}

/* ===================================================================
 * Phase 6 -- outgoing webhook delivery
 * =================================================================== */

/* hex-encode `n` bytes from `in` into `out` (must be 2n+1 bytes). */
static void pb_hexenc(const unsigned char *in, int n, char *out)
{
	static const char hex[] = "0123456789abcdef";
	for (int i = 0; i < n; i++) {
		out[2*i]     = hex[(in[i] >> 4) & 0xf];
		out[2*i + 1] = hex[in[i] & 0xf];
	}
	out[2*n] = '\0';
}

/* Compute HMAC-SHA256(secret, body) and hex-encode it. */
static void pb_hmac_sha256_hex(const char *secret, const char *body, char *hex_out)
{
	unsigned char digest[32];
	unsigned int dlen = 0;
	HMAC(EVP_sha256(),
	     secret, secret ? strlen(secret) : 0,
	     (const unsigned char *)body, body ? strlen(body) : 0,
	     digest, &dlen);
	pb_hexenc(digest, dlen, hex_out);
}

/* Wrap a webhook attempt with retry-state bookkeeping so the response
 * callback knows what to do.  Owned by callback_data. */
typedef struct PbWebhookCtx {
	char *bot_id;     /* don't keep raw pointers; bot may be freed by then */
	char *event_name;
	char *body;       /* original JSON body; preserved across retries */
	int attempt;      /* 0, 1, 2, ... */
} PbWebhookCtx;

static void pb_webhook_ctx_free(PbWebhookCtx *c)
{
	if (!c) return;
	safe_free(c->bot_id);
	safe_free(c->event_name);
	safe_free(c->body);
	safe_free(c);
}

/* Look up a bot by bot_id (used by the response callback). */
static PbBot *pb_find_bot_by_id(const char *id)
{
	if (!id) return NULL;
	for (PbBot *b = bots; b; b = b->next)
		if (b->bot_id && !strcmp(b->bot_id, id))
			return b;
	return NULL;
}

static void pb_webhook_fire(PbBot *b, PbWebhookCtx *ctx)
{
	if (!b || !b->webhook_url) {
		pb_webhook_ctx_free(ctx);
		return;
	}
	OutgoingWebRequest *req = safe_alloc(sizeof(*req));
	safe_strdup(req->url, b->webhook_url);
	req->http_method = HTTP_METHOD_POST;
	safe_strdup(req->body, ctx->body);
	req->connect_timeout  = 5;
	req->transfer_timeout = 10;
	req->max_redirects = 0;
	safe_strdup(req->apicallback, "pb_webhook_response");
	req->callback_data = ctx;

	add_nvplist(&req->headers, 0, "Content-Type", "application/json");
	add_nvplist(&req->headers, 0, "X-PushBot-Event", ctx->event_name ? ctx->event_name : "");
	add_nvplist(&req->headers, 0, "X-PushBot-Bot", b->nick ? b->nick : "");

	/* Sign with HMAC-SHA256 if the bot has a secret. */
	if (b->webhook_secret && *b->webhook_secret) {
		char sig[16 + 64 + 1];
		char hex[65];
		pb_hmac_sha256_hex(b->webhook_secret, ctx->body, hex);
		snprintf(sig, sizeof(sig), "sha256=%s", hex);
		add_nvplist(&req->headers, 0, "X-PushBot-Signature", sig);
	}

	url_start_async(req);
}

static void pb_webhook_dispatch(PbBot *b, const char *event_name, const char *body_json)
{
	if (!b || !body_json) return;
	PbWebhookCtx *ctx = safe_alloc(sizeof(*ctx));
	safe_strdup(ctx->bot_id, b->bot_id);
	safe_strdup(ctx->event_name, event_name ? event_name : "");
	safe_strdup(ctx->body, body_json);
	ctx->attempt = 0;
	pb_webhook_fire(b, ctx);
}

/* Schedule a retry by waking up after `delay` seconds.  We piggyback
 * on the periodic interaction timeout event by stashing the ctx on a
 * pending queue; a tiny one-shot EventAdd handles the actual fire. */
static PbWebhookCtx *pb_retry_pending = NULL; /* unused for now; reserved */

static void pb_webhook_retry_fire(void *data)
{
	PbWebhookCtx *ctx = data;
	PbBot *b = pb_find_bot_by_id(ctx ? ctx->bot_id : NULL);
	if (!b || !b->webhook_url || b->webhook_suspended) {
		pb_webhook_ctx_free(ctx);
		return;
	}
	pb_webhook_fire(b, ctx);
}

static void pb_webhook_schedule_retry(PbWebhookCtx *ctx, int delay_ms)
{
	if (!ctx) return;
	char name[64];
	snprintf(name, sizeof(name), "pb_webhook_retry_%lx",
	         (unsigned long)(uintptr_t)ctx);
	EventAdd(modinfo_ref->handle, name, pb_webhook_retry_fire, ctx, delay_ms, 1);
}

static void pb_webhook_response(OutgoingWebRequest *req, OutgoingWebResponse *resp)
{
	PbWebhookCtx *ctx = resp && resp->ptr ? resp->ptr : NULL;
	PbBot *b = pb_find_bot_by_id(ctx ? ctx->bot_id : NULL);
	if (!ctx) return;

	int code = resp && !resp->errorbuf ? 200 : 0;
	/* OutgoingWebResponse doesn't carry a direct HTTP status code in
	 * the public struct, so we treat "no errorbuf" as success. */
	if (resp && resp->errorbuf) code = 0;

	if (!b) {
		/* Bot gone; just drop. */
		pb_webhook_ctx_free(ctx);
		return;
	}
	if (code >= 200 && code < 300) {
		b->webhook_failures = 0;
		unreal_log(ULOG_DEBUG, "pushbot", "WEBHOOK_OK", NULL,
		           "Webhook delivered for $nick event=$ev",
		           log_data_string("nick", b->nick),
		           log_data_string("ev", ctx->event_name));

		/* Inline-action body: the bot may answer a COMMAND_INVOKE in
		 * the 200 response with {type: "send_message"|..} so a
		 * serverless bot can reply without ever opening a connection
		 * back. The iid for the action is the same as the iid we
		 * delivered in the request body's `d.id`. */
		if (resp && resp->memory && resp->memory_len > 0 &&
		    ctx->event_name && !strcmp(ctx->event_name, "COMMAND_INVOKE")) {
			const char *iid = NULL;
			json_error_t je;
			/* Recover the iid from the body we sent. */
			json_t *sent = ctx->body
			    ? json_loads(ctx->body, 0, &je) : NULL;
			if (sent) {
				json_t *dj = json_object_get(sent, "d");
				if (json_is_object(dj)) {
					json_t *idj = json_object_get(dj, "id");
					if (json_is_string(idj))
						iid = json_string_value(idj);
				}
			}
			json_t *action = json_loadb(resp->memory,
			                            (size_t)resp->memory_len,
			                            0, &je);
			if (action && json_is_object(action) && iid)
				pb_webhook_dispatch_inline_action(b, iid, action);
			if (action) json_decref(action);
			if (sent) json_decref(sent);
		}

		pb_webhook_ctx_free(ctx);
		return;
	}
	/* Failure path. */
	b->webhook_failures++;
	unreal_log(ULOG_INFO, "pushbot", "WEBHOOK_FAIL", NULL,
	           "Webhook FAIL for $nick attempt=$att error=$err",
	           log_data_string("nick", b->nick),
	           log_data_integer("att", ctx->attempt),
	           log_data_string("err", (resp && resp->errorbuf) ? resp->errorbuf : "?"));

	int suspend_after = cfg.webhook_failure_suspend_after > 0
	                    ? cfg.webhook_failure_suspend_after : 20;
	if (b->webhook_failures >= suspend_after) {
		b->webhook_suspended = 1;
		unreal_log(ULOG_WARNING, "pushbot", "WEBHOOK_SUSPENDED", NULL,
		           "Bot $nick webhook suspended after $n consecutive failures",
		           log_data_string("nick", b->nick),
		           log_data_integer("n", b->webhook_failures));
		pb_webhook_ctx_free(ctx);
		return;
	}

	/* Backoff schedule: 1s, 5s, 30s, 60s, then dead-letter. */
	static const int backoff_ms[] = { 1000, 5000, 30000, 60000 };
	if (ctx->attempt >= (int)(sizeof(backoff_ms)/sizeof(backoff_ms[0]))) {
		unreal_log(ULOG_INFO, "pushbot", "WEBHOOK_DEAD_LETTER", NULL,
		           "Bot $nick event $ev dropped after all retries",
		           log_data_string("nick", b->nick),
		           log_data_string("ev", ctx->event_name));
		pb_webhook_ctx_free(ctx);
		return;
	}
	int delay = backoff_ms[ctx->attempt];
	ctx->attempt++;
	pb_webhook_schedule_retry(ctx, delay);
}

/* ===================================================================
 * Phase 3 -- event dispatch to bots in matching channels
 * =================================================================== */

/* Lightweight Client struct serializer; redacts ip/host/geoip/etc by
 * default per the spec.  Full-fidelity comes when phase 5 needs it
 * for COMMAND_INVOKE. */
static json_t *pb_json_client(Client *c)
{
	json_t *j = json_object();
	if (!c) return j;
	json_object_set_new(j, "nick", json_string(c->name[0] ? c->name : ""));
	json_object_set_new(j, "id", json_string(c->id[0] ? c->id : ""));
	if (c->user) {
		json_object_set_new(j, "account",
		    json_string(c->user->account[0] && strcmp(c->user->account, "0")
		                ? c->user->account : ""));
		json_object_set_new(j, "ident",
		    json_string(c->user->username[0] ? c->user->username : ""));
		const char *vhost = c->user->virthost ? c->user->virthost
		                  : c->user->cloakedhost[0] ? c->user->cloakedhost : "";
		json_object_set_new(j, "host", json_string(vhost));
		long bot_bit = find_user_mode('B');
		json_object_set_new(j, "is_bot",
		    json_boolean(bot_bit && (c->umodes & bot_bit) ? 1 : 0));
		char umb[64];
		get_usermode_string_r(c, umb, sizeof(umb));
		json_object_set_new(j, "umodes", json_string(umb));
		json_object_set_new(j, "is_oper", json_boolean(IsOper(c) ? 1 : 0));
		json_object_set_new(j, "is_secure", json_boolean(IsSecure(c) ? 1 : 0));
		json_object_set_new(j, "is_logged_in",
		    json_boolean(IsLoggedIn(c) ? 1 : 0));
	}
	return j;
}

static json_t *pb_json_channel(Channel *ch)
{
	json_t *j = json_object();
	if (!ch) return j;
	json_object_set_new(j, "name", json_string(ch->name[0] ? ch->name : ""));
	json_object_set_new(j, "topic", json_string(ch->topic ? ch->topic : ""));
	int count = 0;
	for (Member *m = ch->members; m; m = m->next) count++;
	json_object_set_new(j, "users_count", json_integer(count));
	return j;
}

static int pb_bot_is_in_channel(PbBot *b, Channel *ch)
{
	if (!b || !b->ghost || !ch) return 0;
	for (Membership *m = b->ghost->user->channel; m; m = m->next)
		if (m->channel == ch) return 1;
	return 0;
}

static int pb_skip_sender(Client *client, PbBot *b)
{
	/* Don't deliver the bot's own messages back to itself -- the
	 * obvious feedback-loop prevention. */
	if (!client || !b || !b->ghost) return 0;
	return (client == b->ghost) ? 1 : 0;
}

/* Returns 1 if the bot has at least one path to deliver events:
 * either a live identified gateway session, or a webhook URL on
 * a webhook|both transport (and not suspended).  Used to skip
 * iterating bots that can't currently receive anything. */
static int pb_bot_deliverable(PbBot *b)
{
	if (!b || b->status != PB_STATUS_ACTIVE) return 0;
	if (b->session && b->session->identified &&
	    b->session->client && !IsDead(b->session->client) &&
	    (b->transport == PB_TRANSPORT_GATEWAY || b->transport == PB_TRANSPORT_BOTH))
		return 1;
	if (b->webhook_url && !b->webhook_suspended &&
	    (b->transport == PB_TRANSPORT_WEBHOOK || b->transport == PB_TRANSPORT_BOTH))
		return 1;
	return 0;
}

/* Hook on every channel PRIVMSG/NOTICE/TAGMSG: deliver MESSAGE_CREATE
 * to every bot in the channel that isn't the source. */
static int pb_hook_chanmsg(Client *client, Channel *channel, int sendflags,
                           const char *member_modes, const char *target,
                           MessageTag *mtags, const char *text, SendType sendtype)
{
	if (!channel || !text) return 0;

	/* Phase 5: a TAGMSG carrying +draft/bot-cmd is a slash-command
	 * invocation, not a regular event.  Route it to COMMAND_INVOKE
	 * instead of MESSAGE_CREATE. */
	if (sendtype == SEND_TYPE_TAGMSG) {
		const char *botcmd_b64 = NULL;
		for (MessageTag *m = mtags; m; m = m->next)
			if (m->name && !strcmp(m->name, "+draft/bot-cmd")) {
				botcmd_b64 = m->value; break;
			}
		if (botcmd_b64)
			return pb_route_botcmd_channel(client, channel, mtags, botcmd_b64);
	}

	for (PbBot *b = bots; b; b = b->next) {
		if (b->status != PB_STATUS_ACTIVE) continue;
		if (!pb_bot_deliverable(b)) continue;
		if (!pb_bot_is_in_channel(b, channel)) continue;
		if (pb_skip_sender(client, b)) continue;

		/* Legacy compat: upgrade a plain "<prefix><cmd> args" PRIVMSG into a
		 * structured invocation for this bot, in place of MESSAGE_CREATE. */
		if (sendtype == SEND_TYPE_PRIVMSG) {
			const char *umsgid = NULL;
			for (MessageTag *m = mtags; m; m = m->next)
				if (m->name && !strcmp(m->name, "msgid")) { umsgid = m->value; break; }
			if (pb_try_upgrade_legacy(b, client, channel->name, umsgid, text))
				continue;
		}

		json_t *d = json_object();
		const char *msgid = NULL;
		for (MessageTag *m = mtags; m; m = m->next)
			if (m->name && !strcmp(m->name, "msgid")) { msgid = m->value; break; }
		json_object_set_new(d, "msgid", json_string(msgid ? msgid : ""));
		json_object_set_new(d, "channel", pb_json_channel(channel));
		json_object_set_new(d, "author", pb_json_client(client));
		json_object_set_new(d, "content", json_string(text));
		json_object_set_new(d, "is_notice",
		    json_boolean(sendtype == SEND_TYPE_NOTICE ? 1 : 0));
		json_object_set_new(d, "is_tagmsg",
		    json_boolean(sendtype == SEND_TYPE_TAGMSG ? 1 : 0));
		/* mention_bot: does the message at-mention or contain the bot's nick? */
		int mentioned = 0;
		if (b->nick && strstr(text, b->nick)) mentioned = 1;
		json_object_set_new(d, "mention_bot", json_boolean(mentioned));
		pb_dispatch_event(b, "MESSAGE_CREATE", d);
	}
	return 0;
}

static int pb_hook_usermsg(Client *client, Client *to, MessageTag *mtags,
                           const char *text, SendType sendtype)
{
	if (!to || !text) return 0;

	/* Phase 5: a TAGMSG to a bot's ghost with +draft/bot-cmd is a
	 * slash invocation in DM (or private-visibility channel context).
	 * +draft/bot-cmds-query is the discovery counterpart.
	 * +draft/bot-tools (msg=action) is a workflow control signal. */
	if (sendtype == SEND_TYPE_TAGMSG) {
		const char *botcmd_b64 = NULL;
		const char *channel_ctx = NULL;
		const char *bottools_b64 = NULL;
		int is_query = 0;
		for (MessageTag *m = mtags; m; m = m->next) {
			if (m->name && !strcmp(m->name, "+draft/bot-cmd"))
				botcmd_b64 = m->value;
			else if (m->name && !strcmp(m->name, "+draft/channel-context"))
				channel_ctx = m->value;
			else if (m->name && !strcmp(m->name, "+draft/bot-cmds-query"))
				is_query = 1;
			else if (m->name && !strcmp(m->name, "+draft/bot-tools"))
				bottools_b64 = m->value;
		}
		if (botcmd_b64)
			return pb_route_botcmd_user(client, to, mtags, botcmd_b64, channel_ctx);
		if (bottools_b64) {
			pb_route_bottools_action(client, to, NULL, bottools_b64);
			/* fall through: bot still sees the TAGMSG as a generic
			 * message-create if anything below catches it. */
		}
		if (is_query) {
			PbBot *b = NULL;
			for (PbBot *bb = bots; bb; bb = bb->next)
				if (bb->ghost == to) { b = bb; break; }
			if (b) pb_send_botcmds_to(client, b);
			return 0;
		}
	}

	for (PbBot *b = bots; b; b = b->next) {
		if (b->status != PB_STATUS_ACTIVE) continue;
		if (!pb_bot_deliverable(b)) continue;
		if (to != b->ghost) continue;     /* DM addressed at this bot only */
		if (pb_skip_sender(client, b)) continue;

		/* Legacy compat: upgrade a plain "<prefix><cmd> args" DM into a
		 * structured (pm-context) invocation, in place of MESSAGE_CREATE. */
		if (sendtype == SEND_TYPE_PRIVMSG) {
			const char *umsgid = NULL;
			for (MessageTag *m = mtags; m; m = m->next)
				if (m->name && !strcmp(m->name, "msgid")) { umsgid = m->value; break; }
			if (pb_try_upgrade_legacy(b, client, NULL, umsgid, text))
				continue;
		}

		json_t *d = json_object();
		const char *msgid = NULL;
		for (MessageTag *m = mtags; m; m = m->next)
			if (m->name && !strcmp(m->name, "msgid")) { msgid = m->value; break; }
		json_object_set_new(d, "msgid", json_string(msgid ? msgid : ""));
		json_object_set_new(d, "channel", json_null());  /* DM */
		json_object_set_new(d, "author", pb_json_client(client));
		json_object_set_new(d, "content", json_string(text));
		json_object_set_new(d, "is_notice",
		    json_boolean(sendtype == SEND_TYPE_NOTICE ? 1 : 0));
		json_object_set_new(d, "is_tagmsg",
		    json_boolean(sendtype == SEND_TYPE_TAGMSG ? 1 : 0));
		json_object_set_new(d, "is_dm", json_true());
		pb_dispatch_event(b, "MESSAGE_CREATE", d);
	}
	return 0;
}

static int pb_hook_local_join(Client *client, Channel *channel, MessageTag *mtags)
{
	if (!channel) return 0;
	/* Channel-scope bots only enter the client's directory now -- the
	 * connect burst sent server-scope bots only; this is the moment
	 * the user shares a channel with each channel-scope bot in here. */
	pb_announce_channel_bots(client, channel);
	for (PbBot *b = bots; b; b = b->next) {
		if (b->status != PB_STATUS_ACTIVE) continue;
		if (!pb_bot_deliverable(b)) continue;
		if (!pb_bot_is_in_channel(b, channel)) continue;
		if (pb_skip_sender(client, b)) continue;
		json_t *d = json_object();
		json_object_set_new(d, "client", pb_json_client(client));
		json_object_set_new(d, "channel", pb_json_channel(channel));
		pb_dispatch_event(b, "CHANNEL_JOIN", d);
	}
	return 0;
}

static int pb_hook_local_part(Client *client, Channel *channel, MessageTag *mtags,
                              const char *comment)
{
	if (!channel) return 0;
	for (PbBot *b = bots; b; b = b->next) {
		if (b->status != PB_STATUS_ACTIVE) continue;
		if (!pb_bot_deliverable(b)) continue;
		if (!pb_bot_is_in_channel(b, channel)) continue;
		if (pb_skip_sender(client, b)) continue;
		json_t *d = json_object();
		json_object_set_new(d, "client", pb_json_client(client));
		json_object_set_new(d, "channel", pb_json_channel(channel));
		json_object_set_new(d, "reason", json_string(comment ? comment : ""));
		pb_dispatch_event(b, "CHANNEL_PART", d);
	}
	return 0;
}

static int pb_hook_local_kick(Client *client, Client *victim, Channel *channel,
                              MessageTag *mtags, const char *comment)
{
	if (!channel) return 0;
	for (PbBot *b = bots; b; b = b->next) {
		if (b->status != PB_STATUS_ACTIVE) continue;
		if (!pb_bot_deliverable(b)) continue;
		if (!pb_bot_is_in_channel(b, channel)) continue;
		json_t *d = json_object();
		json_object_set_new(d, "client", pb_json_client(client));
		json_object_set_new(d, "victim", pb_json_client(victim));
		json_object_set_new(d, "channel", pb_json_channel(channel));
		json_object_set_new(d, "reason", json_string(comment ? comment : ""));
		pb_dispatch_event(b, "CHANNEL_KICK", d);
	}
	return 0;
}

/* ===================================================================
 * Phase 4 -- REST API
 *
 * Routes (all under /pushbot/v1/):
 *   GET    /bot                                 -> bot profile
 *   GET    /channels                            -> list channels
 *   POST   /channels/<name>/join                -> JOIN
 *   POST   /channels/<name>/part                -> PART
 *   POST   /channels/<name>/messages            -> PRIVMSG to channel
 *   POST   /channels/<name>/messages/<msgid>/react      -> add reaction
 *   DELETE /channels/<name>/messages/<msgid>/react/<emoji> -> remove
 *   DELETE /channels/<name>/messages/<msgid>    -> redact
 *   POST   /users/<nick>/messages               -> DM
 *   GET    /channels/<name>/members             -> members
 *
 * All paths are under /pushbot/v1/.  Auth: same Bearer as gateway.
 * Body: JSON for POSTs.  Response: JSON.
 *
 * URL parsing is hand-rolled (UnrealIRCd's webserver has no router);
 * keeps it dependency-free.
 * =================================================================== */

static void pb_rest_send_json(Client *client, int status, json_t *body)
{
	char *json_str = body ? json_dumps(body, JSON_COMPACT) : strdup("{}");
	if (!json_str) json_str = strdup("{}");
	char hdr[512];
	int blen = strlen(json_str);
	snprintf(hdr, sizeof(hdr),
	         "HTTP/1.1 %d OK\r\n"
	         "Content-Type: application/json\r\n"
	         "Content-Length: %d\r\n"
	         "Connection: close\r\n"
	         "\r\n",
	         status, blen);
	dbuf_put(&client->local->sendQ, hdr, strlen(hdr));
	dbuf_put(&client->local->sendQ, json_str, blen);
	send_queued(client);
	free(json_str);
	if (body) json_decref(body);
	dead_socket(client, "REST response sent");
}

static void pb_rest_send_error(Client *client, int status, const char *msg)
{
	json_t *body = json_object();
	json_object_set_new(body, "error", json_string(msg ? msg : ""));
	pb_rest_send_json(client, status, body);
}

/* Decode a single %XX in-place; returns 0 on success, -1 on malformed. */
static int pb_pct_decode(char *s)
{
	char *o = s;
	for (char *p = s; *p; p++) {
		if (*p == '%') {
			if (!p[1] || !p[2]) return -1;
			int hi = (p[1] >= '0' && p[1] <= '9') ? p[1] - '0'
			       : (p[1] >= 'a' && p[1] <= 'f') ? p[1] - 'a' + 10
			       : (p[1] >= 'A' && p[1] <= 'F') ? p[1] - 'A' + 10 : -1;
			int lo = (p[2] >= '0' && p[2] <= '9') ? p[2] - '0'
			       : (p[2] >= 'a' && p[2] <= 'f') ? p[2] - 'a' + 10
			       : (p[2] >= 'A' && p[2] <= 'F') ? p[2] - 'A' + 10 : -1;
			if (hi < 0 || lo < 0) return -1;
			*o++ = (char)(hi * 16 + lo);
			p += 2;
		} else *o++ = *p;
	}
	*o = '\0';
	return 0;
}

/* Generate a fresh random bearer token (40 alnum chars). */
static void pb_generate_token(char *out, size_t outlen)
{
	int n = outlen ? (int)outlen - 1 : 0;
	if (n > 64) n = 64;
	gen_random_alnum(out, n);
	out[n] = '\0';
}

/* Build a minimal PbConfigBot from a parsed JSON body for re-use of
 * pb_upsert_bot_row + pb_apply_pending_bots-style materialisation. */
static int pb_register_bot_internal(json_t *body, int active,
                                    char *bot_id_out, char *token_out)
{
	json_t *jnick = json_object_get(body, "nick");
	if (!json_is_string(jnick)) return -1;
	const char *nick = json_string_value(jnick);
	if (!*nick || pb_find_bot_by_nick(nick) || find_user(nick, NULL))
		return -2;  /* nick clash */

	PbConfigBot tmp;
	memset(&tmp, 0, sizeof(tmp));
	safe_strdup(tmp.nick, nick);
	const char *rn = NULL;
	json_t *jrn = json_object_get(body, "realname");
	if (json_is_string(jrn)) rn = json_string_value(jrn);
	safe_strdup(tmp.realname, rn ? rn : nick);
	json_t *jsc = json_object_get(body, "scope");
	tmp.scope = pb_parse_scope(json_is_string(jsc) ? json_string_value(jsc) : "channel");
	json_t *jtr = json_object_get(body, "transport");
	tmp.transport = pb_parse_transport(json_is_string(jtr) ? json_string_value(jtr) : "gateway");
	json_t *jwh = json_object_get(body, "webhook_url");
	if (json_is_string(jwh)) safe_strdup(tmp.webhook_url, json_string_value(jwh));
	json_t *jws = json_object_get(body, "webhook_secret");
	if (json_is_string(jws)) safe_strdup(tmp.webhook_secret, json_string_value(jws));

	pb_generate_token(token_out, 41);
	safe_strdup(tmp.token, token_out);
	char bot_id[16];
	pb_generate_id(bot_id, sizeof(bot_id));
	strlcpy(bot_id_out, bot_id, 16);

	if (pb_upsert_bot_row(bot_id, &tmp) < 0) {
		safe_free(tmp.nick); safe_free(tmp.realname); safe_free(tmp.token);
		safe_free(tmp.webhook_url); safe_free(tmp.webhook_secret);
		return -3;
	}

	PbBot *b = safe_alloc(sizeof(*b));
	safe_strdup(b->bot_id, bot_id);
	safe_strdup(b->nick, tmp.nick);
	safe_strdup(b->account, tmp.nick);
	safe_strdup(b->realname, tmp.realname);
	b->scope = tmp.scope;
	b->transport = tmp.transport;
	b->status = active ? PB_STATUS_ACTIVE : PB_STATUS_PENDING;
	if (tmp.webhook_url) safe_strdup(b->webhook_url, tmp.webhook_url);
	if (tmp.webhook_secret) safe_strdup(b->webhook_secret, tmp.webhook_secret);
	safe_strdup(b->config_token, tmp.token);
	AddListItem(b, bots);
	if (active) pb_spawn_ghost(b);

	safe_free(tmp.nick); safe_free(tmp.realname); safe_free(tmp.token);
	safe_free(tmp.webhook_url); safe_free(tmp.webhook_secret);
	return 0;
}

static void pb_rest_register_bot(Client *client, WebRequest *web)
{
	if (cfg.registration_mode &&
	    !strcasecmp(cfg.registration_mode, "admin")) {
		pb_rest_send_error(client, 403, "registration mode=admin: config-only");
		return;
	}
	if (!web->request_buffer) {
		pb_rest_send_error(client, 400, "missing body");
		return;
	}
	json_error_t err;
	json_t *body = json_loads(web->request_buffer, 0, &err);
	if (!body || !json_is_object(body)) {
		if (body) json_decref(body);
		pb_rest_send_error(client, 400, "body must be a JSON object");
		return;
	}
	int active = (cfg.registration_mode &&
	              !strcasecmp(cfg.registration_mode, "open")) ? 1 : 0;
	char bot_id[16] = "", token[64] = "";
	int rc = pb_register_bot_internal(body, active, bot_id, token);
	json_decref(body);
	if (rc == -1) { pb_rest_send_error(client, 400, "missing or invalid 'nick'"); return; }
	if (rc == -2) { pb_rest_send_error(client, 409, "nick already in use"); return; }
	if (rc < 0)   { pb_rest_send_error(client, 500, "create failed"); return; }

	json_t *resp = json_object();
	json_object_set_new(resp, "bot_id", json_string(bot_id));
	json_object_set_new(resp, "token", json_string(token));
	json_object_set_new(resp, "status", json_string(active ? "active" : "pending"));
	pb_rest_send_json(client, active ? 201 : 202, resp);

	unreal_log(ULOG_INFO, "pushbot", "SELF_REGISTER", NULL,
	           "Bot $bot_id ($nick) created via REST self-registration ($status)",
	           log_data_string("bot_id", bot_id),
	           log_data_string("nick", "?"),
	           log_data_string("status", active ? "active" : "pending"));
}

static void pb_rest_list_bots(Client *client, WebRequest *web)
{
	json_t *arr = json_array();
	for (PbBot *b = bots; b; b = b->next) {
		json_t *o = json_object();
		json_object_set_new(o, "bot_id", json_string(b->bot_id));
		json_object_set_new(o, "nick", json_string(b->nick));
		json_object_set_new(o, "scope", json_string(pb_scope_str(b->scope)));
		json_object_set_new(o, "transport", json_string(pb_transport_str(b->transport)));
		json_object_set_new(o, "status",
		    json_string(b->status == PB_STATUS_ACTIVE ? "active" :
		                b->status == PB_STATUS_PENDING ? "pending" :
		                b->status == PB_STATUS_SUSPENDED ? "suspended" : "deleted"));
		json_object_set_new(o, "from_config", json_boolean(b->from_config));
		json_array_append_new(arr, o);
	}
	json_t *body = json_object();
	json_object_set_new(body, "bots", arr);
	pb_rest_send_json(client, 200, body);
}

/* ===================================================================
 * Phase 9 -- JSON-RPC parity
 * =================================================================== */

static json_t *pb_bot_to_json(PbBot *b)
{
	json_t *o = json_object();
	json_object_set_new(o, "bot_id", json_string(b->bot_id ? b->bot_id : ""));
	json_object_set_new(o, "nick", json_string(b->nick ? b->nick : ""));
	json_object_set_new(o, "realname", json_string(b->realname ? b->realname : ""));
	json_object_set_new(o, "scope", json_string(pb_scope_str(b->scope)));
	json_object_set_new(o, "transport", json_string(pb_transport_str(b->transport)));
	json_object_set_new(o, "status",
	    json_string(b->status == PB_STATUS_ACTIVE ? "active" :
	                b->status == PB_STATUS_PENDING ? "pending" :
	                b->status == PB_STATUS_SUSPENDED ? "suspended" : "deleted"));
	json_object_set_new(o, "from_config", json_boolean(b->from_config));
	json_object_set_new(o, "webhook_url",
	    json_string(b->webhook_url ? b->webhook_url : ""));
	json_object_set_new(o, "online",
	    json_boolean(b->session && b->session->identified));
	json_object_set_new(o, "channels_count", json_integer(0));  /* TODO membership count */
	return o;
}

RPC_CALL_FUNC(pb_rpc_list)
{
	json_t *result = json_object();
	json_t *list = json_array();
	for (PbBot *b = bots; b; b = b->next)
		json_array_append_new(list, pb_bot_to_json(b));
	json_object_set_new(result, "list", list);
	rpc_response(client, request, result);
	json_decref(result);
}

RPC_CALL_FUNC(pb_rpc_get)
{
	const char *nick;
	REQUIRE_PARAM_STRING("nick", nick);
	PbBot *b = pb_find_bot_by_nick(nick);
	if (!b) {
		rpc_error(client, request, JSON_RPC_ERROR_NOT_FOUND, "No such bot");
		return;
	}
	json_t *result = pb_bot_to_json(b);
	rpc_response(client, request, result);
	json_decref(result);
}

RPC_CALL_FUNC(pb_rpc_register)
{
	if (cfg.registration_mode && !strcasecmp(cfg.registration_mode, "admin")) {
		rpc_error(client, request, JSON_RPC_ERROR_DENIED,
		          "registration mode=admin: config-only");
		return;
	}
	const char *nick;
	REQUIRE_PARAM_STRING("nick", nick);
	if (pb_find_bot_by_nick(nick) || find_user(nick, NULL)) {
		rpc_error(client, request, JSON_RPC_ERROR_ALREADY_EXISTS, "nick already in use");
		return;
	}
	int active = (cfg.registration_mode &&
	              !strcasecmp(cfg.registration_mode, "open")) ? 1 : 0;
	char bot_id[16] = "", token[64] = "";
	int rc = pb_register_bot_internal(params, active, bot_id, token);
	if (rc < 0) {
		rpc_error(client, request, JSON_RPC_ERROR_INTERNAL_ERROR, "create failed");
		return;
	}
	json_t *result = json_object();
	json_object_set_new(result, "bot_id", json_string(bot_id));
	json_object_set_new(result, "token", json_string(token));
	json_object_set_new(result, "status", json_string(active ? "active" : "pending"));
	rpc_response(client, request, result);
	json_decref(result);
}

static void pb_rpc_status_change(Client *client, json_t *request, json_t *params,
                                 PbStatus new_status, const char *verb)
{
	const char *nick;
	REQUIRE_PARAM_STRING("nick", nick);
	PbBot *b = pb_find_bot_by_nick(nick);
	if (!b) {
		rpc_error(client, request, JSON_RPC_ERROR_NOT_FOUND, "No such bot");
		return;
	}
	if (b->from_config) {
		rpc_error(client, request, JSON_RPC_ERROR_DENIED,
		          "config-defined bot; edit obbyircd.conf");
		return;
	}
	b->status = new_status;
	if (new_status == PB_STATUS_ACTIVE && !b->ghost) pb_spawn_ghost(b);
	if (new_status != PB_STATUS_ACTIVE && b->ghost) {
		Client *g = b->ghost; b->ghost = NULL;
		exit_client(g, NULL, "Bot deactivated by RPC");
	}
	/* Persist to DB or the next restart will reload the row as
	 * its previous status -- this is why pushbot.delete used to
	 * appear to work then come back. */
	{
		const char *str =
		    new_status == PB_STATUS_ACTIVE ? "active" :
		    new_status == PB_STATUS_SUSPENDED ? "suspended" :
		    new_status == PB_STATUS_DELETED ? "deleted" : "pending";
		sqlite3_stmt *st = NULL;
		if (sqlite3_prepare_v2(db,
		    "UPDATE pushbots SET status=? WHERE bot_id=?",
		    -1, &st, NULL) == SQLITE_OK)
		{
			sqlite3_bind_text(st, 1, str, -1, SQLITE_STATIC);
			sqlite3_bind_text(st, 2, b->bot_id, -1, SQLITE_STATIC);
			sqlite3_step(st);
			sqlite3_finalize(st);
		}
	}
	pb_broadcast_bot_event(b, new_status == PB_STATUS_DELETED ? "remove" : "update");
	json_t *result = json_object();
	json_object_set_new(result, "ok", json_true());
	json_object_set_new(result, "status", json_string(verb));
	rpc_response(client, request, result);
	json_decref(result);
}

RPC_CALL_FUNC(pb_rpc_approve)   { pb_rpc_status_change(client, request, params, PB_STATUS_ACTIVE, "active"); }
RPC_CALL_FUNC(pb_rpc_suspend)   { pb_rpc_status_change(client, request, params, PB_STATUS_SUSPENDED, "suspended"); }
RPC_CALL_FUNC(pb_rpc_unsuspend) { pb_rpc_status_change(client, request, params, PB_STATUS_ACTIVE, "active"); }
RPC_CALL_FUNC(pb_rpc_delete)    { pb_rpc_status_change(client, request, params, PB_STATUS_DELETED, "deleted"); }

/* ===================================================================
 * Shared cores: behaviours called by gateway op handlers, REST
 * handlers, AND webhook inline-action dispatch. None of these emit
 * HTTP/WS responses themselves -- they perform the action and report
 * success/failure via a small enum (forward-declared above) so each
 * caller can render the appropriate transport reply.
 * =================================================================== */

/* Build a tag list from a JSON object {"+tag": "value", ...}. Caller
 * frees with free_message_tags. */
static MessageTag *pb_build_tags(json_t *tagj)
{
	MessageTag *out = NULL;
	if (!json_is_object(tagj)) return NULL;
	const char *key;
	json_t *val;
	json_object_foreach(tagj, key, val) {
		if (!key || key[0] != '+') continue;
		if (!json_is_string(val)) continue;
		MessageTag *m = safe_alloc(sizeof(*m));
		safe_strdup(m->name, key);
		safe_strdup(m->value, json_string_value(val));
		AddListItem(m, out);
	}
	return out;
}

/* Replace the bot's published command list. The gateway handler and
 * REST POST /commands both funnel through here. */
static PbCoreResult pb_core_register_commands(PbBot *b, json_t *cmds_array)
{
	if (!b || !json_is_array(cmds_array)) return PB_CORE_BAD_REQUEST;
	if (b->commands) json_decref(b->commands);
	b->commands = json_incref(cmds_array);

	json_t *ack_d = json_object();
	json_object_set_new(ack_d, "count", json_integer(json_array_size(cmds_array)));
	pb_dispatch_event(b, "COMMANDS_REGISTERED", ack_d);

	unreal_log(ULOG_INFO, "pushbot", "CMDS_REGISTERED", NULL,
	           "Bot $nick registered $n slash commands",
	           log_data_string("nick", b->nick),
	           log_data_integer("n", (int)json_array_size(cmds_array)));
	pb_broadcast_bot_event(b, "update");
	return PB_CORE_OK;
}

/* Answer a COMMAND_INVOKE interaction. Used by gateway op 21 and REST
 * POST /interactions/:id/respond and webhook inline send_message /
 * ephemeral_reply / error / workflow. */
static PbCoreResult pb_core_interaction_respond(PbBot *b, const char *iid,
                                                const char *content,
                                                const char *visibility,
                                                int ephemeral,
                                                MessageTag *extra_tags)
{
	if (!b || !iid) return PB_CORE_BAD_REQUEST;
	PbInteraction *it = pb_interaction_find(iid);
	if (!it) return PB_CORE_NOT_FOUND;
	if (it->bot != b) return PB_CORE_FORBIDDEN;
	pb_send_interaction_reply(it, content ? content : "",
	                          visibility ? visibility : "public",
	                          ephemeral, extra_tags);
	pb_interaction_free(it);
	return PB_CORE_OK;
}

/* Buy the bot another window of time before the user sees a TIMEOUT
 * FAIL. */
static PbCoreResult pb_core_interaction_defer(PbBot *b, const char *iid,
                                              int seconds)
{
	if (!b || !iid) return PB_CORE_BAD_REQUEST;
	PbInteraction *it = pb_interaction_find(iid);
	if (!it) return PB_CORE_NOT_FOUND;
	if (it->bot != b) return PB_CORE_FORBIDDEN;
	it->expires_at = TStime() + (seconds > 0 ? seconds : PB_INTERACTION_DEFER_SEC);
	it->deferred = 1;
	return PB_CORE_OK;
}

/* Emit a +draft/bot-tools workflow / step / action message. As a side
 * effect, when the payload references a workflow whose `id` matches a
 * still-open interaction owned by this bot, slide that interaction's
 * deadline forward (workflow:start gives the bot the full window, every
 * step refreshes it). This is what lets a bot answer a slash command
 * five minutes later as long as it keeps reporting progress. */
static PbCoreResult pb_core_workflow_event(PbBot *b, const char *target,
                                           json_t *payload)
{
	if (!b || !target || !*target || !json_is_object(payload))
		return PB_CORE_BAD_REQUEST;
	json_t *msgj = json_object_get(payload, "msg");
	if (!json_is_string(msgj)) return PB_CORE_BAD_REQUEST;
	const char *msg = json_string_value(msgj);

	const char *wid = NULL;
	if (!strcmp(msg, "workflow")) {
		json_t *idj = json_object_get(payload, "id");
		if (json_is_string(idj)) wid = json_string_value(idj);
	} else if (!strcmp(msg, "step")) {
		json_t *widj = json_object_get(payload, "wid");
		if (json_is_string(widj)) wid = json_string_value(widj);
	}

	if (!strcmp(msg, "workflow")) {
		json_t *statej = json_object_get(payload, "state");
		if (json_is_string(statej) && wid) {
			PbWorkflow *w = pb_workflow_touch(b, wid, target);
			if (w) {
				const char *state = json_string_value(statej);
				if (!strcmp(state, "complete") ||
				    !strcmp(state, "failed") ||
				    !strcmp(state, "cancelled"))
					pb_workflow_terminate(w);
				/* state=start announces a new workflow. Link it
				 * to the bot's most-recent still-open
				 * interaction (FIFO from interactions; LIFO
				 * after AddListItem) so subsequent step events
				 * on this wid keep that interaction alive. */
				else if (!strcmp(state, "start")) {
					for (PbInteraction *it = interactions; it; it = it->next) {
						if (it->bot != b) continue;
						if (it->workflow_id) continue;
						safe_strdup(it->workflow_id, wid);
						break;
					}
				}
			}
		}
	} else if (!strcmp(msg, "step")) {
		json_t *sidj = json_object_get(payload, "sid");
		if (wid && json_is_string(sidj)) {
			PbWorkflow *w = pb_workflow_touch(b, wid, target);
			if (w) pb_workflow_remember_sid(w, json_string_value(sidj));
		}
	}

	/* Workflow keep-alive: any interaction whose trigger was the
	 * carrying workflow id gets its deadline pushed forward. The bot
	 * can call respond() much later as long as steps keep arriving. */
	if (wid) {
		for (PbInteraction *it = interactions; it; it = it->next) {
			if (it->bot != b) continue;
			if (it->workflow_id && !strcmp(it->workflow_id, wid)) {
				it->expires_at = TStime() + PB_INTERACTION_WORKFLOW_SEC;
				it->deferred = 1;
			}
		}
	}

	pb_workflow_send_tag(b, target, payload);
	return PB_CORE_OK;
}

/* ===================================================================
 * REST handlers for the bot-tools surface: POST /commands,
 * POST /interactions/:id/respond, POST /interactions/:id/defer,
 * POST /workflows/:id/events.
 * =================================================================== */

/* Parse the POST body as a JSON object. Owner-pattern: caller
 * json_decref()s on success; on failure the 400 response is sent and
 * NULL is returned. */
static json_t *pb_rest_parse_object(Client *client, WebRequest *web)
{
	if (!web->request_buffer) {
		pb_rest_send_error(client, 400, "missing body");
		return NULL;
	}
	json_error_t err;
	json_t *body = json_loads(web->request_buffer, 0, &err);
	if (!body || !json_is_object(body)) {
		pb_rest_send_error(client, 400, "body must be a JSON object");
		if (body) json_decref(body);
		return NULL;
	}
	return body;
}

static void pb_rest_ok(Client *client)
{
	json_t *body = json_object();
	json_object_set_new(body, "ok", json_true());
	pb_rest_send_json(client, 200, body);
}

static void pb_rest_core_result(Client *client, PbCoreResult r)
{
	switch (r) {
		case PB_CORE_OK:          pb_rest_ok(client); return;
		case PB_CORE_BAD_REQUEST: pb_rest_send_error(client, 400, "invalid request"); return;
		case PB_CORE_NOT_FOUND:   pb_rest_send_error(client, 404, "not found"); return;
		case PB_CORE_FORBIDDEN:   pb_rest_send_error(client, 403, "forbidden"); return;
	}
}

static void pb_rest_register_commands(Client *client, WebRequest *web, PbBot *b)
{
	json_t *body = pb_rest_parse_object(client, web);
	if (!body) return;
	json_t *cmds = json_object_get(body, "commands");
	if (!json_is_array(cmds)) {
		pb_rest_send_error(client, 400, "commands must be an array");
		json_decref(body);
		return;
	}
	PbCoreResult r = pb_core_register_commands(b, cmds);
	json_decref(body);
	pb_rest_core_result(client, r);
}

static void pb_rest_interaction_respond(Client *client, WebRequest *web,
                                        PbBot *b, const char *iid)
{
	json_t *body = pb_rest_parse_object(client, web);
	if (!body) return;

	const char *content = "";
	const char *vis = "public";
	int ephemeral = 0;
	json_t *cj = json_object_get(body, "content");
	if (json_is_string(cj)) content = json_string_value(cj);
	json_t *vj = json_object_get(body, "visibility");
	if (json_is_string(vj)) vis = json_string_value(vj);
	json_t *ej = json_object_get(body, "ephemeral");
	if (json_is_boolean(ej)) ephemeral = json_is_true(ej) ? 1 : 0;

	MessageTag *extra = pb_build_tags(json_object_get(body, "tags"));
	PbCoreResult r = pb_core_interaction_respond(b, iid, content, vis,
	                                             ephemeral, extra);
	free_message_tags(extra);
	json_decref(body);
	pb_rest_core_result(client, r);
}

static void pb_rest_interaction_defer(Client *client, WebRequest *web,
                                      PbBot *b, const char *iid)
{
	int seconds = 0;
	if (web->request_buffer && *web->request_buffer) {
		json_t *body = pb_rest_parse_object(client, web);
		if (!body) return;
		json_t *sj = json_object_get(body, "seconds");
		if (json_is_integer(sj)) seconds = (int)json_integer_value(sj);
		json_decref(body);
	}
	pb_rest_core_result(client, pb_core_interaction_defer(b, iid, seconds));
}

/* POST /workflows/<id>/events with body {target: "...", payload: {msg:...}}
 * appends a workflow or step event. The bot can call this an unlimited
 * number of times between the COMMAND_INVOKE and the final respond. */
static void pb_rest_workflow_event(Client *client, WebRequest *web,
                                   PbBot *b, const char *wid_in_path)
{
	json_t *body = pb_rest_parse_object(client, web);
	if (!body) return;

	json_t *tj = json_object_get(body, "target");
	json_t *payload = json_object_get(body, "payload");
	if (!json_is_string(tj) || !json_is_object(payload)) {
		pb_rest_send_error(client, 400, "need {target, payload}");
		json_decref(body);
		return;
	}
	/* If the payload doesn't already carry an id/wid, inject the one
	 * from the URL. Lets the bot use the cleaner-looking form
	 * POST /workflows/wf123/events { target, payload: {msg:"step",sid:"s1",...} }
	 * without restating the id inside the payload too. */
	if (wid_in_path && *wid_in_path) {
		json_t *msgj = json_object_get(payload, "msg");
		const char *msg = json_is_string(msgj) ? json_string_value(msgj) : "";
		if (!strcmp(msg, "workflow") && !json_object_get(payload, "id"))
			json_object_set_new(payload, "id", json_string(wid_in_path));
		else if (!strcmp(msg, "step") && !json_object_get(payload, "wid"))
			json_object_set_new(payload, "wid", json_string(wid_in_path));
	}

	PbCoreResult r = pb_core_workflow_event(b, json_string_value(tj), payload);
	json_decref(body);
	pb_rest_core_result(client, r);
}

/* ===================================================================
 * Webhook inline-action dispatch.
 *
 * Per pushbot spec §9, when a bot in transport=webhook mode handles a
 * COMMAND_INVOKE delivery, it can answer in the 200 response body with
 * a JSON object {type: "<action>", ...}. That lets purely-serverless
 * bots (n8n, Cloudflare Workers, Lambda) reply to slash commands
 * without ever opening a connection back to the IRCd. The dispatcher
 * below is called from pb_webhook_response after the HTTP 200 lands.
 * =================================================================== */

static void pb_webhook_dispatch_inline_action(PbBot *b, const char *iid,
                                              json_t *action)
{
	if (!b || !json_is_object(action)) return;
	json_t *tj = json_object_get(action, "type");
	if (!json_is_string(tj)) return;
	const char *type = json_string_value(tj);

	if (!strcmp(type, "send_message")) {
		const char *content = "", *vis = "public";
		int ephemeral = 0;
		json_t *cj = json_object_get(action, "content");
		json_t *vj = json_object_get(action, "visibility");
		json_t *ej = json_object_get(action, "ephemeral");
		if (json_is_string(cj)) content = json_string_value(cj);
		if (json_is_string(vj)) vis = json_string_value(vj);
		if (json_is_true(ej)) ephemeral = 1;
		MessageTag *extra = pb_build_tags(json_object_get(action, "tags"));
		if (iid)
			pb_core_interaction_respond(b, iid, content, vis, ephemeral, extra);
		free_message_tags(extra);
	} else if (!strcmp(type, "ephemeral_reply")) {
		const char *content = "";
		json_t *cj = json_object_get(action, "content");
		if (json_is_string(cj)) content = json_string_value(cj);
		if (iid)
			pb_core_interaction_respond(b, iid, content, "public", 1, NULL);
	} else if (!strcmp(type, "error")) {
		const char *content = "(error)";
		json_t *mj = json_object_get(action, "message");
		if (json_is_string(mj)) content = json_string_value(mj);
		if (iid)
			pb_core_interaction_respond(b, iid, content, "public", 1, NULL);
	} else if (!strcmp(type, "defer")) {
		int seconds = 0;
		json_t *sj = json_object_get(action, "seconds");
		if (json_is_integer(sj)) seconds = (int)json_integer_value(sj);
		if (iid)
			pb_core_interaction_defer(b, iid, seconds);
	} else if (!strcmp(type, "workflow") || !strcmp(type, "step")) {
		/* Inline workflow/step: emit the tag now. Target defaults to
		 * the channel the interaction was invoked on; the bot can
		 * override with action.target. */
		json_t *payload = json_object_get(action, "payload");
		if (!json_is_object(payload)) {
			/* Treat top-level fields as the payload itself for the
			 * convenience case `{type:"workflow", state:"start", id:"..."}`. */
			payload = json_object();
			const char *key; json_t *v;
			json_object_foreach(action, key, v) {
				if (strcmp(key, "type") && strcmp(key, "target"))
					json_object_set(payload, key, v);
			}
			if (!json_object_get(payload, "msg"))
				json_object_set_new(payload, "msg", json_string(type));
			const char *target = NULL;
			json_t *tjj = json_object_get(action, "target");
			if (json_is_string(tjj)) target = json_string_value(tjj);
			if (!target && iid) {
				PbInteraction *it = pb_interaction_find(iid);
				if (it) target = it->channel;
			}
			if (target)
				pb_core_workflow_event(b, target, payload);
			json_decref(payload);
		} else {
			const char *target = NULL;
			json_t *tjj = json_object_get(action, "target");
			if (json_is_string(tjj)) target = json_string_value(tjj);
			if (!target && iid) {
				PbInteraction *it = pb_interaction_find(iid);
				if (it) target = it->channel;
			}
			if (target)
				pb_core_workflow_event(b, target, payload);
		}
	}
	/* Unknown types are silently ignored: spec is permissive about
	 * forward-compat extensions. */
}

static int pb_handle_rest(Client *client, WebRequest *web, PbBot *b)
{
	if (!web->uri || strncmp(web->uri, "/pushbot/v1/", 12) != 0) {
		pb_rest_send_error(client, 404, "not found");
		return 0;
	}
	char path[512];
	strlcpy(path, web->uri + 12, sizeof(path));   /* skip /pushbot/v1/ */
	/* Strip query string if any. */
	char *q = strchr(path, '?');
	if (q) *q = '\0';

	/* /bot */
	if (!strcmp(path, "bot")) {
		if (web->method != HTTP_METHOD_GET) {
			pb_rest_send_error(client, 405, "method not allowed");
			return 0;
		}
		pb_rest_get_bot(client, web, b);
		return 0;
	}

	/* /channels */
	if (!strcmp(path, "channels")) {
		if (web->method != HTTP_METHOD_GET) {
			pb_rest_send_error(client, 405, "method not allowed");
			return 0;
		}
		pb_rest_get_channels(client, web, b);
		return 0;
	}

	/* /channels/<name>/... */
	if (!strncmp(path, "channels/", 9)) {
		char rest[512];
		strlcpy(rest, path + 9, sizeof(rest));
		char *slash = strchr(rest, '/');
		char *channel = rest;
		const char *sub = "";
		if (slash) { *slash = '\0'; sub = slash + 1; }
		if (pb_pct_decode(channel) < 0) {
			pb_rest_send_error(client, 400, "bad channel encoding");
			return 0;
		}

		if (!strcmp(sub, "join") && web->method == HTTP_METHOD_POST) {
			pb_rest_channel_join(client, web, b, channel);
			return 0;
		}
		if (!strcmp(sub, "part") && web->method == HTTP_METHOD_POST) {
			pb_rest_channel_part(client, web, b, channel);
			return 0;
		}
		if (!strcmp(sub, "messages") && web->method == HTTP_METHOD_POST) {
			pb_rest_channel_message(client, web, b, channel);
			return 0;
		}
		if (!strcmp(sub, "members") && web->method == HTTP_METHOD_GET) {
			pb_rest_get_members(client, web, b, channel);
			return 0;
		}
		/* messages/<msgid>/... */
		if (!strncmp(sub, "messages/", 9)) {
			char msub[256];
			strlcpy(msub, sub + 9, sizeof(msub));
			char *mslash = strchr(msub, '/');
			char *msgid = msub;
			const char *msub2 = "";
			if (mslash) { *mslash = '\0'; msub2 = mslash + 1; }
			/* UnrealIRCd's webserver doesn't support DELETE; use POST
			 * with subroutes for delete-style ops. */
			if (!strcmp(msub2, "redact") && web->method == HTTP_METHOD_POST) {
				pb_rest_redact(client, web, b, channel, msgid);
				return 0;
			}
			if (!strcmp(msub2, "react") && web->method == HTTP_METHOD_POST) {
				pb_rest_react(client, web, b, channel, msgid, 0, NULL);
				return 0;
			}
			if (!strcmp(msub2, "unreact") && web->method == HTTP_METHOD_POST) {
				pb_rest_react(client, web, b, channel, msgid, 1, NULL);
				return 0;
			}
		}
	}

	/* /commands -- publish the bot's slash-command schema */
	if (!strcmp(path, "commands")) {
		if (web->method != HTTP_METHOD_POST) {
			pb_rest_send_error(client, 405, "method not allowed");
			return 0;
		}
		pb_rest_register_commands(client, web, b);
		return 0;
	}

	/* /interactions/<id>/respond  and  /interactions/<id>/defer */
	if (!strncmp(path, "interactions/", 13)) {
		char rest[256];
		strlcpy(rest, path + 13, sizeof(rest));
		char *slash = strchr(rest, '/');
		char *iid = rest;
		const char *sub = "";
		if (slash) { *slash = '\0'; sub = slash + 1; }
		if (pb_pct_decode(iid) < 0) {
			pb_rest_send_error(client, 400, "bad id encoding");
			return 0;
		}
		if (!strcmp(sub, "respond") && web->method == HTTP_METHOD_POST) {
			pb_rest_interaction_respond(client, web, b, iid);
			return 0;
		}
		if (!strcmp(sub, "defer") && web->method == HTTP_METHOD_POST) {
			pb_rest_interaction_defer(client, web, b, iid);
			return 0;
		}
	}

	/* /workflows/<wid>/events -- emit workflow / step / action tags
	 * over the life of a long-running task. No 3-second cap here:
	 * each event also slides the linked interaction's expires_at
	 * forward via pb_core_workflow_event. */
	if (!strncmp(path, "workflows/", 10)) {
		char rest[256];
		strlcpy(rest, path + 10, sizeof(rest));
		char *slash = strchr(rest, '/');
		char *wid = rest;
		const char *sub = "";
		if (slash) { *slash = '\0'; sub = slash + 1; }
		if (pb_pct_decode(wid) < 0) {
			pb_rest_send_error(client, 400, "bad wid encoding");
			return 0;
		}
		if (!strcmp(sub, "events") && web->method == HTTP_METHOD_POST) {
			pb_rest_workflow_event(client, web, b, wid);
			return 0;
		}
	}

	/* /users/<nick>/messages */
	if (!strncmp(path, "users/", 6)) {
		char rest[256];
		strlcpy(rest, path + 6, sizeof(rest));
		char *slash = strchr(rest, '/');
		char *nick = rest;
		const char *sub = "";
		if (slash) { *slash = '\0'; sub = slash + 1; }
		pb_pct_decode(nick);
		if (!strcmp(sub, "messages") && web->method == HTTP_METHOD_POST) {
			pb_rest_user_message(client, web, b, nick);
			return 0;
		}
	}

	pb_rest_send_error(client, 404, "no such route");
	return 0;
}

static void pb_rest_get_bot(Client *client, WebRequest *web, PbBot *b)
{
	json_t *body = json_object();
	json_object_set_new(body, "bot_id", json_string(b->bot_id));
	json_object_set_new(body, "nick", json_string(b->nick));
	json_object_set_new(body, "realname", json_string(b->realname));
	json_object_set_new(body, "scope", json_string(pb_scope_str(b->scope)));
	json_object_set_new(body, "transport", json_string(pb_transport_str(b->transport)));
	json_object_set_new(body, "status", json_string(pb_status_str(b->status)));
	json_object_set_new(body, "gateway_connected",
	    json_boolean(b->session && b->session->identified ? 1 : 0));
	pb_rest_send_json(client, 200, body);
}

static void pb_rest_get_channels(Client *client, WebRequest *web, PbBot *b)
{
	json_t *arr = json_array();
	if (b->ghost) {
		for (Membership *m = b->ghost->user->channel; m; m = m->next)
			json_array_append_new(arr, json_string(m->channel->name));
	}
	json_t *body = json_object();
	json_object_set_new(body, "channels", arr);
	pb_rest_send_json(client, 200, body);
}

static void pb_rest_get_members(Client *client, WebRequest *web, PbBot *b,
                                const char *channel)
{
	Channel *ch = find_channel(channel);
	if (!ch) { pb_rest_send_error(client, 404, "no such channel"); return; }
	if (!pb_bot_is_in_channel(b, ch)) {
		pb_rest_send_error(client, 403, "bot not in channel");
		return;
	}
	json_t *arr = json_array();
	for (Member *m = ch->members; m; m = m->next)
		json_array_append_new(arr, pb_json_client(m->client));
	json_t *body = json_object();
	json_object_set_new(body, "members", arr);
	pb_rest_send_json(client, 200, body);
}

/* For POST bodies: jansson-parse, extract string field "content".
 * Returns NULL + writes 400 on bad input. */
static const char *pb_post_string_field(Client *client, WebRequest *web,
                                        const char *field, json_t **owner_out)
{
	if (!web->request_buffer) {
		pb_rest_send_error(client, 400, "missing body");
		return NULL;
	}
	json_error_t err;
	json_t *body = json_loads(web->request_buffer, 0, &err);
	if (!body || !json_is_object(body)) {
		pb_rest_send_error(client, 400, "body must be a JSON object");
		if (body) json_decref(body);
		return NULL;
	}
	json_t *v = json_object_get(body, field);
	if (!json_is_string(v)) {
		pb_rest_send_error(client, 400, "missing string field");
		json_decref(body);
		return NULL;
	}
	*owner_out = body;
	return json_string_value(v);
}

static void pb_rest_channel_message(Client *client, WebRequest *web, PbBot *b,
                                    const char *channel)
{
	Channel *ch = find_channel(channel);
	if (!ch) { pb_rest_send_error(client, 404, "no such channel"); return; }
	if (!pb_bot_is_in_channel(b, ch)) {
		pb_rest_send_error(client, 403, "bot not in channel");
		return;
	}
	json_t *owner = NULL;
	const char *content = pb_post_string_field(client, web, "content", &owner);
	if (!content) return;

	sendto_channel(ch, b->ghost, NULL, 0, 0, SEND_ALL, NULL,
	               "PRIVMSG %s :%s", ch->name, content);
	json_decref(owner);

	json_t *body = json_object();
	json_object_set_new(body, "ok", json_true());
	pb_rest_send_json(client, 200, body);
}

static void pb_rest_user_message(Client *client, WebRequest *web, PbBot *b,
                                 const char *nick)
{
	Client *target = find_user(nick, NULL);
	if (!target) { pb_rest_send_error(client, 404, "no such user"); return; }
	json_t *owner = NULL;
	const char *content = pb_post_string_field(client, web, "content", &owner);
	if (!content) return;

	sendto_one(target, NULL, ":%s PRIVMSG %s :%s",
	           b->ghost ? b->ghost->name : b->nick, target->name, content);
	json_decref(owner);
	json_t *body = json_object();
	json_object_set_new(body, "ok", json_true());
	pb_rest_send_json(client, 200, body);
}

static void pb_rest_react(Client *client, WebRequest *web, PbBot *b,
                          const char *channel, const char *msgid, int remove,
                          const char *emoji)
{
	Channel *ch = find_channel(channel);
	if (!ch) { pb_rest_send_error(client, 404, "no such channel"); return; }
	if (!pb_bot_is_in_channel(b, ch)) {
		pb_rest_send_error(client, 403, "bot not in channel");
		return;
	}
	const char *the_emoji = emoji;
	json_t *owner = NULL;
	if (!the_emoji) {
		the_emoji = pb_post_string_field(client, web, "emoji", &owner);
		if (!the_emoji) return;
	}
	/* React via TAGMSG with the IRCv3 react tag.  Reaction removal is not yet
	 * differentiated on the wire, so add and remove emit the same react. */
	(void)remove;
	sendto_channel(ch, b->ghost, NULL, 0, 0, SEND_ALL, NULL,
	               "@+draft/react=%s;+draft/reply=%s TAGMSG %s",
	               the_emoji, msgid, ch->name);
	if (owner) json_decref(owner);
	json_t *body = json_object();
	json_object_set_new(body, "ok", json_true());
	pb_rest_send_json(client, 200, body);
}

static void pb_rest_redact(Client *client, WebRequest *web, PbBot *b,
                           const char *channel, const char *msgid)
{
	Channel *ch = find_channel(channel);
	if (!ch) { pb_rest_send_error(client, 404, "no such channel"); return; }
	if (!pb_bot_is_in_channel(b, ch)) {
		pb_rest_send_error(client, 403, "bot not in channel");
		return;
	}
	/* draft/message-redaction protocol: REDACT command. */
	const char *parv[4] = { "REDACT", ch->name, msgid, NULL };
	do_cmd(b->ghost, NULL, "REDACT", 3, parv);
	json_t *body = json_object();
	json_object_set_new(body, "ok", json_true());
	pb_rest_send_json(client, 200, body);
}

static void pb_rest_channel_join(Client *client, WebRequest *web, PbBot *b,
                                 const char *channel)
{
	if (!b->ghost) { pb_rest_send_error(client, 500, "ghost not up"); return; }
	Channel *ch = find_channel(channel);
	if (!ch) ch = make_channel(channel);
	if (!ch) { pb_rest_send_error(client, 500, "could not create channel"); return; }
	if (!pb_bot_is_in_channel(b, ch))
		add_user_to_channel(ch, b->ghost, "");
	json_t *body = json_object();
	json_object_set_new(body, "ok", json_true());
	json_object_set_new(body, "channel", json_string(ch->name));
	pb_rest_send_json(client, 200, body);
}

static void pb_rest_channel_part(Client *client, WebRequest *web, PbBot *b,
                                 const char *channel)
{
	if (!b->ghost) { pb_rest_send_error(client, 500, "ghost not up"); return; }
	Channel *ch = find_channel(channel);
	if (!ch) { pb_rest_send_error(client, 404, "no such channel"); return; }
	Membership *target = NULL;
	for (Membership *m = b->ghost->user->channel; m; m = m->next)
		if (m->channel == ch) { target = m; break; }
	if (!target) { pb_rest_send_error(client, 404, "not in channel"); return; }
	remove_user_from_channel_withmb(b->ghost, ch, target, 1);
	json_t *body = json_object();
	json_object_set_new(body, "ok", json_true());
	pb_rest_send_json(client, 200, body);
}

