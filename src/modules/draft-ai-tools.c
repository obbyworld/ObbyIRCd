/*
 * draft-ai-tools.c — obbyircd module for draft/bot-tools
 *
 * Advertises the draft/bot-tools IRCv3 capability (the "Bot Tools" workflow-
 * transparency spec) and registers the single +draft/bot-tools client-only
 * message tag, whose value is the base64 of a compact JSON object carrying all
 * workflow/step/action payloads.
 *
 * Using one tag avoids clienttagdeny slot exhaustion.  The tag is relayed only
 * to clients that have negotiated draft/bot-tools (enforced via clicap_handler),
 * so the workflow stream never reaches clients that would not display it; any
 * client (or server) may send it.
 *
 * Spec: extensions/bot-tools.md
 */

#include "unrealircd.h"

ModuleHeader MOD_HEADER = {
    "draft-ai-tools",
    "0.5",
    "draft/bot-tools — bot workflow transparency tags (single-tag JSON)",
    "irc-ai-tag-framework",
    "unrealircd-6",
};

/* Allocated by ClientCapabilityAdd; used for fast bitmask checks. */
static long CAP_AI_TOOLS = 0L;

/* ── forward declarations ─────────────────────────────────────────────────── */

static int ai_tools_mtag_is_ok(Client *client, const char *name, const char *value);
static void ai_tools_mtag_relay(Client *client, MessageTag *recv_mtags,
                                MessageTag **mtag_list, const char *signature);
static void register_ait_tag(Module *module, ClientCapability *cap, const char *name);

/* ── tag sender validation ────────────────────────────────────────────────── */

/*
 * is_ok — called for every incoming +draft/bot-tools tag from a client or
 * server.  Per IRCv3 client-only-tag semantics (the leading "+"), the server
 * MUST relay these verbatim regardless of whether the sender has negotiated the
 * capability — recipients verify trust themselves.  We therefore accept from
 * anyone and just reject empty values.
 */
static int ai_tools_mtag_is_ok(Client *client, const char *name, const char *value)
{
	if (BadPtr(value))
		return 0;
	return 1;
}

/* ── HOOKTYPE_NEW_MESSAGE relay ────────────────────────────────────────────── */

/*
 * Without a NEW_MESSAGE hook, the +draft/bot-tools tag survives the
 * incoming `is_ok` filter but never gets COPIED onto the outgoing message-
 * tag list `cmd_message` builds.  cmd_message then calls
 * has_client_mtags() on the outgoing list, finds no `+`-prefixed tags, and
 * silently drops the TAGMSG as "empty and useless".  Copying the tag from
 * recv_mtags into mtag_list is the standard pattern (see typing-indicator
 * and reply-tag modules).
 */
static void ai_tools_mtag_relay(Client *client, MessageTag *recv_mtags,
                                MessageTag **mtag_list, const char *signature)
{
	MessageTag *m;

	if (!IsUser(client))
		return;

	m = find_mtag(recv_mtags, "+draft/bot-tools");
	if (m)
	{
		m = duplicate_mtag(m);
		AddListItem(m, *mtag_list);
	}
}

/* ── tag registration helper ──────────────────────────────────────────────── */

static void register_ait_tag(Module *module, ClientCapability *cap, const char *name)
{
	MessageTagHandlerInfo mtag;

	memset(&mtag, 0, sizeof(mtag));
	mtag.name = (char *)name;  /* const-cast safe; API doesn't modify */
	mtag.is_ok = ai_tools_mtag_is_ok;
	mtag.clicap_handler = cap;           /* relay only to draft/bot-tools clients */
	/* should_send_to_client left NULL: clicap_handler already handles filtering */
	MessageTagHandlerAdd(module, &mtag);
}

/* ── module lifecycle ─────────────────────────────────────────────────────── */

MOD_TEST()
{
	return MOD_SUCCESS;
}

MOD_INIT()
{
	ClientCapabilityInfo cap;
	ClientCapability *c;

	/* Register the draft/bot-tools capability.  It carries no value: a bot
	 * advertises the behaviours it supports (interactive/reasoning/approval)
	 * per-workflow in its `features` array, since a server cannot speak for an
	 * individual bot. */
	memset(&cap, 0, sizeof(cap));
	cap.name = "draft/bot-tools";
	/* flags = CLICAP_FLAGS_NONE: individual tags carry their own clicap_handler */
	c = ClientCapabilityAdd(modinfo->handle, &cap, &CAP_AI_TOOLS);
	if (!c)
	{
		config_error("draft-ai-tools: ClientCapabilityAdd failed");
		return MOD_FAILED;
	}

	/* Single JSON-envelope tag (base64 of compact JSON; see spec for schema). */
	register_ait_tag(modinfo->handle, c, "+draft/bot-tools");

	/* Copy the client-only tag from incoming to outgoing on every message --
	 * without this, cmd_message's has_client_mtags() check drops the TAGMSG. */
	HookAddVoid(modinfo->handle, HOOKTYPE_NEW_MESSAGE, 0, ai_tools_mtag_relay);

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
