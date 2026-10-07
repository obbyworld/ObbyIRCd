/*
 * obbypy -- server-side Python scripting for ObbyIRCd
 * (C) 2026 Valerie / ObbyIRCd
 * License: GPLv3 or later
 *
 * Embeds CPython (libpython3 via python3-embed pkg-config).  Drops
 * .py files in <conf>/scripts/python/ and they're imported at
 * module-load.  The `obby` built-in is preinstalled in every script
 * so users can `import obby` and get on with it.
 *
 * This file is the Python counterpart of obbyscript.c (which embeds
 * Duktape for JavaScript).  Both modules can co-exist; pick the
 * language per-script.  API surface (see obby_methods[] near the
 * bottom) covers:
 *
 *   * Hooks: ~30 named hooks including LOCAL_CONNECT, LOCAL_QUIT,
 *     REMOTE_QUIT, LOCAL_JOIN/PART/KICK, CHANMSG, USERMSG, NICK
 *     change, WELCOME, ACCOUNT_LOGIN, channel-mode changes, etc.
 *
 *   * Commands: register_command(name, fn, params=1)
 *
 *   * Sending: send_notice, send_msg, send_raw, send_numeric,
 *     send_to_channel, send_to_server, send_to_all_servers,
 *     send_to_channel_skip
 *
 *   * Lookups: find_client, find_channel, find_server,
 *     all_clients, all_local_clients, all_servers,
 *     all_local_servers, all_opers, all_channels
 *
 *   * Predicates: is_user, is_server, is_oper, is_secure,
 *     is_uline, is_logged_in, has_mode, check_channel_access
 *
 *   * Acting on the IRC state: do_cmd, exit_client, kick, set_topic,
 *     set_user_mode, set_channel_mode, change_nick, set_host,
 *     join_channel, part_channel
 *
 *   * Server-bans (TKL): add_serverban, del_serverban
 *
 *   * Timers: set_timeout, set_interval, clear_timer
 *
 *   * HTTP: http_get(url, callback)
 *
 *   * ModData: register_moddata, set_moddata, get_moddata
 *
 *   * Mode registration: register_channel_mode, register_prefix_mode,
 *     register_user_mode
 *
 *   * RPC: register_rpc_method, rpc_response, rpc_error
 *
 *   * Extbans: register_extban
 *
 *   * Config blocks: register_config_block
 *
 *   * Message-tag handlers: register_message_tag
 *
 *   * Logging: log(msg, level='info')
 *
 * Hook handlers take a single `event` dict and return an int (0 =
 * HOOK_CONTINUE, 1 = HOOK_DENY) or None (treated as 0).  Command
 * handlers take (client, params: list[str]).  Client / Channel /
 * Server are PyTypeObjects with dot-access attrs.
 *
 * Where the upstream UnrealIRCd C API can't be expressed cleanly in
 * Python (callback timing, raw moddata pointers, ...) we either map
 * to a sensible string/dict idiom or document the gap.  This file is
 * intentionally heavy on inline comments because UnrealIRCd's own
 * conventions are subtle in places.
 */

/* Python.h MUST come before any other includes (per Python docs):
 * Py_PYTHON_H pre-defines macros that collide with libc/ctype.h --
 * you'll get cryptic "expected ']'" errors inside common.h's
 * ctype-using macros if anything else gets in first. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "unrealircd.h"
#include <dirent.h>
#include <limits.h>

ModuleHeader MOD_HEADER = {
    "obbypy",
    "1.0",
    "Server-side Python scripting (embedded CPython)",
    "Valerie",
    "unrealircd-6"};

#define MYCONF                 "obbypy"
#define DEFAULT_SCRIPTS_DIR    "scripts/python"
#define HTTP_API_CALLBACK_NAME "obbypy_http_callback"

/* ===================================================================
 * Forward declarations of internal helpers / hook trampolines
 * =================================================================== */

static int obbypy_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
static int obbypy_configrun(ConfigFile *cf, ConfigEntry *ce, int type);
static void load_scripts(void);
static void cleanup_state(void);

static PyObject *py_client_new(Client *c);
static PyObject *py_channel_new(Channel *c);
static PyObject *py_server_new(Client *c);
static PyObject *mtags_to_dict(MessageTag *mtags);
static PyObject *parv_to_list(const char *parv[], int parc, int start);
static Client *unwrap_client(PyObject *o);
static Channel *unwrap_channel(PyObject *o);
static const char *py_str_or(PyObject *o, const char *fallback);
static int call_handler_with_event(PyObject *fn, PyObject *event);
static int call_handler(PyObject *fn, PyObject *args);

static int hook_name_to_type(const char *name);

/* Hook trampolines */
static int htramp_local_connect(Client *client);
static int htramp_remote_connect(Client *client);
static int htramp_secure_connect(Client *client);
static int htramp_welcome(Client *client, int after_authenticated);
static int htramp_local_quit(Client *client, MessageTag *mtags, const char *comment);
static int htramp_remote_quit(Client *client, MessageTag *mtags, const char *comment);
static int htramp_unkuser_quit(Client *client, MessageTag *mtags, const char *comment);
static int htramp_local_join(Client *client, Channel *channel, MessageTag *mtags);
static int htramp_remote_join(Client *client, Channel *channel, MessageTag *mtags);
static int htramp_local_part(Client *client, Channel *channel, MessageTag *mtags, const char *comment);
static int htramp_remote_part(Client *client, Channel *channel, MessageTag *mtags, const char *comment);
static int htramp_local_kick(Client *client, Client *victim, Channel *channel, MessageTag *mtags, const char *comment);
static int htramp_remote_kick(Client *client, Client *victim, Channel *channel, MessageTag *mtags, const char *comment);
static int htramp_chanmsg(Client *client, Channel *channel, int sendflags, const char *prefix, const char *target,
                          MessageTag *mtags, const char *text, SendType sendtype);
static int htramp_usermsg(Client *client, Client *to, MessageTag *mtags, const char *text, SendType sendtype);
static int htramp_local_nickchange(Client *client, MessageTag *mtags, const char *newnick);
static int htramp_remote_nickchange(Client *client, MessageTag *mtags, const char *newnick);
static int htramp_account_login(Client *client, MessageTag *mtags);
static int htramp_topic(Client *client, Channel *channel, MessageTag *mtags, const char *topic);
static int htramp_server_connect(Client *client);
static int htramp_server_synced(Client *client);
static int htramp_server_quit(Client *client, MessageTag *mtags);
static int htramp_close_connection(Client *client);
static int htramp_local_chanmode(Client *client, Channel *channel, MessageTag *mtags, const char *modebuf,
                                 const char *parabuf, time_t sendts, int samode, int *destroy_channel);

/* Command dispatcher (one C func; the registry maps name -> Python). */
CMD_FUNC(cmd_py_dispatch);

/* HTTP / timer / event-driven trampolines (signatures below). */
static void obbypy_http_callback(OutgoingWebRequest *req, OutgoingWebResponse *res);

/* ===================================================================
 * Internal state
 * =================================================================== */

typedef struct PyHook PyHook;
struct PyHook {
	PyHook *prev, *next;
	int hooktype;
	PyObject *fn;
	char *script;
};

typedef struct PyCmd PyCmd;
struct PyCmd {
	PyCmd *prev, *next;
	char *name;
	int params;
	PyObject *fn;
	Command *cmd;
	char *script;
};

typedef struct PyTimer PyTimer;
struct PyTimer {
	PyTimer *prev, *next;
	int id;
	int is_interval;
	int cancelled;
	Event *event;
	PyObject *fn;
};

typedef struct PyHttp PyHttp;
struct PyHttp {
	PyHttp *prev, *next;
	PyObject *fn;
};

typedef struct PyModData PyModData;
struct PyModData {
	PyModData *prev, *next;
	char *name;
	int type;            /* MODDATATYPE_* */
	int sync;            /* 0 or 1 */
	ModDataInfo *md;
};

typedef struct PyChanmode PyChanmode;
struct PyChanmode {
	PyChanmode *prev, *next;
	char letter;
	char *name;
	int paracount;
	Cmode *cmode;
	Cmode_t mode_bit;
	PyObject *is_ok;
};

typedef struct PyPrefixmode PyPrefixmode;
struct PyPrefixmode {
	PyPrefixmode *prev, *next;
	char letter;
	char prefix;
	int rank;
	char *name;
	Cmode *cmode;
	PyObject *is_ok;
};

typedef struct PyUsermode PyUsermode;
struct PyUsermode {
	PyUsermode *prev, *next;
	char letter;
	char *name;
	int global;
	int unset_on_deoper;
	Umode *umode;
	long mode_bit;
	PyObject *allowed;
};

typedef struct PyRpc PyRpc;
struct PyRpc {
	PyRpc *prev, *next;
	char *method;
	PyObject *fn;
};

typedef struct PyExtban PyExtban;
struct PyExtban {
	PyExtban *prev, *next;
	char letter;
	char *name;
	PyObject *is_ok;
	PyObject *is_banned;
};

typedef struct PyCfgBlock PyCfgBlock;
struct PyCfgBlock {
	PyCfgBlock *prev, *next;
	char *blockname;
	PyObject *test_fn;
	PyObject *run_fn;
};

typedef struct PyMtagHandler PyMtagHandler;
struct PyMtagHandler {
	PyMtagHandler *prev, *next;
	char *name;
	MessageTagHandler *handle;
	PyObject *is_ok;
	PyObject *can_send;
};

static PyHook *hooks_list = NULL;
static PyCmd *cmds_list = NULL;
static PyTimer *timers_list = NULL;
static PyHttp *https_list = NULL;
static PyModData *moddatas_list = NULL;
static PyChanmode *chanmodes_list = NULL;
static PyPrefixmode *prefixmodes_list = NULL;
static PyUsermode *usermodes_list = NULL;
static PyRpc *rpcs_list = NULL;
static PyExtban *extbans_list = NULL;
static PyCfgBlock *cfg_blocks_list = NULL;
static PyMtagHandler *mtag_handlers_list = NULL;

static int hook_added[2048] = {0};
static int next_timer_id = 1;

static struct {
	char *scripts_dir;
} cfg;

static ModuleInfo *modinfo_ref = NULL;

/* ===================================================================
 * Hook name table
 * =================================================================== */

static const struct {
	const char *name;
	int type;
} hook_names[] = {
        /* Connection lifecycle */
    {"PRE_LOCAL_CONNECT", HOOKTYPE_PRE_LOCAL_CONNECT},
    {"LOCAL_CONNECT", HOOKTYPE_LOCAL_CONNECT},
    {"REMOTE_CONNECT", HOOKTYPE_REMOTE_CONNECT},
    {"SECURE_CONNECT", HOOKTYPE_SECURE_CONNECT},
    {"WELCOME", HOOKTYPE_WELCOME},
    {"CLOSE_CONNECTION", HOOKTYPE_CLOSE_CONNECTION},
    {"PRE_LOCAL_QUIT", HOOKTYPE_PRE_LOCAL_QUIT},
    {"LOCAL_QUIT", HOOKTYPE_LOCAL_QUIT},
    {"REMOTE_QUIT", HOOKTYPE_REMOTE_QUIT},
    {"UNKUSER_QUIT", HOOKTYPE_UNKUSER_QUIT},
    {"ACCOUNT_LOGIN", HOOKTYPE_ACCOUNT_LOGIN},

        /* Nick changes */
    {"LOCAL_NICKCHANGE", HOOKTYPE_LOCAL_NICKCHANGE},
    {"NICK_CHANGE", HOOKTYPE_LOCAL_NICKCHANGE}, /* alias */
    {"REMOTE_NICKCHANGE", HOOKTYPE_REMOTE_NICKCHANGE},
    {"POST_LOCAL_NICKCHANGE", HOOKTYPE_POST_LOCAL_NICKCHANGE},
    {"POST_REMOTE_NICKCHANGE", HOOKTYPE_POST_REMOTE_NICKCHANGE},

        /* Join / Part / Kick */
    {"LOCAL_JOIN", HOOKTYPE_LOCAL_JOIN},
    {"REMOTE_JOIN", HOOKTYPE_REMOTE_JOIN},
    {"LOCAL_PART", HOOKTYPE_LOCAL_PART},
    {"REMOTE_PART", HOOKTYPE_REMOTE_PART},
    {"LOCAL_KICK", HOOKTYPE_LOCAL_KICK},
    {"REMOTE_KICK", HOOKTYPE_REMOTE_KICK},

        /* Messages */
    {"CHANMSG", HOOKTYPE_CHANMSG},
    {"USERMSG", HOOKTYPE_USERMSG},

        /* Topic & modes */
    {"TOPIC", HOOKTYPE_TOPIC},
    {"LOCAL_CHANMODE", HOOKTYPE_LOCAL_CHANMODE},

        /* Server-to-server */
    {"SERVER_CONNECT", HOOKTYPE_SERVER_CONNECT},
    {"SERVER_SYNCED", HOOKTYPE_SERVER_SYNCED},
    {"SERVER_QUIT", HOOKTYPE_SERVER_QUIT},

    {NULL, 0}};

static int hook_name_to_type(const char *name)
{
	for (int i = 0; hook_names[i].name; i++)
		if (!strcasecmp(hook_names[i].name, name))
			return hook_names[i].type;
	return -1;
}

/* ===================================================================
 * Client / Channel / Server / Member PyTypeObjects
 * =================================================================== */

typedef struct {
	PyObject_HEAD Client *c;
} PyClientObject;

typedef struct {
	PyObject_HEAD Channel *ch;
} PyChannelObject;

typedef struct {
	PyObject_HEAD Client *c; /* a server-flavoured Client */
} PyServerObject;

static PyObject *PyClient_getattro(PyObject *self, PyObject *name_obj)
{
	PyClientObject *o = (PyClientObject *)self;
	const char *name = PyUnicode_AsUTF8(name_obj);
	if (!name)
		return NULL;
	if (!o->c)
		Py_RETURN_NONE;

	if (!strcmp(name, "name"))
		return PyUnicode_FromString(o->c->name[0] ? o->c->name : "");
	if (!strcmp(name, "id"))
		return PyUnicode_FromString(o->c->id[0] ? o->c->id : "");
	if (!strcmp(name, "info"))
		return PyUnicode_FromString(o->c->info[0] ? o->c->info : "");
	if (!strcmp(name, "host"))
	{
		const char *h = NULL;
		if (o->c->user)
			h = o->c->user->virthost ? o->c->user->virthost : o->c->user->realhost;
		if (!h)
			h = GetHost(o->c);
		return PyUnicode_FromString(h ? h : "");
	}
	if (!strcmp(name, "realhost"))
		return PyUnicode_FromString(o->c->user && o->c->user->realhost[0] ? o->c->user->realhost : "");
	if (!strcmp(name, "ip"))
		return PyUnicode_FromString(o->c->ip ? o->c->ip : "");
	if (!strcmp(name, "account"))
	{
		if (o->c->user && o->c->user->account[0] && strcmp(o->c->user->account, "0"))
			return PyUnicode_FromString(o->c->user->account);
		Py_RETURN_NONE;
	}
	if (!strcmp(name, "realname"))
	{
		if (o->c->user)
			return PyUnicode_FromString(o->c->info[0] ? o->c->info : "");
		Py_RETURN_NONE;
	}
	if (!strcmp(name, "ident") || !strcmp(name, "username"))
	{
		return PyUnicode_FromString(o->c->user && o->c->user->username[0] ? o->c->user->username : "");
	}
	if (!strcmp(name, "umodes"))
	{
		if (!o->c->user)
			return PyUnicode_FromString("");
		char buf[64];
		get_usermode_string_r(o->c, buf, sizeof(buf));
		return PyUnicode_FromString(buf);
	}
	if (!strcmp(name, "is_user"))
		return PyBool_FromLong(IsUser(o->c) ? 1 : 0);
	if (!strcmp(name, "is_server"))
		return PyBool_FromLong(IsServer(o->c) ? 1 : 0);
	if (!strcmp(name, "is_oper"))
		return PyBool_FromLong(IsOper(o->c) ? 1 : 0);
	if (!strcmp(name, "is_secure"))
		return PyBool_FromLong(IsSecure(o->c) ? 1 : 0);
	if (!strcmp(name, "is_uline"))
		return PyBool_FromLong(IsULine(o->c) ? 1 : 0);
	if (!strcmp(name, "is_logged_in"))
		return PyBool_FromLong((o->c->user && IsLoggedIn(o->c)) ? 1 : 0);
	if (!strcmp(name, "is_local"))
		return PyBool_FromLong(MyConnect(o->c) ? 1 : 0);
	if (!strcmp(name, "server"))
	{
		Client *s = o->c->user ? find_server_quick(o->c->user->server) : o->c->uplink;
		if (s)
			return py_server_new(s);
		Py_RETURN_NONE;
	}
	if (!strcmp(name, "channels"))
	{
		PyObject *list = PyList_New(0);
		if (!list)
			return NULL;
		if (o->c->user)
		{
			Membership *m;
			for (m = o->c->user->channel; m; m = m->next)
			{
				PyObject *ch = py_channel_new(m->channel);
				if (ch)
				{
					PyList_Append(list, ch);
					Py_DECREF(ch);
				}
			}
		}
		return list;
	}

	return PyObject_GenericGetAttr(self, name_obj);
}

static PyObject *PyClient_repr(PyObject *self)
{
	PyClientObject *o = (PyClientObject *)self;
	if (!o->c)
		return PyUnicode_FromString("<Client (gone)>");
	return PyUnicode_FromFormat("<Client %s>", o->c->name[0] ? o->c->name : "?");
}

static PyTypeObject PyClient_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name = "obby.Client",
    .tp_basicsize = sizeof(PyClientObject),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_getattro = PyClient_getattro,
    .tp_repr = PyClient_repr,
};

static PyObject *py_client_new(Client *c)
{
	if (!c)
		Py_RETURN_NONE;
	PyClientObject *o = PyObject_New(PyClientObject, &PyClient_Type);
	if (!o)
		return NULL;
	o->c = c;
	return (PyObject *)o;
}

static PyObject *PyChannel_getattro(PyObject *self, PyObject *name_obj)
{
	PyChannelObject *o = (PyChannelObject *)self;
	const char *name = PyUnicode_AsUTF8(name_obj);
	if (!name)
		return NULL;
	if (!o->ch)
		Py_RETURN_NONE;

	if (!strcmp(name, "name"))
		return PyUnicode_FromString(o->ch->name[0] ? o->ch->name : "");
	if (!strcmp(name, "topic"))
		return PyUnicode_FromString(o->ch->topic ? o->ch->topic : "");
	if (!strcmp(name, "topic_nick"))
		return PyUnicode_FromString(o->ch->topic_nick ? o->ch->topic_nick : "");
	if (!strcmp(name, "topic_time"))
		return PyLong_FromLongLong((long long)o->ch->topic_time);
	if (!strcmp(name, "creation_time"))
		return PyLong_FromLongLong((long long)o->ch->creationtime);
	if (!strcmp(name, "modes"))
	{
		char mbuf[128], pbuf[256];
		channel_modes(&me, mbuf, pbuf, sizeof(mbuf), sizeof(pbuf), o->ch, 0);
		if (pbuf[0])
		{
			char both[512];
			snprintf(both, sizeof(both), "%s %s", mbuf, pbuf);
			return PyUnicode_FromString(both);
		}
		return PyUnicode_FromString(mbuf);
	}
	if (!strcmp(name, "users"))
	{
		PyObject *list = PyList_New(0);
		if (!list)
			return NULL;
		for (Member *m = o->ch->members; m; m = m->next)
		{
			PyObject *n = PyUnicode_FromString(m->client->name[0] ? m->client->name : "");
			if (n)
			{
				PyList_Append(list, n);
				Py_DECREF(n);
			}
		}
		return list;
	}
	if (!strcmp(name, "members"))
	{
		/* Like users but yields Client wrappers + per-member modes. */
		PyObject *list = PyList_New(0);
		if (!list)
			return NULL;
		for (Member *m = o->ch->members; m; m = m->next)
		{
			PyObject *d = PyDict_New();
			if (!d)
				continue;
			PyDict_SetItemString(d, "client", py_client_new(m->client));
			char modebuf[16];
			int j = 0;
			if (m->member_modes[0])
			{
				strlcpy(modebuf, m->member_modes, sizeof(modebuf));
				j = strlen(modebuf);
			}
			modebuf[j] = '\0';
			PyDict_SetItemString(d, "modes", PyUnicode_FromString(modebuf));
			PyList_Append(list, d);
			Py_DECREF(d);
		}
		return list;
	}
	if (!strcmp(name, "users_count") || !strcmp(name, "num_users"))
	{
		int count = 0;
		for (Member *m = o->ch->members; m; m = m->next)
			count++;
		return PyLong_FromLong(count);
	}

	return PyObject_GenericGetAttr(self, name_obj);
}

static PyObject *PyChannel_repr(PyObject *self)
{
	PyChannelObject *o = (PyChannelObject *)self;
	if (!o->ch)
		return PyUnicode_FromString("<Channel (gone)>");
	return PyUnicode_FromFormat("<Channel %s>", o->ch->name[0] ? o->ch->name : "?");
}

static PyTypeObject PyChannel_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name = "obby.Channel",
    .tp_basicsize = sizeof(PyChannelObject),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_getattro = PyChannel_getattro,
    .tp_repr = PyChannel_repr,
};

static PyObject *py_channel_new(Channel *c)
{
	if (!c)
		Py_RETURN_NONE;
	PyChannelObject *o = PyObject_New(PyChannelObject, &PyChannel_Type);
	if (!o)
		return NULL;
	o->ch = c;
	return (PyObject *)o;
}

static PyObject *PyServer_getattro(PyObject *self, PyObject *name_obj)
{
	PyServerObject *o = (PyServerObject *)self;
	const char *name = PyUnicode_AsUTF8(name_obj);
	if (!name)
		return NULL;
	if (!o->c)
		Py_RETURN_NONE;

	if (!strcmp(name, "name"))
		return PyUnicode_FromString(o->c->name[0] ? o->c->name : "");
	if (!strcmp(name, "info"))
		return PyUnicode_FromString(o->c->info[0] ? o->c->info : "");
	if (!strcmp(name, "id"))
		return PyUnicode_FromString(o->c->id[0] ? o->c->id : "");
	if (!strcmp(name, "is_local"))
		return PyBool_FromLong(MyConnect(o->c) ? 1 : 0);
	if (!strcmp(name, "is_uline"))
		return PyBool_FromLong(IsULine(o->c) ? 1 : 0);
	if (!strcmp(name, "uplink"))
	{
		if (o->c->uplink)
			return py_server_new(o->c->uplink);
		Py_RETURN_NONE;
	}

	return PyObject_GenericGetAttr(self, name_obj);
}

static PyObject *PyServer_repr(PyObject *self)
{
	PyServerObject *o = (PyServerObject *)self;
	if (!o->c)
		return PyUnicode_FromString("<Server (gone)>");
	return PyUnicode_FromFormat("<Server %s>", o->c->name[0] ? o->c->name : "?");
}

static PyTypeObject PyServer_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name = "obby.Server",
    .tp_basicsize = sizeof(PyServerObject),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_getattro = PyServer_getattro,
    .tp_repr = PyServer_repr,
};

static PyObject *py_server_new(Client *c)
{
	if (!c)
		Py_RETURN_NONE;
	PyServerObject *o = PyObject_New(PyServerObject, &PyServer_Type);
	if (!o)
		return NULL;
	o->c = c;
	return (PyObject *)o;
}

/* ===================================================================
 * Conversion helpers
 * =================================================================== */

static Client *unwrap_client(PyObject *o)
{
	if (!o || o == Py_None)
		return NULL;
	if (PyObject_TypeCheck(o, &PyClient_Type))
		return ((PyClientObject *)o)->c;
	if (PyObject_TypeCheck(o, &PyServer_Type))
		return ((PyServerObject *)o)->c;
	if (PyUnicode_Check(o))
	{
		const char *s = PyUnicode_AsUTF8(o);
		return s ? find_user(s, NULL) : NULL;
	}
	PyErr_SetString(PyExc_TypeError, "expected Client or nick string");
	return NULL;
}

static Channel *unwrap_channel(PyObject *o)
{
	if (!o || o == Py_None)
		return NULL;
	if (PyObject_TypeCheck(o, &PyChannel_Type))
		return ((PyChannelObject *)o)->ch;
	if (PyUnicode_Check(o))
	{
		const char *s = PyUnicode_AsUTF8(o);
		return s ? find_channel(s) : NULL;
	}
	PyErr_SetString(PyExc_TypeError, "expected Channel or name string");
	return NULL;
}

static const char *py_str_or(PyObject *o, const char *fallback)
{
	if (!o || !PyUnicode_Check(o))
		return fallback;
	const char *s = PyUnicode_AsUTF8(o);
	return s ? s : fallback;
}

static PyObject *mtags_to_dict(MessageTag *mtags)
{
	PyObject *d = PyDict_New();
	if (!d)
		return NULL;
	for (MessageTag *m = mtags; m; m = m->next)
	{
		if (!m->name)
			continue;
		PyObject *v = PyUnicode_FromString(m->value ? m->value : "");
		if (v)
		{
			PyDict_SetItemString(d, m->name, v);
			Py_DECREF(v);
		}
	}
	return d;
}

static PyObject *parv_to_list(const char *parv[], int parc, int start)
{
	PyObject *l = PyList_New(0);
	if (!l)
		return l;
	for (int i = start; i < parc; i++)
	{
		if (!parv[i])
			continue;
		PyObject *s = PyUnicode_FromString(parv[i]);
		if (s)
		{
			PyList_Append(l, s);
			Py_DECREF(s);
		}
	}
	return l;
}

/* Run fn(*args), logging any Python exception and returning the
 * integer result (None or non-int -> 0). Steals args. */
static int call_handler(PyObject *fn, PyObject *args)
{
	if (!fn || !args)
	{
		Py_XDECREF(args);
		return 0;
	}
	PyObject *rv = PyObject_Call(fn, args, NULL);
	Py_DECREF(args);
	if (!rv)
	{
		PyObject *type, *val, *tb;
		PyErr_Fetch(&type, &val, &tb);
		PyErr_NormalizeException(&type, &val, &tb);
		PyObject *vstr = val ? PyObject_Str(val) : NULL;
		const char *vs = vstr ? PyUnicode_AsUTF8(vstr) : "";
		unreal_log(ULOG_ERROR, "obbypy", "PY_HANDLER_ERROR", NULL,
		           "Python handler raised: $err",
		           log_data_string("err", vs ? vs : "?"));
		Py_XDECREF(vstr);
		Py_XDECREF(type);
		Py_XDECREF(val);
		Py_XDECREF(tb);
		return 0;
	}
	int r = 0;
	if (PyLong_Check(rv))
		r = (int)PyLong_AsLong(rv);
	else if (PyBool_Check(rv))
		r = (rv == Py_True) ? 1 : 0;
	Py_DECREF(rv);
	return r;
}

static int call_handler_with_event(PyObject *fn, PyObject *event)
{
	PyObject *args = PyTuple_Pack(1, event ? event : Py_None);
	return call_handler(fn, args);
}

/* Walk hooks_list for htype and call each. */
static int dispatch_hook(int htype, PyObject *event)
{
	int rv = 0;
	for (PyHook *h = hooks_list; h; h = h->next)
	{
		if (h->hooktype != htype)
			continue;
		int r = call_handler_with_event(h->fn, event);
		if (r)
			rv = r;
	}
	Py_XDECREF(event);
	return rv;
}

/* ===================================================================
 * Hook trampolines (C -> Python)
 * =================================================================== */

#define EVENT_NEW(name) \
	PyObject *name = PyDict_New(); \
	if (!name) \
	return 0
#define EVENT_SET(d, key, val) \
	do \
	{ \
		PyObject *_v = (val); \
		if (_v) \
		{ \
			PyDict_SetItemString((d), (key), _v); \
			Py_DECREF(_v); \
		} \
	} while (0)

static int htramp_local_connect(Client *client)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	return dispatch_hook(HOOKTYPE_LOCAL_CONNECT, e);
}

static int htramp_remote_connect(Client *client)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	return dispatch_hook(HOOKTYPE_REMOTE_CONNECT, e);
}

static int htramp_secure_connect(Client *client)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	return dispatch_hook(HOOKTYPE_SECURE_CONNECT, e);
}

static int htramp_welcome(Client *client, int after_authenticated)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "after_authenticated", PyBool_FromLong(after_authenticated ? 1 : 0));
	return dispatch_hook(HOOKTYPE_WELCOME, e);
}

static int htramp_close_connection(Client *client)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	return dispatch_hook(HOOKTYPE_CLOSE_CONNECTION, e);
}

static int htramp_local_quit(Client *client, MessageTag *mtags, const char *comment)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "reason", PyUnicode_FromString(comment ? comment : ""));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	return dispatch_hook(HOOKTYPE_LOCAL_QUIT, e);
}

static int htramp_remote_quit(Client *client, MessageTag *mtags, const char *comment)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "reason", PyUnicode_FromString(comment ? comment : ""));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	return dispatch_hook(HOOKTYPE_REMOTE_QUIT, e);
}

static int htramp_unkuser_quit(Client *client, MessageTag *mtags, const char *comment)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "reason", PyUnicode_FromString(comment ? comment : ""));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	return dispatch_hook(HOOKTYPE_UNKUSER_QUIT, e);
}

static int htramp_local_join(Client *client, Channel *channel, MessageTag *mtags)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "channel", py_channel_new(channel));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	return dispatch_hook(HOOKTYPE_LOCAL_JOIN, e);
}

static int htramp_remote_join(Client *client, Channel *channel, MessageTag *mtags)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "channel", py_channel_new(channel));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	return dispatch_hook(HOOKTYPE_REMOTE_JOIN, e);
}

static int htramp_local_part(Client *client, Channel *channel, MessageTag *mtags, const char *comment)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "channel", py_channel_new(channel));
	EVENT_SET(e, "reason", PyUnicode_FromString(comment ? comment : ""));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	return dispatch_hook(HOOKTYPE_LOCAL_PART, e);
}

static int htramp_remote_part(Client *client, Channel *channel, MessageTag *mtags, const char *comment)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "channel", py_channel_new(channel));
	EVENT_SET(e, "reason", PyUnicode_FromString(comment ? comment : ""));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	return dispatch_hook(HOOKTYPE_REMOTE_PART, e);
}

static int htramp_local_kick(Client *client, Client *victim, Channel *channel, MessageTag *mtags, const char *comment)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "victim", py_client_new(victim));
	EVENT_SET(e, "channel", py_channel_new(channel));
	EVENT_SET(e, "reason", PyUnicode_FromString(comment ? comment : ""));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	return dispatch_hook(HOOKTYPE_LOCAL_KICK, e);
}

static int htramp_remote_kick(Client *client, Client *victim, Channel *channel, MessageTag *mtags, const char *comment)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "victim", py_client_new(victim));
	EVENT_SET(e, "channel", py_channel_new(channel));
	EVENT_SET(e, "reason", PyUnicode_FromString(comment ? comment : ""));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	return dispatch_hook(HOOKTYPE_REMOTE_KICK, e);
}

static int htramp_chanmsg(Client *client, Channel *channel, int sendflags, const char *prefix, const char *target,
                          MessageTag *mtags, const char *text, SendType sendtype)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "channel", py_channel_new(channel));
	EVENT_SET(e, "msg", PyUnicode_FromString(text ? text : ""));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	EVENT_SET(e, "is_notice", PyBool_FromLong(sendtype == SEND_TYPE_NOTICE ? 1 : 0));
	EVENT_SET(e, "is_tagmsg", PyBool_FromLong(sendtype == SEND_TYPE_TAGMSG ? 1 : 0));
	return dispatch_hook(HOOKTYPE_CHANMSG, e);
}

static int htramp_usermsg(Client *client, Client *to, MessageTag *mtags, const char *text, SendType sendtype)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "target", py_client_new(to));
	EVENT_SET(e, "msg", PyUnicode_FromString(text ? text : ""));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	EVENT_SET(e, "is_notice", PyBool_FromLong(sendtype == SEND_TYPE_NOTICE ? 1 : 0));
	EVENT_SET(e, "is_tagmsg", PyBool_FromLong(sendtype == SEND_TYPE_TAGMSG ? 1 : 0));
	return dispatch_hook(HOOKTYPE_USERMSG, e);
}

static int htramp_local_nickchange(Client *client, MessageTag *mtags, const char *newnick)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "oldnick", PyUnicode_FromString(client && client->name ? client->name : ""));
	EVENT_SET(e, "newnick", PyUnicode_FromString(newnick ? newnick : ""));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	return dispatch_hook(HOOKTYPE_LOCAL_NICKCHANGE, e);
}

static int htramp_remote_nickchange(Client *client, MessageTag *mtags, const char *newnick)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "oldnick", PyUnicode_FromString(client && client->name ? client->name : ""));
	EVENT_SET(e, "newnick", PyUnicode_FromString(newnick ? newnick : ""));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	return dispatch_hook(HOOKTYPE_REMOTE_NICKCHANGE, e);
}

static int htramp_account_login(Client *client, MessageTag *mtags)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	EVENT_SET(e, "account",
	          PyUnicode_FromString((client && client->user && client->user->account) ? client->user->account : ""));
	return dispatch_hook(HOOKTYPE_ACCOUNT_LOGIN, e);
}

static int htramp_topic(Client *client, Channel *channel, MessageTag *mtags, const char *topic)
{
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "channel", py_channel_new(channel));
	EVENT_SET(e, "topic", PyUnicode_FromString(topic ? topic : ""));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	return dispatch_hook(HOOKTYPE_TOPIC, e);
}

static int htramp_server_connect(Client *client)
{
	EVENT_NEW(e);
	EVENT_SET(e, "server", py_server_new(client));
	return dispatch_hook(HOOKTYPE_SERVER_CONNECT, e);
}

static int htramp_server_synced(Client *client)
{
	EVENT_NEW(e);
	EVENT_SET(e, "server", py_server_new(client));
	return dispatch_hook(HOOKTYPE_SERVER_SYNCED, e);
}

static int htramp_server_quit(Client *client, MessageTag *mtags)
{
	EVENT_NEW(e);
	EVENT_SET(e, "server", py_server_new(client));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	return dispatch_hook(HOOKTYPE_SERVER_QUIT, e);
}

static int htramp_local_chanmode(Client *client, Channel *channel, MessageTag *mtags, const char *modebuf,
                                 const char *parabuf, time_t sendts, int samode, int *destroy_channel)
{
	(void)destroy_channel;
	EVENT_NEW(e);
	EVENT_SET(e, "client", py_client_new(client));
	EVENT_SET(e, "channel", py_channel_new(channel));
	EVENT_SET(e, "modes", PyUnicode_FromString(modebuf ? modebuf : ""));
	EVENT_SET(e, "params", PyUnicode_FromString(parabuf ? parabuf : ""));
	EVENT_SET(e, "samode", PyBool_FromLong(samode ? 1 : 0));
	EVENT_SET(e, "mtags", mtags_to_dict(mtags));
	return dispatch_hook(HOOKTYPE_LOCAL_CHANMODE, e);
}

/* Map hooktype -> trampoline. Called at register_hook() time. */
static int install_hook_trampoline(int hooktype)
{
	if (hook_added[hooktype % 2048])
		return 1;
	hook_added[hooktype % 2048] = 1;
	switch (hooktype)
	{
		case HOOKTYPE_LOCAL_CONNECT:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_local_connect);
			return 1;
		case HOOKTYPE_REMOTE_CONNECT:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_remote_connect);
			return 1;
		case HOOKTYPE_SECURE_CONNECT:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_secure_connect);
			return 1;
		case HOOKTYPE_WELCOME:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_welcome);
			return 1;
		case HOOKTYPE_CLOSE_CONNECTION:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_close_connection);
			return 1;
		case HOOKTYPE_LOCAL_QUIT:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_local_quit);
			return 1;
		case HOOKTYPE_REMOTE_QUIT:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_remote_quit);
			return 1;
		case HOOKTYPE_UNKUSER_QUIT:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_unkuser_quit);
			return 1;
		case HOOKTYPE_LOCAL_JOIN:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_local_join);
			return 1;
		case HOOKTYPE_REMOTE_JOIN:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_remote_join);
			return 1;
		case HOOKTYPE_LOCAL_PART:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_local_part);
			return 1;
		case HOOKTYPE_REMOTE_PART:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_remote_part);
			return 1;
		case HOOKTYPE_LOCAL_KICK:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_local_kick);
			return 1;
		case HOOKTYPE_REMOTE_KICK:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_remote_kick);
			return 1;
		case HOOKTYPE_CHANMSG:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_chanmsg);
			return 1;
		case HOOKTYPE_USERMSG:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_usermsg);
			return 1;
		case HOOKTYPE_LOCAL_NICKCHANGE:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_local_nickchange);
			return 1;
		case HOOKTYPE_REMOTE_NICKCHANGE:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_remote_nickchange);
			return 1;
		case HOOKTYPE_ACCOUNT_LOGIN:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_account_login);
			return 1;
		case HOOKTYPE_TOPIC:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_topic);
			return 1;
		case HOOKTYPE_SERVER_CONNECT:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_server_connect);
			return 1;
		case HOOKTYPE_SERVER_SYNCED:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_server_synced);
			return 1;
		case HOOKTYPE_SERVER_QUIT:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_server_quit);
			return 1;
		case HOOKTYPE_LOCAL_CHANMODE:
			HookAdd(modinfo_ref->handle, hooktype, 0, htramp_local_chanmode);
			return 1;
	}
	/* If we got here it's a hook we name-recognised but don't have a
	 * trampoline for. Reset the flag so a future registration that
	 * adds a trampoline doesn't deadlock. */
	hook_added[hooktype % 2048] = 0;
	return 0;
}

/* ===================================================================
 * Command dispatcher
 * =================================================================== */

CMD_FUNC(cmd_py_dispatch)
{
	const char *cmdname = (parc > 0 && parv[0]) ? parv[0] : NULL;
	if (!cmdname)
		return;

	PyCmd *pc = NULL;
	for (PyCmd *p = cmds_list; p; p = p->next)
	{
		if (!strcasecmp(p->name, cmdname))
		{
			pc = p;
			break;
		}
	}
	if (!pc)
		return;

	PyObject *cli = py_client_new(client);
	PyObject *params = parv_to_list(parv, parc, 1);
	PyObject *args = PyTuple_Pack(2, cli, params);
	Py_XDECREF(cli);
	Py_XDECREF(params);
	call_handler(pc->fn, args);
}

/* ===================================================================
 * Timer event
 * =================================================================== */

EVENT(obbypy_timer_event)
{
	PyTimer *t = (PyTimer *)data;
	if (!t)
		return;
	if (t->cancelled)
	{
		DelListItem(t, timers_list);
		Py_XDECREF(t->fn);
		safe_free(t);
		return;
	}
	if (t->fn)
	{
		PyObject *args = PyTuple_New(0);
		call_handler(t->fn, args);
	}
	if (!t->is_interval)
	{
		/* Single-shot: UnrealIRCd's event system auto-removes count=1
		 * events after fire, but we still own the bookkeeping. */
		DelListItem(t, timers_list);
		Py_XDECREF(t->fn);
		safe_free(t);
	}
}

/* ===================================================================
 * HTTP callback
 * =================================================================== */

static void obbypy_http_callback(OutgoingWebRequest *req, OutgoingWebResponse *res)
{
	PyHttp *h = (PyHttp *)res->ptr;
	if (!h)
		return;

	const char *err = NULL;
	const char *body = NULL;
	if (res->errorbuf)
		err = res->errorbuf;
	else if (res->memory)
		body = res->memory;
	else
		err = "empty response";

	PyObject *err_obj = err ? PyUnicode_FromString(err) : (Py_INCREF(Py_None), Py_None);
	PyObject *body_obj = body ? PyUnicode_FromString(body) : (Py_INCREF(Py_None), Py_None);
	PyObject *args = PyTuple_Pack(2, err_obj, body_obj);
	Py_DECREF(err_obj);
	Py_DECREF(body_obj);
	call_handler(h->fn, args);

	DelListItem(h, https_list);
	Py_XDECREF(h->fn);
	safe_free(h);
}

/* ===================================================================
 * ModData free/serialize/unserialize (string-typed payload)
 * =================================================================== */

static void pymd_free(ModData *md)
{
	if (md && md->ptr)
	{
		safe_free(md->ptr);
		md->ptr = NULL;
	}
}

static const char *pymd_serialize(ModData *md)
{
	if (!md || !md->ptr)
		return NULL;
	return (const char *)md->ptr;
}

static void pymd_unserialize(const char *str, ModData *md)
{
	if (!md)
		return;
	safe_free(md->ptr);
	md->ptr = str ? raw_strdup(str) : NULL;
}

/* ===================================================================
 * Custom channel/prefix/user mode trampolines.
 *
 * UnrealIRCd's mode infrastructure wants a specific function-pointer
 * shape for the "is the mode change allowed?" predicate.  We register
 * a single C wrapper per script-registered mode that delegates to
 * the stored Python `is_ok` callable.  Falls back to "allowed" if
 * the script didn't supply a predicate.
 * =================================================================== */

static int pycm_is_ok(Client *client, Channel *channel, char mode, const char *para, int checkt, int what)
{
	for (PyChanmode *p = chanmodes_list; p; p = p->next)
	{
		if (p->letter != mode)
			continue;
		if (!p->is_ok)
			return EX_ALLOW;
		PyObject *cli = py_client_new(client);
		PyObject *ch = py_channel_new(channel);
		PyObject *args = Py_BuildValue("(OOCsii)", cli, ch, mode,
		                               para ? para : "", checkt, what);
		Py_XDECREF(cli);
		Py_XDECREF(ch);
		int r = call_handler(p->is_ok, args);
		return r ? EX_DENY : EX_ALLOW;
	}
	return EX_ALLOW;
}

static int pypm_is_ok(Client *client, Channel *channel, char mode, const char *para, int checkt, int what)
{
	for (PyPrefixmode *p = prefixmodes_list; p; p = p->next)
	{
		if (p->letter != mode)
			continue;
		if (!p->is_ok)
			return EX_ALLOW;
		PyObject *cli = py_client_new(client);
		PyObject *ch = py_channel_new(channel);
		PyObject *args = Py_BuildValue("(OOCsii)", cli, ch, mode,
		                               para ? para : "", checkt, what);
		Py_XDECREF(cli);
		Py_XDECREF(ch);
		int r = call_handler(p->is_ok, args);
		return r ? EX_DENY : EX_ALLOW;
	}
	return EX_ALLOW;
}

static int pyum_allowed(Client *client, int what)
{
	for (PyUsermode *p = usermodes_list; p; p = p->next)
	{
		if (!p->allowed)
			return 1;
		PyObject *cli = py_client_new(client);
		PyObject *args = Py_BuildValue("(Oi)", cli, what);
		Py_XDECREF(cli);
		int r = call_handler(p->allowed, args);
		if (r == 0)
			return 1;  /* default: allow */
	}
	return 1;
}

/* ===================================================================
 * RPC method trampoline
 * =================================================================== */

static void pyrpc_handler(Client *client, json_t *request, json_t *params)
{
	const char *method = NULL;
	json_t *m = json_object_get(request, "method");
	if (m && json_is_string(m))
		method = json_string_value(m);
	if (!method)
		return;

	PyRpc *r = NULL;
	for (PyRpc *p = rpcs_list; p; p = p->next)
	{
		if (!strcmp(p->method, method))
		{
			r = p;
			break;
		}
	}
	if (!r)
		return;

	/* Marshal params -> Python dict via JSON round-trip (simplest). */
	PyObject *py_params = Py_None;
	Py_INCREF(Py_None);
	if (params)
	{
		char *jstr = json_dumps(params, JSON_COMPACT);
		if (jstr)
		{
			PyObject *jmod = PyImport_ImportModule("json");
			if (jmod)
			{
				PyObject *loads = PyObject_GetAttrString(jmod, "loads");
				if (loads)
				{
					PyObject *jstr_obj = PyUnicode_FromString(jstr);
					PyObject *args = PyTuple_Pack(1, jstr_obj);
					Py_DECREF(jstr_obj);
					PyObject *parsed = PyObject_Call(loads, args, NULL);
					Py_DECREF(args);
					Py_DECREF(loads);
					if (parsed)
					{
						Py_DECREF(py_params);
						py_params = parsed;
					}
				}
				Py_DECREF(jmod);
			}
			free(jstr);
		}
	}

	/* Stash request id + client pointer in a small context dict the
	 * handler reads via obby.rpc_response()/obby.rpc_error(). */
	PyObject *ctx = PyDict_New();
	if (ctx)
	{
		PyObject *rid = json_object_get(request, "id") ? (json_is_string(json_object_get(request, "id"))
		                                                      ? PyUnicode_FromString(json_string_value(json_object_get(request, "id")))
		                                                      : PyLong_FromLongLong((long long)json_integer_value(json_object_get(request, "id"))))
		                                               : (Py_INCREF(Py_None), Py_None);
		PyDict_SetItemString(ctx, "id", rid);
		Py_DECREF(rid);
		PyObject *cap = PyCapsule_New(client, "obby.rpc_client", NULL);
		PyDict_SetItemString(ctx, "_client_cap", cap);
		Py_DECREF(cap);
		PyObject *reqcap = PyCapsule_New(request, "obby.rpc_request", NULL);
		PyDict_SetItemString(ctx, "_request_cap", reqcap);
		Py_DECREF(reqcap);
	}

	PyObject *args = PyTuple_Pack(2, py_params, ctx ? ctx : Py_None);
	Py_DECREF(py_params);
	Py_XDECREF(ctx);
	call_handler(r->fn, args);
}

/* ===================================================================
 * Extban trampolines
 * =================================================================== */

static int pyextban_is_ok(BanContext *b)
{
	for (PyExtban *p = extbans_list; p; p = p->next)
	{
		if (p->letter != b->banstr[0])
			continue;
		if (!p->is_ok)
			return 1;
		PyObject *cli = py_client_new(b->client);
		PyObject *channel = b->channel ? py_channel_new(b->channel) : (Py_INCREF(Py_None), Py_None);
		PyObject *banstr = PyUnicode_FromString(b->banstr ? b->banstr : "");
		PyObject *args = PyTuple_Pack(3, cli, channel, banstr);
		Py_DECREF(cli);
		Py_DECREF(channel);
		Py_DECREF(banstr);
		int r = call_handler(p->is_ok, args);
		return r ? 1 : 0;
	}
	return 1;
}

static int pyextban_is_banned(BanContext *b)
{
	for (PyExtban *p = extbans_list; p; p = p->next)
	{
		if (p->letter != b->banstr[0])
			continue;
		if (!p->is_banned)
			return 0;
		PyObject *cli = py_client_new(b->client);
		PyObject *channel = b->channel ? py_channel_new(b->channel) : (Py_INCREF(Py_None), Py_None);
		PyObject *banstr = PyUnicode_FromString(b->banstr ? b->banstr : "");
		PyObject *args = PyTuple_Pack(3, cli, channel, banstr);
		Py_DECREF(cli);
		Py_DECREF(channel);
		Py_DECREF(banstr);
		int r = call_handler(p->is_banned, args);
		return r ? 1 : 0;
	}
	return 0;
}

/* ===================================================================
 * Custom config block trampolines
 * =================================================================== */

static int pycfg_test(ConfigFile *cf, ConfigEntry *ce, int type, int *errs)
{
	if (type != CONFIG_MAIN || !ce || !ce->name)
		return 0;
	for (PyCfgBlock *b = cfg_blocks_list; b; b = b->next)
	{
		if (strcmp(b->blockname, ce->name))
			continue;
		if (!b->test_fn)
		{
			*errs = 0;
			return 1;
		}
		/* Build a nested dict of (name -> value or sub-dict) from the
		 * config tree. Lossy (drops position info, multi-value blocks
		 * with the same key collapse) but works for the common case. */
		PyObject *root = PyDict_New();
		for (ConfigEntry *cep = ce->items; cep; cep = cep->next)
		{
			if (!cep->name)
				continue;
			PyObject *v = cep->value ? PyUnicode_FromString(cep->value) : (Py_INCREF(Py_None), Py_None);
			PyDict_SetItemString(root, cep->name, v);
			Py_DECREF(v);
		}
		PyObject *args = PyTuple_Pack(1, root);
		Py_DECREF(root);
		int r = call_handler(b->test_fn, args);
		*errs = r;
		return r ? -1 : 1;
	}
	return 0;
}

static int pycfg_run(ConfigFile *cf, ConfigEntry *ce, int type)
{
	if (type != CONFIG_MAIN || !ce || !ce->name)
		return 0;
	for (PyCfgBlock *b = cfg_blocks_list; b; b = b->next)
	{
		if (strcmp(b->blockname, ce->name))
			continue;
		if (!b->run_fn)
			return 1;
		PyObject *root = PyDict_New();
		for (ConfigEntry *cep = ce->items; cep; cep = cep->next)
		{
			if (!cep->name)
				continue;
			PyObject *v = cep->value ? PyUnicode_FromString(cep->value) : (Py_INCREF(Py_None), Py_None);
			PyDict_SetItemString(root, cep->name, v);
			Py_DECREF(v);
		}
		PyObject *args = PyTuple_Pack(1, root);
		Py_DECREF(root);
		call_handler(b->run_fn, args);
		return 1;
	}
	return 0;
}

/* ===================================================================
 * Built-in `obby` module functions
 * =================================================================== */

static PyObject *api_log(PyObject *self, PyObject *args, PyObject *kw)
{
	const char *msg = NULL;
	const char *level = "info";
	static char *kwlist[] = {"msg", "level", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kw, "s|s", kwlist, &msg, &level))
		return NULL;
	int lv = ULOG_INFO;
	if (!strcasecmp(level, "debug"))
		lv = ULOG_DEBUG;
	else if (!strcasecmp(level, "warn") || !strcasecmp(level, "warning"))
		lv = ULOG_WARNING;
	else if (!strcasecmp(level, "error"))
		lv = ULOG_ERROR;
	unreal_log(lv, "obbypy", "PY_LOG", NULL, "$msg", log_data_string("msg", msg));
	Py_RETURN_NONE;
}

static PyObject *api_send_notice(PyObject *self, PyObject *args)
{
	PyObject *t;
	const char *msg;
	if (!PyArg_ParseTuple(args, "Os", &t, &msg))
		return NULL;
	Client *c = unwrap_client(t);
	if (PyErr_Occurred())
		return NULL;
	if (!c)
	{
		PyErr_SetString(PyExc_LookupError, "target not found");
		return NULL;
	}
	sendnotice(c, "%s", msg);
	Py_RETURN_NONE;
}

static PyObject *api_send_msg(PyObject *self, PyObject *args)
{
	PyObject *t;
	const char *msg;
	if (!PyArg_ParseTuple(args, "Os", &t, &msg))
		return NULL;

	Client *c = NULL;
	Channel *ch = NULL;
	if (PyUnicode_Check(t))
	{
		const char *s = PyUnicode_AsUTF8(t);
		if (s && s[0] == '#')
			ch = find_channel(s);
		else if (s)
			c = find_user(s, NULL);
	} else if (PyObject_TypeCheck(t, &PyClient_Type))
	{
		c = ((PyClientObject *)t)->c;
	} else if (PyObject_TypeCheck(t, &PyChannel_Type))
	{
		ch = ((PyChannelObject *)t)->ch;
	}

	if (ch)
	{
		sendto_channel(ch, &me, NULL, 0, 0, SEND_LOCAL, NULL,
		               "PRIVMSG %s :%s", ch->name, msg);
		Py_RETURN_NONE;
	}
	if (c)
	{
		sendto_one(c, NULL, ":%s PRIVMSG %s :%s", me.name, c->name, msg);
		Py_RETURN_NONE;
	}
	PyErr_SetString(PyExc_LookupError, "target not found");
	return NULL;
}

static PyObject *api_send_raw(PyObject *self, PyObject *args)
{
	PyObject *t;
	const char *line;
	if (!PyArg_ParseTuple(args, "Os", &t, &line))
		return NULL;
	Client *c = unwrap_client(t);
	if (PyErr_Occurred())
		return NULL;
	if (!c)
	{
		PyErr_SetString(PyExc_LookupError, "target not found");
		return NULL;
	}
	sendto_one(c, NULL, "%s", line);
	Py_RETURN_NONE;
}

static PyObject *api_send_numeric(PyObject *self, PyObject *args)
{
	PyObject *t;
	int numeric;
	const char *msg;
	if (!PyArg_ParseTuple(args, "Ois", &t, &numeric, &msg))
		return NULL;
	Client *c = unwrap_client(t);
	if (PyErr_Occurred())
		return NULL;
	if (!c)
		Py_RETURN_NONE;
	sendto_one(c, NULL, ":%s %03d %s :%s", me.name, numeric,
	           c->name[0] ? c->name : "*", msg);
	Py_RETURN_NONE;
}

static PyObject *api_send_to_channel(PyObject *self, PyObject *args)
{
	PyObject *t;
	const char *line;
	if (!PyArg_ParseTuple(args, "Os", &t, &line))
		return NULL;
	Channel *ch = unwrap_channel(t);
	if (PyErr_Occurred())
		return NULL;
	if (!ch)
	{
		PyErr_SetString(PyExc_LookupError, "channel not found");
		return NULL;
	}
	sendto_channel(ch, &me, NULL, 0, 0, SEND_LOCAL, NULL, "%s", line);
	Py_RETURN_NONE;
}

static PyObject *api_send_to_server(PyObject *self, PyObject *args)
{
	PyObject *t;
	const char *line;
	if (!PyArg_ParseTuple(args, "Os", &t, &line))
		return NULL;
	Client *s = NULL;
	if (PyObject_TypeCheck(t, &PyServer_Type))
		s = ((PyServerObject *)t)->c;
	else if (PyUnicode_Check(t))
	{
		const char *n = PyUnicode_AsUTF8(t);
		s = n ? find_server(n, NULL) : NULL;
	}
	if (!s)
	{
		PyErr_SetString(PyExc_LookupError, "server not found");
		return NULL;
	}
	sendto_one(s, NULL, "%s", line);
	Py_RETURN_NONE;
}

static PyObject *api_send_to_all_servers(PyObject *self, PyObject *args)
{
	const char *line;
	if (!PyArg_ParseTuple(args, "s", &line))
		return NULL;
	sendto_server(NULL, 0, 0, NULL, "%s", line);
	Py_RETURN_NONE;
}

static PyObject *api_find_client(PyObject *self, PyObject *args)
{
	const char *name;
	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;
	return py_client_new(find_user(name, NULL));
}

static PyObject *api_find_channel(PyObject *self, PyObject *args)
{
	const char *name;
	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;
	return py_channel_new(find_channel(name));
}

static PyObject *api_find_server(PyObject *self, PyObject *args)
{
	const char *name;
	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;
	return py_server_new(find_server(name, NULL));
}

#define PRED_API(fn_name, expr) \
	static PyObject *fn_name(PyObject *self, PyObject *args) \
	{ \
		PyObject *o; \
		if (!PyArg_ParseTuple(args, "O", &o)) \
			return NULL; \
		Client *c = unwrap_client(o); \
		if (PyErr_Occurred()) \
			return NULL; \
		return PyBool_FromLong(c && (expr) ? 1 : 0); \
	}

PRED_API(api_is_user, IsUser(c))
PRED_API(api_is_server, IsServer(c))
PRED_API(api_is_oper, IsOper(c))
PRED_API(api_is_secure, IsSecure(c))
PRED_API(api_is_uline, IsULine(c))
PRED_API(api_is_logged_in, c->user &&IsLoggedIn(c))

static PyObject *api_has_mode(PyObject *self, PyObject *args)
{
	PyObject *t;
	int mode_char;
	if (!PyArg_ParseTuple(args, "OC", &t, &mode_char))
		return NULL;
	char m = (char)mode_char;
	if (PyObject_TypeCheck(t, &PyChannel_Type))
	{
		Channel *ch = ((PyChannelObject *)t)->ch;
		return PyBool_FromLong(ch && has_channel_mode(ch, m) ? 1 : 0);
	}
	if (PyUnicode_Check(t))
	{
		const char *s = PyUnicode_AsUTF8(t);
		if (s && s[0] == '#')
		{
			Channel *ch = find_channel(s);
			return PyBool_FromLong(ch && has_channel_mode(ch, m) ? 1 : 0);
		}
	}
	Client *c = unwrap_client(t);
	if (PyErr_Occurred())
		return NULL;
	if (!c || !c->user)
		return PyBool_FromLong(0);
	char buf[64];
	get_usermode_string_r(c, buf, sizeof(buf));
	return PyBool_FromLong(strchr(buf, m) ? 1 : 0);
}

static PyObject *api_check_channel_access(PyObject *self, PyObject *args)
{
	PyObject *cli_o, *chan_o;
	const char *flags;
	if (!PyArg_ParseTuple(args, "OOs", &cli_o, &chan_o, &flags))
		return NULL;
	Client *c = unwrap_client(cli_o);
	Channel *ch = unwrap_channel(chan_o);
	if (!c || !ch)
		return PyBool_FromLong(0);
	return PyBool_FromLong(check_channel_access(c, ch, flags) ? 1 : 0);
}

/* Iteration helpers */
static PyObject *api_all_clients(PyObject *self, PyObject *args)
{
	(void)args;
	PyObject *l = PyList_New(0);
	if (!l)
		return NULL;
	Client *c;
	list_for_each_entry(c, &client_list, client_node)
	{
		if (!IsUser(c))
			continue;
		PyObject *o = py_client_new(c);
		if (o)
		{
			PyList_Append(l, o);
			Py_DECREF(o);
		}
	}
	return l;
}

static PyObject *api_all_local_clients(PyObject *self, PyObject *args)
{
	(void)args;
	PyObject *l = PyList_New(0);
	if (!l)
		return NULL;
	Client *c;
	list_for_each_entry(c, &lclient_list, lclient_node)
	{
		if (!IsUser(c))
			continue;
		PyObject *o = py_client_new(c);
		if (o)
		{
			PyList_Append(l, o);
			Py_DECREF(o);
		}
	}
	return l;
}

static PyObject *api_all_servers(PyObject *self, PyObject *args)
{
	(void)args;
	PyObject *l = PyList_New(0);
	if (!l)
		return NULL;
	Client *c;
	list_for_each_entry(c, &global_server_list, client_node)
	{
		PyObject *o = py_server_new(c);
		if (o)
		{
			PyList_Append(l, o);
			Py_DECREF(o);
		}
	}
	return l;
}

static PyObject *api_all_opers(PyObject *self, PyObject *args)
{
	(void)args;
	PyObject *l = PyList_New(0);
	if (!l)
		return NULL;
	Client *c;
	list_for_each_entry(c, &oper_list, special_node)
	{
		PyObject *o = py_client_new(c);
		if (o)
		{
			PyList_Append(l, o);
			Py_DECREF(o);
		}
	}
	return l;
}

static PyObject *api_all_channels(PyObject *self, PyObject *args)
{
	(void)args;
	PyObject *l = PyList_New(0);
	if (!l)
		return NULL;
	for (Channel *ch = channels; ch; ch = ch->nextch)
	{
		PyObject *o = py_channel_new(ch);
		if (o)
		{
			PyList_Append(l, o);
			Py_DECREF(o);
		}
	}
	return l;
}

/* Actions */
static PyObject *api_do_cmd(PyObject *self, PyObject *args)
{
	PyObject *cli_o, *params_o;
	const char *cmd;
	if (!PyArg_ParseTuple(args, "OsO", &cli_o, &cmd, &params_o))
		return NULL;
	Client *c = unwrap_client(cli_o);
	if (PyErr_Occurred())
		return NULL;
	if (!c)
		Py_RETURN_NONE;
	if (!PyList_Check(params_o) && !PyTuple_Check(params_o))
	{
		PyErr_SetString(PyExc_TypeError, "params must be list or tuple");
		return NULL;
	}
	Py_ssize_t n = PyObject_Length(params_o);
	const char **parv = safe_alloc(sizeof(char *) * (n + 2));
	parv[0] = cmd;
	int i;
	for (i = 0; i < n; i++)
	{
		PyObject *item = PySequence_GetItem(params_o, i);
		parv[i + 1] = item ? PyUnicode_AsUTF8(item) : "";
		Py_XDECREF(item);
	}
	parv[i + 1] = NULL;
	do_cmd(c, NULL, cmd, (int)n + 1, parv);
	safe_free(parv);
	Py_RETURN_NONE;
}

static PyObject *api_exit_client(PyObject *self, PyObject *args)
{
	PyObject *cli_o;
	const char *reason = "Disconnected by script";
	if (!PyArg_ParseTuple(args, "O|s", &cli_o, &reason))
		return NULL;
	Client *c = unwrap_client(cli_o);
	if (PyErr_Occurred())
		return NULL;
	if (!c)
		Py_RETURN_NONE;
	exit_client(c, NULL, reason);
	Py_RETURN_NONE;
}

static PyObject *api_kick(PyObject *self, PyObject *args)
{
	PyObject *victim_o, *chan_o;
	const char *reason = "kicked";
	if (!PyArg_ParseTuple(args, "OO|s", &victim_o, &chan_o, &reason))
		return NULL;
	Client *v = unwrap_client(victim_o);
	Channel *ch = unwrap_channel(chan_o);
	if (PyErr_Occurred())
		return NULL;
	if (!v || !ch)
		Py_RETURN_NONE;
	const char *parv[5];
	parv[0] = "KICK";
	parv[1] = ch->name;
	parv[2] = v->name;
	parv[3] = reason;
	parv[4] = NULL;
	do_cmd(&me, NULL, "KICK", 4, parv);
	Py_RETURN_NONE;
}

static PyObject *api_set_topic(PyObject *self, PyObject *args)
{
	PyObject *chan_o;
	const char *topic;
	const char *set_by = NULL;
	if (!PyArg_ParseTuple(args, "Os|s", &chan_o, &topic, &set_by))
		return NULL;
	Channel *ch = unwrap_channel(chan_o);
	if (PyErr_Occurred())
		return NULL;
	if (!ch)
		Py_RETURN_NONE;
	set_channel_topic(&me, ch, NULL, topic, set_by ? set_by : me.name, TStime());
	Py_RETURN_NONE;
}

static PyObject *api_set_channel_mode(PyObject *self, PyObject *args)
{
	PyObject *chan_o;
	const char *modes;
	const char *params = "";
	if (!PyArg_ParseTuple(args, "Os|s", &chan_o, &modes, &params))
		return NULL;
	Channel *ch = unwrap_channel(chan_o);
	if (PyErr_Occurred())
		return NULL;
	if (!ch)
		Py_RETURN_NONE;
	set_channel_mode(ch, NULL, modes, params);
	Py_RETURN_NONE;
}

static PyObject *api_set_user_mode(PyObject *self, PyObject *args)
{
	PyObject *cli_o;
	const char *modes;
	if (!PyArg_ParseTuple(args, "Os", &cli_o, &modes))
		return NULL;
	Client *c = unwrap_client(cli_o);
	if (PyErr_Occurred())
		return NULL;
	if (!c)
		Py_RETURN_NONE;
	const char *parv[4];
	parv[0] = "MODE";
	parv[1] = c->name;
	parv[2] = modes;
	parv[3] = NULL;
	do_cmd(&me, NULL, "MODE", 3, parv);
	Py_RETURN_NONE;
}

static PyObject *api_change_nick(PyObject *self, PyObject *args)
{
	PyObject *cli_o;
	const char *newnick;
	if (!PyArg_ParseTuple(args, "Os", &cli_o, &newnick))
		return NULL;
	Client *c = unwrap_client(cli_o);
	if (PyErr_Occurred())
		return NULL;
	if (!c)
		Py_RETURN_NONE;
	const char *parv[3];
	parv[0] = "NICK";
	parv[1] = newnick;
	parv[2] = NULL;
	do_cmd(c, NULL, "NICK", 2, parv);
	Py_RETURN_NONE;
}

static PyObject *api_set_host(PyObject *self, PyObject *args)
{
	PyObject *cli_o;
	const char *host;
	if (!PyArg_ParseTuple(args, "Os", &cli_o, &host))
		return NULL;
	Client *c = unwrap_client(cli_o);
	if (PyErr_Occurred())
		return NULL;
	if (!c || !c->user)
		Py_RETURN_NONE;
	safe_strdup(c->user->virthost, host);
	const char *parv[4] = {"CHGHOST", c->name, host, NULL};
	do_cmd(&me, NULL, "CHGHOST", 3, parv);
	Py_RETURN_NONE;
}

static PyObject *api_join_channel(PyObject *self, PyObject *args)
{
	PyObject *cli_o;
	const char *chname;
	if (!PyArg_ParseTuple(args, "Os", &cli_o, &chname))
		return NULL;
	Client *c = unwrap_client(cli_o);
	if (PyErr_Occurred())
		return NULL;
	if (!c)
		Py_RETURN_NONE;
	Channel *ch = find_channel(chname);
	if (!ch)
		ch = make_channel(chname);
	if (ch)
		join_channel(ch, c, NULL, NULL);
	Py_RETURN_NONE;
}

static PyObject *api_part_channel(PyObject *self, PyObject *args)
{
	PyObject *cli_o;
	const char *chname;
	const char *reason = "Leaving";
	if (!PyArg_ParseTuple(args, "Os|s", &cli_o, &chname, &reason))
		return NULL;
	Client *c = unwrap_client(cli_o);
	if (PyErr_Occurred())
		return NULL;
	if (!c)
		Py_RETURN_NONE;
	const char *parv[4] = {"PART", chname, reason, NULL};
	do_cmd(c, NULL, "PART", 3, parv);
	Py_RETURN_NONE;
}

/* TKL (server bans) */
static PyObject *api_add_serverban(PyObject *self, PyObject *args)
{
	const char *user;
	const char *host;
	const char *reason;
	int duration = 0;
	const char *setby = NULL;
	if (!PyArg_ParseTuple(args, "sss|is", &user, &host, &reason, &duration, &setby))
		return NULL;
	time_t expires = duration > 0 ? TStime() + duration : 0;
	tkl_add_serverban(TKL_KILL | TKL_GLOBAL, user, host, NULL, reason,
	                  setby ? setby : me.name, expires, TStime(), 0, 0);
	Py_RETURN_NONE;
}

static PyObject *api_del_serverban(PyObject *self, PyObject *args)
{
	const char *user;
	const char *host;
	if (!PyArg_ParseTuple(args, "ss", &user, &host))
		return NULL;
	TKL *tkl = find_tkl_serverban(TKL_KILL | TKL_GLOBAL, user, host, 0);
	if (tkl)
	{
		tkl_del_line(tkl);
		Py_RETURN_TRUE;
	}
	Py_RETURN_FALSE;
}

/* Hooks + commands */
static PyObject *api_register_hook(PyObject *self, PyObject *args)
{
	const char *name;
	PyObject *fn;
	if (!PyArg_ParseTuple(args, "sO", &name, &fn))
		return NULL;
	if (!PyCallable_Check(fn))
	{
		PyErr_SetString(PyExc_TypeError, "handler must be callable");
		return NULL;
	}
	int hooktype = hook_name_to_type(name);
	if (hooktype < 0)
	{
		PyErr_Format(PyExc_ValueError, "unknown hook name: %s", name);
		return NULL;
	}
	if (!install_hook_trampoline(hooktype))
	{
		PyErr_Format(PyExc_NotImplementedError,
		             "hook %s has no trampoline yet -- file an issue", name);
		return NULL;
	}
	PyHook *h = safe_alloc(sizeof(*h));
	Py_INCREF(fn);
	h->fn = fn;
	h->hooktype = hooktype;
	AddListItem(h, hooks_list);
	Py_RETURN_NONE;
}

static PyObject *api_register_command(PyObject *self, PyObject *args, PyObject *kw)
{
	const char *name;
	PyObject *fn;
	int params = 1;
	static char *kwlist[] = {"name", "fn", "params", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kw, "sO|i", kwlist, &name, &fn, &params))
		return NULL;
	if (!PyCallable_Check(fn))
	{
		PyErr_SetString(PyExc_TypeError, "handler must be callable");
		return NULL;
	}
	for (PyCmd *p = cmds_list; p; p = p->next)
	{
		if (!strcasecmp(p->name, name))
		{
			PyErr_Format(PyExc_ValueError, "command %s already registered", name);
			return NULL;
		}
	}
	PyCmd *c = safe_alloc(sizeof(*c));
	c->name = strdup(name);
	c->params = params;
	Py_INCREF(fn);
	c->fn = fn;
	c->cmd = CommandAdd(modinfo_ref->handle, name, cmd_py_dispatch,
	                    (unsigned char)params, CMD_USER);
	if (!c->cmd)
	{
		Py_DECREF(c->fn);
		safe_free(c->name);
		safe_free(c);
		PyErr_Format(PyExc_RuntimeError, "CommandAdd failed for %s", name);
		return NULL;
	}
	AddListItem(c, cmds_list);
	Py_RETURN_NONE;
}

/* Timers */
static PyObject *api_set_timeout(PyObject *self, PyObject *args)
{
	PyObject *fn;
	int ms;
	if (!PyArg_ParseTuple(args, "Oi", &fn, &ms))
		return NULL;
	if (!PyCallable_Check(fn))
	{
		PyErr_SetString(PyExc_TypeError, "fn must be callable");
		return NULL;
	}
	if (ms < 10)
		ms = 10;
	PyTimer *t = safe_alloc(sizeof(*t));
	t->id = next_timer_id++;
	t->is_interval = 0;
	Py_INCREF(fn);
	t->fn = fn;
	char ename[64];
	snprintf(ename, sizeof(ename), "obbypy_t%d", t->id);
	t->event = EventAdd(modinfo_ref->handle, ename, obbypy_timer_event, t, ms, 1);
	AddListItem(t, timers_list);
	return PyLong_FromLong(t->id);
}

static PyObject *api_set_interval(PyObject *self, PyObject *args)
{
	PyObject *fn;
	int ms;
	if (!PyArg_ParseTuple(args, "Oi", &fn, &ms))
		return NULL;
	if (!PyCallable_Check(fn))
	{
		PyErr_SetString(PyExc_TypeError, "fn must be callable");
		return NULL;
	}
	if (ms < 10)
		ms = 10;
	PyTimer *t = safe_alloc(sizeof(*t));
	t->id = next_timer_id++;
	t->is_interval = 1;
	Py_INCREF(fn);
	t->fn = fn;
	char ename[64];
	snprintf(ename, sizeof(ename), "obbypy_i%d", t->id);
	t->event = EventAdd(modinfo_ref->handle, ename, obbypy_timer_event, t, ms, 0);
	AddListItem(t, timers_list);
	return PyLong_FromLong(t->id);
}

static PyObject *api_clear_timer(PyObject *self, PyObject *args)
{
	int id;
	if (!PyArg_ParseTuple(args, "i", &id))
		return NULL;
	for (PyTimer *t = timers_list; t; t = t->next)
	{
		if (t->id == id)
		{
			t->cancelled = 1;
			if (t->event)
			{
				EventDel(t->event);
				t->event = NULL;
			}
			Py_RETURN_TRUE;
		}
	}
	Py_RETURN_FALSE;
}

/* HTTP */
static PyObject *api_http_get(PyObject *self, PyObject *args, PyObject *kw)
{
	const char *url;
	PyObject *fn;
	int max_redirects = 3;
	int connect_timeout = 10;
	int transfer_timeout = 30;
	static char *kwlist[] = {"url", "callback", "max_redirects", "connect_timeout", "transfer_timeout", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kw, "sO|iii", kwlist,
	                                 &url, &fn, &max_redirects,
	                                 &connect_timeout, &transfer_timeout))
		return NULL;
	if (!PyCallable_Check(fn))
	{
		PyErr_SetString(PyExc_TypeError, "callback must be callable");
		return NULL;
	}
	if (strncmp(url, "http://", 7) && strncmp(url, "https://", 8))
	{
		PyErr_SetString(PyExc_ValueError, "URL must start with http:// or https://");
		return NULL;
	}
	PyHttp *h = safe_alloc(sizeof(*h));
	Py_INCREF(fn);
	h->fn = fn;
	AddListItem(h, https_list);

	OutgoingWebRequest *req = safe_alloc(sizeof(*req));
	safe_strdup(req->url, url);
	req->http_method = HTTP_METHOD_GET;
	safe_strdup(req->apicallback, HTTP_API_CALLBACK_NAME);
	req->callback_data = h;
	req->max_redirects = max_redirects;
	req->connect_timeout = connect_timeout;
	req->transfer_timeout = transfer_timeout;
	url_start_async(req);
	Py_RETURN_NONE;
}

/* ModData */
static PyObject *api_register_moddata(PyObject *self, PyObject *args, PyObject *kw)
{
	const char *name;
	int type;
	int sync = 0;
	static char *kwlist[] = {"name", "type", "sync", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kw, "si|i", kwlist, &name, &type, &sync))
		return NULL;
	if (type < MODDATATYPE_LOCAL_VARIABLE || type > MODDATATYPE_MEMBERSHIP)
	{
		PyErr_Format(PyExc_ValueError, "invalid moddata type %d", type);
		return NULL;
	}
	for (PyModData *p = moddatas_list; p; p = p->next)
	{
		if (!strcmp(p->name, name))
		{
			PyErr_Format(PyExc_ValueError, "moddata %s already registered", name);
			return NULL;
		}
	}
	PyModData *m = safe_alloc(sizeof(*m));
	m->name = strdup(name);
	m->type = type;
	m->sync = sync ? 1 : 0;
	ModDataInfo req;
	memset(&req, 0, sizeof(req));
	req.name = m->name;
	req.type = type;
	req.free = pymd_free;
	req.serialize = pymd_serialize;
	req.unserialize = pymd_unserialize;
	req.sync = sync ? MODDATA_SYNC_EARLY : 0;
	m->md = ModDataAdd(modinfo_ref->handle, req);
	if (!m->md)
	{
		safe_free(m->name);
		safe_free(m);
		PyErr_Format(PyExc_RuntimeError, "ModDataAdd failed for %s", name);
		return NULL;
	}
	AddListItem(m, moddatas_list);
	Py_RETURN_NONE;
}

static PyModData *find_moddata(const char *name)
{
	for (PyModData *p = moddatas_list; p; p = p->next)
		if (!strcmp(p->name, name))
			return p;
	return NULL;
}

static PyObject *api_set_moddata(PyObject *self, PyObject *args)
{
	PyObject *target;
	const char *name;
	PyObject *value;
	if (!PyArg_ParseTuple(args, "OsO", &target, &name, &value))
		return NULL;
	PyModData *m = find_moddata(name);
	if (!m)
	{
		PyErr_Format(PyExc_LookupError,
		             "moddata %s not registered (call register_moddata first)", name);
		return NULL;
	}
	const char *vs = (value == Py_None) ? NULL : py_str_or(value, NULL);
	if (m->type == MODDATATYPE_CLIENT || m->type == MODDATATYPE_LOCAL_CLIENT)
	{
		Client *c = unwrap_client(target);
		if (PyErr_Occurred() || !c)
			return NULL;
		moddata_client_set(c, name, vs);
	} else if (m->type == MODDATATYPE_CHANNEL)
	{
		Channel *ch = unwrap_channel(target);
		if (PyErr_Occurred() || !ch)
			return NULL;
		ModData *md = &moddata_channel(ch, m->md);
		safe_free(md->ptr);
		md->ptr = vs ? raw_strdup(vs) : NULL;
	} else
	{
		PyErr_SetString(PyExc_NotImplementedError,
		                "moddata type not supported for set yet");
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *api_get_moddata(PyObject *self, PyObject *args)
{
	PyObject *target;
	const char *name;
	if (!PyArg_ParseTuple(args, "Os", &target, &name))
		return NULL;
	PyModData *m = find_moddata(name);
	if (!m)
		Py_RETURN_NONE;
	if (m->type == MODDATATYPE_CLIENT || m->type == MODDATATYPE_LOCAL_CLIENT)
	{
		Client *c = unwrap_client(target);
		if (PyErr_Occurred() || !c)
			Py_RETURN_NONE;
		const char *v = moddata_client_get(c, name);
		return v ? PyUnicode_FromString(v) : (Py_INCREF(Py_None), Py_None);
	}
	if (m->type == MODDATATYPE_CHANNEL)
	{
		Channel *ch = unwrap_channel(target);
		if (PyErr_Occurred() || !ch)
			Py_RETURN_NONE;
		ModData *md = &moddata_channel(ch, m->md);
		return md->ptr ? PyUnicode_FromString((const char *)md->ptr) : (Py_INCREF(Py_None), Py_None);
	}
	Py_RETURN_NONE;
}

/* Channel mode registration */
static PyObject *api_register_channel_mode(PyObject *self, PyObject *args, PyObject *kw)
{
	int letter_char;
	PyObject *is_ok = Py_None;
	int paracount = 0;
	const char *modename = "";
	static char *kwlist[] = {"letter", "name", "paracount", "is_ok", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kw, "Cs|iO", kwlist,
	                                 &letter_char, &modename, &paracount, &is_ok))
		return NULL;
	char letter = (char)letter_char;
	for (PyChanmode *p = chanmodes_list; p; p = p->next)
	{
		if (p->letter == letter)
		{
			PyErr_Format(PyExc_ValueError,
			             "channel mode +%c already registered by this module", letter);
			return NULL;
		}
	}
	PyChanmode *m = safe_alloc(sizeof(*m));
	m->letter = letter;
	m->name = strdup(modename);
	m->paracount = paracount;
	if (PyCallable_Check(is_ok))
	{
		Py_INCREF(is_ok);
		m->is_ok = is_ok;
	}
	CmodeInfo req;
	memset(&req, 0, sizeof(req));
	req.letter = letter;
	req.name = m->name;
	req.is_ok = pycm_is_ok;
	req.paracount = paracount;
	m->cmode = CmodeAdd(modinfo_ref->handle, req, &m->mode_bit);
	if (!m->cmode)
	{
		Py_XDECREF(m->is_ok);
		safe_free(m->name);
		safe_free(m);
		PyErr_Format(PyExc_RuntimeError, "CmodeAdd failed for +%c", letter);
		return NULL;
	}
	AddListItem(m, chanmodes_list);
	Py_RETURN_NONE;
}

/* Prefix mode registration (uses CmodeAdd with prefix info). */
static PyObject *api_register_prefix_mode(PyObject *self, PyObject *args, PyObject *kw)
{
	int letter_char;
	int prefix_char;
	int rank = 0;
	const char *modename = "";
	PyObject *is_ok = Py_None;
	static char *kwlist[] = {"letter", "prefix", "name", "rank", "is_ok", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kw, "CCs|iO", kwlist,
	                                 &letter_char, &prefix_char, &modename, &rank, &is_ok))
		return NULL;
	char letter = (char)letter_char;
	char prefix = (char)prefix_char;
	for (PyPrefixmode *p = prefixmodes_list; p; p = p->next)
	{
		if (p->letter == letter)
		{
			PyErr_Format(PyExc_ValueError,
			             "prefix mode +%c already registered by this module", letter);
			return NULL;
		}
	}
	PyPrefixmode *m = safe_alloc(sizeof(*m));
	m->letter = letter;
	m->prefix = prefix;
	m->rank = rank;
	m->name = strdup(modename);
	if (PyCallable_Check(is_ok))
	{
		Py_INCREF(is_ok);
		m->is_ok = is_ok;
	}
	CmodeInfo req;
	memset(&req, 0, sizeof(req));
	req.letter = letter;
	req.name = m->name;
	req.is_ok = pypm_is_ok;
	req.prefix = prefix;
	req.rank = rank;
	req.type = CMODE_MEMBER;
	req.paracount = 1;
	Cmode_t bit = 0;
	m->cmode = CmodeAdd(modinfo_ref->handle, req, &bit);
	if (!m->cmode)
	{
		Py_XDECREF(m->is_ok);
		safe_free(m->name);
		safe_free(m);
		PyErr_Format(PyExc_RuntimeError, "prefix CmodeAdd failed for +%c", letter);
		return NULL;
	}
	AddListItem(m, prefixmodes_list);
	Py_RETURN_NONE;
}

/* User mode registration */
static PyObject *api_register_user_mode(PyObject *self, PyObject *args, PyObject *kw)
{
	int letter_char;
	const char *modename = "";
	int global = 1;
	int unset_on_deoper = 0;
	PyObject *allowed = Py_None;
	static char *kwlist[] = {"letter", "name", "global", "unset_on_deoper", "allowed", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kw, "Cs|iiO", kwlist,
	                                 &letter_char, &modename, &global,
	                                 &unset_on_deoper, &allowed))
		return NULL;
	char letter = (char)letter_char;
	for (PyUsermode *p = usermodes_list; p; p = p->next)
	{
		if (p->letter == letter)
		{
			PyErr_Format(PyExc_ValueError,
			             "user mode +%c already registered by this module", letter);
			return NULL;
		}
	}
	PyUsermode *m = safe_alloc(sizeof(*m));
	m->letter = letter;
	m->name = strdup(modename);
	m->global = global;
	m->unset_on_deoper = unset_on_deoper;
	if (PyCallable_Check(allowed))
	{
		Py_INCREF(allowed);
		m->allowed = allowed;
	}
	m->umode = UmodeAdd(modinfo_ref->handle, m->name, letter,
	                    global ? UMODE_GLOBAL : UMODE_LOCAL,
	                    unset_on_deoper, pyum_allowed, &m->mode_bit);
	if (!m->umode)
	{
		Py_XDECREF(m->allowed);
		safe_free(m->name);
		safe_free(m);
		PyErr_Format(PyExc_RuntimeError, "UmodeAdd failed for +%c", letter);
		return NULL;
	}
	AddListItem(m, usermodes_list);
	Py_RETURN_NONE;
}

/* RPC */
static PyObject *api_register_rpc_method(PyObject *self, PyObject *args)
{
	const char *method;
	PyObject *fn;
	if (!PyArg_ParseTuple(args, "sO", &method, &fn))
		return NULL;
	if (!PyCallable_Check(fn))
	{
		PyErr_SetString(PyExc_TypeError, "fn must be callable");
		return NULL;
	}
	for (PyRpc *p = rpcs_list; p; p = p->next)
	{
		if (!strcmp(p->method, method))
		{
			PyErr_Format(PyExc_ValueError, "RPC method %s already registered", method);
			return NULL;
		}
	}
	PyRpc *r = safe_alloc(sizeof(*r));
	r->method = strdup(method);
	Py_INCREF(fn);
	r->fn = fn;
	RPCHandlerInfo req;
	memset(&req, 0, sizeof(req));
	req.method = r->method;
	req.loglevel = ULOG_DEBUG;
	req.call = pyrpc_handler;
	if (!RPCHandlerAdd(modinfo_ref->handle, &req))
	{
		Py_DECREF(fn);
		safe_free(r->method);
		safe_free(r);
		PyErr_Format(PyExc_RuntimeError, "RPCHandlerAdd failed for %s", method);
		return NULL;
	}
	AddListItem(r, rpcs_list);
	Py_RETURN_NONE;
}

static PyObject *api_rpc_response(PyObject *self, PyObject *args)
{
	PyObject *ctx, *result;
	if (!PyArg_ParseTuple(args, "OO", &ctx, &result))
		return NULL;
	if (!PyDict_Check(ctx))
	{
		PyErr_SetString(PyExc_TypeError, "ctx must be dict");
		return NULL;
	}
	PyObject *clicap = PyDict_GetItemString(ctx, "_client_cap");
	PyObject *reqcap = PyDict_GetItemString(ctx, "_request_cap");
	if (!clicap || !reqcap)
		Py_RETURN_NONE;
	Client *cli = (Client *)PyCapsule_GetPointer(clicap, "obby.rpc_client");
	json_t *req = (json_t *)PyCapsule_GetPointer(reqcap, "obby.rpc_request");
	if (!cli || !req)
		Py_RETURN_NONE;

	/* JSON encode the Python result. */
	PyObject *jmod = PyImport_ImportModule("json");
	if (!jmod)
		Py_RETURN_NONE;
	PyObject *dumps = PyObject_GetAttrString(jmod, "dumps");
	Py_DECREF(jmod);
	if (!dumps)
		Py_RETURN_NONE;
	PyObject *jstr_obj = PyObject_CallOneArg(dumps, result);
	Py_DECREF(dumps);
	if (!jstr_obj)
	{
		PyErr_Clear();
		Py_RETURN_NONE;
	}
	const char *jstr = PyUnicode_AsUTF8(jstr_obj);
	json_error_t err;
	json_t *result_json = jstr ? json_loads(jstr, 0, &err) : NULL;
	Py_DECREF(jstr_obj);
	if (!result_json)
		Py_RETURN_NONE;
	rpc_response(cli, req, result_json);
	json_decref(result_json);
	Py_RETURN_NONE;
}

static PyObject *api_rpc_error(PyObject *self, PyObject *args)
{
	PyObject *ctx;
	int code;
	const char *message;
	if (!PyArg_ParseTuple(args, "Ois", &ctx, &code, &message))
		return NULL;
	if (!PyDict_Check(ctx))
	{
		PyErr_SetString(PyExc_TypeError, "ctx must be dict");
		return NULL;
	}
	PyObject *clicap = PyDict_GetItemString(ctx, "_client_cap");
	PyObject *reqcap = PyDict_GetItemString(ctx, "_request_cap");
	if (!clicap || !reqcap)
		Py_RETURN_NONE;
	Client *cli = (Client *)PyCapsule_GetPointer(clicap, "obby.rpc_client");
	json_t *req = (json_t *)PyCapsule_GetPointer(reqcap, "obby.rpc_request");
	if (!cli || !req)
		Py_RETURN_NONE;
	rpc_error(cli, req, code, message);
	Py_RETURN_NONE;
}

/* Extban */
static PyObject *api_register_extban(PyObject *self, PyObject *args, PyObject *kw)
{
	int letter_char;
	const char *name;
	PyObject *is_ok = Py_None;
	PyObject *is_banned = Py_None;
	static char *kwlist[] = {"letter", "name", "is_ok", "is_banned", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kw, "Cs|OO", kwlist,
	                                 &letter_char, &name, &is_ok, &is_banned))
		return NULL;
	char letter = (char)letter_char;
	for (PyExtban *p = extbans_list; p; p = p->next)
	{
		if (p->letter == letter)
		{
			PyErr_Format(PyExc_ValueError,
			             "extban %c already registered by this module", letter);
			return NULL;
		}
	}
	PyExtban *e = safe_alloc(sizeof(*e));
	e->letter = letter;
	e->name = strdup(name);
	if (PyCallable_Check(is_ok))
	{
		Py_INCREF(is_ok);
		e->is_ok = is_ok;
	}
	if (PyCallable_Check(is_banned))
	{
		Py_INCREF(is_banned);
		e->is_banned = is_banned;
	}
	ExtbanInfo req;
	memset(&req, 0, sizeof(req));
	req.letter = letter;
	req.name = e->name;
	req.is_ok = pyextban_is_ok;
	req.is_banned = pyextban_is_banned;
	if (!ExtbanAdd(modinfo_ref->handle, req))
	{
		Py_XDECREF(e->is_ok);
		Py_XDECREF(e->is_banned);
		safe_free(e->name);
		safe_free(e);
		PyErr_Format(PyExc_RuntimeError, "ExtbanAdd failed for %c", letter);
		return NULL;
	}
	AddListItem(e, extbans_list);
	Py_RETURN_NONE;
}

/* Config blocks */
static PyObject *api_register_config_block(PyObject *self, PyObject *args, PyObject *kw)
{
	const char *blockname;
	PyObject *test_fn = Py_None;
	PyObject *run_fn = Py_None;
	static char *kwlist[] = {"name", "test", "run", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kw, "s|OO", kwlist,
	                                 &blockname, &test_fn, &run_fn))
		return NULL;
	for (PyCfgBlock *p = cfg_blocks_list; p; p = p->next)
	{
		if (!strcmp(p->blockname, blockname))
		{
			PyErr_Format(PyExc_ValueError,
			             "config block %s already registered", blockname);
			return NULL;
		}
	}
	PyCfgBlock *b = safe_alloc(sizeof(*b));
	b->blockname = strdup(blockname);
	if (PyCallable_Check(test_fn))
	{
		Py_INCREF(test_fn);
		b->test_fn = test_fn;
	}
	if (PyCallable_Check(run_fn))
	{
		Py_INCREF(run_fn);
		b->run_fn = run_fn;
	}
	AddListItem(b, cfg_blocks_list);
	Py_RETURN_NONE;
}

/* Message tag handler registration -- minimal: hooks the tag name into
 * UnrealIRCd's MTH framework with our trampoline.  Both predicates
 * (is_ok, can_send) optional; default is "allowed". */
static int pymtag_is_ok(Client *client, const char *name, const char *value)
{
	for (PyMtagHandler *m = mtag_handlers_list; m; m = m->next)
	{
		if (strcmp(m->name, name))
			continue;
		if (!m->is_ok)
			return 1;
		PyObject *cli = py_client_new(client);
		PyObject *args = Py_BuildValue("(Oss)", cli, name, value ? value : "");
		Py_DECREF(cli);
		int r = call_handler(m->is_ok, args);
		return r == 0 ? 1 : 0;
	}
	return 1;
}

static int pymtag_can_send(Client *target)
{
	(void)target;
	return 1;
}

static PyObject *api_register_message_tag(PyObject *self, PyObject *args, PyObject *kw)
{
	const char *name;
	PyObject *is_ok = Py_None;
	PyObject *can_send = Py_None;
	static char *kwlist[] = {"name", "is_ok", "can_send", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kw, "s|OO", kwlist,
	                                 &name, &is_ok, &can_send))
		return NULL;
	for (PyMtagHandler *p = mtag_handlers_list; p; p = p->next)
	{
		if (!strcmp(p->name, name))
		{
			PyErr_Format(PyExc_ValueError,
			             "message tag %s already registered", name);
			return NULL;
		}
	}
	PyMtagHandler *m = safe_alloc(sizeof(*m));
	m->name = strdup(name);
	if (PyCallable_Check(is_ok))
	{
		Py_INCREF(is_ok);
		m->is_ok = is_ok;
	}
	if (PyCallable_Check(can_send))
	{
		Py_INCREF(can_send);
		m->can_send = can_send;
	}
	MessageTagHandlerInfo mreq;
	memset(&mreq, 0, sizeof(mreq));
	mreq.name = m->name;
	mreq.is_ok = pymtag_is_ok;
	mreq.should_send_to_client = pymtag_can_send;
	m->handle = MessageTagHandlerAdd(modinfo_ref->handle, &mreq);
	if (!m->handle)
	{
		Py_XDECREF(m->is_ok);
		Py_XDECREF(m->can_send);
		safe_free(m->name);
		safe_free(m);
		PyErr_Format(PyExc_RuntimeError, "MessageTagHandlerAdd failed for %s", name);
		return NULL;
	}
	AddListItem(m, mtag_handlers_list);
	Py_RETURN_NONE;
}

/* ===================================================================
 * Method table
 * =================================================================== */

static PyMethodDef obby_methods[] = {
    {"log", (PyCFunction)api_log, METH_VARARGS | METH_KEYWORDS,
     "log(msg, level='info'). level: debug|info|warn|error."},
    {"send_notice", api_send_notice, METH_VARARGS,
     "send_notice(target, msg) -- NOTICE to a Client/nick."},
    {"send_msg", api_send_msg, METH_VARARGS,
     "send_msg(target, msg) -- PRIVMSG to a Client/Channel/nick/'#chan'."},
    {"send_raw", api_send_raw, METH_VARARGS,
     "send_raw(target, line) -- raw line, already formatted."},
    {"send_numeric", api_send_numeric, METH_VARARGS,
     "send_numeric(target, n, msg) -- :server n target :msg"},
    {"send_to_channel", api_send_to_channel, METH_VARARGS,
     "send_to_channel(channel, raw_line)"},
    {"send_to_server", api_send_to_server, METH_VARARGS,
     "send_to_server(server, raw_line)"},
    {"send_to_all_servers", api_send_to_all_servers, METH_VARARGS,
     "send_to_all_servers(raw_line)"},
    {"find_client", api_find_client, METH_VARARGS, "find_client(nick)"},
    {"find_channel", api_find_channel, METH_VARARGS, "find_channel(name)"},
    {"find_server", api_find_server, METH_VARARGS, "find_server(name)"},
    {"is_oper", api_is_oper, METH_VARARGS, "is_oper(client)"},
    {"is_user", api_is_user, METH_VARARGS, "is_user(client)"},
    {"is_server", api_is_server, METH_VARARGS, "is_server(client)"},
    {"is_secure", api_is_secure, METH_VARARGS, "is_secure(client)"},
    {"is_uline", api_is_uline, METH_VARARGS, "is_uline(client)"},
    {"is_logged_in", api_is_logged_in, METH_VARARGS, "is_logged_in(client)"},
    {"has_mode", api_has_mode, METH_VARARGS, "has_mode(client_or_channel, mode_char)"},
    {"check_channel_access", api_check_channel_access, METH_VARARGS,
     "check_channel_access(client, channel, flags) -- e.g. 'o' for op, 'h' for halfop+"},
    {"all_clients", api_all_clients, METH_NOARGS, "all users on the network"},
    {"all_local_clients", api_all_local_clients, METH_NOARGS, "local users on this server"},
    {"all_servers", api_all_servers, METH_NOARGS, "all servers on the network"},
    {"all_opers", api_all_opers, METH_NOARGS, "all IRC operators"},
    {"all_channels", api_all_channels, METH_NOARGS, "all channels"},
    {"do_cmd", api_do_cmd, METH_VARARGS,
     "do_cmd(client, cmd, [params]) -- execute an IRC command as `client`"},
    {"exit_client", api_exit_client, METH_VARARGS, "exit_client(client, reason=...)"},
    {"kick", api_kick, METH_VARARGS, "kick(victim, channel, reason=...)"},
    {"set_topic", api_set_topic, METH_VARARGS, "set_topic(channel, topic, set_by=None)"},
    {"set_channel_mode", api_set_channel_mode, METH_VARARGS, "set_channel_mode(channel, modes, params='')"},
    {"set_user_mode", api_set_user_mode, METH_VARARGS, "set_user_mode(client, modes)"},
    {"change_nick", api_change_nick, METH_VARARGS, "change_nick(client, newnick)"},
    {"set_host", api_set_host, METH_VARARGS, "set_host(client, host)"},
    {"join_channel", api_join_channel, METH_VARARGS, "join_channel(client, channel)"},
    {"part_channel", api_part_channel, METH_VARARGS, "part_channel(client, channel, reason='Leaving')"},
    {"add_serverban", api_add_serverban, METH_VARARGS,
     "add_serverban(user, host, reason, duration_seconds=0, setby=None)"},
    {"del_serverban", api_del_serverban, METH_VARARGS, "del_serverban(user, host)"},
    {"register_hook", api_register_hook, METH_VARARGS,
     "register_hook(name, fn) -- see hook_names[] in the source for valid names."},
    {"register_command", (PyCFunction)api_register_command, METH_VARARGS | METH_KEYWORDS,
     "register_command(name, fn, params=1)"},
    {"set_timeout", api_set_timeout, METH_VARARGS,
     "set_timeout(fn, ms) -> id"},
    {"set_interval", api_set_interval, METH_VARARGS,
     "set_interval(fn, ms) -> id"},
    {"clear_timer", api_clear_timer, METH_VARARGS, "clear_timer(id)"},
    {"http_get", (PyCFunction)api_http_get, METH_VARARGS | METH_KEYWORDS,
     "http_get(url, callback, max_redirects=3, connect_timeout=10, transfer_timeout=30); callback(err, body)."},
    {"register_moddata", (PyCFunction)api_register_moddata, METH_VARARGS | METH_KEYWORDS,
     "register_moddata(name, type, sync=False); type one of MODDATATYPE_*"},
    {"set_moddata", api_set_moddata, METH_VARARGS, "set_moddata(target, name, value)"},
    {"get_moddata", api_get_moddata, METH_VARARGS, "get_moddata(target, name)"},
    {"register_channel_mode", (PyCFunction)api_register_channel_mode, METH_VARARGS | METH_KEYWORDS,
     "register_channel_mode(letter, name, paracount=0, is_ok=None)"},
    {"register_prefix_mode", (PyCFunction)api_register_prefix_mode, METH_VARARGS | METH_KEYWORDS,
     "register_prefix_mode(letter, prefix, name, rank=0, is_ok=None)"},
    {"register_user_mode", (PyCFunction)api_register_user_mode, METH_VARARGS | METH_KEYWORDS,
     "register_user_mode(letter, name, global=1, unset_on_deoper=0, allowed=None)"},
    {"register_rpc_method", api_register_rpc_method, METH_VARARGS,
     "register_rpc_method(method, fn); fn(params, ctx) calls rpc_response/rpc_error."},
    {"rpc_response", api_rpc_response, METH_VARARGS, "rpc_response(ctx, result_dict_or_list)"},
    {"rpc_error", api_rpc_error, METH_VARARGS, "rpc_error(ctx, code, message)"},
    {"register_extban", (PyCFunction)api_register_extban, METH_VARARGS | METH_KEYWORDS,
     "register_extban(letter, name, is_ok=None, is_banned=None)"},
    {"register_config_block", (PyCFunction)api_register_config_block, METH_VARARGS | METH_KEYWORDS,
     "register_config_block(name, test=None, run=None) -- both callbacks get a dict"},
    {"register_message_tag", (PyCFunction)api_register_message_tag, METH_VARARGS | METH_KEYWORDS,
     "register_message_tag(name, is_ok=None, can_send=None)"},
    {NULL, NULL, 0, NULL}};

static struct PyModuleDef obby_module_def = {
    PyModuleDef_HEAD_INIT,
    "obby",
    "ObbyIRCd scripting API",
    -1,
    obby_methods};

static PyObject *PyInit_obby(void)
{
	if (PyType_Ready(&PyClient_Type) < 0)
		return NULL;
	if (PyType_Ready(&PyChannel_Type) < 0)
		return NULL;
	if (PyType_Ready(&PyServer_Type) < 0)
		return NULL;
	PyObject *m = PyModule_Create(&obby_module_def);
	if (!m)
		return NULL;
	Py_INCREF(&PyClient_Type);
	PyModule_AddObject(m, "Client", (PyObject *)&PyClient_Type);
	Py_INCREF(&PyChannel_Type);
	PyModule_AddObject(m, "Channel", (PyObject *)&PyChannel_Type);
	Py_INCREF(&PyServer_Type);
	PyModule_AddObject(m, "Server", (PyObject *)&PyServer_Type);

	/* Expose MODDATATYPE_* enum values to scripts. */
	PyModule_AddIntConstant(m, "MODDATATYPE_LOCAL_VARIABLE", MODDATATYPE_LOCAL_VARIABLE);
	PyModule_AddIntConstant(m, "MODDATATYPE_GLOBAL_VARIABLE", MODDATATYPE_GLOBAL_VARIABLE);
	PyModule_AddIntConstant(m, "MODDATATYPE_CLIENT", MODDATATYPE_CLIENT);
	PyModule_AddIntConstant(m, "MODDATATYPE_LOCAL_CLIENT", MODDATATYPE_LOCAL_CLIENT);
	PyModule_AddIntConstant(m, "MODDATATYPE_CHANNEL", MODDATATYPE_CHANNEL);
	PyModule_AddIntConstant(m, "MODDATATYPE_MEMBER", MODDATATYPE_MEMBER);
	PyModule_AddIntConstant(m, "MODDATATYPE_MEMBERSHIP", MODDATATYPE_MEMBERSHIP);
	return m;
}

/* ===================================================================
 * Script loader
 * =================================================================== */

static void load_one_script(const char *dirpath, const char *fname)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/%s", dirpath, fname);

	FILE *fp = fopen(path, "rb");
	if (!fp)
	{
		unreal_log(ULOG_WARNING, "obbypy", "PY_OPEN_FAILED", NULL,
		           "Failed to open script $path: $err",
		           log_data_string("path", path),
		           log_data_string("err", strerror(errno)));
		return;
	}
	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (size <= 0 || size > 4 * 1024 * 1024)
	{
		fclose(fp);
		unreal_log(ULOG_WARNING, "obbypy", "PY_INVALID_SIZE", NULL,
		           "Script $path has implausible size, skipping",
		           log_data_string("path", path));
		return;
	}
	char *buf = safe_alloc(size + 1);
	if (fread(buf, 1, size, fp) != (size_t)size)
	{
		fclose(fp);
		safe_free(buf);
		unreal_log(ULOG_WARNING, "obbypy", "PY_READ_FAILED", NULL,
		           "Failed to read script $path",
		           log_data_string("path", path));
		return;
	}
	fclose(fp);
	buf[size] = '\0';

	char modname[256];
	strlcpy(modname, fname, sizeof(modname));
	char *dot = strrchr(modname, '.');
	if (dot)
		*dot = '\0';

	PyObject *code = Py_CompileString(buf, fname, Py_file_input);
	safe_free(buf);
	if (!code)
	{
		PyObject *type, *val, *tb;
		PyErr_Fetch(&type, &val, &tb);
		PyErr_NormalizeException(&type, &val, &tb);
		PyObject *vstr = val ? PyObject_Str(val) : NULL;
		const char *vs = vstr ? PyUnicode_AsUTF8(vstr) : "";
		unreal_log(ULOG_ERROR, "obbypy", "PY_COMPILE_ERROR", NULL,
		           "Failed to compile $path: $err",
		           log_data_string("path", path),
		           log_data_string("err", vs ? vs : "?"));
		Py_XDECREF(vstr);
		Py_XDECREF(type);
		Py_XDECREF(val);
		Py_XDECREF(tb);
		return;
	}

	PyObject *mod = PyImport_ExecCodeModule(modname, code);
	Py_DECREF(code);
	if (!mod)
	{
		PyObject *type, *val, *tb;
		PyErr_Fetch(&type, &val, &tb);
		PyErr_NormalizeException(&type, &val, &tb);
		PyObject *vstr = val ? PyObject_Str(val) : NULL;
		const char *vs = vstr ? PyUnicode_AsUTF8(vstr) : "";
		unreal_log(ULOG_ERROR, "obbypy", "PY_EXEC_ERROR", NULL,
		           "Failed to run $path: $err",
		           log_data_string("path", path),
		           log_data_string("err", vs ? vs : "?"));
		Py_XDECREF(vstr);
		Py_XDECREF(type);
		Py_XDECREF(val);
		Py_XDECREF(tb);
		return;
	}
	Py_DECREF(mod);
	unreal_log(ULOG_INFO, "obbypy", "PY_SCRIPT_LOADED", NULL,
	           "Loaded $path", log_data_string("path", path));
}

static void load_scripts(void)
{
	char dirpath[PATH_MAX];
	snprintf(dirpath, sizeof(dirpath), "%s/%s", CONFDIR,
	         cfg.scripts_dir ? cfg.scripts_dir : DEFAULT_SCRIPTS_DIR);
	DIR *d = opendir(dirpath);
	if (!d)
	{
		unreal_log(ULOG_INFO, "obbypy", "PY_NO_SCRIPTS_DIR", NULL,
		           "Scripts dir not found at $path",
		           log_data_string("path", dirpath));
		return;
	}
	struct dirent *ent;
	while ((ent = readdir(d)))
	{
		if (ent->d_name[0] == '.')
			continue;
		size_t n = strlen(ent->d_name);
		if (n < 3 || strcmp(ent->d_name + n - 3, ".py"))
			continue;
		load_one_script(dirpath, ent->d_name);
	}
	closedir(d);
}

static void cleanup_state(void)
{
	for (PyHook *h = hooks_list; h;)
	{
		PyHook *n = h->next;
		Py_XDECREF(h->fn);
		safe_free(h);
		h = n;
	}
	hooks_list = NULL;
	for (PyCmd *c = cmds_list; c;)
	{
		PyCmd *n = c->next;
		if (c->cmd)
			CommandDel(c->cmd);
		Py_XDECREF(c->fn);
		safe_free(c->name);
		safe_free(c);
		c = n;
	}
	cmds_list = NULL;
	for (PyTimer *t = timers_list; t;)
	{
		PyTimer *n = t->next;
		if (t->event)
			EventDel(t->event);
		Py_XDECREF(t->fn);
		safe_free(t);
		t = n;
	}
	timers_list = NULL;
	for (PyHttp *h = https_list; h;)
	{
		PyHttp *n = h->next;
		Py_XDECREF(h->fn);
		safe_free(h);
		h = n;
	}
	https_list = NULL;
	for (PyModData *m = moddatas_list; m;)
	{
		PyModData *n = m->next;
		if (m->md)
			ModDataDel(m->md);
		safe_free(m->name);
		safe_free(m);
		m = n;
	}
	moddatas_list = NULL;
	for (PyChanmode *m = chanmodes_list; m;)
	{
		PyChanmode *n = m->next;
		Py_XDECREF(m->is_ok);
		safe_free(m->name);
		safe_free(m);
		m = n;
	}
	chanmodes_list = NULL;
	for (PyPrefixmode *m = prefixmodes_list; m;)
	{
		PyPrefixmode *n = m->next;
		Py_XDECREF(m->is_ok);
		safe_free(m->name);
		safe_free(m);
		m = n;
	}
	prefixmodes_list = NULL;
	for (PyUsermode *m = usermodes_list; m;)
	{
		PyUsermode *n = m->next;
		Py_XDECREF(m->allowed);
		safe_free(m->name);
		safe_free(m);
		m = n;
	}
	usermodes_list = NULL;
	for (PyRpc *r = rpcs_list; r;)
	{
		PyRpc *n = r->next;
		Py_XDECREF(r->fn);
		safe_free(r->method);
		safe_free(r);
		r = n;
	}
	rpcs_list = NULL;
	for (PyExtban *e = extbans_list; e;)
	{
		PyExtban *n = e->next;
		Py_XDECREF(e->is_ok);
		Py_XDECREF(e->is_banned);
		safe_free(e->name);
		safe_free(e);
		e = n;
	}
	extbans_list = NULL;
	for (PyCfgBlock *b = cfg_blocks_list; b;)
	{
		PyCfgBlock *n = b->next;
		Py_XDECREF(b->test_fn);
		Py_XDECREF(b->run_fn);
		safe_free(b->blockname);
		safe_free(b);
		b = n;
	}
	cfg_blocks_list = NULL;
	for (PyMtagHandler *m = mtag_handlers_list; m;)
	{
		PyMtagHandler *n = m->next;
		Py_XDECREF(m->is_ok);
		Py_XDECREF(m->can_send);
		safe_free(m->name);
		safe_free(m);
		m = n;
	}
	mtag_handlers_list = NULL;
	memset(hook_added, 0, sizeof(hook_added));
}

/* ===================================================================
 * Config block: obbypy { scripts-dir "..."; };
 * =================================================================== */

static int obbypy_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs)
{
	int errors = 0;
	if (type != CONFIG_MAIN)
		return 0;
	if (!ce || !ce->name || strcmp(ce->name, MYCONF))
		return 0;
	for (ConfigEntry *cep = ce->items; cep; cep = cep->next)
	{
		if (!cep->value)
		{
			config_error("%s:%d: blank %s::%s",
			             cep->file->filename, cep->line_number,
			             MYCONF, cep->name);
			errors++;
			continue;
		}
		if (!strcmp(cep->name, "scripts-dir"))
			continue;
		config_error("%s:%d: unknown directive %s::%s",
		             cep->file->filename, cep->line_number,
		             MYCONF, cep->name);
		errors++;
	}
	*errs = errors;
	return errors ? -1 : 1;
}

static int obbypy_configrun(ConfigFile *cf, ConfigEntry *ce, int type)
{
	if (type != CONFIG_MAIN)
		return 0;
	if (!ce || !ce->name || strcmp(ce->name, MYCONF))
		return 0;
	for (ConfigEntry *cep = ce->items; cep; cep = cep->next)
	{
		if (!strcmp(cep->name, "scripts-dir") && cep->value)
			safe_strdup(cfg.scripts_dir, cep->value);
	}
	return 1;
}

/* User-registered config blocks need to be hooked into the global
 * configtest/configrun chain.  We install one wrapper that walks
 * cfg_blocks_list and dispatches to whichever matches. */
static int obbypy_dispatch_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs)
{
	return pycfg_test(cf, ce, type, errs);
}

static int obbypy_dispatch_configrun(ConfigFile *cf, ConfigEntry *ce, int type)
{
	return pycfg_run(cf, ce, type);
}

/* ===================================================================
 * Module lifecycle
 * =================================================================== */

MOD_TEST()
{
	memset(&cfg, 0, sizeof(cfg));
	safe_strdup(cfg.scripts_dir, DEFAULT_SCRIPTS_DIR);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, obbypy_configtest);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 1, obbypy_dispatch_configtest);
	return MOD_SUCCESS;
}

MOD_INIT()
{
	modinfo_ref = modinfo;
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, obbypy_configrun);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 1, obbypy_dispatch_configrun);

	RegisterApiCallbackWebResponse(modinfo->handle, HTTP_API_CALLBACK_NAME,
	                               obbypy_http_callback);
	return MOD_SUCCESS;
}

MOD_LOAD()
{
	/* AppendInittab + Py_Initialize is a one-time-per-process setup;
	 * Python aborts the process if AppendInittab is called after
	 * Py_Initialize.  We do this in MOD_LOAD rather than MOD_INIT so the
	 * interpreter is created only in the actually-running server.  The
	 * config-test parent (and the -DTESTSUITE Init_all_testing_modules
	 * dry-run) call MOD_INIT but never MOD_LOAD, then exit -- initialising
	 * Python there left the interpreter unreferenced at exit, which
	 * LeakSanitizer reports as a ~600KB leak.  On /REHASH MOD_LOAD runs
	 * again on the freshly dlopened obbypy.so, so guard behind
	 * IsInitialized (we never Py_Finalize, see MOD_UNLOAD). */
	if (!Py_IsInitialized())
	{
		if (PyImport_AppendInittab("obby", PyInit_obby) == -1)
		{
			config_error("[obbypy] PyImport_AppendInittab failed");
			return MOD_FAILED;
		}
		Py_Initialize();
		if (!Py_IsInitialized())
		{
			config_error("[obbypy] Py_Initialize failed");
			return MOD_FAILED;
		}
	}

	load_scripts();
	return MOD_SUCCESS;
}

MOD_UNLOAD()
{
	cleanup_state();
	/* Do NOT call Py_Finalize() here.  libpython is process-global,
	 * and Python's embedded API does not survive a finalize +
	 * re-initialise cycle: the next MOD_INIT after /REHASH SEGVs
	 * inside Py_InitializeFromConfig (strlen on a NULL from the
	 * post-finalize config-bootstrap path).  cleanup_state() above
	 * already releases every Python ref we own; leaving the
	 * interpreter alive for the process lifetime is the documented
	 * workaround and keeps /REHASH safe. */
	safe_free(cfg.scripts_dir);
	return MOD_SUCCESS;
}
