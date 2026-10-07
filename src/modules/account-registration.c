/*
 * src/modules/account-registration.c
 * Native account registration system for ObbyIRCd.
 *
 * Features:
 *   - SQLite3-backed account storage (PERMDATADIR/obsidian.db)
 *   - IRCv3 draft/account-registration capability
 *   - Commands: REGISTER, IDENTIFY, LOGOUT, LISTACC (oper)
 *   - Built-in SASL server: PLAIN and ANONYMOUS mechanisms
 *   - RPC: obsidianirc.accounts.list, obsidianirc.accounts.find
 *   - Config block: account-registration { ... }
 *   - Custom hook HOOKTYPE_ACCOUNT_REGISTER (133) fired on new registrations
 *
 * Config example (obbyircd.conf):
 *   account-registration {
 *       min-name-length 3;
 *       max-name-length 50;
 *       min-password-length 8;
 *       max-password-length 200;
 *       require-email yes;
 *   };
 *
 * Requires: sqlite3 (-lsqlite3)
 */

#include "unrealircd.h"
#include "obsidian.h"
#include "smtp.h"

/* ===================================================================
 * Module header
 * =================================================================== */
ModuleHeader MOD_HEADER = {
    "account-registration",
    "1.0",
    "Native account registration with built-in SASL (PLAIN, ANONYMOUS)",
    "ObbyIRCd Team",
    "unrealircd-6",
};

/* ===================================================================
 * Module globals (definitions; obsidian.h has the externs)
 * =================================================================== */
sqlite3 *obsidian_db = NULL;
ModDataInfo *sasl_md = NULL;
static long CAP_ACCOUNTREGISTRATION = 0L;
static struct AccountRegistrationConfStruct MyConf;

/* ===================================================================
 * Forward declarations
 * =================================================================== */
static int accreg_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
static int accreg_configposttest(int *errs);
static int accreg_configrun(ConfigFile *cf, ConfigEntry *ce, int type);
static int authenticate_attempt(Client *client, int first, const char *param);
static const char *saslmechs(Client *client);
static const char *accreg_capability_parameter(Client *client);
static int accreg_capability_visible(Client *client);
static json_t *account2json(const Account *acc);
static void set_accreg_conf(void);
static void free_accreg_conf(void);
static void oauth_free_providers(void);

/* Pair every ERR_SASLFAIL with an audit log so operators can diagnose
 * failures the same way they can for successes (SASL_LOGIN). */
static inline void log_sasl_fail(Client *client,
                                 const char *mech,
                                 const char *account,
                                 const char *reason)
{
	unreal_log(ULOG_INFO, "account", "SASL_FAIL", client,
	           "SASL $mech failure for $client.details "
	           "[account: $account] [reason: $reason]",
	           log_data_string("mech", mech ? mech : "?"),
	           log_data_string("account", account && *account ? account : "?"),
	           log_data_string("reason", reason ? reason : "?"));
}

CMD_FUNC(register_account);
CMD_FUNC(list_accounts);
CMD_FUNC(cmd_identify);
CMD_FUNC(cmd_logout);
CMD_FUNC(cmd_verify);
CMD_FUNC(cmd_2fa);

static int try_send_email_loaded(void);
static int send_verify_email(const Account *acc);

/* SCRAM forward decls (impl in SCRAM section below) */
typedef struct ScramState_ ScramState;
static ModDataInfo *scram_md;
static void scram_md_free(ModData *m);
static int scram_make_credentials(Account *acc, const char *password);

/* 2FA forward decls (impl in 2FA section below) */
typedef struct TwoFAEnroll_ {
	char *type;
	char *secret_b32;
    /* OAuth-only: provider chosen at /2FA CHALLENGE oauth <provider>,
     * and chunked token buffer assembled from /2FA TOKEN <chunk> calls. */
	char *oauth_provider;
	char *oauth_token;
	size_t oauth_token_len;
	size_t oauth_token_cap;
	time_t expires_at;
} TwoFAEnroll;
typedef struct TwoFAStepup_ {
	int active;
	char account[ACCOUNTLEN + 1];
    /* Credential type used for primary auth ("password", "oauth",
     * "external"). The step-up handler refuses any mech whose factor
     * type matches this -- you can't satisfy both factors with the
     * same proof. */
	char primary_factor[16];
} TwoFAStepup;
static ModDataInfo *twofa_enroll_md;
static ModDataInfo *twofa_stepup_md;
static void twofa_enroll_md_free(ModData *m);
static void twofa_stepup_md_free(ModData *m);
static int twofa_maybe_start_stepup(Client *client, Account *acc,
                                    const char *primary_factor);
static int twofa_handle_stepup_authenticate(Client *client, const char *param);
static const char *twofa_capability_parameter(Client *client);
static int twofa_capability_visible(Client *client);
static void twofa_clear_stepup(Client *c);
/* Registration-timeout extension: when SASL is mid-flight (especially
 * during a 2FA step-up where the user is fishing their phone out of
 * a pocket or completing an OAuth consent screen) the default 40s
 * handshake timeout fires before they can finish. The sasl_timeout
 * event (now 300s default) is the real ceiling; this hook just stops
 * the handshake_timeout event from racing it. */
static int accreg_pre_local_handshake_timeout(Client *client,
                                              const char **comment);

/* WebAuthn forward decls (impl in webauthn section below) */
typedef struct WebAuthnSaslState_ {
	int step;
	char username_hint[ACCOUNTLEN + 1];
	unsigned char challenge[32];
} WebAuthnSaslState;
static ModDataInfo *webauthn_sasl_md;
static void webauthn_sasl_md_free(ModData *m);
static void webauthn_sasl_handle_hello(Client *client, const char *param);
static void webauthn_sasl_handle_assertion(Client *client, const char *param);
static void webauthn_sasl_clear(Client *c);
static int webauthn_2fa_handle_add(Client *client, Account *acc,
                                   const char *name, const char *data_b64);
static void webauthn_2fa_handle_challenge(Client *client, Account *acc);
static const char *webauthn_rp_id_capability_parameter(Client *client);
#define WebAuthnSaslGet(c) ((WebAuthnSaslState *)moddata_local_client((c), webauthn_sasl_md).ptr)
#define WebAuthnSaslSet(c, p) \
	do \
	{ \
		moddata_local_client((c), webauthn_sasl_md).ptr = (p); \
	} while (0)
#define TwoFAStepupGet(c) ((TwoFAStepup *)moddata_local_client((c), twofa_stepup_md).ptr)
#define TwoFAStepupSet(c, p) \
	do \
	{ \
		moddata_local_client((c), twofa_stepup_md).ptr = (p); \
	} while (0)
#define TwoFAEnrollGet(c) ((TwoFAEnroll *)moddata_local_client((c), twofa_enroll_md).ptr)
#define TwoFAEnrollSet(c, p) \
	do \
	{ \
		moddata_local_client((c), twofa_enroll_md).ptr = (p); \
	} while (0)
RPC_CALL_FUNC(rpc_list_accounts);
RPC_CALL_FUNC(rpc_accounts_find);

/* ===================================================================
 * OAuth 2.0 / OIDC bearer-token authentication
 *
 * Configuration:
 *
 *   account-registration {
 *       ...
 *       oauth-provider "logto" {
 *           issuer        "https://my-tenant.logto.app/oidc";
 *           audience      "https://api.example.com";
 *           jwks-file     "/home/valware/obby/conf/logto-jwks.json";
 *           subject-claim "sub";       # default; "preferred_username" also OK
 *       }
 *   }
 *
 * On startup we load the JWKS from the file and cache it in memory.
 * Re-fetch the JWKS by /REHASH (the file is reread). For now, JWKS
 * fetching from the IdP URL is left to the admin's cron + curl;
 * adding async download_file_async() integration is a small follow-up.
 *
 * Validation: standard RS256 / ES256 verification of the JWT,
 * plus iss/aud/exp/nbf claim checks. The verified `sub` (or whatever
 * subject-claim points at) is then looked up in account_oauth_links;
 * a hit logs the user into the linked account, a miss returns
 * "no account linked to this OAuth identity, /OAUTHLINK first".
 *
 * Per-user linking via /OAUTHLINK ADD <provider> <token>:
 *   - caller MUST already be logged in (PLAIN / SCRAM / cert).
 *   - server validates the token, extracts subject, inserts the row.
 *   - subsequent SASL OAUTHBEARER / IRCV3BEARER then succeeds.
 * =================================================================== */

#define MAX_OAUTH_JWKS_KEYS 16

typedef struct OAuthJwksKey {
	char *kid;            /* base64url-encoded key id */
	char *alg;            /* "RS256" / "RS512" / "ES256" / "ES384" / "ES512" */
	char *kty;            /* "RSA" or "EC" */
	EVP_PKEY *pkey;       /* parsed public key, ready for EVP_DigestVerify */
} OAuthJwksKey;

typedef struct OAuthProvider {
	char *name;            /* config block label, lower-cased */
	char *issuer;          /* expected `iss` claim (JWT path) */
	char *audience;        /* expected `aud` claim, optional */
	char *jwks_file;       /* path to a local JWKS json file (JWT path) */
	char *userinfo_url;    /* HTTPS URL hit with Authorization: Bearer <token>
                            * (opaque path -- e.g. https://api.github.com/user) */
	char *subject_claim;   /* defaults to "sub"; for GitHub use "login" or "id" */
	OAuthJwksKey keys[MAX_OAUTH_JWKS_KEYS];
	int nkeys;
	int loaded;
	struct OAuthProvider *next;
} OAuthProvider;

static OAuthProvider *oauth_providers = NULL;

static int oauthbearer_dispatch(Client *client, const char *param);
static int ircv3bearer_dispatch(Client *client, const char *param);
static int oauth_load_jwks_file(struct OAuthProvider *p);
static int oauth_validate_opaque_async(Client *client, struct OAuthProvider *prov,
                                       const char *token);
static void oauth_userinfo_callback(OutgoingWebRequest *request,
                                    OutgoingWebResponse *response);
/* Forward decls for the 2FA helpers used inside the userinfo callback;
 * the actual definitions live in the 2FA section further down. */
static void twofa_fail(Client *c, const char *code, const char *param,
                       const char *human);
static void twofa_clear_enroll(Client *c);
static void format_cred_id(char *out, size_t out_size, long int id);

/* Multi-line AUTHENTICATE accumulator for OAUTHBEARER / IRCV3BEARER.
 * IRC SASL chunks at 400 bytes; tokens are easily larger.
 * Returns NULL while accumulating (caller should not finalize),
 * returns the full concatenated base64 string when the final chunk is
 * received (chunk shorter than 400 bytes, or "+" continuation marker
 * indicating no further data).  The returned pointer is owned by the
 * accumulator and freed when the SASL state is cleared. */
typedef struct {
	char *buf;
	size_t len;
	size_t cap;
} OAuthSaslBuf;
static ModDataInfo *oauth_sasl_md = NULL;
static void oauth_sasl_md_free(ModData *m);
static const char *oauth_sasl_accumulate(Client *client, const char *param);
static void oauth_sasl_clear(Client *client);

/* SASL mech identifiers we add. Their values are arbitrary as long as
 * they don't collide with the existing ones in obsidian.h. */
#define SASL_TYPE_OAUTHBEARER  9
#define SASL_TYPE_IRCV3BEARER  10
#define SASL_TYPE_OAUTH_STEPUP 11   /* second-factor OAuth after PLAIN/SCRAM/EXTERNAL */

/* ===================================================================
 * Module lifecycle
 * =================================================================== */
MOD_TEST()
{
	MARK_AS_OFFICIAL_MODULE(modinfo);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, accreg_configtest);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGPOSTTEST, 0, accreg_configposttest);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, accreg_configrun);
	return MOD_SUCCESS;
}

// COPILOT DO NOT REMOVE >:/
CMD_FUNC(cmd_debuglmao)
{
	Client *c;
	list_for_each_entry(c, &client_list, client_node)
	{
		sendnotice(client, "%s (%s)", c->name, c->id);
	}
}

MOD_INIT()
{
	ClientCapabilityInfo cap;
	ModDataInfo mdi;
	RPCHandlerInfo rpc;

	MARK_AS_OFFICIAL_MODULE(modinfo);
	set_accreg_conf();

    /* SASL ModData — tracks which SASL mechanism is in progress per client */
	memset(&mdi, 0, sizeof(mdi));
	mdi.name = "sasl_auth_type";
	mdi.free = sat_free;
	mdi.serialize = sat_serialize;
	mdi.unserialize = sat_unserialize;
	mdi.type = MODDATATYPE_CLIENT;
	sasl_md = ModDataAdd(modinfo->handle, mdi);
	if (!sasl_md)
	{
		config_error("account-registration: Could not add ModData for sasl_auth_type");
		return MOD_FAILED;
	}

    /* SCRAM-SHA-256 in-flight state, per-local-client */
	memset(&mdi, 0, sizeof(mdi));
	mdi.name = "scram_state";
	mdi.free = scram_md_free;
	mdi.type = MODDATATYPE_LOCAL_CLIENT;
	scram_md = ModDataAdd(modinfo->handle, mdi);
	if (!scram_md)
	{
		config_error("account-registration: Could not add ModData for scram_state");
		return MOD_FAILED;
	}

    /* 2FA enrolment challenge state, per-local-client */
	memset(&mdi, 0, sizeof(mdi));
	mdi.name = "twofa_enroll";
	mdi.free = twofa_enroll_md_free;
	mdi.type = MODDATATYPE_LOCAL_CLIENT;
	twofa_enroll_md = ModDataAdd(modinfo->handle, mdi);
	if (!twofa_enroll_md)
	{
		config_error("account-registration: Could not add ModData for twofa_enroll");
		return MOD_FAILED;
	}

    /* 2FA SASL step-up state, per-local-client */
	memset(&mdi, 0, sizeof(mdi));
	mdi.name = "twofa_stepup";
	mdi.free = twofa_stepup_md_free;
	mdi.type = MODDATATYPE_LOCAL_CLIENT;
	twofa_stepup_md = ModDataAdd(modinfo->handle, mdi);
	if (!twofa_stepup_md)
	{
		config_error("account-registration: Could not add ModData for twofa_stepup");
		return MOD_FAILED;
	}

    /* WEBAUTHN-BIO SASL state, per-local-client */
	memset(&mdi, 0, sizeof(mdi));
	mdi.name = "webauthn_sasl";
	mdi.free = webauthn_sasl_md_free;
	mdi.type = MODDATATYPE_LOCAL_CLIENT;
	webauthn_sasl_md = ModDataAdd(modinfo->handle, mdi);
	if (!webauthn_sasl_md)
	{
		config_error("account-registration: Could not add ModData for webauthn_sasl");
		return MOD_FAILED;
	}

    /* OAuth (OAUTHBEARER + IRCV3BEARER) multi-line AUTHENTICATE buffer */
	memset(&mdi, 0, sizeof(mdi));
	mdi.name = "oauth_sasl_buf";
	mdi.free = oauth_sasl_md_free;
	mdi.type = MODDATATYPE_LOCAL_CLIENT;
	oauth_sasl_md = ModDataAdd(modinfo->handle, mdi);
	if (!oauth_sasl_md)
	{
		config_error("account-registration: Could not add ModData for oauth_sasl_buf");
		return MOD_FAILED;
	}

    /* Open DB during init to verify it is accessible */
	if (obsidian_open_database(OBSIDIAN_DB) != SQLITE_OK)
	{
		config_error("account-registration: Could not open database at %s", OBSIDIAN_DB);
		return MOD_FAILED;
	}

    /* CAP: draft/account-registration */
	memset(&cap, 0, sizeof(cap));
	cap.name = REGCAP_NAME;
	cap.visible = accreg_capability_visible;
	cap.parameter = accreg_capability_parameter;
	if (!ClientCapabilityAdd(modinfo->handle, &cap, &CAP_ACCOUNTREGISTRATION))
	{
		config_error("account-registration: Could not add CAP " REGCAP_NAME);
		return MOD_FAILED;
	}

    /* CAP: draft/account-2fa */
	{
		static long CAP_TWOFA = 0L;
		ClientCapabilityInfo cap2;
		memset(&cap2, 0, sizeof(cap2));
		cap2.name = "draft/account-2fa";
		cap2.visible = twofa_capability_visible;
		cap2.parameter = twofa_capability_parameter;
		if (!ClientCapabilityAdd(modinfo->handle, &cap2, &CAP_TWOFA))
		{
			config_error("account-registration: Could not add CAP draft/account-2fa");
			return MOD_FAILED;
		}
	}

    /* CAP: draft/webauthn-rp-id (advertise the WebAuthn RP ID) */
	{
		static long CAP_WAUTH_RPID = 0L;
		ClientCapabilityInfo cap3;
		memset(&cap3, 0, sizeof(cap3));
		cap3.name = "draft/webauthn-rp-id";
		cap3.visible = twofa_capability_visible;
		cap3.parameter = webauthn_rp_id_capability_parameter;
		if (!ClientCapabilityAdd(modinfo->handle, &cap3, &CAP_WAUTH_RPID))
		{
			config_error("account-registration: Could not add CAP draft/webauthn-rp-id");
			return MOD_FAILED;
		}
	}

    /* Commands */
	CommandAdd(modinfo->handle, CMD_REGISTER, register_account, MAXPARA,
	           CMD_USER | CMD_UNREGISTERED);
	CommandAdd(modinfo->handle, CMD_LISTACC, list_accounts, MAXPARA, CMD_OPER);
	CommandAdd(modinfo->handle, CMD_IDENTIFY, cmd_identify, MAXPARA, CMD_USER);
	CommandAdd(modinfo->handle, CMD_LOGOUT, cmd_logout, MAXPARA, CMD_USER);
	CommandAdd(modinfo->handle, CMD_VERIFY, cmd_verify, MAXPARA,
	           CMD_USER | CMD_UNREGISTERED);
	CommandAdd(modinfo->handle, CMD_2FA, cmd_2fa, MAXPARA, CMD_USER);
	CommandAdd(modinfo->handle, "DEBUGLMAO", cmd_debuglmao, 0, CMD_USER); // Stop removing my command, copilot! >:/

    /* Built-in SASL hooks */
	HookAddConstString(modinfo->handle, HOOKTYPE_SASL_MECHS, 0, saslmechs);
	HookAdd(modinfo->handle, HOOKTYPE_SASL_AUTHENTICATE, 0, authenticate_attempt);

    /* Veto the handshake timeout for clients mid-SASL (2FA, OAuth, etc.)
     * so they don't get killed for being slow on a multi-step auth. */
	HookAdd(modinfo->handle, HOOKTYPE_PRE_LOCAL_HANDSHAKE_TIMEOUT, 0,
	        accreg_pre_local_handshake_timeout);

    /* Async HTTP callback for opaque-token (userinfo) validation. */
	RegisterApiCallbackWebResponse(modinfo->handle,
	                               "oauth_userinfo_callback",
	                               oauth_userinfo_callback);

    /* RPC handlers */
	memset(&rpc, 0, sizeof(rpc));
	rpc.method = "obsidianirc.accounts.list";
	rpc.loglevel = ULOG_DEBUG;
	rpc.call = rpc_list_accounts;
	RPCHandlerAdd(modinfo->handle, &rpc);

	memset(&rpc, 0, sizeof(rpc));
	rpc.method = "obsidianirc.accounts.find";
	rpc.loglevel = ULOG_DEBUG;
	rpc.call = rpc_accounts_find;
	RPCHandlerAdd(modinfo->handle, &rpc);

	return MOD_SUCCESS;
}

MOD_LOAD()
{
	ModuleSetOptions(modinfo->handle, MOD_OPT_PERM_RELOADABLE, 1);

	if (obsidian_open_database(OBSIDIAN_DB) != SQLITE_OK)
	{
		config_error("account-registration: Could not open database on load");
		return MOD_FAILED;
	}

    /* Advertise ourselves as the SASL server so sasl.c routes AUTHENTICATE here */
	safe_strdup(iConf.sasl_server, me.name);
	moddata_client_set(&me, "saslmechlist",
	                   "PLAIN,TOTP,DRAFT-WEBAUTHN-BIO,ANONYMOUS");

	return MOD_SUCCESS;
}

MOD_UNLOAD()
{
	obsidian_close_database();
	safe_free(iConf.sasl_server);
	iConf.sasl_server = NULL;
	free_accreg_conf();
	return MOD_SUCCESS;
}

/* ===================================================================
 * Config
 * =================================================================== */
static int accreg_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs)
{
	ConfigEntry *cep;
	int errors = 0;

	if (type != CONFIG_MAIN)
		return 0;
	if (!ce || !ce->name || strcmp(ce->name, CONF_ACCOUNT_BLOCK))
		return 0;

	for (cep = ce->items; cep; cep = cep->next)
	{
		if (!cep->value)
		{
			config_error("%s:%i: blank value for %s::%s",
			             cep->file->filename, cep->line_number,
			             CONF_ACCOUNT_BLOCK, cep->name ? cep->name : "(null)");
			errors++;
			continue;
		}
		if (!cep->name)
		{
			config_error("%s:%i: blank item name in %s block",
			             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK);
			errors++;
			continue;
		}
		if (!strcmp(cep->name, "min-name-length"))
		{
			if (MyConf.got_min_name_length)
			{
				config_error("%s:%i: duplicate %s::min-name-length",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK);
				errors++;
			}
			int v = atoi(cep->value);
			if (v < MIN_ACCOUNT_NAME_LENGTH || v > MAX_ACCOUNT_NAME_LENGTH)
			{
				config_error("%s:%i: %s::min-name-length must be %d-%d",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK,
				             MIN_ACCOUNT_NAME_LENGTH, MAX_ACCOUNT_NAME_LENGTH);
				errors++;
			}
			MyConf.got_min_name_length = 1;
		} else if (!strcmp(cep->name, "max-name-length"))
		{
			if (MyConf.got_max_name_length)
			{
				config_error("%s:%i: duplicate %s::max-name-length",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK);
				errors++;
			}
			int v = atoi(cep->value);
			if (v < MIN_ACCOUNT_NAME_LENGTH || v > MAX_ACCOUNT_NAME_LENGTH)
			{
				config_error("%s:%i: %s::max-name-length must be %d-%d",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK,
				             MIN_ACCOUNT_NAME_LENGTH, MAX_ACCOUNT_NAME_LENGTH);
				errors++;
			}
			MyConf.got_max_name_length = 1;
		} else if (!strcmp(cep->name, "min-password-length"))
		{
			if (MyConf.got_min_password_length)
			{
				config_error("%s:%i: duplicate %s::min-password-length",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK);
				errors++;
			}
			int v = atoi(cep->value);
			if (v < MIN_PASSWORD_LENGTH || v > MAX_PASSWORD_LENGTH)
			{
				config_error("%s:%i: %s::min-password-length must be %d-%d",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK,
				             MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
				errors++;
			}
			MyConf.got_min_password_length = 1;
		} else if (!strcmp(cep->name, "max-password-length"))
		{
			if (MyConf.got_max_password_length)
			{
				config_error("%s:%i: duplicate %s::max-password-length",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK);
				errors++;
			}
			int v = atoi(cep->value);
			if (v < MIN_PASSWORD_LENGTH || v > MAX_PASSWORD_LENGTH)
			{
				config_error("%s:%i: %s::max-password-length must be %d-%d",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK,
				             MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
				errors++;
			}
			MyConf.got_max_password_length = 1;
		} else if (!strcmp(cep->name, "require-email"))
		{
			if (MyConf.got_require_email)
			{
				config_error("%s:%i: duplicate %s::require-email",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK);
				errors++;
			}
			MyConf.got_require_email = 1;
		} else if (!strcmp(cep->name, "require-terms-acceptance"))
		{
			if (MyConf.got_require_terms_acceptance)
			{
				config_error("%s:%i: duplicate %s::require-terms-acceptance",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK);
				errors++;
			}
			MyConf.got_require_terms_acceptance = 1;
		} else if (!strcmp(cep->name, "allow-username-changes"))
		{
			if (MyConf.got_allow_username_changes)
			{
				config_error("%s:%i: duplicate %s::allow-username-changes",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK);
				errors++;
			}
			MyConf.got_allow_username_changes = 1;
		} else if (!strcmp(cep->name, "allow-password-changes"))
		{
			if (MyConf.got_allow_password_changes)
			{
				config_error("%s:%i: duplicate %s::allow-password-changes",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK);
				errors++;
			}
			MyConf.got_allow_password_changes = 1;
		} else if (!strcmp(cep->name, "allow-email-changes"))
		{
			if (MyConf.got_allow_email_changes)
			{
				config_error("%s:%i: duplicate %s::allow-email-changes",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK);
				errors++;
			}
			MyConf.got_allow_email_changes = 1;
		} else if (!strcmp(cep->name, "guest-nick-format"))
		{
			if (MyConf.got_guest_nick_format)
			{
				config_error("%s:%i: duplicate %s::guest-nick-format",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK);
				errors++;
			}
			if (BadPtr(cep->value))
			{
				config_error("%s:%i: %s::guest-nick-format cannot be empty",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK);
				errors++;
			}
			MyConf.got_guest_nick_format = 1;
		} else if (!strcmp(cep->name, "verify-email"))
		{
			if (MyConf.got_verify_email)
			{
				config_error("%s:%i: duplicate %s::verify-email",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK);
				errors++;
			}
			MyConf.got_verify_email = 1;
		} else if (!strcmp(cep->name, "verify-code-lifetime"))
		{
			if (MyConf.got_verify_code_lifetime)
			{
				config_error("%s:%i: duplicate %s::verify-code-lifetime",
				             cep->file->filename, cep->line_number, CONF_ACCOUNT_BLOCK);
				errors++;
			}
			MyConf.got_verify_code_lifetime = 1;
		} else if (!strcmp(cep->name, "oauth-provider"))
		{
			ConfigEntry *cepp;
			int got_jwks = 0, got_userinfo = 0;
			for (cepp = cep->items; cepp; cepp = cepp->next)
			{
				if (!cepp->name)
					continue;
				if (!strcmp(cepp->name, "issuer"))
				{
				} else if (!strcmp(cepp->name, "jwks-file"))
					got_jwks = 1;
				else if (!strcmp(cepp->name, "userinfo-url"))
					got_userinfo = 1;
				else if (!strcmp(cepp->name, "audience"))
				{
				} else if (!strcmp(cepp->name, "subject-claim"))
				{
				} else
					config_warn("%s:%i: unknown directive %s::oauth-provider::%s",
					            cepp->file->filename, cepp->line_number,
					            CONF_ACCOUNT_BLOCK, cepp->name);
			}
            /* Either path is fine; both is also fine -- jwks-file feeds the
             * JWT validator (Logto/Auth0/Keycloak/Google id_token), and
             * userinfo-url feeds the opaque-token validator (GitHub,
             * Discord, Slack, ...). At least one must be configured. */
			if (!got_jwks && !got_userinfo)
			{
				config_error("%s:%i: %s::oauth-provider \"%s\" requires "
				             "either 'jwks-file' (for JWT tokens) or "
				             "'userinfo-url' (for opaque tokens), or both.",
				             cep->file->filename, cep->line_number,
				             CONF_ACCOUNT_BLOCK, cep->value);
				errors++;
			}
		} else
		{
			config_warn("%s:%i: unknown directive %s::%s",
			            cep->file->filename, cep->line_number,
			            CONF_ACCOUNT_BLOCK, cep->name);
		}
	}

	*errs = errors;
	return errors ? -1 : 1;
}

static int accreg_configposttest(int *errs)
{
	return 0;
}


static int accreg_configrun(ConfigFile *cf, ConfigEntry *ce, int type)
{
	ConfigEntry *cep;

	if (type != CONFIG_MAIN)
		return 0;
	if (!ce || !ce->name || strcmp(ce->name, CONF_ACCOUNT_BLOCK))
		return 0;

    /* On /REHASH, drop the previous provider list so we don't accumulate
     * duplicates. On first load this is a no-op. */
	oauth_free_providers();

	for (cep = ce->items; cep; cep = cep->next)
	{
		if (!cep->name)
			continue;
		if (!strcmp(cep->name, "min-name-length"))
			MyConf.min_name_length = atoi(cep->value);
		else if (!strcmp(cep->name, "max-name-length"))
			MyConf.max_name_length = atoi(cep->value);
		else if (!strcmp(cep->name, "min-password-length"))
			MyConf.min_password_length = atoi(cep->value);
		else if (!strcmp(cep->name, "max-password-length"))
			MyConf.max_password_length = atoi(cep->value);
		else if (!strcmp(cep->name, "require-email"))
			MyConf.require_email = config_checkval(cep->value, CFG_YESNO);
		else if (!strcmp(cep->name, "require-terms-acceptance"))
			MyConf.require_terms_acceptance = config_checkval(cep->value, CFG_YESNO);
		else if (!strcmp(cep->name, "allow-username-changes"))
			MyConf.allow_username_changes = config_checkval(cep->value, CFG_YESNO);
		else if (!strcmp(cep->name, "allow-password-changes"))
			MyConf.allow_password_changes = config_checkval(cep->value, CFG_YESNO);
		else if (!strcmp(cep->name, "allow-email-changes"))
			MyConf.allow_email_changes = config_checkval(cep->value, CFG_YESNO);
		else if (!strcmp(cep->name, "guest-nick-format"))
		{
			safe_free(MyConf.guest_nick_format);
			safe_strdup(MyConf.guest_nick_format, cep->value);
		} else if (!strcmp(cep->name, "verify-email"))
			MyConf.verify_email = config_checkval(cep->value, CFG_YESNO);
		else if (!strcmp(cep->name, "verify-code-lifetime"))
			MyConf.verify_code_lifetime = config_checkval(cep->value, CFG_TIME);
		else if (!strcmp(cep->name, "oauth-provider") && cep->value)
		{
			ConfigEntry *cepp;
			OAuthProvider *p = safe_alloc(sizeof(*p));
			safe_strdup(p->name, cep->value);
			for (cepp = cep->items; cepp; cepp = cepp->next)
			{
				if (!cepp->name || !cepp->value)
					continue;
				if (!strcmp(cepp->name, "issuer"))
					safe_strdup(p->issuer, cepp->value);
				else if (!strcmp(cepp->name, "audience"))
					safe_strdup(p->audience, cepp->value);
				else if (!strcmp(cepp->name, "jwks-file"))
					safe_strdup(p->jwks_file, cepp->value);
				else if (!strcmp(cepp->name, "userinfo-url"))
					safe_strdup(p->userinfo_url, cepp->value);
				else if (!strcmp(cepp->name, "subject-claim"))
					safe_strdup(p->subject_claim, cepp->value);
			}
			if (!p->subject_claim)
				safe_strdup(p->subject_claim, "sub");
            /* Try to load JWKS now; failure is logged but not fatal --
             * admin may /REHASH after fixing the file path. Userinfo-only
             * providers (GitHub etc.) skip this entirely. */
			if (p->jwks_file)
				oauth_load_jwks_file(p);
            /* Mark the provider 'loaded' if either path is operational.
             * Opaque-only providers don't have keys but are still usable
             * via their userinfo-url. */
			if (!p->loaded && p->userinfo_url)
				p->loaded = 1;
            /* Prepend so the most recently configured wins on iss
             * collisions (rare). */
			p->next = oauth_providers;
			oauth_providers = p;
		}
	}
	return 1;
}

/* ===================================================================
 * Config defaults / cleanup
 * =================================================================== */
static void set_accreg_conf(void)
{
	memset(&MyConf, 0, sizeof(MyConf));
	MyConf.min_name_length = 3;
	MyConf.max_name_length = 50;
	MyConf.min_password_length = 8;
	MyConf.max_password_length = 200;
	MyConf.require_email = 1;
	MyConf.require_terms_acceptance = 1;
	MyConf.allow_username_changes = 1;
	MyConf.allow_password_changes = 1;
	MyConf.allow_email_changes = 1;
	MyConf.verify_email = 0;
	MyConf.verify_code_lifetime = VERIFY_CODE_LIFETIME_DEFAULT;
	safe_strdup(MyConf.guest_nick_format, "Guest$d$d$d$d");
}

static void oauth_free_keys(OAuthProvider *p);

static void oauth_free_providers(void)
{
	OAuthProvider *p = oauth_providers, *n;
	while (p)
	{
		n = p->next;
		oauth_free_keys(p);
		safe_free(p->name);
		safe_free(p->issuer);
		safe_free(p->audience);
		safe_free(p->jwks_file);
		safe_free(p->userinfo_url);
		safe_free(p->subject_claim);
		safe_free(p);
		p = n;
	}
	oauth_providers = NULL;
}

static void free_accreg_conf(void)
{
	safe_free(MyConf.guest_nick_format);
	oauth_free_providers();
}

/* ===================================================================
 * SQLite3 database layer
 * =================================================================== */
extern int obsidian_open_database(const char *filename)
{
	const char *sql;
	char *errmsg;

	if (obsidian_db)
		return SQLITE_OK; /* already open */

	if (sqlite3_open(filename, &obsidian_db) != SQLITE_OK)
	{
		obsidian_db = NULL;
		return SQLITE_ERROR;
	}

	sql =
	    "CREATE TABLE IF NOT EXISTS accounts ("
	    "  id                INTEGER PRIMARY KEY AUTOINCREMENT,"
	    "  name              TEXT NOT NULL COLLATE NOCASE,"
	    "  email             TEXT,"
	    "  password          TEXT,"
	    "  password_scheme   TEXT DEFAULT 'argon2id',"
	    "  time_registered   INTEGER,"
	    "  verified          INTEGER DEFAULT 0,"
	    "  verify_code       TEXT,"
	    "  verify_expires    INTEGER,"
	    "  scram_salt        TEXT,"
	    "  scram_iterations  INTEGER,"
	    "  scram_stored_key  TEXT,"
	    "  scram_server_key  TEXT,"
	    "  twofa_enabled     INTEGER DEFAULT 0,"
	    "  vhost             TEXT,"
	    "  vhost_set_at      INTEGER,"
	    "  suspended_until   INTEGER,"
	    "  suspended_reason  TEXT,"
	    "  suspended_by      TEXT,"
	    "  flags             TEXT"
	    ");"
	    "CREATE TABLE IF NOT EXISTS account_2fa_credentials ("
	    "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
	    "  account_id  INTEGER NOT NULL,"
	    "  type        TEXT NOT NULL,"
	    "  name        TEXT NOT NULL,"
	    "  secret      TEXT NOT NULL,"
	    "  created_at  INTEGER NOT NULL,"
	    "  FOREIGN KEY (account_id) REFERENCES accounts(id)"
	    ");"
        /* Phase 0 (§6.1) sibling tables for SASL EXTERNAL + nick aliases.
         * Created up-front; the migration tool will populate rows here
         * when the source carries certfps / additional registered nicks. */
	    "CREATE TABLE IF NOT EXISTS account_certfps ("
	    "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
	    "  account_id  INTEGER NOT NULL,"
	    "  fingerprint TEXT NOT NULL,"
	    "  added_at    INTEGER NOT NULL,"
	    "  UNIQUE(account_id, fingerprint),"
	    "  FOREIGN KEY (account_id) REFERENCES accounts(id)"
	    ");"
	    "CREATE TABLE IF NOT EXISTS account_aliases ("
	    "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
	    "  account_id  INTEGER NOT NULL,"
	    "  alias       TEXT NOT NULL COLLATE NOCASE,"
	    "  UNIQUE(alias),"
	    "  FOREIGN KEY (account_id) REFERENCES accounts(id)"
	    ");"
        /* Memos: one row per delivered memo. recipient_id keys back into
         * accounts(id); sender is stored as the canonical account name
         * (or '*' for system memos). read_at = 0 means unread. */
	    "CREATE TABLE IF NOT EXISTS memos ("
	    "  id            INTEGER PRIMARY KEY AUTOINCREMENT,"
	    "  recipient_id  INTEGER NOT NULL,"
	    "  sender        TEXT NOT NULL,"
	    "  body          TEXT NOT NULL,"
	    "  sent_at       INTEGER NOT NULL,"
	    "  read_at       INTEGER DEFAULT 0,"
	    "  FOREIGN KEY (recipient_id) REFERENCES accounts(id)"
	    ");";

	errmsg = NULL;
	if (sqlite3_exec(obsidian_db, sql, NULL, NULL, &errmsg) != SQLITE_OK)
	{
		sqlite3_free(errmsg);
		sqlite3_close(obsidian_db);
		obsidian_db = NULL;
		return SQLITE_ERROR;
	}

    /* Drop the obsolete account_oauth_links table (early prototype path);
     * OAuth identities are now stored as account_2fa_credentials rows
     * with type='oauth'. */
	errmsg = NULL;
	sqlite3_exec(obsidian_db,
	             "DROP TABLE IF EXISTS account_oauth_links;",
	             NULL, NULL, &errmsg);
	if (errmsg)
		sqlite3_free(errmsg);

    /* Schema migrations for installations created before these columns existed.
     * SQLite has no portable IF NOT EXISTS for ADD COLUMN, so we just try and
     * swallow the "duplicate column" error. */
	errmsg = NULL;
	sqlite3_exec(obsidian_db,
	             "ALTER TABLE accounts ADD COLUMN verify_code TEXT;",
	             NULL, NULL, &errmsg);
	if (errmsg)
		sqlite3_free(errmsg);
	errmsg = NULL;
	sqlite3_exec(obsidian_db,
	             "ALTER TABLE accounts ADD COLUMN verify_expires INTEGER;",
	             NULL, NULL, &errmsg);
	if (errmsg)
		sqlite3_free(errmsg);
	errmsg = NULL;
	sqlite3_exec(obsidian_db,
	             "ALTER TABLE accounts ADD COLUMN scram_salt TEXT;",
	             NULL, NULL, &errmsg);
	if (errmsg)
		sqlite3_free(errmsg);
	errmsg = NULL;
	sqlite3_exec(obsidian_db,
	             "ALTER TABLE accounts ADD COLUMN scram_iterations INTEGER;",
	             NULL, NULL, &errmsg);
	if (errmsg)
		sqlite3_free(errmsg);
	errmsg = NULL;
	sqlite3_exec(obsidian_db,
	             "ALTER TABLE accounts ADD COLUMN scram_stored_key TEXT;",
	             NULL, NULL, &errmsg);
	if (errmsg)
		sqlite3_free(errmsg);
	errmsg = NULL;
	sqlite3_exec(obsidian_db,
	             "ALTER TABLE accounts ADD COLUMN scram_server_key TEXT;",
	             NULL, NULL, &errmsg);
	if (errmsg)
		sqlite3_free(errmsg);
	errmsg = NULL;
	sqlite3_exec(obsidian_db,
	             "ALTER TABLE accounts ADD COLUMN twofa_enabled INTEGER DEFAULT 0;",
	             NULL, NULL, &errmsg);
	if (errmsg)
		sqlite3_free(errmsg);
    /* Phase 0 (§6.1) additions, idempotent. */
	errmsg = NULL;
	sqlite3_exec(obsidian_db,
	             "ALTER TABLE accounts ADD COLUMN password_scheme TEXT DEFAULT 'argon2id';",
	             NULL, NULL, &errmsg);
	if (errmsg)
		sqlite3_free(errmsg);
	errmsg = NULL;
	sqlite3_exec(obsidian_db,
	             "ALTER TABLE accounts ADD COLUMN vhost TEXT;",
	             NULL, NULL, &errmsg);
	if (errmsg)
		sqlite3_free(errmsg);
	errmsg = NULL;
	sqlite3_exec(obsidian_db,
	             "ALTER TABLE accounts ADD COLUMN vhost_set_at INTEGER;",
	             NULL, NULL, &errmsg);
	if (errmsg)
		sqlite3_free(errmsg);
	errmsg = NULL;
	sqlite3_exec(obsidian_db,
	             "ALTER TABLE accounts ADD COLUMN suspended_until INTEGER;",
	             NULL, NULL, &errmsg);
	if (errmsg)
		sqlite3_free(errmsg);
	errmsg = NULL;
	sqlite3_exec(obsidian_db,
	             "ALTER TABLE accounts ADD COLUMN suspended_reason TEXT;",
	             NULL, NULL, &errmsg);
	if (errmsg)
		sqlite3_free(errmsg);
	errmsg = NULL;
	sqlite3_exec(obsidian_db,
	             "ALTER TABLE accounts ADD COLUMN suspended_by TEXT;",
	             NULL, NULL, &errmsg);
	if (errmsg)
		sqlite3_free(errmsg);
	errmsg = NULL;
	sqlite3_exec(obsidian_db,
	             "ALTER TABLE accounts ADD COLUMN flags TEXT;",
	             NULL, NULL, &errmsg);
	if (errmsg)
		sqlite3_free(errmsg);

	return SQLITE_OK;
}

void obsidian_close_database(void)
{
	if (obsidian_db)
	{
		sqlite3_close(obsidian_db);
		obsidian_db = NULL;
	}
}

void free_account(Account *acc)
{
	if (!acc)
		return;
	free(acc->name);
	free(acc->email);
	free(acc->password);
	free(acc->password_scheme);
	free(acc->verify_code);
	free(acc->scram_salt);
	free(acc->scram_stored_key);
	free(acc->scram_server_key);
	if (acc->channels)
	{
		for (char **c = acc->channels; *c; c++)
			free(*c);
		free(acc->channels);
	}
    /* Free online member list (Client* pointers are NOT freed) */
	AccountMember *m = acc->members, *mnext;
	while (m)
	{
		mnext = m->next;
		free(m);
		m = mnext;
	}
	free_metadata(acc->metadata_head);
	free(acc);
}

int write_account_to_db(const Account *acc)
{
	const char *sql =
	    "INSERT INTO accounts"
	    " (name, email, password, time_registered, verified,"
	    "  verify_code, verify_expires,"
	    "  scram_salt, scram_iterations, scram_stored_key, scram_server_key,"
	    "  twofa_enabled)"
	    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
	sqlite3_stmt *stmt;
	int result;

	if (!obsidian_db)
		return 0;
	if (find_account(acc->name))
		return 0; /* already exists */

	if (sqlite3_prepare_v2(obsidian_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;

	sqlite3_bind_text(stmt, 1, acc->name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, acc->email, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, acc->password, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 4, (int)acc->time_registered);
	sqlite3_bind_int(stmt, 5, acc->verified);
	if (acc->verify_code)
		sqlite3_bind_text(stmt, 6, acc->verify_code, -1, SQLITE_STATIC);
	else
		sqlite3_bind_null(stmt, 6);
	if (acc->verify_expires)
		sqlite3_bind_int(stmt, 7, (int)acc->verify_expires);
	else
		sqlite3_bind_null(stmt, 7);
	if (acc->scram_salt)
		sqlite3_bind_text(stmt, 8, acc->scram_salt, -1, SQLITE_STATIC);
	else
		sqlite3_bind_null(stmt, 8);
	if (acc->scram_iterations)
		sqlite3_bind_int(stmt, 9, acc->scram_iterations);
	else
		sqlite3_bind_null(stmt, 9);
	if (acc->scram_stored_key)
		sqlite3_bind_text(stmt, 10, acc->scram_stored_key, -1, SQLITE_STATIC);
	else
		sqlite3_bind_null(stmt, 10);
	if (acc->scram_server_key)
		sqlite3_bind_text(stmt, 11, acc->scram_server_key, -1, SQLITE_STATIC);
	else
		sqlite3_bind_null(stmt, 11);
	sqlite3_bind_int(stmt, 12, acc->twofa_enabled);

	result = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return result == SQLITE_DONE ? 1 : 0;
}

int update_account_twofa_enabled(const Account *acc)
{
	const char *sql = "UPDATE accounts SET twofa_enabled = ? WHERE id = ?";
	sqlite3_stmt *stmt;
	int result;

	if (!obsidian_db)
		return 0;
	if (sqlite3_prepare_v2(obsidian_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;
	sqlite3_bind_int(stmt, 1, acc->twofa_enabled);
	sqlite3_bind_int(stmt, 2, (int)acc->id);
	result = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return result == SQLITE_DONE ? 1 : 0;
}

/* Persist a password rehash (used by the verifier-dispatcher upgrade
 * path: after a successful non-argon2id verify we rehash with argon2id
 * and call this). */
int update_account_password(const Account *acc)
{
	const char *sql =
	    "UPDATE accounts SET password = ?, password_scheme = ? WHERE id = ?";
	sqlite3_stmt *stmt;
	int result;

	if (!obsidian_db)
		return 0;
	if (sqlite3_prepare_v2(obsidian_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;

	sqlite3_bind_text(stmt, 1, acc->password, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2,
	                  acc->password_scheme ? acc->password_scheme : "argon2id",
	                  -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 3, (int)acc->id);

	result = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return result == SQLITE_DONE ? 1 : 0;
}

int update_account_scram(const Account *acc)
{
	const char *sql =
	    "UPDATE accounts SET scram_salt = ?, scram_iterations = ?,"
	    "  scram_stored_key = ?, scram_server_key = ?"
	    " WHERE id = ?";
	sqlite3_stmt *stmt;
	int result;

	if (!obsidian_db)
		return 0;
	if (sqlite3_prepare_v2(obsidian_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;

	sqlite3_bind_text(stmt, 1, acc->scram_salt, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 2, acc->scram_iterations);
	sqlite3_bind_text(stmt, 3, acc->scram_stored_key, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, acc->scram_server_key, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 5, (int)acc->id);

	result = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return result == SQLITE_DONE ? 1 : 0;
}

int update_account_verification(const Account *acc)
{
	const char *sql =
	    "UPDATE accounts SET verified = ?, verify_code = ?, verify_expires = ?"
	    " WHERE id = ?";
	sqlite3_stmt *stmt;
	int result;

	if (!obsidian_db)
		return 0;
	if (sqlite3_prepare_v2(obsidian_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;

	sqlite3_bind_int(stmt, 1, acc->verified);
	if (acc->verify_code)
		sqlite3_bind_text(stmt, 2, acc->verify_code, -1, SQLITE_STATIC);
	else
		sqlite3_bind_null(stmt, 2);
	if (acc->verify_expires)
		sqlite3_bind_int(stmt, 3, (int)acc->verify_expires);
	else
		sqlite3_bind_null(stmt, 3);
	sqlite3_bind_int(stmt, 4, (int)acc->id);

	result = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return result == SQLITE_DONE ? 1 : 0;
}

Account **read_accounts_from_db(const char *name)
{
	const char *sql_all = "SELECT id,name,email,password,time_registered,verified,"
	                      "verify_code,verify_expires,"
	                      "scram_salt,scram_iterations,scram_stored_key,scram_server_key,"
	                      "twofa_enabled,password_scheme"
	                      " FROM accounts";
	const char *sql_one = "SELECT id,name,email,password,time_registered,verified,"
	                      "verify_code,verify_expires,"
	                      "scram_salt,scram_iterations,scram_stored_key,scram_server_key,"
	                      "twofa_enabled,password_scheme"
	                      " FROM accounts WHERE lower(name) = lower(?) LIMIT 1";
	sqlite3_stmt *stmt;
	Account **accounts = NULL;
	size_t count = 0;
	Client *cptr;

	if (!obsidian_db)
		return NULL;

	if (sqlite3_prepare_v2(obsidian_db, name ? sql_one : sql_all, -1, &stmt, NULL) != SQLITE_OK)
		return NULL;

	if (name)
		sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

	while (sqlite3_step(stmt) == SQLITE_ROW)
	{
		Account *acc = safe_alloc(sizeof(Account));
		const unsigned char *col;
		acc->id = sqlite3_column_int(stmt, 0);
		col = sqlite3_column_text(stmt, 1);
		acc->name = strdup(col ? (const char *)col : "");
		col = sqlite3_column_text(stmt, 2);
		acc->email = strdup(col ? (const char *)col : "");
		col = sqlite3_column_text(stmt, 3);
		acc->password = strdup(col ? (const char *)col : "");
		acc->time_registered = (time_t)sqlite3_column_int(stmt, 4);
		acc->verified = sqlite3_column_int(stmt, 5);
		col = sqlite3_column_text(stmt, 6);
		acc->verify_code = col ? strdup((const char *)col) : NULL;
		acc->verify_expires = (time_t)sqlite3_column_int(stmt, 7);
		col = sqlite3_column_text(stmt, 8);
		acc->scram_salt = col ? strdup((const char *)col) : NULL;
		acc->scram_iterations = sqlite3_column_int(stmt, 9);
		col = sqlite3_column_text(stmt, 10);
		acc->scram_stored_key = col ? strdup((const char *)col) : NULL;
		col = sqlite3_column_text(stmt, 11);
		acc->scram_server_key = col ? strdup((const char *)col) : NULL;
		acc->twofa_enabled = sqlite3_column_int(stmt, 12);
		col = sqlite3_column_text(stmt, 13);
		acc->password_scheme = col && *col ? strdup((const char *)col) : NULL;
		acc->channels = NULL;
		acc->metadata_head = NULL;
		acc->members = NULL;

        /* Populate online clients for this account */
		list_for_each_entry(cptr, &client_list, client_node)
		{
			if (IsUser(cptr) && IsLoggedIn(cptr) &&
			    !strcasecmp(cptr->user->account, acc->name))
			{
				AccountMember *member = safe_alloc(sizeof(AccountMember));
				member->client = cptr;
				member->next = acc->members;
				acc->members = member;
			}
		}

		Account **tmp = realloc(accounts, sizeof(Account *) * (count + 2));
		if (!tmp)
		{
			for (size_t i = 0; accounts && accounts[i]; i++)
				free_account(accounts[i]);
			free(accounts);
			sqlite3_finalize(stmt);
			free_account(acc);
			return NULL;
		}
		accounts = tmp;
		accounts[count++] = acc;
	}
	sqlite3_finalize(stmt);

	if (!accounts)
	{
		accounts = safe_alloc(sizeof(Account *));
		accounts[0] = NULL;
	} else
	{
		accounts[count] = NULL;
	}
	return accounts;
}

Account *find_account(const char *name)
{
	Account **accounts;
	Account *result = NULL;

	if (!obsidian_db || !name)
		return NULL;

	accounts = read_accounts_from_db(name);
	if (!accounts)
		return NULL;

	if (accounts[0])
	{
		result = accounts[0];
		accounts[0] = NULL; /* don't free the result */
	}
	for (size_t i = 0; accounts[i]; i++)
		free_account(accounts[i]);
	free(accounts);
	return result;
}

Account *find_account_by_client(Client *client)
{
	if (!obsidian_db || !client || !IsLoggedIn(client))
		return NULL;
	return find_account(client->user->account);
}

/* ===================================================================
 * Metadata helpers
 * =================================================================== */
Metadata *create_metadata(const char *key, const char *value)
{
	Metadata *m = safe_alloc(sizeof(Metadata));
	m->key = strdup(key);
	m->value = strdup(value);
	m->prev = m->next = NULL;
	return m;
}

void add_metadata(Account *acc, const char *key, const char *value)
{
	Metadata *m = create_metadata(key, value);
	m->next = acc->metadata_head;
	if (acc->metadata_head)
		acc->metadata_head->prev = m;
	acc->metadata_head = m;
}

void free_metadata(Metadata *head)
{
	Metadata *cur = head, *tmp;
	while (cur)
	{
		tmp = cur->next;
		free(cur->key);
		free(cur->value);
		free(cur);
		cur = tmp;
	}
}

/* ===================================================================
 * TKL nameban check
 * =================================================================== */
TKL *my_find_tkl_nameban(const char *name)
{
	TKL *tkl;
	for (tkl = tklines[tkl_hash('Q')]; tkl; tkl = tkl->next)
	{
		if (!TKLIsNameBan(tkl))
			continue;
		if (!strcasecmp(name, tkl->ptr.nameban->name))
			return tkl;
	}
	return NULL;
}

/* ===================================================================
 * SASL ModData serialization
 * =================================================================== */
void sat_free(ModData *m)
{
	m->i = 0;
}

const char *sat_serialize(ModData *m)
{
	static char buf[32];
	if (m->i == 0)
		return NULL;
	snprintf(buf, sizeof(buf), "%d", m->i);
	return buf;
}

void sat_unserialize(const char *str, ModData *m)
{
	m->i = atoi(str);
}

/* ===================================================================
 * OAuth 2.0 / OIDC bearer token validation + linking + SASL mechs.
 *
 * Flow:
 *
 *   1. Admin configures `account-registration { oauth-provider "name"
 *      { issuer ...; audience ...; jwks-file ...; subject-claim ...; } }`.
 *      JWKS is read from disk at module load + every /REHASH.
 *
 *   2. End user authenticates by their existing local creds (SASL
 *      PLAIN / SCRAM / EXTERNAL) and runs:
 *
 *           /OAUTHLINK ADD logto <token>
 *
 *      Server validates the token, extracts subject, inserts into
 *      account_oauth_links. /OAUTHLINK LIST shows current links;
 *      /OAUTHLINK REMOVE <provider> drops one.
 *
 *   3. Subsequent SASL OAUTHBEARER (RFC 7628) or SASL IRCV3BEARER
 *      from the same client matches the JWT against the link table
 *      and logs them straight in -- no password prompt.
 * =================================================================== */

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/param_build.h>
#include <jansson.h>
#include <crypt.h>     /* for libcrypt's crypt_r() — bcrypt + crypt-sha256/512 */
#include "crypt_blowfish.h" /* for ergo's sha3-prehash bcrypt path */
#include <string.h>

/* base64url-decode `in` of length `inlen` into `out`. Accepts
 * both padded and unpadded input; tolerates '+/' as well as '-_'.
 * Returns the number of bytes decoded, or -1 on bad input. */
static int oauth_b64url_decode(const char *in, int inlen, unsigned char *out, int outcap)
{
	char *tmp;
	int padlen = (4 - (inlen & 3)) & 3;
	if (inlen + padlen >= 65536)
		return -1;
	tmp = safe_alloc(inlen + padlen + 1);
	int j = 0;
	for (int i = 0; i < inlen; i++)
	{
		char c = in[i];
		if (c == '-')
			c = '+';
		else if (c == '_')
			c = '/';
		tmp[j++] = c;
	}
	int realpad = padlen > 2 ? 2 : padlen;
	while (padlen--)
		tmp[j++] = '=';
	tmp[j] = 0;
	int n = EVP_DecodeBlock(out, (const unsigned char *)tmp, j);
	safe_free(tmp);
	if (n <= 0)
		return -1;
	n -= realpad;
	if (n < 0 || n > outcap)
		return -1;
	return n;
}

/* Build an RSA EVP_PKEY from base64url-encoded modulus 'n' + exponent 'e'. */
static EVP_PKEY *jwks_build_rsa_key(const char *n_b64u, const char *e_b64u)
{
	unsigned char n_buf[1024], e_buf[16];
	int nlen = oauth_b64url_decode(n_b64u, strlen(n_b64u), n_buf, sizeof(n_buf));
	int elen = oauth_b64url_decode(e_b64u, strlen(e_b64u), e_buf, sizeof(e_buf));
	if (nlen <= 0 || elen <= 0)
		return NULL;
	BIGNUM *bn_n = BN_bin2bn(n_buf, nlen, NULL);
	BIGNUM *bn_e = BN_bin2bn(e_buf, elen, NULL);
	if (!bn_n || !bn_e)
	{
		BN_free(bn_n);
		BN_free(bn_e);
		return NULL;
	}
	OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
	OSSL_PARAM_BLD_push_BN(bld, "n", bn_n);
	OSSL_PARAM_BLD_push_BN(bld, "e", bn_e);
	OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
	OSSL_PARAM_BLD_free(bld);

	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	EVP_PKEY *pkey = NULL;
	if (pctx)
	{
		EVP_PKEY_fromdata_init(pctx);
		EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
		EVP_PKEY_CTX_free(pctx);
	}
	OSSL_PARAM_free(params);
	BN_free(bn_n);
	BN_free(bn_e);
	return pkey;
}

static void oauth_free_keys(OAuthProvider *p)
{
	for (int i = 0; i < p->nkeys; i++)
	{
		safe_free(p->keys[i].kid);
		safe_free(p->keys[i].alg);
		safe_free(p->keys[i].kty);
		if (p->keys[i].pkey)
			EVP_PKEY_free(p->keys[i].pkey);
	}
	memset(p->keys, 0, sizeof(p->keys));
	p->nkeys = 0;
	p->loaded = 0;
}

/* Read a JWKS json file and populate p->keys[]. Returns 1 on success. */
static int oauth_load_jwks_file(OAuthProvider *p)
{
	json_error_t jerr;
	json_t *root = NULL, *keys, *k;
	size_t i;

	oauth_free_keys(p);
	if (!p->jwks_file)
		return 0;

	root = json_load_file(p->jwks_file, 0, &jerr);
	if (!root)
	{
		unreal_log(ULOG_ERROR, "account", "OAUTH_JWKS_LOAD_ERROR", NULL,
		           "Could not parse JWKS file $file: $err",
		           log_data_string("file", p->jwks_file),
		           log_data_string("err", jerr.text));
		return 0;
	}
	keys = json_object_get(root, "keys");
	if (!json_is_array(keys))
	{
		json_decref(root);
		return 0;
	}
	json_array_foreach(keys, i, k)
	{
		if (p->nkeys >= MAX_OAUTH_JWKS_KEYS)
			break;
		const char *kty = json_string_value(json_object_get(k, "kty"));
		const char *kid = json_string_value(json_object_get(k, "kid"));
		const char *alg = json_string_value(json_object_get(k, "alg"));
		if (!kty)
			continue;
		EVP_PKEY *pkey = NULL;
		if (!strcmp(kty, "RSA"))
		{
			const char *n = json_string_value(json_object_get(k, "n"));
			const char *e = json_string_value(json_object_get(k, "e"));
			if (!n || !e)
				continue;
			pkey = jwks_build_rsa_key(n, e);
		} else
		{
            /* EC and other key types: skipped for now. RSA covers
             * Logto, Auth0, Keycloak, Okta defaults. */
			continue;
		}
		if (!pkey)
			continue;
		OAuthJwksKey *slot = &p->keys[p->nkeys++];
		slot->kid = kid ? strdup(kid) : strdup("");
		slot->alg = alg ? strdup(alg) : strdup("RS256");
		slot->kty = strdup(kty);
		slot->pkey = pkey;
	}
	json_decref(root);
	p->loaded = 1;
	unreal_log(ULOG_INFO, "account", "OAUTH_JWKS_LOADED", NULL,
	           "Loaded $count JWKS keys for provider $provider",
	           log_data_integer("count", p->nkeys),
	           log_data_string("provider", p->name));
	return p->nkeys > 0;
}

static OAuthProvider *oauth_find_provider(const char *name)
{
	for (OAuthProvider *p = oauth_providers; p; p = p->next)
		if (!strcasecmp(p->name, name))
			return p;
	return NULL;
}

static OAuthJwksKey *oauth_find_key(OAuthProvider *p, const char *kid)
{
    /* Prefer kid match; fall back to first if token has no kid */
	if (kid)
	{
		for (int i = 0; i < p->nkeys; i++)
			if (p->keys[i].kid && !strcmp(p->keys[i].kid, kid))
				return &p->keys[i];
		return NULL;
	}
	return p->nkeys > 0 ? &p->keys[0] : NULL;
}

/* Validate a JWT. On success returns a strdup'd subject string the
 * caller must free, AND fills *out_provider with the provider used.
 * On failure returns NULL. */
static char *oauth_validate_jwt(const char *token, OAuthProvider **out_provider)
{
	const char *dot1 = strchr(token, '.');
	if (!dot1)
		return NULL;
	const char *dot2 = strchr(dot1 + 1, '.');
	if (!dot2)
		return NULL;
	const char *header_b64 = token;
	int header_len = (int)(dot1 - header_b64);
	const char *payload_b64 = dot1 + 1;
	int payload_len = (int)(dot2 - payload_b64);
	const char *sig_b64 = dot2 + 1;
	int sig_len = (int)strlen(sig_b64);
	if (header_len <= 0 || payload_len <= 0 || sig_len <= 0)
		return NULL;

	unsigned char header_buf[2048], payload_buf[8192], sig_buf[1024];
	int hl = oauth_b64url_decode(header_b64, header_len, header_buf, sizeof(header_buf) - 1);
	int pl = oauth_b64url_decode(payload_b64, payload_len, payload_buf, sizeof(payload_buf) - 1);
	int sl = oauth_b64url_decode(sig_b64, sig_len, sig_buf, sizeof(sig_buf));
	if (hl <= 0 || pl <= 0 || sl <= 0)
		return NULL;
	header_buf[hl] = 0;
	payload_buf[pl] = 0;

    /* --- Parse header --- */
	json_error_t jerr;
	json_t *header = json_loadb((const char *)header_buf, hl, 0, &jerr);
	if (!header)
		return NULL;
	const char *alg = json_string_value(json_object_get(header, "alg"));
	const char *kid = json_string_value(json_object_get(header, "kid"));
	if (!alg)
	{
		json_decref(header);
		return NULL;
	}
	char alg_dup[16];
	strlcpy(alg_dup, alg, sizeof(alg_dup));
	char *kid_dup = kid ? strdup(kid) : NULL;
	json_decref(header);

    /* --- Parse payload --- */
	json_t *payload = json_loadb((const char *)payload_buf, pl, 0, &jerr);
	if (!payload)
	{
		safe_free(kid_dup);
		return NULL;
	}
	const char *iss = json_string_value(json_object_get(payload, "iss"));
	json_t *exp_j = json_object_get(payload, "exp");
	json_t *nbf_j = json_object_get(payload, "nbf");

    /* --- Find provider by issuer --- */
	OAuthProvider *prov = NULL;
	if (iss)
	{
		for (OAuthProvider *p = oauth_providers; p; p = p->next)
		{
			if (p->issuer && !strcmp(p->issuer, iss))
			{
				prov = p;
				break;
			}
		}
	}
	if (!prov || !prov->loaded)
	{
		json_decref(payload);
		safe_free(kid_dup);
		return NULL;
	}

    /* --- Audience check: aud may be a string or array of strings --- */
	if (prov->audience)
	{
		json_t *aud_j = json_object_get(payload, "aud");
		int aud_ok = 0;
		if (json_is_string(aud_j))
		{
			aud_ok = !strcmp(json_string_value(aud_j), prov->audience);
		} else if (json_is_array(aud_j))
		{
			size_t i;
			json_t *e;
			json_array_foreach(aud_j, i, e)
			{
				if (json_is_string(e) && !strcmp(json_string_value(e), prov->audience))
				{
					aud_ok = 1;
					break;
				}
			}
		}
		if (!aud_ok)
		{
			json_decref(payload);
			safe_free(kid_dup);
			return NULL;
		}
	}

    /* --- exp / nbf --- */
	time_t now = TStime();
	if (json_is_integer(exp_j) && (time_t)json_integer_value(exp_j) < now)
	{
		json_decref(payload);
		safe_free(kid_dup);
		return NULL;
	}
	if (json_is_integer(nbf_j) && (time_t)json_integer_value(nbf_j) > now + 60)
	{
		json_decref(payload);
		safe_free(kid_dup);
		return NULL;
	}

    /* --- Find key + verify signature --- */
	OAuthJwksKey *key = oauth_find_key(prov, kid_dup);
	safe_free(kid_dup);
	if (!key || !key->pkey)
	{
		json_decref(payload);
		return NULL;
	}
	const EVP_MD *md = NULL;
	if (!strcmp(alg_dup, "RS256"))
		md = EVP_sha256();
	else if (!strcmp(alg_dup, "RS384"))
		md = EVP_sha384();
	else if (!strcmp(alg_dup, "RS512"))
		md = EVP_sha512();
	else
	{
		json_decref(payload);
		return NULL;
	}

    /* The data being signed is "<header_b64>.<payload_b64>" --
     * the original ASCII form, NOT the decoded bytes. */
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	int ok = 0;
	if (ctx &&
	    EVP_DigestVerifyInit(ctx, NULL, md, NULL, key->pkey) == 1 &&
	    EVP_DigestVerifyUpdate(ctx, header_b64, header_len) == 1 &&
	    EVP_DigestVerifyUpdate(ctx, ".", 1) == 1 &&
	    EVP_DigestVerifyUpdate(ctx, payload_b64, payload_len) == 1 &&
	    EVP_DigestVerifyFinal(ctx, sig_buf, sl) == 1)
	{
		ok = 1;
	}
	if (ctx)
		EVP_MD_CTX_free(ctx);
	if (!ok)
	{
		json_decref(payload);
		return NULL;
	}

    /* --- Extract subject claim --- */
	const char *claim = prov->subject_claim ? prov->subject_claim : "sub";
	const char *subj = json_string_value(json_object_get(payload, claim));
	char *result = subj ? strdup(subj) : NULL;
	json_decref(payload);
	if (result && out_provider)
		*out_provider = prov;
	return result;
}

/* Look up an account by id (helper). Caller frees with free_account. */
static Account *find_account_by_id(long id)
{
	sqlite3_stmt *stmt;
	Account *acc = NULL;
	char *name_copy = NULL;
	if (sqlite3_prepare_v2(obsidian_db,
	                       "SELECT name FROM accounts WHERE id = ? LIMIT 1",
	                       -1, &stmt, NULL) != SQLITE_OK)
		return NULL;
	sqlite3_bind_int64(stmt, 1, id);
	if (sqlite3_step(stmt) == SQLITE_ROW)
	{
		const unsigned char *name = sqlite3_column_text(stmt, 0);
		if (name)
			name_copy = strdup((const char *)name);
	}
	sqlite3_finalize(stmt);
	if (name_copy)
	{
		acc = find_account(name_copy);
		free(name_copy);
	}
	return acc;
}

/* OAuth credentials are stored in account_2fa_credentials with
 * type='oauth' and secret='<provider>\x1F<subject>'. */
#define OAUTH_CRED_SEP '\x1F'

/* Build the credential 'secret' string for an (provider, subject) pair. */
static char *oauth_make_cred_secret(const char *provider, const char *subject)
{
	size_t pl = strlen(provider), sl = strlen(subject);
	char *out = safe_alloc(pl + 1 + sl + 1);
	memcpy(out, provider, pl);
	out[pl] = OAUTH_CRED_SEP;
	memcpy(out + pl + 1, subject, sl);
	out[pl + 1 + sl] = 0;
	return out;
}

/* Returns account_id whose 2fa credential matches (provider, subject), or 0. */
static long oauth_lookup_account_by_credential(const char *provider, const char *subject)
{
	if (!obsidian_db)
		return 0;
	char *needle = oauth_make_cred_secret(provider, subject);
	sqlite3_stmt *stmt;
	long id = 0;
	if (sqlite3_prepare_v2(obsidian_db,
	                       "SELECT account_id FROM account_2fa_credentials"
	                       " WHERE type = 'oauth' AND secret = ? LIMIT 1",
	                       -1, &stmt, NULL) == SQLITE_OK)
	{
		sqlite3_bind_text(stmt, 1, needle, -1, SQLITE_STATIC);
		if (sqlite3_step(stmt) == SQLITE_ROW)
			id = (long)sqlite3_column_int64(stmt, 0);
		sqlite3_finalize(stmt);
	}
	safe_free(needle);
	return id;
}

/* Given a verified (provider, subject) pair, finish the SASL handshake:
 * find the linked account, optionally route into 2FA step-up, otherwise
 * complete the login. Used by both the synchronous JWT path and the
 * async userinfo callback. Returns 1 on success, 0 on failure (and
 * sends the appropriate numeric in either case). */
static int oauth_complete_login(Client *client, OAuthProvider *prov,
                                const char *subject)
{
	long acc_id = oauth_lookup_account_by_credential(prov->name, subject);
	if (acc_id == 0)
	{
		sendnumeric(client, ERR_SASLFAIL);
		sendto_one(client, NULL,
		           ":%s NOTE AUTHENTICATE OAUTH_NOT_LINKED :That OAuth identity is not linked to an account; log in via PLAIN/SCRAM and run /2FA ADD oauth <name> via /2FA CHALLENGE oauth %s first.",
		           me.name, prov->name);
		return 0;
	}
	Account *acc = find_account_by_id(acc_id);
	if (!acc)
	{
		sendnumeric(client, ERR_SASLFAIL);
		return 0;
	}
	if (twofa_maybe_start_stepup(client, acc, "oauth"))
	{
		DelSaslType(client);
		unreal_log(ULOG_INFO, "account", "OAUTH_SASL_2FA_STEPUP", client,
		           "OAuth first-factor verified; awaiting 2FA "
		           "[account: $account] [provider: $provider] [subject: $subject]",
		           log_data_string("account", acc->name),
		           log_data_string("provider", prov->name),
		           log_data_string("subject", subject));
		free_account(acc);
		return 1;
	}
	strlcpy(client->user->account, acc->name, sizeof(client->user->account));
	user_account_login(NULL, client);
	client->local->sasl_complete = 1;
	sendnumeric(client, RPL_SASLSUCCESS);
	DelSaslType(client);
	unreal_log(ULOG_INFO, "account", "OAUTH_SASL_LOGIN", client,
	           "OAuth SASL login: $client.details [account: $account] [provider: $provider] [subject: $subject]",
	           log_data_string("account", acc->name),
	           log_data_string("provider", prov->name),
	           log_data_string("subject", subject));
	free_account(acc);
	return 1;
}

/* Common JWT-path token-->account-login. Returns 1 on success
 * (and sets sasl_complete + sends RPL_SASLSUCCESS), 0 on failure
 * (and sends ERR_SASLFAIL). */
static int oauth_login_by_token(Client *client, const char *token)
{
	OAuthProvider *prov = NULL;
	char *subject = oauth_validate_jwt(token, &prov);
	if (!subject)
	{
		sendnumeric(client, ERR_SASLFAIL);
		return 0;
	}
	int rc = oauth_complete_login(client, prov, subject);
	safe_free(subject);
	return rc;
}

/* ============================================================
 * Opaque-token validation (GitHub-style)
 *
 * For tokens that are not JWTs (no embedded subject claims), we ask
 * the IdP's userinfo endpoint who the bearer is. This is the path
 * used by GitHub, Discord, Slack, Reddit, Twitter, etc. -- any IdP
 * that issues OAuth2 access tokens without an OIDC id_token.
 *
 * We can't block the IRC server while waiting for the upstream HTTP
 * response, so the SASL handshake is suspended: we emit no numeric
 * after the AUTHENTICATE payload arrives, kick off url_start_async(),
 * and complete (903 / 904) inside oauth_userinfo_callback() once the
 * response lands. The client side just sees a brief stall.
 *
 * The pending request struct stashes client->id (a stable string id
 * that survives the client_t pointer becoming invalid after a
 * disconnect) so the callback can safely re-resolve the Client* and
 * bail if the user gave up first.
 * ============================================================ */
typedef enum {
	OAUTH_OP_LOGIN,   /* primary IRCV3BEARER/OAUTHBEARER */
	OAUTH_OP_ENROLL,  /* /2FA ADD oauth from a logged-in user */
	OAUTH_OP_STEPUP,  /* AUTHENTICATE 2FA-OAUTH after PLAIN/SCRAM/EXTERNAL */
} OAuthOpaqueOp;

typedef struct {
	OAuthOpaqueOp op;
	char *session_id;       /* client->id at request time */
	char *provider_name;    /* re-resolved on callback to dodge /REHASH */
    /* enroll-only: */
	long account_id;
	char *credential_name;
    /* stepup-only: must match the account that primary auth verified */
	char *stepup_account;
} OAuthOpaquePending;

static void oauth_opaque_free(OAuthOpaquePending *p)
{
	if (!p)
		return;
	safe_free(p->session_id);
	safe_free(p->provider_name);
	safe_free(p->credential_name);
	safe_free(p->stepup_account);
	safe_free(p);
}

/* Async HTTP callback: parse the userinfo JSON and either complete
 * SASL (903) or fail (904). */
static void oauth_userinfo_callback(OutgoingWebRequest *request,
                                    OutgoingWebResponse *response)
{
	OAuthOpaquePending *pending = (OAuthOpaquePending *)response->ptr;
	if (!pending)
		return;

	Client *client = hash_find_id(pending->session_id, NULL);
	if (!client || !client->local)
	{
		oauth_opaque_free(pending);
		return;
	}

	OAuthProvider *prov = oauth_find_provider(pending->provider_name);
	if (!prov)
	{
		sendnumeric(client, ERR_SASLFAIL);
		oauth_opaque_free(pending);
		return;
	}

	if (response->errorbuf)
	{
		unreal_log(ULOG_WARNING, "account", "OAUTH_USERINFO_HTTP_ERROR", client,
		           "Userinfo fetch failed for provider $provider: $err",
		           log_data_string("provider", prov->name),
		           log_data_string("err", response->errorbuf));
		sendnumeric(client, ERR_SASLFAIL);
		oauth_opaque_free(pending);
		return;
	}
	if (!response->memory || response->memory_len <= 0)
	{
		sendnumeric(client, ERR_SASLFAIL);
		oauth_opaque_free(pending);
		return;
	}

	json_error_t jerr;
	json_t *body = json_loadb(response->memory, response->memory_len, 0, &jerr);
	if (!body)
	{
		sendnumeric(client, ERR_SASLFAIL);
		oauth_opaque_free(pending);
		return;
	}
    /* Subject claim may be a string ("login") or an integer ("id" on
     * GitHub). Coerce integers to a decimal string so the credential
     * row format matches what /2FA CHALLENGE oauth + /2FA TOKEN +
     * /2FA ADD oauth stored. */
	const char *claim = prov->subject_claim ? prov->subject_claim : "sub";
	json_t *sj = json_object_get(body, claim);
	char subject_buf[128];
	const char *subject = NULL;
	if (json_is_string(sj))
	{
		subject = json_string_value(sj);
	} else if (json_is_integer(sj))
	{
		snprintf(subject_buf, sizeof(subject_buf), "%lld",
		         (long long)json_integer_value(sj));
		subject = subject_buf;
	}
	if (!subject || !*subject)
	{
		json_decref(body);
		if (pending->op == OAUTH_OP_LOGIN || pending->op == OAUTH_OP_STEPUP)
			sendnumeric(client, ERR_SASLFAIL);
		else
			twofa_fail(client, "INVALID_CREDENTIAL_DATA", NULL,
			           "Userinfo response had no subject claim.");
		oauth_opaque_free(pending);
		return;
	}
	if (pending->op == OAUTH_OP_LOGIN)
	{
		oauth_complete_login(client, prov, subject);
	} else if (pending->op == OAUTH_OP_STEPUP)
	{
        /* The bearer must resolve to a (provider, subject) credential
         * already bound to the account that primary auth verified. */
		long bound = oauth_lookup_account_by_credential(prov->name, subject);
		Account *acc = pending->stepup_account
		                   ? find_account(pending->stepup_account)
		                   : NULL;
		int ok = acc && bound == acc->id;
		if (!ok)
		{
			sendnumeric(client, ERR_SASLFAIL);
			twofa_clear_stepup(client);
			DelSaslType(client);
		} else
		{
			strlcpy(client->user->account, acc->name,
			        sizeof(client->user->account));
			user_account_login(NULL, client);
			if (!IsDead(client))
			{
				client->local->sasl_complete = 1;
				sendnumeric(client, RPL_SASLSUCCESS);
			}
			DelSaslType(client);
			twofa_clear_stepup(client);
			unreal_log(ULOG_INFO, "account", "SASL_LOGIN", client,
			           "SASL+2FA-OAUTH login for $client.details "
			           "[account: $account] [provider: $provider]",
			           log_data_string("account", acc->name),
			           log_data_string("provider", prov->name));
		}
		if (acc)
			free_account(acc);
	} else
	{
        /* Enrollment path: store the credential row and tell the user. */
		char *cred = oauth_make_cred_secret(prov->name, subject);
		long existing = oauth_lookup_account_by_credential(prov->name, subject);
		if (existing && existing != pending->account_id)
		{
			twofa_fail(client, "ALREADY_LINKED", NULL,
			           "That OAuth identity is already linked to another account.");
			safe_free(cred);
		} else if (existing == pending->account_id)
		{
			sendto_one(client, NULL,
			           ":%s 2FA ADD ALREADY_LINKED oauth %s :Already linked.",
			           me.name, prov->name);
			safe_free(cred);
		} else
		{
			long int new_id = 0;
			if (!twofa_insert_credential(pending->account_id, "oauth",
			                             pending->credential_name, cred,
			                             &new_id))
			{
				twofa_fail(client, "TEMPORARILY_UNAVAILABLE", NULL,
				           "Could not persist credential.");
			} else
			{
				char id_buf[TWOFA_ID_MAX + 1];
				format_cred_id(id_buf, sizeof(id_buf), new_id);
				sendto_one(client, NULL,
				           ":%s 2FA ADD SUCCESS oauth %s :Credential '%s' "
				           "registered (provider=%s subject=%s).",
				           me.name, id_buf, pending->credential_name,
				           prov->name, subject);
				unreal_log(ULOG_INFO, "account", "2FA_OAUTH_LINK", client,
				           "$client.details linked OAuth identity to "
				           "account [provider: $provider] [subject: $subject]",
				           log_data_string("provider", prov->name),
				           log_data_string("subject", subject));
			}
			safe_free(cred);
		}
		twofa_clear_enroll(client);
	}
	json_decref(body);
	oauth_opaque_free(pending);
}

/* Internal helper: assemble + dispatch the userinfo HTTP request. */
static void oauth_userinfo_request(OAuthProvider *prov, const char *token,
                                   OAuthOpaquePending *pending)
{
	NameValuePrioList *headers = NULL;
	char auth[1024];
	snprintf(auth, sizeof(auth), "Bearer %s", token);
	add_nvplist(&headers, 0, "Authorization", auth);
    /* GitHub demands a User-Agent or returns 403; harmless on others. */
	add_nvplist(&headers, 0, "User-Agent", "obbyircd/oauth");
	add_nvplist(&headers, 0, "Accept", "application/json");

	OutgoingWebRequest *w = safe_alloc(sizeof(OutgoingWebRequest));
	safe_strdup(w->url, prov->userinfo_url);
	w->http_method = HTTP_METHOD_GET;
	w->headers = headers;
	w->max_redirects = 1;
	w->connect_timeout = 10;
	w->transfer_timeout = 15;
	safe_strdup(w->apicallback, "oauth_userinfo_callback");
	w->callback_data = pending;

	url_start_async(w);
}

/* SASL login path: validate an opaque token via userinfo, then
 * complete the SASL handshake. Returns 1 if the request was enqueued
 * (caller MUST NOT send any SASL numeric -- the callback will), 0 if
 * the kickoff itself failed (caller has already gotten ERR_SASLFAIL). */
static int oauth_validate_opaque_async(Client *client, OAuthProvider *prov,
                                       const char *token)
{
	if (!prov->userinfo_url || !*prov->userinfo_url)
	{
		sendnumeric(client, ERR_SASLFAIL);
		return 0;
	}
	OAuthOpaquePending *pending = safe_alloc(sizeof(*pending));
	pending->op = OAUTH_OP_LOGIN;
	safe_strdup(pending->session_id, client->id);
	safe_strdup(pending->provider_name, prov->name);
	oauth_userinfo_request(prov, token, pending);
	return 1;
}

/* /2FA ADD oauth path for opaque providers: validate via userinfo,
 * then store a credential row keyed by (provider, subject). */
static int oauth_enroll_opaque_async(Client *client, OAuthProvider *prov,
                                     const char *token, long account_id,
                                     const char *credential_name)
{
	if (!prov->userinfo_url || !*prov->userinfo_url)
	{
		twofa_fail(client, "NO_SUCH_PROVIDER", prov->name,
		           "Opaque-token provider missing userinfo-url config.");
		return 0;
	}
	OAuthOpaquePending *pending = safe_alloc(sizeof(*pending));
	pending->op = OAUTH_OP_ENROLL;
	pending->account_id = account_id;
	safe_strdup(pending->session_id, client->id);
	safe_strdup(pending->provider_name, prov->name);
	safe_strdup(pending->credential_name, credential_name);
	oauth_userinfo_request(prov, token, pending);
	return 1;
}

/* AUTHENTICATE 2FA-OAUTH path: validate the bearer (sync for JWT, async
 * for opaque) and only complete login if the resulting (provider,
 * subject) is bound to the account that primary auth proved. */
static int oauth_stepup_opaque_async(Client *client, OAuthProvider *prov,
                                     const char *token,
                                     const char *expected_account)
{
	if (!prov->userinfo_url || !*prov->userinfo_url)
	{
		sendnumeric(client, ERR_SASLFAIL);
		return 0;
	}
	OAuthOpaquePending *pending = safe_alloc(sizeof(*pending));
	pending->op = OAUTH_OP_STEPUP;
	safe_strdup(pending->session_id, client->id);
	safe_strdup(pending->provider_name, prov->name);
	safe_strdup(pending->stepup_account, expected_account);
	oauth_userinfo_request(prov, token, pending);
	return 1;
}

/* --- Multi-line AUTHENTICATE accumulator ---
 * The IRC SASL spec splits payloads bigger than 400 base64 chars
 * across multiple AUTHENTICATE lines. Final chunk is < 400 chars
 * (possibly empty -- indicated by a literal "+"). */
static void oauth_sasl_md_free(ModData *m)
{
	OAuthSaslBuf *b = (OAuthSaslBuf *)m->ptr;
	if (b)
	{
		safe_free(b->buf);
		safe_free(b);
		m->ptr = NULL;
	}
}

static void oauth_sasl_clear(Client *client)
{
	if (!client || !client->local)
		return;
	ModData *m = &moddata_local_client(client, oauth_sasl_md);
	OAuthSaslBuf *b = (OAuthSaslBuf *)m->ptr;
	if (b)
	{
		safe_free(b->buf);
		safe_free(b);
		m->ptr = NULL;
	}
}

static const char *oauth_sasl_accumulate(Client *client, const char *param)
{
	if (!client || !client->local || !param)
		return NULL;
	ModData *m = &moddata_local_client(client, oauth_sasl_md);
	OAuthSaslBuf *b = (OAuthSaslBuf *)m->ptr;
	if (!b)
	{
		b = safe_alloc(sizeof(*b));
		b->buf = NULL;
		b->len = 0;
		b->cap = 0;
		m->ptr = b;
	}

    /* Bare "+" is the empty-final-chunk signal -- finalize whatever we
     * have buffered. Don't append. */
	int is_plus = (param[0] == '+' && param[1] == 0);
	size_t plen = strlen(param);
	int is_final = is_plus || plen < 400;

	if (!is_plus && plen > 0)
	{
		size_t need = b->len + plen + 1;
		if (need > b->cap)
		{
			size_t nc = b->cap ? b->cap : 512;
			while (nc < need)
				nc *= 2;
			char *nb = safe_alloc(nc);
			if (b->buf)
				memcpy(nb, b->buf, b->len);
			safe_free(b->buf);
			b->buf = nb;
			b->cap = nc;
		}
		memcpy(b->buf + b->len, param, plen);
		b->len += plen;
		b->buf[b->len] = 0;
	}

	if (!is_final)
		return NULL;
    /* Reject empty final */
	if (b->len == 0)
	{
		oauth_sasl_clear(client);
		return NULL;
	}
    /* Caller will read b->buf, then we free in caller via oauth_sasl_clear. */
	return b->buf;
}

/* --- SASL OAUTHBEARER (RFC 7628) ---
 * Client sends GS2-framed:
 *   n,a=username,\x01host=..\x01port=..\x01auth=Bearer <token>\x01\x01
 * We only care about the auth=Bearer token. */
static int oauthbearer_dispatch(Client *client, const char *param)
{
    /* Decode base64 SASL payload (standard base64, not base64url). */
	unsigned char buf[8192] = {0};
	int n = EVP_DecodeBlock(buf, (const unsigned char *)param, strlen(param));
	if (n <= 0)
	{
		sendnumeric(client, ERR_SASLFAIL);
		return 0;
	}
	size_t plen = strlen(param);
	int real_pad = 0;
	if (plen >= 1 && param[plen - 1] == '=')
		real_pad++;
	if (plen >= 2 && param[plen - 2] == '=')
		real_pad++;
	n -= real_pad;
	if (n <= 0 || n >= (int)sizeof(buf))
	{
		sendnumeric(client, ERR_SASLFAIL);
		return 0;
	}
	buf[n] = 0;

    /* Walk to the first 0x01 (start of key=value pairs). */
	const char *p = (const char *)buf;
	const char *end = (const char *)buf + n;
	const char *kv = memchr(p, 0x01, end - p);
	if (!kv)
	{
		sendnumeric(client, ERR_SASLFAIL);
		return 0;
	}
	kv++;

    /* Pull out auth=Bearer <token>, plus an optional provider=<name>
     * hint that lets the caller route opaque tokens to the right
     * userinfo endpoint. The provider hint is an obbyircd extension
     * over RFC 7628 -- vanilla OAUTHBEARER clients omit it and we
     * treat the token as a JWT. */
	const char *token = NULL;
	static char prov_buf[128];
	prov_buf[0] = 0;
	while (kv < end)
	{
		const char *eol = memchr(kv, 0x01, end - kv);
		if (!eol)
			break;
		size_t len = eol - kv;
		if (len >= 13 && !strncmp(kv, "auth=Bearer ", 12))
		{
			static char tokbuf[8192];
			size_t tlen = len - 12;
			if (tlen < sizeof(tokbuf))
			{
				memcpy(tokbuf, kv + 12, tlen);
				tokbuf[tlen] = 0;
				token = tokbuf;
			}
		} else if (len > 9 && !strncmp(kv, "provider=", 9))
		{
			size_t plen = len - 9;
			if (plen < sizeof(prov_buf))
			{
				memcpy(prov_buf, kv + 9, plen);
				prov_buf[plen] = 0;
			}
		}
		kv = eol + 1;
	}
	if (!token)
	{
		sendnumeric(client, ERR_SASLFAIL);
		return 0;
	}
	if (prov_buf[0])
	{
		OAuthProvider *prov = oauth_find_provider(prov_buf);
		if (!prov || !prov->loaded || !prov->userinfo_url)
		{
			sendnumeric(client, ERR_SASLFAIL);
			return 0;
		}
		return oauth_validate_opaque_async(client, prov, token);
	}
	return oauth_login_by_token(client, token);
}

/* --- SASL IRCV3BEARER ---
 *   [authzid] \x00 <token_type> \x00 <token>
 * We accept oauth2 / jwt token types (treated identically -- both
 * route through oauth_validate_jwt; an opaque-typed token would
 * need a separate validator). */
static int ircv3bearer_dispatch(Client *client, const char *param)
{
	unsigned char buf[8192] = {0};
	int n = EVP_DecodeBlock(buf, (const unsigned char *)param, strlen(param));
	if (n <= 0)
	{
		sendnumeric(client, ERR_SASLFAIL);
		return 0;
	}
    /* EVP_DecodeBlock pads its output to a multiple of 3 bytes; the
     * extra bytes correspond to '=' padding in the base64 input. Trim
     * those, but ONLY based on the input padding count -- we cannot use
     * data values to find the boundary because real payloads contain
     * NUL bytes. */
	size_t plen = strlen(param);
	int real_pad = 0;
	if (plen >= 1 && param[plen - 1] == '=')
		real_pad++;
	if (plen >= 2 && param[plen - 2] == '=')
		real_pad++;
	n -= real_pad;
	if (n <= 0 || n >= (int)sizeof(buf))
	{
		sendnumeric(client, ERR_SASLFAIL);
		return 0;
	}
	buf[n] = 0;

	int nul1 = -1, nul2 = -1;
	for (int i = 0; i < n; i++)
	{
		if (buf[i] == 0)
		{
			if (nul1 < 0)
				nul1 = i;
			else if (nul2 < 0)
			{
				nul2 = i;
				break;
			}
		}
	}
	if (nul1 < 0 || nul2 < 0 || nul2 + 1 >= n)
	{
		sendnumeric(client, ERR_SASLFAIL);
		return 0;
	}
	const char *authzid = (const char *)buf;          /* may be empty */
	const char *type = (const char *)(buf + nul1 + 1);
	const char *token = (const char *)(buf + nul2 + 1);

    /* type=opaque routes to the userinfo HTTP path; the authzid carries
     * the provider-name hint (no per-token claims to look at, so we
     * have to be told). */
	if (!strcmp(type, "opaque"))
	{
		if (!*authzid)
		{
			sendnumeric(client, ERR_SASLFAIL);
			return 0;
		}
		OAuthProvider *prov = oauth_find_provider(authzid);
		if (!prov || !prov->loaded || !prov->userinfo_url)
		{
			sendnumeric(client, ERR_SASLFAIL);
			return 0;
		}
		return oauth_validate_opaque_async(client, prov, token);
	}

	if (strcmp(type, "oauth2") && strcmp(type, "jwt"))
	{
		sendnumeric(client, ERR_SASLFAIL);
		return 0;
	}
	return oauth_login_by_token(client, token);
}

/* ===================================================================
 * SCRAM-SHA-256 (RFC 7677) implementation
 * =================================================================== */

/* ===================================================================
 * Password-scheme verifier dispatcher.
 *
 * Migrated accounts may carry hashes from any of:
 *
 *   argon2id     -- obbyircd native (default for new registrations)
 *   bcrypt       -- $2a$/$2b$/$2y$    (Anope, Atheme bcrypt, Ergo)
 *   pbkdf2v2     -- $z$pbkdf2-<prf>$<iter>$<salt-b64>$<hash-b64> (Atheme)
 *   crypt-sha256 -- $5$  (Atheme crypt3-sha256)
 *   crypt-sha512 -- $6$  (Atheme crypt3-sha512)
 *
 * The migration tool stamps `accounts.password_scheme`. At login,
 * verify_password_for_scheme() picks the right verifier. argon2id is
 * the only scheme that gets opportunistically upgraded -- when a
 * non-argon2id verify succeeds we re-hash with argon2id and persist
 * (best-effort; failure is non-fatal).
 *
 * "reset-required" is a sentinel meaning the source had a hash we
 * can't safely verify (raw md5/sha1/plain). Logins are rejected and
 * the user is steered toward the existing recovery flow.
 * =================================================================== */

static int crypt_verify_via_libcrypt(const char *stored, const char *password)
{
	struct crypt_data data;
	char *out;
	int eq;

	memset(&data, 0, sizeof(data));
	out = crypt_r(password, stored, &data);
	if (!out)
		return 0;
	eq = (strcmp(out, stored) == 0);
	OPENSSL_cleanse(&data, sizeof(data));
	return eq;
}

/* Verify a bcrypt hash whose input was produced by sha3-512(password),
 * i.e. Ergo's "Dropbox-style" derivation. Uses obbyircd's bundled
 * crypt_blowfish (length-aware variant) instead of libcrypt's crypt_r:
 * libcrypt would NUL-truncate the binary sha3 output, and sha3-512
 * outputs contain a 0x00 byte ~22% of the time, so the libcrypt path
 * silently fails for a large minority of users. */
static int ergo_bcrypt_verify(const char *stored, const char *password)
{
	unsigned char sum[EVP_MAX_MD_SIZE];
	unsigned int sumlen = 0;
	char out[80]; /* bcrypt output is at most 60 + NUL */
	char *p;

	if (!stored || stored[0] != '$' || stored[1] != '2')
		return 0;
	if (!EVP_Digest(password, strlen(password), sum, &sumlen,
	                EVP_sha3_512(), NULL))
		return 0;
	if (sumlen != 64)
		return 0;
	p = _crypt_blowfish_rn_n((const char *)sum, (int)sumlen,
	                         stored, out, sizeof(out));
	if (!p)
		return 0;
	return strcmp(p, stored) == 0;
}

/* base64 decoding shim using OpenSSL EVP. Returns number of decoded
 * bytes, or -1 on failure. `out` must be at least len(in) bytes.
 * Atheme's pbkdf2v2 module emits "url-safe" b64 with no padding for
 * the salt, but standard b64 with padding for the hash. We try both. */
static int b64_decode_any(const char *in, unsigned char *out, int outcap)
{
	int n = EVP_DecodeBlock(out, (const unsigned char *)in, strlen(in));
	if (n <= 0 || n > outcap)
		return -1;
    /* EVP_DecodeBlock returns the number of bytes decoded BEFORE
     * stripping pad nuls; figure out actual length by walking back
     * over '=' padding in the input. */
	int pad = 0;
	int inlen = strlen(in);
	if (inlen >= 1 && in[inlen - 1] == '=')
		pad++;
	if (inlen >= 2 && in[inlen - 2] == '=')
		pad++;
	return n - pad;
}

/* Verify an Atheme PBKDF2v2 hash. Two on-disk forms exist:
 *
 *   Old textual:     $z$pbkdf2-<prf>$<iter>$<salt-b64>$<hash-b64>
 *                    (<prf> = "sha256" or "sha512")
 *
 *   Numeric (default in Atheme 7.x):
 *     non-SCRAM:     $z$<algo>$<iter>$<salt-b64>$<hash-b64>
 *                    algo: 3,4,5,6 = HMAC-{MD5,SHA1,SHA-256,SHA-512} raw-salt
 *                          23,24,25,26 = same, with base64-string-as-salt
 *     SCRAM:         $z$<algo>$<iter>$<salt-b64>$<storedkey-b64>$<serverkey-b64>
 *                    algo: 43,44,45,46 = SCRAM-{MD5,SHA1,SHA-256,SHA-512}
 *                          63,64,65,66 = same, with base64-string-as-salt
 *                    (we verify by recomputing StoredKey only;
 *                    ServerKey is unused for the password check.)
 *
 * Numeric algo IDs come from Atheme's `pbkdf2.h`
 * (PBKDF2_PRF_HMAC_*, PBKDF2_PRF_SCRAM_*). Salt-as-b64-string
 * variants (23-26, 63-66) feed the literal base64 ASCII as the salt to
 * PBKDF2 instead of decoding first; that matches Atheme's
 * atheme_pbkdf2v2_salt_is_b64() == true branch.
 *
 * Returns 1 on match, 0 on mismatch or parse error. */
static int pbkdf2v2_verify(const char *stored, const char *password)
{
	char buf[768];
	char *p, *iter_part, *salt_b64, *hash_b64, *server_b64;
	long iterations;
	const EVP_MD *md = NULL;
	unsigned char salt_raw[128];
	unsigned char hash_expect[128];
	unsigned char hash_actual[128];
	int salt_len, hash_len;
	int is_scram = 0;
	int salt_is_b64 = 0;
	long algo = 0;

	if (strncmp(stored, "$z$", 3) != 0)
		return 0;
	if (strlen(stored) >= sizeof(buf))
		return 0;
	strcpy(buf, stored);
	p = buf + 3;

    /* Tokenise. First field after $z$ is either "pbkdf2-<prf>" or a
     * numeric algo id. */
	char *first = p;
	p = strchr(p, '$');
	if (!p)
		return 0;
	*p++ = 0;
	iter_part = p;
	p = strchr(p, '$');
	if (!p)
		return 0;
	*p++ = 0;
	salt_b64 = p;
	p = strchr(p, '$');
	if (!p)
		return 0;
	*p++ = 0;
	hash_b64 = p;
    /* Optional 5th field: server key (only for SCRAM variants). */
	p = strchr(p, '$');
	if (p)
	{
		*p++ = 0;
		server_b64 = p;
	} else
	{
		server_b64 = NULL;
	}

	if (!strncmp(first, "pbkdf2-", 7))
	{
		const char *prf = first + 7;
		if (!strcmp(prf, "sha256"))
			md = EVP_sha256();
		else if (!strcmp(prf, "sha512"))
			md = EVP_sha512();
		else
			return 0;
		salt_is_b64 = 0;
	} else
	{
        /* Numeric algo id. */
		char *endp = NULL;
		algo = strtol(first, &endp, 10);
		if (!endp || *endp != 0)
			return 0;
		switch (algo)
		{
			case 4:
				md = EVP_sha1();
				salt_is_b64 = 0;
				break;
			case 5:
				md = EVP_sha256();
				salt_is_b64 = 0;
				break;
			case 6:
				md = EVP_sha512();
				salt_is_b64 = 0;
				break;
			case 24:
				md = EVP_sha1();
				salt_is_b64 = 1;
				break;
			case 25:
				md = EVP_sha256();
				salt_is_b64 = 1;
				break;
			case 26:
				md = EVP_sha512();
				salt_is_b64 = 1;
				break;
			case 44:
				md = EVP_sha1();
				salt_is_b64 = 0;
				is_scram = 1;
				break;
			case 45:
				md = EVP_sha256();
				salt_is_b64 = 0;
				is_scram = 1;
				break;
			case 46:
				md = EVP_sha512();
				salt_is_b64 = 0;
				is_scram = 1;
				break;
			case 64:
				md = EVP_sha1();
				salt_is_b64 = 1;
				is_scram = 1;
				break;
			case 65:
				md = EVP_sha256();
				salt_is_b64 = 1;
				is_scram = 1;
				break;
			case 66:
				md = EVP_sha512();
				salt_is_b64 = 1;
				is_scram = 1;
				break;
			default:
				return 0;  /* MD5 variants intentionally unsupported */
		}
		if (is_scram && !server_b64)
			return 0;  /* SCRAM needs 2 hash fields */
	}
	(void)server_b64;  /* we don't need ServerKey for verifying a password */

	iterations = strtol(iter_part, NULL, 10);
	if (iterations <= 0 || iterations > 10000000)
		return 0;

    /* Salt: either the literal base64 ASCII string (S64 variants) or
     * the decoded raw bytes. */
	const unsigned char *salt_p;
	int salt_used_len;
	if (salt_is_b64)
	{
		salt_p = (const unsigned char *)salt_b64;
		salt_used_len = (int)strlen(salt_b64);
	} else
	{
		salt_len = b64_decode_any(salt_b64, salt_raw, sizeof(salt_raw));
		if (salt_len <= 0)
			return 0;
		salt_p = salt_raw;
		salt_used_len = salt_len;
	}

	hash_len = b64_decode_any(hash_b64, hash_expect, sizeof(hash_expect));
	if (hash_len <= 0 || hash_len > (int)sizeof(hash_actual))
		return 0;

    /* PBKDF2 derives a key the size of the digest output. */
	int dlen = EVP_MD_size(md);
	unsigned char salted_password[64];
	if (dlen <= 0 || dlen > (int)sizeof(salted_password))
		return 0;

	if (PKCS5_PBKDF2_HMAC(password, strlen(password),
	                      salt_p, salt_used_len,
	                      (int)iterations, md,
	                      dlen, salted_password) != 1)
		return 0;

	if (!is_scram)
	{
        /* Plain HMAC PBKDF2: the stored hash IS the PBKDF2 output. */
		if (hash_len != dlen)
			return 0;
		int ok = (CRYPTO_memcmp(hash_expect, salted_password, dlen) == 0);
		OPENSSL_cleanse(salted_password, sizeof(salted_password));
		OPENSSL_cleanse(salt_raw, sizeof(salt_raw));
		return ok;
	}

    /* SCRAM: stored hash is StoredKey = H(HMAC(SaltedPassword, "Client Key")). */
	unsigned int hmac_len = 0;
	unsigned char client_key[64];
	static const unsigned char ck_label[] = "Client Key";
	if (!HMAC(md, salted_password, dlen, ck_label, sizeof(ck_label) - 1,
	          client_key, &hmac_len) ||
	    (int)hmac_len != dlen)
	{
		OPENSSL_cleanse(salted_password, sizeof(salted_password));
		return 0;
	}
	unsigned char stored_key_actual[64];
	unsigned int sk_len = 0;
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if (!mdctx ||
	    EVP_DigestInit_ex(mdctx, md, NULL) != 1 ||
	    EVP_DigestUpdate(mdctx, client_key, dlen) != 1 ||
	    EVP_DigestFinal_ex(mdctx, stored_key_actual, &sk_len) != 1 ||
	    (int)sk_len != dlen ||
	    hash_len != dlen)
	{
		if (mdctx)
			EVP_MD_CTX_free(mdctx);
		OPENSSL_cleanse(salted_password, sizeof(salted_password));
		OPENSSL_cleanse(client_key, sizeof(client_key));
		return 0;
	}
	EVP_MD_CTX_free(mdctx);

	int ok = (CRYPTO_memcmp(hash_expect, stored_key_actual, dlen) == 0);
	OPENSSL_cleanse(salted_password, sizeof(salted_password));
	OPENSSL_cleanse(client_key, sizeof(client_key));
	OPENSSL_cleanse(stored_key_actual, sizeof(stored_key_actual));
	OPENSSL_cleanse(salt_raw, sizeof(salt_raw));
	return ok;
}

/* Verify an Anope hmac-{sha256,sha512} hash. The stored value (after
 * scheme stripping by splitAnopePassword in the migration tool) is
 *   <hex-of-HMAC-output>:<hex-of-key>
 * matching modules/encryption/enc_sha2.cpp:
 *   enc = Hex(HMAC(key, password)) + ":" + Hex(key)
 * Verifier: hex-decode key, compute HMAC(key, password), hex-encode,
 * constant-time-compare to the first part. */
static int anope_hmac_verify(const char *stored, const char *password,
                             const EVP_MD *md)
{
	const char *colon = strchr(stored, ':');
	if (!colon || colon == stored)
		return 0;

	int hash_hex_len = (int)(colon - stored);
	const char *key_hex = colon + 1;
	int key_hex_len = (int)strlen(key_hex);
	if (hash_hex_len & 1 || key_hex_len & 1)
		return 0;
	if (hash_hex_len > 256 || key_hex_len > 256)
		return 0;

	unsigned char key[128];
	int key_len = key_hex_len / 2;
	for (int i = 0; i < key_len; i++)
	{
		if (sscanf(key_hex + 2 * i, "%2hhx", &key[i]) != 1)
			return 0;
	}

	unsigned char hmac_out[EVP_MAX_MD_SIZE];
	unsigned int hmac_len = 0;
	if (!HMAC(md, key, key_len,
	          (const unsigned char *)password, strlen(password),
	          hmac_out, &hmac_len))
	{
		OPENSSL_cleanse(key, sizeof(key));
		return 0;
	}
	if ((int)(hmac_len * 2) != hash_hex_len)
	{
		OPENSSL_cleanse(key, sizeof(key));
		OPENSSL_cleanse(hmac_out, sizeof(hmac_out));
		return 0;
	}
	char actual_hex[2 * EVP_MAX_MD_SIZE + 1];
	for (unsigned int i = 0; i < hmac_len; i++)
		snprintf(actual_hex + 2 * i, 3, "%02x", hmac_out[i]);
	actual_hex[hmac_len * 2] = 0;

	int ok = (CRYPTO_memcmp(stored, actual_hex, hash_hex_len) == 0);
	OPENSSL_cleanse(key, sizeof(key));
	OPENSSL_cleanse(hmac_out, sizeof(hmac_out));
	OPENSSL_cleanse(actual_hex, sizeof(actual_hex));
	return ok;
}

/* Single entry point. Inspects scheme + the hash format; falls back
 * gracefully when scheme is NULL/empty (legacy rows pre-Phase 0 are
 * always argon2id). Returns 1 on match, 0 on mismatch or unknown. */
static int verify_password_for_scheme(const char *scheme,
                                      const char *stored,
                                      const char *password)
{
	if (!stored || !password)
		return 0;

    /* Heuristic when scheme isn't set: try argon2id first (legacy
     * accounts), fall through to libcrypt for $2a/$5/$6 hashes. */
	if (!scheme || !*scheme || !strcmp(scheme, "argon2id"))
	{
		if (argon2_verify(stored, password, strlen(password), Argon2_id) == ARGON2_OK)
			return 1;
        /* If argon2_verify failed AND the hash *looks* like a
         * non-argon2 format the migration tool didn't flag, try the
         * fallback chain. This protects against a rehash loop where
         * the column wasn't set during a partial migration. */
		if (stored[0] == '$' && (stored[1] == '2' || stored[1] == '5' || stored[1] == '6'))
		{
			if (crypt_verify_via_libcrypt(stored, password))
				return 1;
			if (stored[1] == '2')
				return ergo_bcrypt_verify(stored, password);
			return 0;
		}
		if (!strncmp(stored, "$z$pbkdf2-", 10))
			return pbkdf2v2_verify(stored, password);
		return 0;
	}
	if (!strcmp(scheme, "bcrypt"))
	{
		if (crypt_verify_via_libcrypt(stored, password))
			return 1;
        /* Ergo-migrated bcrypt hashes were tagged "bcrypt" by the
         * migration tool but were produced via sha3-512 prehash + bcrypt
         * (Dropbox style). The direct-bcrypt path can't verify them,
         * so try the prehashed path as a fallback. Successful match
         * here triggers the same roll-forward to argon2id at the call
         * site, so accounts only do the fallback dance once. */
		return ergo_bcrypt_verify(stored, password);
	}
	if (!strcmp(scheme, "ergo-bcrypt"))
		return ergo_bcrypt_verify(stored, password);
	if (!strcmp(scheme, "pbkdf2v2"))
		return pbkdf2v2_verify(stored, password);
	if (!strcmp(scheme, "crypt-sha256") || !strcmp(scheme, "crypt-sha512"))
		return crypt_verify_via_libcrypt(stored, password);
	if (!strcmp(scheme, "hmac-sha256"))
		return anope_hmac_verify(stored, password, EVP_sha256());
	if (!strcmp(scheme, "hmac-sha512"))
		return anope_hmac_verify(stored, password, EVP_sha512());
	if (!strcmp(scheme, "reset-required"))
		return 0;  /* user must reset via /RECOVER */
    /* Unknown scheme — try argon2id as a last resort. */
	return argon2_verify(stored, password, strlen(password), Argon2_id) == ARGON2_OK;
}

struct ScramState_ {
	int step;                /* 0 = expect client-first, 1 = expect client-final */
	Account *account;        /* loaded after client-first; NULL until then */
	char *client_first_bare; /* "n=user,r=clientNonce" */
	char *server_first;      /* "r=combinedNonce,s=salt,i=iters" */
	char *combined_nonce;    /* what we put in server-first's r= */
};

#define ScramGet(c) ((ScramState *)moddata_local_client((c), scram_md).ptr)
#define ScramSet(c, p) \
	do \
	{ \
		moddata_local_client((c), scram_md).ptr = (p); \
	} while (0)

static void scram_state_free(ScramState *s)
{
	if (!s)
		return;
	free_account(s->account);
	safe_free(s->client_first_bare);
	safe_free(s->server_first);
	safe_free(s->combined_nonce);
	safe_free(s);
}

static void scram_md_free(ModData *m)
{
	if (m->ptr)
	{
		scram_state_free((ScramState *)m->ptr);
		m->ptr = NULL;
	}
}

static void scram_clear(Client *client)
{
	ScramState *s = ScramGet(client);
	if (s)
	{
		scram_state_free(s);
		ScramSet(client, NULL);
	}
}

/* ----- Crypto primitives ----- */

static void scram_xor(const unsigned char *a, const unsigned char *b,
                      size_t n, unsigned char *out)
{
	size_t i;
	for (i = 0; i < n; i++)
		out[i] = a[i] ^ b[i];
}

/** Compute (StoredKey, ServerKey) from (password, salt, iterations). */
static int scram_compute_credentials(const char *password, size_t passlen,
                                     const unsigned char *salt, size_t saltlen,
                                     int iterations,
                                     unsigned char stored_key_out[SCRAM_KEY_BYTES],
                                     unsigned char server_key_out[SCRAM_KEY_BYTES])
{
	unsigned char salted[SCRAM_KEY_BYTES];
	unsigned char client_key[SCRAM_KEY_BYTES];
	unsigned int outlen = 0;
	int ok = 0;

	if (!PKCS5_PBKDF2_HMAC(password, (int)passlen,
	                       salt, (int)saltlen,
	                       iterations,
	                       EVP_sha256(),
	                       SCRAM_KEY_BYTES, salted))
		goto out;

	if (!HMAC(EVP_sha256(), salted, SCRAM_KEY_BYTES,
	          (const unsigned char *)"Client Key", 10,
	          client_key, &outlen) ||
	    outlen != SCRAM_KEY_BYTES)
		goto out;

	if (!SHA256(client_key, SCRAM_KEY_BYTES, stored_key_out))
		goto out;

	if (!HMAC(EVP_sha256(), salted, SCRAM_KEY_BYTES,
	          (const unsigned char *)"Server Key", 10,
	          server_key_out, &outlen) ||
	    outlen != SCRAM_KEY_BYTES)
		goto out;

	ok = 1;
out:
    /* Wipe key material from the stack so it can't linger and leak via
     * uninitialised-stack reads in unrelated callers. */
	OPENSSL_cleanse(salted, sizeof(salted));
	OPENSSL_cleanse(client_key, sizeof(client_key));
	return ok;
}

/** Generate fresh SCRAM credentials from a plaintext password and write them
 *  into acc->scram_*.  Returns 1 on success, 0 on crypto failure. */
static int scram_make_credentials(Account *acc, const char *password)
{
	unsigned char salt[SCRAM_SALT_BYTES];
	unsigned char stored_key[SCRAM_KEY_BYTES];
	unsigned char server_key[SCRAM_KEY_BYTES];
	char salt_b64[64];
	char stored_b64[64];
	char server_b64[64];
	int ok = 0;

	if (RAND_bytes(salt, SCRAM_SALT_BYTES) != 1)
		goto out;

	if (!scram_compute_credentials(password, strlen(password),
	                               salt, SCRAM_SALT_BYTES,
	                               SCRAM_DEFAULT_ITERATIONS,
	                               stored_key, server_key))
		goto out;

	if (b64_encode(salt, SCRAM_SALT_BYTES, salt_b64, sizeof(salt_b64)) <= 0 ||
	    b64_encode(stored_key, SCRAM_KEY_BYTES, stored_b64, sizeof(stored_b64)) <= 0 ||
	    b64_encode(server_key, SCRAM_KEY_BYTES, server_b64, sizeof(server_b64)) <= 0)
		goto out;

	free(acc->scram_salt);
	free(acc->scram_stored_key);
	free(acc->scram_server_key);
	acc->scram_salt = strdup(salt_b64);
	acc->scram_iterations = SCRAM_DEFAULT_ITERATIONS;
	acc->scram_stored_key = strdup(stored_b64);
	acc->scram_server_key = strdup(server_b64);
	ok = 1;
out:
	OPENSSL_cleanse(salt, sizeof(salt));
	OPENSSL_cleanse(stored_key, sizeof(stored_key));
	OPENSSL_cleanse(server_key, sizeof(server_key));
    /* The base64 encodings of stored_key / server_key end up persisted in the
     * DB anyway, so cleansing them here is mostly belt-and-suspenders. */
	OPENSSL_cleanse(stored_b64, sizeof(stored_b64));
	OPENSSL_cleanse(server_b64, sizeof(server_b64));
	return ok;
}

/* ----- Wire-format parsers ----- */

/* SCRAM usernames have ',' and '=' escaped as =2C and =3D.  Returns a
 * heap-allocated unescaped string, or NULL on malformed input. */
static char *scram_unescape_username(const char *s)
{
	size_t n = strlen(s);
	char *out = safe_alloc(n + 1);
	char *q = out;
	while (*s)
	{
		if (*s == '=')
		{
			if (s[1] == '2' && s[2] == 'C')
			{
				*q++ = ',';
				s += 3;
				continue;
			}
			if (s[1] == '3' && s[2] == 'D')
			{
				*q++ = '=';
				s += 3;
				continue;
			}
			safe_free(out);
			return NULL;
		}
		if (*s == ',')
		{
			safe_free(out);
			return NULL;
		}
		*q++ = *s++;
	}
	*q = 0;
	return out;
}

/* Extract attribute from "n=foo,r=bar,..." sequence.  Returns a heap-allocated
 * string, or NULL if the attribute isn't present. */
static char *scram_get_attr(const char *msg, char attr)
{
	const char *p = msg;
	while (*p)
	{
		char a = *p++;
		if (*p++ != '=')
			return NULL;
		const char *vstart = p;
		while (*p && *p != ',')
			p++;
		if (a == attr)
		{
			size_t vlen = (size_t)(p - vstart);
			char *out = safe_alloc(vlen + 1);
			memcpy(out, vstart, vlen);
			out[vlen] = 0;
			return out;
		}
		if (*p == ',')
			p++;
	}
	return NULL;
}

/* Parse client-first-message.  Layout: gs2-header "," client-first-message-bare
 *   gs2-header   = "n,," | "y,," (we don't accept channel binding, no authzid)
 *   bare         = "n=username,r=clientNonce" (additional attrs allowed/ignored)
 * On success populates *bare, *username, *client_nonce (all heap-allocated). */
static int scram_parse_client_first(const char *msg,
                                    char **bare_out,
                                    char **username_out,
                                    char **client_nonce_out)
{
	const char *p = msg;
	const char *bare;
	char *username = NULL, *escaped_user = NULL, *cnonce = NULL;

	*bare_out = *username_out = *client_nonce_out = NULL;

    /* gs2 cb-flag: 'n' or 'y' (we reject 'p' since we don't advertise -PLUS) */
	if (*p != 'n' && *p != 'y')
		return 0;
	p++;
	if (*p++ != ',')
		return 0;
    /* authzid optional ("a=..."), we don't accept one for v1 */
	if (*p && *p != ',')
		return 0;
	if (*p++ != ',')
		return 0;

	bare = p;

	escaped_user = scram_get_attr(bare, 'n');
	cnonce = scram_get_attr(bare, 'r');
	if (!escaped_user || !cnonce)
	{
		safe_free(escaped_user);
		safe_free(cnonce);
		return 0;
	}

	username = scram_unescape_username(escaped_user);
	safe_free(escaped_user);
	if (!username)
	{
		safe_free(cnonce);
		return 0;
	}

	safe_strdup(*bare_out, bare);
	*username_out = username;
	*client_nonce_out = cnonce;
	return 1;
}

/* ----- Protocol handlers ----- */

static void scram_fail(Client *client)
{
	ScramState *st = ScramGet(client);
	const char *username = (st && st->account) ? st->account->name : NULL;
	client->local->sasl_sent_time = 0;
	add_fake_lag(client, 5000);
	log_sasl_fail(client, "SCRAM-SHA-256", username,
	              st ? (st->step == 0 ? "client_first_invalid"
	                                  : "client_final_invalid_or_proof_mismatch")
	                 : "no_state");
	sendnumeric(client, ERR_SASLFAIL);
	DelSaslType(client);
	scram_clear(client);
}

static int scram_send_b64(Client *client, const char *plain, size_t len)
{
    /* Result line: "AUTHENTICATE <base64>" -- max 400 bytes per IRC SASL.
     * If empty, send "+" placeholder. */
	if (len == 0)
	{
		sendto_one(client, NULL, ":%s AUTHENTICATE +", me.name);
		return 1;
	}
    /* Worst-case b64 size = ((len+2)/3)*4 + 1 */
	size_t outsize = ((len + 2) / 3) * 4 + 1;
	char *b64 = safe_alloc(outsize);
	int n = b64_encode((const unsigned char *)plain, len, b64, outsize);
	if (n <= 0 || n > 400)
	{
		safe_free(b64);
		return 0;
	}
	sendto_one(client, NULL, ":%s AUTHENTICATE %s", me.name, b64);
	safe_free(b64);
	return 1;
}

static void scram_handle_client_first(Client *client, const char *msg, size_t msglen)
{
	char *bare = NULL, *username = NULL, *cnonce = NULL;
	Account *account = NULL;
	char server_nonce[SCRAM_SERVER_NONCE_BYTES + 1];
	char *combined = NULL;
	char *server_first = NULL;
	int sf_len;
	ScramState *st;
	(void)msglen;

	if (!scram_parse_client_first(msg, &bare, &username, &cnonce))
		goto fail;

	account = find_account(username);
	if (!account || !account->scram_salt || !account->scram_stored_key ||
	    account->scram_iterations <= 0)
	{
        /* Don't leak whether the account exists.  Generate a dummy nonce
         * and reply normally; final step will fail with bad proof. */
		free_account(account);
		account = NULL;
		goto fail; /* simpler: just fail outright (legitimate clients only hit this rarely) */
	}

	gen_random_alnum(server_nonce, SCRAM_SERVER_NONCE_BYTES);
	server_nonce[SCRAM_SERVER_NONCE_BYTES] = 0;

    /* combined nonce = client nonce || server nonce */
	{
		size_t need = strlen(cnonce) + SCRAM_SERVER_NONCE_BYTES + 1;
		combined = safe_alloc(need);
		snprintf(combined, need, "%s%s", cnonce, server_nonce);
	}

    /* server-first-message = "r=" combined "," "s=" salt "," "i=" iters */
	{
		size_t need = 16 + strlen(combined) + strlen(account->scram_salt) + 16;
		server_first = safe_alloc(need);
		sf_len = snprintf(server_first, need, "r=%s,s=%s,i=%d",
		                  combined, account->scram_salt,
		                  account->scram_iterations);
	}

    /* Persist state for step 2. */
	st = safe_alloc(sizeof(*st));
	st->step = 1;
	st->account = account;
	account = NULL; /* moved */
	safe_strdup(st->client_first_bare, bare);
	safe_strdup(st->server_first, server_first);
	safe_strdup(st->combined_nonce, combined);

	scram_clear(client); /* in case of stale state */
	ScramSet(client, st);

	if (!scram_send_b64(client, server_first, sf_len))
		goto fail;

	safe_free(bare);
	safe_free(username);
	safe_free(cnonce);
	safe_free(combined);
	safe_free(server_first);
	return;

fail:
	safe_free(bare);
	safe_free(username);
	safe_free(cnonce);
	safe_free(combined);
	safe_free(server_first);
	free_account(account);
	scram_fail(client);
}

static void scram_handle_client_final(Client *client, const char *msg, size_t msglen)
{
	ScramState *st = ScramGet(client);
	char *cb_b64 = NULL;          /* "c=" attribute (channel binding header) */
	char *full_nonce = NULL;
	char *proof_b64 = NULL;
	char *final_no_proof = NULL;
	Account *acc;
	unsigned char client_proof[SCRAM_KEY_BYTES];
	unsigned char stored_key[SCRAM_KEY_BYTES];
	unsigned char server_key[SCRAM_KEY_BYTES];
	unsigned char client_signature[SCRAM_KEY_BYTES];
	unsigned char client_key[SCRAM_KEY_BYTES];
	unsigned char computed_stored[SCRAM_KEY_BYTES];
	unsigned char server_sig[SCRAM_KEY_BYTES];
	unsigned int outlen = 0;
	char *auth_message = NULL;
	char server_final[80];
	int sf_len;
	(void)msglen;

	if (!st || st->step != 1 || !st->account)
	{
		scram_fail(client);
		return;
	}
	acc = st->account;
	if (!acc->scram_stored_key || !acc->scram_server_key)
	{
		scram_fail(client);
		return;
	}

    /* Extract attributes.  We need at minimum c, r, p. */
	cb_b64 = scram_get_attr(msg, 'c');
	full_nonce = scram_get_attr(msg, 'r');
	proof_b64 = scram_get_attr(msg, 'p');
	if (!cb_b64 || !full_nonce || !proof_b64)
		goto fail;

    /* "biws" is base64 of "n,," -- the only GS2 header we accept. */
	if (strcmp(cb_b64, "biws") && strcmp(cb_b64, "eSws") /* "y,," */)
		goto fail;

    /* Nonce must match exactly. */
	if (strcmp(full_nonce, st->combined_nonce))
		goto fail;

    /* Decode client proof. */
	{
		unsigned char tmp[64];
		int n = b64_decode(proof_b64, tmp, sizeof(tmp));
		if (n != SCRAM_KEY_BYTES)
			goto fail;
		memcpy(client_proof, tmp, SCRAM_KEY_BYTES);
	}

    /* Decode stored_key and server_key from account. */
	{
		unsigned char tmp[64];
		int n = b64_decode(acc->scram_stored_key, tmp, sizeof(tmp));
		if (n != SCRAM_KEY_BYTES)
			goto fail;
		memcpy(stored_key, tmp, SCRAM_KEY_BYTES);

		n = b64_decode(acc->scram_server_key, tmp, sizeof(tmp));
		if (n != SCRAM_KEY_BYTES)
			goto fail;
		memcpy(server_key, tmp, SCRAM_KEY_BYTES);
	}

    /* Build client-final-message-without-proof: drop ",p=..." tail */
	{
		const char *p_attr = strstr(msg, ",p=");
		if (!p_attr)
			goto fail;
		size_t len = (size_t)(p_attr - msg);
		final_no_proof = safe_alloc(len + 1);
		memcpy(final_no_proof, msg, len);
		final_no_proof[len] = 0;
	}

    /* AuthMessage = client_first_bare + "," + server_first + "," + final_no_proof */
	{
		size_t need = strlen(st->client_first_bare) + 1 +
		              strlen(st->server_first) + 1 +
		              strlen(final_no_proof) + 1;
		auth_message = safe_alloc(need);
		snprintf(auth_message, need, "%s,%s,%s",
		         st->client_first_bare, st->server_first, final_no_proof);
	}

    /* ClientSignature = HMAC(StoredKey, AuthMessage) */
	if (!HMAC(EVP_sha256(), stored_key, SCRAM_KEY_BYTES,
	          (const unsigned char *)auth_message, strlen(auth_message),
	          client_signature, &outlen) ||
	    outlen != SCRAM_KEY_BYTES)
		goto fail;

    /* ClientKey = ClientProof XOR ClientSignature */
	scram_xor(client_proof, client_signature, SCRAM_KEY_BYTES, client_key);

    /* Verify SHA-256(ClientKey) == StoredKey using a constant-time compare so
     * the failure path doesn't leak how many leading bytes matched. */
	if (!SHA256(client_key, SCRAM_KEY_BYTES, computed_stored))
		goto fail;
	if (CRYPTO_memcmp(computed_stored, stored_key, SCRAM_KEY_BYTES) != 0)
		goto fail;

    /* ServerSignature = HMAC(ServerKey, AuthMessage) */
	if (!HMAC(EVP_sha256(), server_key, SCRAM_KEY_BYTES,
	          (const unsigned char *)auth_message, strlen(auth_message),
	          server_sig, &outlen) ||
	    outlen != SCRAM_KEY_BYTES)
		goto fail;

    /* Reply: server-final-message = "v=" base64(server_sig) */
	{
		char sig_b64[64];
		if (b64_encode(server_sig, SCRAM_KEY_BYTES, sig_b64, sizeof(sig_b64)) <= 0)
			goto fail;
		sf_len = snprintf(server_final, sizeof(server_final), "v=%s", sig_b64);
	}

	if (!scram_send_b64(client, server_final, sf_len))
		goto fail;

    /* If 2FA is enforced, swap into step-up mode instead of completing
     * login.  Save the account name (twofa_maybe_start_stepup makes a copy)
     * BEFORE scram_clear() destroys st->account. */
	if (twofa_maybe_start_stepup(client, acc, "password"))
	{
		DelSaslType(client);
		scram_clear(client);
		safe_free(cb_b64);
		safe_free(full_nonce);
		safe_free(proof_b64);
		safe_free(final_no_proof);
		safe_free(auth_message);
		OPENSSL_cleanse(client_proof, sizeof(client_proof));
		OPENSSL_cleanse(stored_key, sizeof(stored_key));
		OPENSSL_cleanse(server_key, sizeof(server_key));
		OPENSSL_cleanse(client_signature, sizeof(client_signature));
		OPENSSL_cleanse(client_key, sizeof(client_key));
		OPENSSL_cleanse(computed_stored, sizeof(computed_stored));
		OPENSSL_cleanse(server_sig, sizeof(server_sig));
		return;
	}

    /* Log the user in. */
	strlcpy(client->user->account, acc->name, sizeof(client->user->account));
	unreal_log(ULOG_INFO, "account", "SASL_LOGIN", client,
	           "SASL/SCRAM-SHA-256 login for $client.details "
	           "[account: $account] [email: $email]",
	           log_data_string("account", acc->name),
	           log_data_string("email", acc->email));
	user_account_login(NULL, client);
	if (!IsDead(client))
	{
		client->local->sasl_complete = 1;
		sendnumeric(client, RPL_SASLSUCCESS);
	}
	DelSaslType(client);
	scram_clear(client);

	safe_free(cb_b64);
	safe_free(full_nonce);
	safe_free(proof_b64);
	safe_free(final_no_proof);
	safe_free(auth_message);
	OPENSSL_cleanse(client_proof, sizeof(client_proof));
	OPENSSL_cleanse(stored_key, sizeof(stored_key));
	OPENSSL_cleanse(server_key, sizeof(server_key));
	OPENSSL_cleanse(client_signature, sizeof(client_signature));
	OPENSSL_cleanse(client_key, sizeof(client_key));
	OPENSSL_cleanse(computed_stored, sizeof(computed_stored));
	OPENSSL_cleanse(server_sig, sizeof(server_sig));
	return;

fail:
	safe_free(cb_b64);
	safe_free(full_nonce);
	safe_free(proof_b64);
	safe_free(final_no_proof);
	safe_free(auth_message);
	OPENSSL_cleanse(client_proof, sizeof(client_proof));
	OPENSSL_cleanse(stored_key, sizeof(stored_key));
	OPENSSL_cleanse(server_key, sizeof(server_key));
	OPENSSL_cleanse(client_signature, sizeof(client_signature));
	OPENSSL_cleanse(client_key, sizeof(client_key));
	OPENSSL_cleanse(computed_stored, sizeof(computed_stored));
	OPENSSL_cleanse(server_sig, sizeof(server_sig));
	scram_fail(client);
}

/* ===================================================================
 * CAP helpers
 * =================================================================== */
static const char *accreg_capability_parameter(Client *client)
{
	return "before-connect,custom-account-name,email-required";
}

static int accreg_capability_visible(Client *client)
{
	return 1;
}

/* ===================================================================
 * SASL hook: authenticate_attempt
 * Called by sasl.c cmd_authenticate when SASL_SERVER == &me.
 * =================================================================== */
static int authenticate_attempt(Client *client, int first, const char *param)
{
	if (!SASL_SERVER || !MyConnect(client) || !param || !*param)
		return 0;

    /* If we are in the middle of a 2FA step-up, route AUTHENTICATE
     * messages to the step-up handler before normal mechanism dispatch. */
	{
		TwoFAStepup *s = TwoFAStepupGet(client);
		if (s && s->active)
		{
			if (twofa_handle_stepup_authenticate(client, param))
				return 0;
		}
	}

	if (!strcmp(param, "*"))
	{
		if (GetSaslType(client))
			DelSaslType(client);
		twofa_clear_stepup(client);
		return 0;
	} else if (!strcmp(param, "PLAIN"))
	{
		SetSaslType(client, SASL_TYPE_PLAIN);
		sendto_one(client, NULL, ":%s AUTHENTICATE +", me.name);
		return 0;
	} else if (!strcmp(param, "ANONYMOUS"))
	{
		strlcpy(client->user->account, "0", sizeof(client->user->account));
		user_account_login(NULL, client);
		if (IsDead(client))
			return 0;
		client->local->sasl_complete = 1;
		sendnumeric(client, RPL_SASLSUCCESS);
		DelSaslType(client);
		return 0;
	} else if (!strcmp(param, "EXTERNAL"))
	{
        /* SASL EXTERNAL: client identity is taken from the TLS cert
         * fingerprint, matched against any account that has registered
         * an `external` credential whose secret == fingerprint. */
		SetSaslType(client, SASL_TYPE_EXTERNAL);
		sendto_one(client, NULL, ":%s AUTHENTICATE +", me.name);
		return 0;
	} else if (!strcasecmp(param, "DRAFT-WEBAUTHN-BIO") ||
	           !strcasecmp(param, "WEBAUTHN-BIO"))
	{
		SetSaslType(client, SASL_TYPE_WEBAUTHN_BIO);
		webauthn_sasl_clear(client);
		WebAuthnSaslState *st = safe_alloc(sizeof(*st));
		st->step = 0;
		if (RAND_bytes(st->challenge, sizeof(st->challenge)) != 1)
		{
			safe_free(st);
			sendnumeric(client, ERR_SASLFAIL);
			DelSaslType(client);
			return 0;
		}
		WebAuthnSaslSet(client, st);
		sendto_one(client, NULL, ":%s AUTHENTICATE +", me.name);
		return 0;
	} else if (!strcasecmp(param, "SCRAM-SHA-256"))
	{
		SetSaslType(client, SASL_TYPE_SCRAM_SHA_256);
		scram_clear(client);
		sendto_one(client, NULL, ":%s AUTHENTICATE +", me.name);
		return 0;
	} else if (!strcasecmp(param, "OAUTHBEARER"))
	{
		SetSaslType(client, SASL_TYPE_OAUTHBEARER);
		sendto_one(client, NULL, ":%s AUTHENTICATE +", me.name);
		return 0;
	} else if (!strcasecmp(param, "IRCV3BEARER"))
	{
		SetSaslType(client, SASL_TYPE_IRCV3BEARER);
		sendto_one(client, NULL, ":%s AUTHENTICATE +", me.name);
		return 0;
	}

	if (!GetSaslType(client) || GetSaslType(client) == SASL_TYPE_NONE)
		return 0;

	if (GetSaslType(client) == SASL_TYPE_OAUTHBEARER)
	{
		const char *full = oauth_sasl_accumulate(client, param);
		if (!full)
			return 0;       /* still accumulating */
		oauthbearer_dispatch(client, full);
		oauth_sasl_clear(client);
		DelSaslType(client);
		return 0;
	}
	if (GetSaslType(client) == SASL_TYPE_IRCV3BEARER)
	{
		const char *full = oauth_sasl_accumulate(client, param);
		if (!full)
			return 0;
		ircv3bearer_dispatch(client, full);
		oauth_sasl_clear(client);
		DelSaslType(client);
		return 0;
	}

	if (GetSaslType(client) == SASL_TYPE_EXTERNAL)
	{
        /* SASL EXTERNAL: client sends `+` (or a base64 authzid which
         * we tolerate but don't use; the TLS handshake is the source
         * of truth).  Map the connection's cert fingerprint to a
         * registered account.
         */
		const char *fp = moddata_client_get(client, "certfp");
		if (!fp || !*fp)
		{
			client->local->sasl_sent_time = 0;
			add_fake_lag(client, 3000);
			log_sasl_fail(client, "EXTERNAL", NULL, "no_certfp");
			sendnumeric(client, ERR_SASLFAIL);
			DelSaslType(client);
			return 0;
		}

        /* Normalise to lowercase to match the hex form used by the
         * spec and by 2FA `external` enrolments. */
		size_t fplen = strlen(fp);
		char *fp_lower = safe_alloc(fplen + 1);
		for (size_t i = 0; i < fplen; i++)
		{
			char c = fp[i];
			fp_lower[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
		}
		fp_lower[fplen] = '\0';

        /* Look up the account whose 2FA `external` credential matches
         * this fingerprint.  We compare case-insensitively in SQL. */
		Account *account = NULL;
		if (obsidian_db ||
		    obsidian_open_database(OBSIDIAN_DB) == SQLITE_OK)
		{
			const char *sql =
			    "SELECT a.name FROM accounts a"
			    "  JOIN account_2fa_credentials c ON c.account_id = a.id"
			    " WHERE c.type = 'external'"
			    "   AND lower(c.secret) = ?"
			    " LIMIT 1";
			sqlite3_stmt *stmt;
			if (sqlite3_prepare_v2(obsidian_db, sql, -1, &stmt, NULL) == SQLITE_OK)
			{
				sqlite3_bind_text(stmt, 1, fp_lower, -1, SQLITE_STATIC);
				if (sqlite3_step(stmt) == SQLITE_ROW)
				{
					const unsigned char *name = sqlite3_column_text(stmt, 0);
					if (name)
						account = find_account((const char *)name);
				}
				sqlite3_finalize(stmt);
			}
		}
		safe_free(fp_lower);

		if (!account)
		{
			client->local->sasl_sent_time = 0;
			add_fake_lag(client, 3000);
			log_sasl_fail(client, "EXTERNAL", NULL,
			              "no_account_for_certfp");
			sendnumeric(client, ERR_SASLFAIL);
			DelSaslType(client);
			return 0;
		}

        /* If 2FA is enforced, withhold success and start the step-up.
         * EXTERNAL alone is one factor; the cert match doesn't double
         * as the second factor when twofa_enabled is on. */
		if (twofa_maybe_start_stepup(client, account, "external"))
		{
			free_account(account);
			return 0;
		}

		strlcpy(client->user->account, account->name,
		        sizeof(client->user->account));
		unreal_log(ULOG_INFO, "account", "SASL_LOGIN_EXTERNAL", client,
		           "SASL EXTERNAL login for $client.details "
		           "[account: $account] [certfp: $certfp]",
		           log_data_string("account", account->name),
		           log_data_string("certfp", fp));
		user_account_login(NULL, client);
		client->local->sasl_complete = 1;
		sendnumeric(client, RPL_SASLSUCCESS);
		DelSaslType(client);
		free_account(account);
		return 0;
	}

	if (GetSaslType(client) == SASL_TYPE_WEBAUTHN_BIO)
	{
		WebAuthnSaslState *st = WebAuthnSaslGet(client);
		if (!st)
		{
			sendnumeric(client, ERR_SASLFAIL);
			DelSaslType(client);
			return 0;
		}
		if (st->step == 0)
			webauthn_sasl_handle_hello(client, param);
		else
			webauthn_sasl_handle_assertion(client, param);
		return 0;
	}

	if (GetSaslType(client) == SASL_TYPE_SCRAM_SHA_256)
	{
		unsigned char buf[1024];
		int n = b64_decode(param, buf, sizeof(buf) - 1);
		if (n <= 0)
		{
			scram_fail(client);
			return 0;
		}
		buf[n] = 0;

		ScramState *st = ScramGet(client);
		if (!st || st->step == 0)
			scram_handle_client_first(client, (const char *)buf, (size_t)n);
		else
			scram_handle_client_final(client, (const char *)buf, (size_t)n);
		return 0;
	}

	if (GetSaslType(client) == SASL_TYPE_PLAIN)
	{
		char *auth_id, *username, *password;

		if (!decode_authenticate_plain(param, &auth_id, &username, &password))
		{
			client->local->sasl_sent_time = 0;
			add_fake_lag(client, 7000);
			log_sasl_fail(client, "PLAIN", NULL, "decode_failed");
			sendnumeric(client, ERR_SASLFAIL);
			DelSaslType(client);
			return 0;
		}

		if (BadPtr(username) || BadPtr(password))
		{
			log_sasl_fail(client, "PLAIN", username,
			              "missing username or password");
			sendnumeric(client, ERR_SASLFAIL);
			DelSaslType(client);
			return 0;
		}

		Account *account = find_account(username);
		if (account &&
		    verify_password_for_scheme(account->password_scheme,
		                               account->password, password))
		{
            /* Regenerate SCRAM credentials on every successful PLAIN
             * verify: migrated accounts may carry a SCRAM verifier from
             * a different derivation (e.g. Ergo) that this server's
             * SCRAM-SHA-256 verifier won't accept. Rederiving from the
             * verified plaintext guarantees the on-disk SCRAM is
             * consistent with how we'd compute it locally. */
			if (scram_make_credentials(account, password))
				update_account_scram(account);
            /* Migrated non-argon2id accounts get rolled forward on first
             * successful login: rehash with argon2id and persist. Best
             * effort -- failure is logged but doesn't abort login. */
			if (account->password_scheme && strcmp(account->password_scheme, "argon2id"))
			{
				const char *new_hash = Auth_Hash(AUTHTYPE_ARGON2, password);
				if (new_hash)
				{
					free(account->password);
					account->password = strdup(new_hash);
					free(account->password_scheme);
					account->password_scheme = strdup("argon2id");
					update_account_password(account);
				}
			}

            /* If 2FA is enforced, withhold the success reply and ask the
             * client to do a second-factor SASL exchange. */
			if (twofa_maybe_start_stepup(client, account, "password"))
			{
                /* Keep SaslType set so subsequent AUTHENTICATE messages
                 * keep flowing through this hook; the step-up handler
                 * dispatches them. */
				free_account(account);
				return 0;
			}

			strlcpy(client->user->account, account->name,
			        sizeof(client->user->account));
			unreal_log(ULOG_INFO, "account", "SASL_LOGIN", client,
			           "SASL login for $client.details [account: $account] [email: $email]",
			           log_data_string("account", account->name),
			           log_data_string("email", account->email));
			user_account_login(NULL, client);
			client->local->sasl_complete = 1;
			sendnumeric(client, RPL_SASLSUCCESS);
			DelSaslType(client);
		} else
		{
			client->local->sasl_sent_time = 0;
			add_fake_lag(client, 7000);
			log_sasl_fail(client, "PLAIN", username,
			              account ? (account->password_scheme
			                             ? account->password_scheme
			                             : "argon2id_or_legacy")
			                      : "account_not_found");
			sendnumeric(client, ERR_SASLFAIL);
			DelSaslType(client);
		}
		free_account(account);
	}
	return 0;
}

/* ===================================================================
 * 2FA - draft/account-2fa (TOTP / RFC 6238)
 * =================================================================== */

/* ----- Base32 (RFC 4648) ----- */

static int base32_encode(const unsigned char *in, size_t in_len,
                         char *out, size_t out_size)
{
	static const char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	size_t in_pos = 0, out_pos = 0;
	int bits = 0;
	unsigned int value = 0;

	while (in_pos < in_len)
	{
		value = (value << 8) | in[in_pos++];
		bits += 8;
		while (bits >= 5)
		{
			if (out_pos + 1 >= out_size)
				return -1;
			out[out_pos++] = alpha[(value >> (bits - 5)) & 0x1F];
			bits -= 5;
		}
	}
	if (bits > 0)
	{
		if (out_pos + 1 >= out_size)
			return -1;
		out[out_pos++] = alpha[(value << (5 - bits)) & 0x1F];
	}
	while (out_pos % 8 != 0)
	{
		if (out_pos + 1 >= out_size)
			return -1;
		out[out_pos++] = '=';
	}
	if (out_pos >= out_size)
		return -1;
	out[out_pos] = '\0';
	return (int)out_pos;
}

static int base32_decode(const char *in, unsigned char *out, size_t out_size)
{
	int bits = 0;
	unsigned int value = 0;
	size_t out_pos = 0;
	while (*in && *in != '=')
	{
		char c = *in++;
		int v;
		if (c >= 'A' && c <= 'Z')
			v = c - 'A';
		else if (c >= 'a' && c <= 'z')
			v = c - 'a';
		else if (c >= '2' && c <= '7')
			v = c - '2' + 26;
		else if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
			continue;
		else
			return -1;
		value = (value << 5) | v;
		bits += 5;
		if (bits >= 8)
		{
			if (out_pos >= out_size)
				return -1;
			out[out_pos++] = (value >> (bits - 8)) & 0xFF;
			bits -= 8;
		}
	}
	return (int)out_pos;
}

/* ----- HMAC-SHA1 TOTP (RFC 6238) ----- */

static int totp_compute_at(const unsigned char *key, size_t key_len,
                           uint64_t counter)
{
	unsigned char counter_buf[8];
	unsigned char hmac_buf[20];
	unsigned int hmac_len = 0;
	int offset, code;

	for (int i = 7; i >= 0; i--)
	{
		counter_buf[i] = counter & 0xFF;
		counter >>= 8;
	}

	if (!HMAC(EVP_sha1(), key, (int)key_len, counter_buf, sizeof(counter_buf),
	          hmac_buf, &hmac_len) ||
	    hmac_len != 20)
	{
		OPENSSL_cleanse(hmac_buf, sizeof(hmac_buf));
		return -1;
	}

	offset = hmac_buf[19] & 0x0F;
	code = ((hmac_buf[offset] & 0x7F) << 24) |
	       ((hmac_buf[offset + 1] & 0xFF) << 16) |
	       ((hmac_buf[offset + 2] & 0xFF) << 8) |
	       (hmac_buf[offset + 3] & 0xFF);
	OPENSSL_cleanse(hmac_buf, sizeof(hmac_buf));
	return code % 1000000;
}

/** Returns 1 if 'code_str' (6 ASCII digits) matches the TOTP for 'secret_b32'
 *  within the configured ±N skew window.  Constant-time compare.  */
static int totp_verify(const char *secret_b32, const char *code_str)
{
	unsigned char key[64];
	int key_len;
	int matched = 0;
	uint64_t now;

	if (!secret_b32 || !code_str || strlen(code_str) != TWOFA_CODE_DIGITS)
		return 0;
    /* All chars must be ASCII digits */
	for (int i = 0; i < TWOFA_CODE_DIGITS; i++)
		if (code_str[i] < '0' || code_str[i] > '9')
			return 0;

	key_len = base32_decode(secret_b32, key, sizeof(key));
	if (key_len <= 0)
	{
		OPENSSL_cleanse(key, sizeof(key));
		return 0;
	}

	now = (uint64_t)time(NULL) / TWOFA_PERIOD_SECONDS;
	for (int delta = -TWOFA_SKEW_WINDOWS; delta <= TWOFA_SKEW_WINDOWS; delta++)
	{
		int expected = totp_compute_at(key, key_len, now + delta);
		if (expected < 0)
			continue;
		char expected_str[TWOFA_CODE_DIGITS + 1];
		snprintf(expected_str, sizeof(expected_str), "%0*d",
		         TWOFA_CODE_DIGITS, expected);
		if (CRYPTO_memcmp(expected_str, code_str, TWOFA_CODE_DIGITS) == 0)
			matched = 1;
		OPENSSL_cleanse(expected_str, sizeof(expected_str));
        /* Don't break early -- keep timing constant. */
	}

	OPENSSL_cleanse(key, sizeof(key));
	return matched;
}

static char *totp_make_secret_b32(void)
{
	unsigned char raw[TWOFA_SECRET_BYTES];
	char *out;
	int outsize = ((TWOFA_SECRET_BYTES + 4) / 5) * 8 + 1;

	if (RAND_bytes(raw, sizeof(raw)) != 1)
		return NULL;
	out = safe_alloc(outsize);
	if (base32_encode(raw, sizeof(raw), out, outsize) <= 0)
	{
		safe_free(out);
		OPENSSL_cleanse(raw, sizeof(raw));
		return NULL;
	}
	OPENSSL_cleanse(raw, sizeof(raw));
	return out;
}

/* ----- otpauth:// URI ----- */

static void otpauth_url_encode(const char *in, char *out, size_t out_size)
{
	size_t pos = 0;
	while (*in && pos + 4 < out_size)
	{
		unsigned char c = (unsigned char)*in++;
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') || c == '-' || c == '_' ||
		    c == '.' || c == '~')
		{
			out[pos++] = (char)c;
		} else
		{
			if (pos + 3 >= out_size)
				break;
			out[pos++] = '%';
			static const char hex[] = "0123456789ABCDEF";
			out[pos++] = hex[(c >> 4) & 0xF];
			out[pos++] = hex[c & 0xF];
		}
	}
	out[pos] = '\0';
}

static char *totp_build_otpauth_uri(const char *issuer, const char *account,
                                    const char *secret_b32)
{
	char enc_issuer[256];
	char enc_account[256];
	char *uri;
	size_t need;

	otpauth_url_encode(issuer, enc_issuer, sizeof(enc_issuer));
	otpauth_url_encode(account, enc_account, sizeof(enc_account));

	need = strlen(enc_issuer) * 2 + strlen(enc_account) +
	       strlen(secret_b32) + 128;
	uri = safe_alloc(need);
	snprintf(uri, need,
	         "otpauth://totp/%s:%s?secret=%s&issuer=%s"
	         "&algorithm=SHA1&digits=%d&period=%d",
	         enc_issuer, enc_account, secret_b32, enc_issuer,
	         TWOFA_CODE_DIGITS, TWOFA_PERIOD_SECONDS);
	return uri;
}

/* ----- 2FA credential CRUD ----- */

void twofa_free_credential_list(TwoFACredential *head)
{
	TwoFACredential *cur = head, *n;
	while (cur)
	{
		n = cur->next;
		free(cur->type);
		free(cur->name);
		free(cur->secret);
		free(cur);
		cur = n;
	}
}

TwoFACredential *twofa_list_credentials(long int account_id)
{
	const char *sql =
	    "SELECT id,account_id,type,name,secret,created_at"
	    " FROM account_2fa_credentials WHERE account_id = ? ORDER BY id ASC";
	sqlite3_stmt *stmt;
	TwoFACredential *head = NULL, *tail = NULL;

	if (!obsidian_db)
		return NULL;
	if (sqlite3_prepare_v2(obsidian_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return NULL;
	sqlite3_bind_int(stmt, 1, (int)account_id);
	while (sqlite3_step(stmt) == SQLITE_ROW)
	{
		TwoFACredential *c = safe_alloc(sizeof(*c));
		c->id = sqlite3_column_int(stmt, 0);
		c->account_id = sqlite3_column_int(stmt, 1);
		c->type = strdup((const char *)sqlite3_column_text(stmt, 2));
		c->name = strdup((const char *)sqlite3_column_text(stmt, 3));
		c->secret = strdup((const char *)sqlite3_column_text(stmt, 4));
		c->created_at = (time_t)sqlite3_column_int(stmt, 5);
		c->next = NULL;
		if (tail)
			tail->next = c;
		else
			head = c;
		tail = c;
	}
	sqlite3_finalize(stmt);
	return head;
}

int twofa_count_credentials(long int account_id)
{
	const char *sql =
	    "SELECT COUNT(*) FROM account_2fa_credentials WHERE account_id = ?";
	sqlite3_stmt *stmt;
	int n = -1;
	if (!obsidian_db)
		return -1;
	if (sqlite3_prepare_v2(obsidian_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_int(stmt, 1, (int)account_id);
	if (sqlite3_step(stmt) == SQLITE_ROW)
		n = sqlite3_column_int(stmt, 0);
	sqlite3_finalize(stmt);
	return n;
}

/* Count 2FA credentials excluding a given type. Used by the step-up
 * planner to answer "are there any factors I can demand that aren't the
 * one the user just used as primary?". `exclude` may be NULL or "" to
 * count everything. */
static int twofa_count_credentials_excluding(long int account_id,
                                             const char *exclude)
{
	const char *sql =
	    "SELECT COUNT(*) FROM account_2fa_credentials"
	    " WHERE account_id = ? AND type != ?";
	sqlite3_stmt *stmt;
	int n = 0;
	if (!obsidian_db)
		return 0;
	if (sqlite3_prepare_v2(obsidian_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;
	sqlite3_bind_int(stmt, 1, (int)account_id);
	sqlite3_bind_text(stmt, 2, exclude ? exclude : "", -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_ROW)
		n = sqlite3_column_int(stmt, 0);
	sqlite3_finalize(stmt);
	return n;
}

int twofa_insert_credential(long int account_id, const char *type,
                            const char *name, const char *secret,
                            long int *out_id)
{
	const char *sql =
	    "INSERT INTO account_2fa_credentials"
	    " (account_id, type, name, secret, created_at) VALUES (?, ?, ?, ?, ?)";
	sqlite3_stmt *stmt;
	int result;

	if (!obsidian_db)
		return 0;
	if (sqlite3_prepare_v2(obsidian_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;
	sqlite3_bind_int(stmt, 1, (int)account_id);
	sqlite3_bind_text(stmt, 2, type, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, secret, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 5, (int)time(NULL));
	result = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (result != SQLITE_DONE)
		return 0;
	if (out_id)
		*out_id = (long int)sqlite3_last_insert_rowid(obsidian_db);
	return 1;
}

int twofa_delete_credential(long int account_id, long int cred_id)
{
	const char *sql =
	    "DELETE FROM account_2fa_credentials"
	    " WHERE id = ? AND account_id = ?";
	sqlite3_stmt *stmt;
	int result, rows;

	if (!obsidian_db)
		return 0;
	if (sqlite3_prepare_v2(obsidian_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;
	sqlite3_bind_int(stmt, 1, (int)cred_id);
	sqlite3_bind_int(stmt, 2, (int)account_id);
	result = sqlite3_step(stmt);
	rows = sqlite3_changes(obsidian_db);
	sqlite3_finalize(stmt);
	return (result == SQLITE_DONE && rows > 0) ? 1 : 0;
}

/* ----- Per-client enrolment + step-up state -----
 * (struct types and ModData macros are forward-declared near the top of
 * the file so the SASL hook can reference them.) */

static void twofa_enroll_free(TwoFAEnroll *e)
{
	if (!e)
		return;
	if (e->secret_b32)
		OPENSSL_cleanse(e->secret_b32, strlen(e->secret_b32));
	safe_free(e->secret_b32);
	safe_free(e->type);
	safe_free(e->oauth_provider);
	if (e->oauth_token)
	{
		OPENSSL_cleanse(e->oauth_token, e->oauth_token_len);
		safe_free(e->oauth_token);
	}
	safe_free(e);
}

static void twofa_enroll_md_free(ModData *m)
{
	if (m->ptr)
	{
		twofa_enroll_free((TwoFAEnroll *)m->ptr);
		m->ptr = NULL;
	}
}

static void twofa_clear_enroll(Client *c)
{
	TwoFAEnroll *e = TwoFAEnrollGet(c);
	if (e)
	{
		twofa_enroll_free(e);
		TwoFAEnrollSet(c, NULL);
	}
}

static void twofa_stepup_md_free(ModData *m)
{
	if (m->ptr)
	{
		safe_free(m->ptr);
		m->ptr = NULL;
	}
}

static void twofa_clear_stepup(Client *c)
{
	TwoFAStepup *s = TwoFAStepupGet(c);
	if (s)
	{
		safe_free(s);
		TwoFAStepupSet(c, NULL);
	}
}

/* HOOKTYPE_PRE_LOCAL_HANDSHAKE_TIMEOUT.
 *
 * The handshake timeout (set::handshake-timeout, default 40s) races the
 * SASL timeout (set::sasl-timeout, default 300s) when the user is in
 * the middle of an interactive auth step -- 2FA TOTP prompt, WebAuthn
 * gesture, OAuth consent flow. We tell ircd to skip the registration
 * kill while a SASL session is in flight; sasl_timeout remains the
 * real ceiling so we don't leak a stalled handshake forever.
 *
 * We also extend during an active 2FA step-up even after the primary
 * SASL frame succeeded -- on UnrealIRCd's model that's a separate
 * AUTHENTICATE round-trip and the user is the one slowing things down. */
static int accreg_pre_local_handshake_timeout(Client *client,
                                              const char **comment)
{
	int saslType = GetSaslType(client);
	TwoFAStepup *stepup = TwoFAStepupGet(client);

	if ((saslType && saslType != SASL_TYPE_NONE) ||
	    (stepup && stepup->active))
	{
		if (comment)
			*comment = "Authentication in progress";
		return HOOK_ALLOW;
	}

	return HOOK_CONTINUE;
}

/* ----- Helpers ----- */

static int twofa_valid_name(const char *s)
{
	if (!s || !*s)
		return 0;
	size_t n = strlen(s);
	if (n > TWOFA_NAME_MAX)
		return 0;
	for (size_t i = 0; i < n; i++)
	{
		unsigned char c = (unsigned char)s[i];
		if (c <= 0x20 || c == 0x7F)
			return 0;
	}
	return 1;
}

static int parse_cred_id(const char *id_str, long int *out_id)
{
    /* Format: "cred-<int>". */
	if (!id_str || strncmp(id_str, "cred-", 5))
		return 0;
	const char *p = id_str + 5;
	if (!*p)
		return 0;
	char *end;
	long n = strtol(p, &end, 10);
	if (*end || n <= 0)
		return 0;
	*out_id = (long int)n;
	return 1;
}

static void format_cred_id(char *out, size_t out_size, long int id)
{
	snprintf(out, out_size, "cred-%ld", id);
}

static char *iso8601_utc(time_t t)
{
	static char buf[32];
	struct tm *tm = gmtime(&t);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm);
	return buf;
}

/* ----- Standard-replies senders ----- */

static void twofa_fail(Client *c, const char *code,
                       const char *p1, const char *msg)
{
	if (p1)
		sendto_one(c, NULL, ":%s FAIL 2FA %s %s :%s", me.name, code, p1, msg);
	else
		sendto_one(c, NULL, ":%s FAIL 2FA %s :%s", me.name, code, msg);
}

static void twofa_note(Client *c, const char *code,
                       const char *p1, const char *p2, const char *msg)
{
	if (p1 && p2)
		sendto_one(c, NULL, ":%s NOTE 2FA %s %s %s :%s",
		           me.name, code, p1, p2, msg);
	else if (p1)
		sendto_one(c, NULL, ":%s NOTE 2FA %s %s :%s",
		           me.name, code, p1, msg);
	else
		sendto_one(c, NULL, ":%s NOTE 2FA %s :%s", me.name, code, msg);
}

/* ----- Subcommand handlers ----- */

static void twofa_cmd_status(Client *client, Account *acc)
{
	if (acc->twofa_enabled)
		twofa_note(client, "ENABLED", NULL, NULL,
		           "Two-factor authentication is enabled on your account.");
	else
		twofa_note(client, "DISABLED", NULL, NULL,
		           "Two-factor authentication is not enabled on your account.");
}

static void twofa_cmd_list(Client *client, Account *acc)
{
	TwoFACredential *creds = twofa_list_credentials(acc->id);
	if (!creds)
	{
		twofa_note(client, "NO_CREDENTIALS", NULL, NULL,
		           "You have no 2FA credentials registered.");
		return;
	}
	char id_buf[TWOFA_ID_MAX + 1];
	for (TwoFACredential *c = creds; c; c = c->next)
	{
		format_cred_id(id_buf, sizeof(id_buf), c->id);
		sendto_one(client, NULL,
		           ":%s NOTE 2FA CREDENTIAL %s %s %s %s :Registered credential",
		           me.name, id_buf, c->type, c->name, iso8601_utc(c->created_at));
	}
	twofa_free_credential_list(creds);
}

static void twofa_cmd_challenge(Client *client, Account *acc, int parc, const char *parv[])
{
	const char *type;
	if (parc < 3 || BadPtr(parv[2]))
	{
		twofa_fail(client, "INVALID_TYPE", NULL,
		           "Syntax: /2FA CHALLENGE <type>");
		return;
	}
	type = parv[2];
	if (!strcasecmp(type, "webauthn"))
	{
		webauthn_2fa_handle_challenge(client, acc);
		return;
	}
	if (!strcasecmp(type, "oauth"))
	{
        /* /2FA CHALLENGE oauth <provider> -- pin a provider, open a
         * token-input session. Token is then sent across multiple
         * /2FA TOKEN <chunk> calls and finalized by /2FA ADD oauth <name>. */
		if (parc < 4 || BadPtr(parv[3]))
		{
			twofa_fail(client, "INVALID_TYPE", NULL,
			           "Syntax: /2FA CHALLENGE oauth <provider>");
			return;
		}
		OAuthProvider *prov = oauth_find_provider(parv[3]);
		if (!prov || !prov->loaded)
		{
			twofa_fail(client, "NO_SUCH_PROVIDER", parv[3],
			           "Unknown / unloaded OAuth provider.");
			return;
		}
		twofa_clear_enroll(client);
		TwoFAEnroll *e = safe_alloc(sizeof(*e));
		safe_strdup(e->type, "oauth");
		safe_strdup(e->oauth_provider, prov->name);
		e->oauth_token = NULL;
		e->oauth_token_len = 0;
		e->oauth_token_cap = 0;
		e->expires_at = time(NULL) + TWOFA_CHALLENGE_LIFETIME;
		TwoFAEnrollSet(client, e);
		sendto_one(client, NULL,
		           ":%s NOTE 2FA REGISTRATION_CHALLENGE oauth %s :"
		           "Send the bearer token via repeated /2FA TOKEN <chunk> calls "
		           "(<= 400 bytes each), then finalize with "
		           "/2FA ADD oauth <name>.",
		           me.name, prov->name);
		return;
	}
	if (strcasecmp(type, TWOFA_TYPE_TOTP))
	{
		twofa_fail(client, "INVALID_TYPE", type,
		           "Unsupported credential type.");
		return;
	}

	char *secret = totp_make_secret_b32();
	if (!secret)
	{
		twofa_fail(client, "TEMPORARILY_UNAVAILABLE", NULL,
		           "Could not generate a TOTP secret.");
		return;
	}

	char *uri = totp_build_otpauth_uri(me.name, acc->name, secret);

    /* Build the JSON challenge payload, then base64 it. */
	json_t *j = json_object();
	json_object_set_new(j, "type", json_string("totp"));
	json_object_set_new(j, "secret", json_string(secret));
	json_object_set_new(j, "issuer", json_string(me.name));
	json_object_set_new(j, "account", json_string(acc->name));
	json_object_set_new(j, "algorithm", json_string("SHA1"));
	json_object_set_new(j, "digits", json_integer(TWOFA_CODE_DIGITS));
	json_object_set_new(j, "period", json_integer(TWOFA_PERIOD_SECONDS));
	json_object_set_new(j, "uri", json_string(uri));
	char *json_str = json_dumps(j, JSON_COMPACT);
	json_decref(j);
	safe_free(uri);

	if (!json_str)
	{
		OPENSSL_cleanse(secret, strlen(secret));
		safe_free(secret);
		twofa_fail(client, "TEMPORARILY_UNAVAILABLE", NULL,
		           "Could not encode challenge.");
		return;
	}

    /* base64 the JSON */
	size_t jlen = strlen(json_str);
	size_t b64size = ((jlen + 2) / 3) * 4 + 1;
	char *b64 = safe_alloc(b64size);
	int n = b64_encode((const unsigned char *)json_str, jlen, b64, b64size);
	OPENSSL_cleanse(json_str, jlen);
	free(json_str);
	if (n <= 0)
	{
		OPENSSL_cleanse(secret, strlen(secret));
		safe_free(secret);
		safe_free(b64);
		twofa_fail(client, "TEMPORARILY_UNAVAILABLE", NULL,
		           "Could not encode challenge.");
		return;
	}

    /* Save the pending secret on the client. */
	twofa_clear_enroll(client);
	TwoFAEnroll *e = safe_alloc(sizeof(*e));
	safe_strdup(e->type, "totp");
	e->secret_b32 = secret; /* moved */
	e->expires_at = time(NULL) + TWOFA_CHALLENGE_LIFETIME;
	TwoFAEnrollSet(client, e);

	sendto_one(client, NULL,
	           ":%s NOTE 2FA REGISTRATION_CHALLENGE totp %s :"
	           "Add the secret to your authenticator app then run "
	           "/2FA ADD totp <name> <code>",
	           me.name, b64);
	safe_free(b64);
}

/* /2FA TOKEN <chunk> -- append a chunk to the in-flight OAuth enrolment.
 * The buffered token is then validated by /2FA ADD oauth <name>. */
static void twofa_cmd_oauth_token(Client *client, int parc, const char *parv[])
{
	if (parc < 3 || BadPtr(parv[2]))
	{
		twofa_fail(client, "INVALID_CREDENTIAL_DATA", NULL,
		           "Syntax: /2FA TOKEN <chunk>");
		return;
	}
	TwoFAEnroll *e = TwoFAEnrollGet(client);
	if (!e || !e->type || strcmp(e->type, "oauth") ||
	    time(NULL) > e->expires_at)
	{
		twofa_fail(client, "NO_CHALLENGE", NULL,
		           "No active OAuth enrolment; run /2FA CHALLENGE oauth <provider> first.");
		return;
	}
	size_t add = strlen(parv[2]);
	if (add > 512)
	{
		twofa_fail(client, "INVALID_CREDENTIAL_DATA", NULL,
		           "Token chunk exceeds 512 bytes.");
		return;
	}
	size_t need = e->oauth_token_len + add + 1;
	if (need > 16384)
	{
		twofa_clear_enroll(client);
		twofa_fail(client, "INVALID_CREDENTIAL_DATA", NULL,
		           "Buffered token exceeds 16 KiB; cancelled.");
		return;
	}
	if (need > e->oauth_token_cap)
	{
		size_t nc = e->oauth_token_cap ? e->oauth_token_cap : 1024;
		while (nc < need)
			nc *= 2;
		char *nb = safe_alloc(nc);
		if (e->oauth_token)
			memcpy(nb, e->oauth_token, e->oauth_token_len);
		if (e->oauth_token)
		{
			OPENSSL_cleanse(e->oauth_token, e->oauth_token_len);
			safe_free(e->oauth_token);
		}
		e->oauth_token = nb;
		e->oauth_token_cap = nc;
	}
	memcpy(e->oauth_token + e->oauth_token_len, parv[2], add);
	e->oauth_token_len += add;
	e->oauth_token[e->oauth_token_len] = 0;
}

static void twofa_cmd_add(Client *client, Account *acc, int parc, const char *parv[])
{
	const char *type, *name, *data;

	if (parc < 4 || BadPtr(parv[2]) || BadPtr(parv[3]))
	{
		twofa_fail(client, "INVALID_CREDENTIAL_DATA", NULL,
		           "Syntax: /2FA ADD <type> <name> <data>");
		return;
	}
	type = parv[2];
	name = parv[3];
	data = (parc >= 5 && !BadPtr(parv[4])) ? parv[4] : NULL;

	if (!twofa_valid_name(name))
	{
		twofa_fail(client, "INVALID_NAME", NULL,
		           "Name must be printable, no whitespace, max 64 bytes.");
		return;
	}
	if (!strcasecmp(type, "oauth"))
	{
        /* Token was streamed via prior /2FA CHALLENGE oauth + /2FA TOKEN
         * <chunk> calls; finalize from the enroll buffer. */
		TwoFAEnroll *e = TwoFAEnrollGet(client);
		if (!e || !e->type || strcmp(e->type, "oauth") ||
		    !e->oauth_provider || !e->oauth_token || e->oauth_token_len == 0 ||
		    time(NULL) > e->expires_at)
		{
			twofa_fail(client, "NO_CHALLENGE", NULL,
			           "No active OAuth enrolment; run /2FA CHALLENGE oauth <provider> "
			           "and stream the token via /2FA TOKEN <chunk> first.");
			return;
		}
		OAuthProvider *prov = oauth_find_provider(e->oauth_provider);
		if (!prov || !prov->loaded)
		{
			twofa_fail(client, "NO_SUCH_PROVIDER", e->oauth_provider,
			           "OAuth provider is no longer configured.");
			twofa_clear_enroll(client);
			return;
		}

        /* JWT tokens have exactly two '.' separators. If the buffered
         * token doesn't look like a JWT and the provider has a
         * userinfo-url configured (e.g. GitHub), route through the
         * opaque-validation async path instead. The callback completes
         * the enrollment on its own. */
		const char *d1 = strchr(e->oauth_token, '.');
		const char *d2 = d1 ? strchr(d1 + 1, '.') : NULL;
		int looks_like_jwt = (d1 != NULL && d2 != NULL);
		if (!looks_like_jwt && prov->userinfo_url)
		{
			oauth_enroll_opaque_async(client, prov, e->oauth_token,
			                          acc->id, name);
            /* keep the enroll buffer alive until the callback fires */
			return;
		}

		OAuthProvider *seen = NULL;
		char *subject = oauth_validate_jwt(e->oauth_token, &seen);
		if (!subject || seen != prov)
		{
			safe_free(subject);
			add_fake_lag(client, 2000);
			twofa_fail(client, "INVALID_CREDENTIAL_DATA", NULL,
			           "Token is not valid for that provider.");
			twofa_clear_enroll(client);
			return;
		}
		char *cred = oauth_make_cred_secret(prov->name, subject);
		long existing = oauth_lookup_account_by_credential(prov->name, subject);
		if (existing && existing != acc->id)
		{
			safe_free(subject);
			safe_free(cred);
			twofa_clear_enroll(client);
			twofa_fail(client, "ALREADY_LINKED", NULL,
			           "That OAuth identity is already linked to another account.");
			return;
		}
		if (existing == acc->id)
		{
			safe_free(subject);
			safe_free(cred);
			twofa_clear_enroll(client);
			sendto_one(client, NULL,
			           ":%s 2FA ADD ALREADY_LINKED oauth %s :Already linked.",
			           me.name, prov->name);
			return;
		}
		long int new_id = 0;
		if (!twofa_insert_credential(acc->id, "oauth", name, cred, &new_id))
		{
			safe_free(subject);
			safe_free(cred);
			twofa_clear_enroll(client);
			twofa_fail(client, "TEMPORARILY_UNAVAILABLE", NULL,
			           "Could not persist credential.");
			return;
		}
		char id_buf[TWOFA_ID_MAX + 1];
		format_cred_id(id_buf, sizeof(id_buf), new_id);
		sendto_one(client, NULL,
		           ":%s 2FA ADD SUCCESS oauth %s :Credential '%s' registered "
		           "(provider=%s subject=%s).",
		           me.name, id_buf, name, prov->name, subject);
		unreal_log(ULOG_INFO, "account", "2FA_OAUTH_LINK", client,
		           "$client.details linked OAuth identity to account $account "
		           "[provider: $provider] [subject: $subject]",
		           log_data_string("account", acc->name),
		           log_data_string("provider", prov->name),
		           log_data_string("subject", subject));
		safe_free(subject);
		safe_free(cred);
		twofa_clear_enroll(client);
		return;
	}
	if (!data)
	{
		twofa_fail(client, "INVALID_CREDENTIAL_DATA", NULL,
		           "Syntax: /2FA ADD <type> <name> <data>");
		return;
	}
	if (!strcasecmp(type, "webauthn"))
	{
		if (!webauthn_2fa_handle_add(client, acc, name, data))
		{
			add_fake_lag(client, 3000);
			twofa_fail(client, "INVALID_CREDENTIAL_DATA", NULL,
			           "WebAuthn registration data did not verify.");
		}
		return;
	}
	if (!strcasecmp(type, "external"))
	{
        /* SHA-256 hex fingerprint = 64 hex chars.  Lowercase per spec. */
		size_t dlen = strlen(data);
		if (dlen != 64)
		{
			twofa_fail(client, "INVALID_CREDENTIAL_DATA", NULL,
			           "Fingerprint must be 64 hex characters (SHA-256).");
			return;
		}
		char normalised[65];
		for (size_t i = 0; i < dlen; i++)
		{
			char c = data[i];
			if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
				normalised[i] = c;
			else if (c >= 'A' && c <= 'F')
				normalised[i] = (char)(c - 'A' + 'a');
			else
			{
				twofa_fail(client, "INVALID_CREDENTIAL_DATA", NULL,
				           "Fingerprint must be lowercase hex SHA-256.");
				return;
			}
		}
		normalised[64] = '\0';

		long int new_id = 0;
		if (!twofa_insert_credential(acc->id, "external", name,
		                             normalised, &new_id))
		{
			twofa_fail(client, "TEMPORARILY_UNAVAILABLE", NULL,
			           "Could not persist credential.");
			return;
		}
		char id_buf[TWOFA_ID_MAX + 1];
		format_cred_id(id_buf, sizeof(id_buf), new_id);
		sendto_one(client, NULL,
		           ":%s 2FA ADD SUCCESS external %s :Credential '%s' registered.",
		           me.name, id_buf, name);
		return;
	}
	if (strcasecmp(type, TWOFA_TYPE_TOTP))
	{
		twofa_fail(client, "INVALID_TYPE", type,
		           "Unsupported credential type.");
		return;
	}

	TwoFAEnroll *e = TwoFAEnrollGet(client);
	if (!e || strcmp(e->type, "totp") || time(NULL) > e->expires_at ||
	    !e->secret_b32)
	{
		twofa_fail(client, "NO_CHALLENGE", NULL,
		           "No active TOTP enrolment challenge; run /2FA CHALLENGE totp first.");
		return;
	}

	if (!totp_verify(e->secret_b32, data))
	{
		add_fake_lag(client, 3000);
		twofa_fail(client, "INVALID_CREDENTIAL_DATA", NULL,
		           "TOTP code did not verify.");
		return;
	}

	long int new_id = 0;
	if (!twofa_insert_credential(acc->id, "totp", name, e->secret_b32, &new_id))
	{
		twofa_fail(client, "TEMPORARILY_UNAVAILABLE", NULL,
		           "Could not persist credential.");
		return;
	}

	char id_buf[TWOFA_ID_MAX + 1];
	format_cred_id(id_buf, sizeof(id_buf), new_id);
	sendto_one(client, NULL,
	           ":%s 2FA ADD SUCCESS totp %s :Credential '%s' registered.",
	           me.name, id_buf, name);

	twofa_clear_enroll(client);
}

static void twofa_cmd_remove(Client *client, Account *acc, int parc, const char *parv[])
{
	const char *id_str;
	long int cred_id;
	int count;

	if (parc < 3 || BadPtr(parv[2]))
	{
		twofa_fail(client, "UNKNOWN_CREDENTIAL", NULL,
		           "Syntax: /2FA REMOVE <id>");
		return;
	}
	id_str = parv[2];
	if (!parse_cred_id(id_str, &cred_id))
	{
		twofa_fail(client, "UNKNOWN_CREDENTIAL", id_str,
		           "Bad credential id.");
		return;
	}

	if (acc->twofa_enabled)
	{
		count = twofa_count_credentials(acc->id);
		if (count <= 1)
		{
			twofa_fail(client, "REMOVE_LAST_CREDENTIAL", NULL,
			           "Cannot remove the last credential while 2FA is enabled.  "
			           "Run /2FA DISABLE first.");
			return;
		}
	}

	if (!twofa_delete_credential(acc->id, cred_id))
	{
		twofa_fail(client, "UNKNOWN_CREDENTIAL", id_str,
		           "No such credential.");
		return;
	}

	sendto_one(client, NULL,
	           ":%s 2FA REMOVE SUCCESS %s :Credential removed.",
	           me.name, id_str);
}

static void twofa_cmd_enable(Client *client, Account *acc)
{
	int count;
	if (acc->twofa_enabled)
	{
		twofa_fail(client, "ALREADY_ENABLED", NULL,
		           "Two-factor authentication is already enabled.");
		return;
	}
	count = twofa_count_credentials(acc->id);
	if (count <= 0)
	{
		twofa_fail(client, "NO_CREDENTIALS", NULL,
		           "Add at least one credential before enabling 2FA.");
		return;
	}
	acc->twofa_enabled = 1;
	if (!update_account_twofa_enabled(acc))
	{
		acc->twofa_enabled = 0;
		twofa_fail(client, "TEMPORARILY_UNAVAILABLE", NULL,
		           "Could not persist 2FA state.");
		return;
	}
	sendto_one(client, NULL,
	           ":%s 2FA ENABLE SUCCESS :Two-factor authentication is now "
	           "required for login.",
	           me.name);
	unreal_log(ULOG_INFO, "account", "2FA_ENABLE", client,
	           "$client.details enabled 2FA on account $account",
	           log_data_string("account", acc->name));
}

static int twofa_verify_proof(Account *acc, const char *type,
                              const char *data)
{
    /* For TOTP, walk every TOTP credential and try to match.  Constant
     * time per credential; not constant overall (depends on count) but
     * acceptable. */
	if (!strcasecmp(type, TWOFA_TYPE_TOTP))
	{
		TwoFACredential *creds = twofa_list_credentials(acc->id);
		int matched = 0;
		for (TwoFACredential *c = creds; c; c = c->next)
		{
			if (strcasecmp(c->type, "totp"))
				continue;
			if (totp_verify(c->secret, data))
				matched = 1;
		}
		twofa_free_credential_list(creds);
		return matched;
	}
	if (!strcasecmp(type, "external"))
	{
        /* Compare submitted fingerprint (lowercased) against any
         * registered `external` credential for the account. */
		TwoFACredential *creds = twofa_list_credentials(acc->id);
		size_t dlen = strlen(data);
		char *low = safe_alloc(dlen + 1);
		for (size_t i = 0; i < dlen; i++)
		{
			char c = data[i];
			low[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
		}
		low[dlen] = '\0';
		int matched = 0;
		for (TwoFACredential *c = creds; c; c = c->next)
		{
			if (strcasecmp(c->type, "external"))
				continue;
			if (c->secret && !strcmp(c->secret, low))
				matched = 1;
		}
		safe_free(low);
		twofa_free_credential_list(creds);
		return matched;
	}
	return 0;
}

static void twofa_cmd_disable(Client *client, Account *acc, int parc, const char *parv[])
{
	const char *type, *data;

	if (!acc->twofa_enabled)
	{
		twofa_fail(client, "ALREADY_DISABLED", NULL,
		           "Two-factor authentication is not enabled.");
		return;
	}
	if (parc < 4 || BadPtr(parv[2]) || BadPtr(parv[3]))
	{
		twofa_fail(client, "INVALID_CHALLENGE_RESPONSE", NULL,
		           "Syntax: /2FA DISABLE <type> <data>");
		return;
	}
	type = parv[2];
	data = parv[3];

	if (!twofa_verify_proof(acc, type, data))
	{
		add_fake_lag(client, 3000);
		twofa_fail(client, "INVALID_CHALLENGE_RESPONSE", NULL,
		           "Second-factor proof did not verify.");
		return;
	}

	acc->twofa_enabled = 0;
	if (!update_account_twofa_enabled(acc))
	{
		acc->twofa_enabled = 1;
		twofa_fail(client, "TEMPORARILY_UNAVAILABLE", NULL,
		           "Could not persist 2FA state.");
		return;
	}
	sendto_one(client, NULL,
	           ":%s 2FA DISABLE SUCCESS :Two-factor authentication has been "
	           "disabled.",
	           me.name);
	unreal_log(ULOG_INFO, "account", "2FA_DISABLE", client,
	           "$client.details disabled 2FA on account $account",
	           log_data_string("account", acc->name));
}

/* ----- Top-level dispatcher ----- */

CMD_FUNC(cmd_2fa)
{
	Account *acc;
	const char *sub;

	if (!IsLoggedIn(client))
	{
		twofa_fail(client, "NOT_AUTHENTICATED", NULL,
		           "You must be logged in to use 2FA commands.");
		return;
	}
	if (parc < 2 || BadPtr(parv[1]))
	{
		twofa_fail(client, "INVALID_TYPE", NULL,
		           "Syntax: /2FA <STATUS|LIST|CHALLENGE|ADD|REMOVE|ENABLE|DISABLE> ...");
		return;
	}
	acc = find_account_by_client(client);
	if (!acc)
	{
		twofa_fail(client, "NOT_AUTHENTICATED", NULL,
		           "Could not load your account.");
		return;
	}
	sub = parv[1];

	if (!strcasecmp(sub, "STATUS"))
		twofa_cmd_status(client, acc);
	else if (!strcasecmp(sub, "LIST"))
		twofa_cmd_list(client, acc);
	else if (!strcasecmp(sub, "CHALLENGE"))
		twofa_cmd_challenge(client, acc, parc, parv);
	else if (!strcasecmp(sub, "ADD"))
		twofa_cmd_add(client, acc, parc, parv);
	else if (!strcasecmp(sub, "TOKEN"))
		twofa_cmd_oauth_token(client, parc, parv);
	else if (!strcasecmp(sub, "REMOVE"))
		twofa_cmd_remove(client, acc, parc, parv);
	else if (!strcasecmp(sub, "ENABLE"))
		twofa_cmd_enable(client, acc);
	else if (!strcasecmp(sub, "DISABLE"))
		twofa_cmd_disable(client, acc, parc, parv);
	else
		twofa_fail(client, "INVALID_TYPE", sub, "Unknown 2FA subcommand.");

	free_account(acc);
}

/* ----- SASL step-up integration ----- */

/** Called after a first-factor SASL exchange has verified the user.
 *  `primary_factor` names the credential type that just verified (so we
 *  can exclude it when shopping for a step-up factor):
 *
 *    - "password" -- PLAIN/SCRAM authenticated.  All 2FA factor types
 *                    are eligible step-up candidates (TOTP, WebAuthn,
 *                    OAuth, external/cert).
 *    - "oauth"    -- IRCV3BEARER / OAUTHBEARER authenticated; the
 *                    bound oauth credential row IS what just verified
 *                    primary.  Step-up still happens if the account
 *                    has a non-oauth factor (TOTP/WebAuthn) -- the
 *                    user explicitly enabled 2FA so they want belt-
 *                    and-suspenders.  But if the only factor is OAuth
 *                    itself, accept the primary as both factors and
 *                    skip step-up; otherwise the user is locked out.
 *    - "external" -- SASL EXTERNAL cert fingerprint matched.  Step-up
 *                    via any non-external factor.
 *
 *  If 2FA is enforced AND a non-primary factor exists, withholds
 *  900/903 and emits AUTHENTICATE 2FA-REQUIRED. Returns 1 in that case
 *  (caller MUST NOT log the user in or send 900/903), 0 otherwise. */
static int twofa_maybe_start_stepup(Client *client, Account *acc,
                                    const char *primary_factor)
{
	if (!acc || !acc->twofa_enabled)
		return 0;
    /* Total cred count is 0: 2FA flagged on but DB-edited away. Degrade
     * to first-factor only rather than permanently lock the user out. */
	if (twofa_count_credentials(acc->id) <= 0)
		return 0;
    /* No factor of a type other than what we just used? Then the
     * primary already proved the strongest thing the user has -- demanding
     * the same proof again would only lock them out. */
	if (twofa_count_credentials_excluding(acc->id, primary_factor) <= 0)
		return 0;

	twofa_clear_stepup(client);
	TwoFAStepup *s = safe_alloc(sizeof(*s));
	s->active = 1;
	strlcpy(s->account, acc->name, sizeof(s->account));
	strlcpy(s->primary_factor, primary_factor ? primary_factor : "",
	        sizeof(s->primary_factor));
	TwoFAStepupSet(client, s);

	sendto_one(client, NULL, ":%s AUTHENTICATE 2FA-REQUIRED", me.name);
	return 1;
}

/* Decode the buffered base64 SASL payload from an AUTHENTICATE 2FA-OAUTH
 * exchange and either complete login (JWT path, sync) or kick off an
 * async userinfo round-trip (opaque path). The (provider, subject) the
 * bearer resolves to must be bound to s->account; otherwise SASL fails. */
static void twofa_handle_stepup_oauth(Client *client, const char *full_b64)
{
	TwoFAStepup *s = TwoFAStepupGet(client);
	if (!s || !s->active)
	{
		sendnumeric(client, ERR_SASLFAIL);
		DelSaslType(client);
		return;
	}
	unsigned char buf[8192] = {0};
	int n = EVP_DecodeBlock(buf, (const unsigned char *)full_b64,
	                        strlen(full_b64));
	if (n <= 0)
	{
		sendnumeric(client, ERR_SASLFAIL);
		DelSaslType(client);
		twofa_clear_stepup(client);
		return;
	}
	size_t plen = strlen(full_b64);
	int real_pad = 0;
	if (plen >= 1 && full_b64[plen - 1] == '=')
		real_pad++;
	if (plen >= 2 && full_b64[plen - 2] == '=')
		real_pad++;
	n -= real_pad;
	if (n <= 0 || n >= (int)sizeof(buf))
	{
		sendnumeric(client, ERR_SASLFAIL);
		DelSaslType(client);
		twofa_clear_stepup(client);
		return;
	}
	buf[n] = 0;

	int nul1 = -1, nul2 = -1;
	for (int i = 0; i < n; i++)
	{
		if (buf[i] == 0)
		{
			if (nul1 < 0)
				nul1 = i;
			else if (nul2 < 0)
			{
				nul2 = i;
				break;
			}
		}
	}
	if (nul1 < 0 || nul2 < 0 || nul2 + 1 >= n)
	{
		sendnumeric(client, ERR_SASLFAIL);
		DelSaslType(client);
		twofa_clear_stepup(client);
		return;
	}
	const char *authzid = (const char *)buf;
	const char *type = (const char *)(buf + nul1 + 1);
	const char *token = (const char *)(buf + nul2 + 1);

	if (!strcmp(type, "opaque"))
	{
		if (!*authzid)
		{
			sendnumeric(client, ERR_SASLFAIL);
			DelSaslType(client);
			twofa_clear_stepup(client);
			return;
		}
		OAuthProvider *prov = oauth_find_provider(authzid);
		if (!prov || !prov->loaded || !prov->userinfo_url)
		{
			sendnumeric(client, ERR_SASLFAIL);
			DelSaslType(client);
			twofa_clear_stepup(client);
			return;
		}
		oauth_stepup_opaque_async(client, prov, token, s->account);
        /* deliberate: TwoFAStepup state stays alive until callback fires */
		return;
	}
	if (strcmp(type, "oauth2") && strcmp(type, "jwt"))
	{
		sendnumeric(client, ERR_SASLFAIL);
		DelSaslType(client);
		twofa_clear_stepup(client);
		return;
	}
    /* JWT path -- validate locally against JWKS, check the resulting
     * (provider, subject) is bound to s->account. */
	OAuthProvider *prov = NULL;
	char *subject = oauth_validate_jwt(token, &prov);
	if (!subject)
	{
		sendnumeric(client, ERR_SASLFAIL);
		DelSaslType(client);
		twofa_clear_stepup(client);
		return;
	}
	long bound = oauth_lookup_account_by_credential(prov->name, subject);
	Account *acc = find_account(s->account);
	int ok = acc && bound == acc->id;
	if (!ok)
	{
		safe_free(subject);
		if (acc)
			free_account(acc);
		sendnumeric(client, ERR_SASLFAIL);
		DelSaslType(client);
		twofa_clear_stepup(client);
		return;
	}
	strlcpy(client->user->account, acc->name, sizeof(client->user->account));
	user_account_login(NULL, client);
	if (!IsDead(client))
	{
		client->local->sasl_complete = 1;
		sendnumeric(client, RPL_SASLSUCCESS);
	}
	DelSaslType(client);
	twofa_clear_stepup(client);
	unreal_log(ULOG_INFO, "account", "SASL_LOGIN", client,
	           "SASL+2FA-OAUTH login for $client.details "
	           "[account: $account] [provider: $provider]",
	           log_data_string("account", acc->name),
	           log_data_string("provider", prov->name));
	free_account(acc);
	safe_free(subject);
}

/** Handle an AUTHENTICATE message in the TOTP step-up phase.
 *  Returns 1 if it consumed the message, 0 to fall through. */
static int twofa_handle_stepup_authenticate(Client *client, const char *param)
{
	TwoFAStepup *s = TwoFAStepupGet(client);
	if (!s || !s->active)
		return 0;

    /* If client says "*", abort. */
	if (!strcmp(param, "*"))
	{
		twofa_clear_stepup(client);
		DelSaslType(client);
		sendnumeric(client, ERR_SASLABORTED);
		return 1;
	}

    /* Mechanism selection: client sends "AUTHENTICATE TOTP" */
	if (!strcasecmp(param, "TOTP"))
	{
		SetSaslType(client, SASL_TYPE_TOTP_STEPUP);
		sendto_one(client, NULL, ":%s AUTHENTICATE +", me.name);
		return 1;
	}
    /* Mechanism selection: client sends "AUTHENTICATE 2FA-OAUTH" --
     * the second-factor variant of OAUTHBEARER/IRCV3BEARER. Wire format
     * mirrors IRCV3BEARER: [authzid]\0<token_type>\0<token>, chunked.
     * Server validates the bearer (locally for jwt, async-userinfo for
     * opaque) and only accepts it if the resulting (provider, subject)
     * matches a credential row already bound to s->account. */
    /* Step-up via the real IRCV3BEARER SASL mech. Wire format is the
     * same as primary; the server routes here based on TwoFAStepup
     * state. (OAUTHBEARER uses GS2 framing and isn't accepted as a
     * step-up factor right now -- IRCV3BEARER's [authzid]\0type\0token
     * is what every client we ship sends.) */
	if (!strcasecmp(param, "IRCV3BEARER"))
	{
        /* Refuse to "satisfy" 2FA with the same proof type that just
         * verified primary auth. Otherwise an attacker (or a confused
         * client) could replay the same OAuth bearer for both factors. */
		if (!strcasecmp(s->primary_factor, "oauth"))
		{
			twofa_clear_stepup(client);
			DelSaslType(client);
			add_fake_lag(client, 2000);
			sendnumeric(client, ERR_SASLFAIL);
			return 1;
		}
		SetSaslType(client, SASL_TYPE_OAUTH_STEPUP);
		oauth_sasl_clear(client);
		sendto_one(client, NULL, ":%s AUTHENTICATE +", me.name);
		return 1;
	}
	if (GetSaslType(client) == SASL_TYPE_OAUTH_STEPUP)
	{
		const char *full = oauth_sasl_accumulate(client, param);
		if (!full)
			return 1;       /* still chunking */
		twofa_handle_stepup_oauth(client, full);
		oauth_sasl_clear(client);
		return 1;
	}

    /* Code message: arrives when SaslType == SASL_TYPE_TOTP_STEPUP */
	if (GetSaslType(client) != SASL_TYPE_TOTP_STEPUP)
	{
        /* Unexpected -- abort. */
		twofa_clear_stepup(client);
		DelSaslType(client);
		sendnumeric(client, ERR_SASLFAIL);
		return 1;
	}

    /* Decode base64 to get the 6-digit code. */
	unsigned char buf[64];
	int n = b64_decode(param, buf, sizeof(buf) - 1);
	if (n <= 0)
	{
		twofa_clear_stepup(client);
		DelSaslType(client);
		add_fake_lag(client, 5000);
		sendnumeric(client, ERR_SASLFAIL);
		return 1;
	}
	buf[n] = 0;

	Account *acc = find_account(s->account);
	if (!acc)
	{
		twofa_clear_stepup(client);
		DelSaslType(client);
		sendnumeric(client, ERR_SASLFAIL);
		return 1;
	}

	if (!twofa_verify_proof(acc, "totp", (const char *)buf))
	{
		free_account(acc);
		twofa_clear_stepup(client);
		DelSaslType(client);
		add_fake_lag(client, 5000);
		sendnumeric(client, ERR_SASLFAIL);
		return 1;
	}

    /* Both factors satisfied: complete login. */
	strlcpy(client->user->account, acc->name, sizeof(client->user->account));
	unreal_log(ULOG_INFO, "account", "SASL_LOGIN", client,
	           "SASL+2FA login for $client.details [account: $account]",
	           log_data_string("account", acc->name));
	user_account_login(NULL, client);
	if (!IsDead(client))
	{
		client->local->sasl_complete = 1;
		sendnumeric(client, RPL_SASLSUCCESS);
	}
	DelSaslType(client);
	twofa_clear_stepup(client);
	free_account(acc);
	OPENSSL_cleanse(buf, sizeof(buf));
	return 1;
}

/* CAP value provider for draft/account-2fa */
static const char *twofa_capability_parameter(Client *client)
{
    /* Credential types this server supports for the second factor.
     * `oauth` is added so clients (e.g. obbyworld's TwoFactorSettingsModal)
     * know to surface "Link with <provider>" enrolment + AUTHENTICATE
     * 2FA-OAUTH step-up. Step-up only accepts a factor type that
     * differs from the one used for primary auth -- see
     * twofa_maybe_start_stepup() for the policy. */
	return "totp,webauthn,oauth";
}

/* CAP value provider for draft/webauthn-rp-id */
static const char *webauthn_rp_id_capability_parameter(Client *client)
{
	return me.name;
}

static int twofa_capability_visible(Client *client)
{
	return 1;
}

/* ===================================================================
 * WEBAUTHN-BIO SASL mechanism + WebAuthn registration
 * (RFC: see ircv3-specifications/extensions/sasl-webauthn-bio.md and
 *  account-2fa.md)
 *
 * Limitations of this implementation:
 *  - ES256 (alg=-7, ECDSA P-256/SHA-256) only.  RS256/EdDSA not supported.
 *  - Attestation is NOT verified -- registration accepts any well-formed
 *    attestation object.  This is acceptable for many deployments but
 *    operators that require attestation must add a verifier.
 * =================================================================== */

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

/* ----- base64url (no padding) ----- */

static int b64url_decode(const char *in, unsigned char *out, size_t out_size)
{
	char buf[2048];
	size_t n = strlen(in);
	if (n + 4 >= sizeof(buf))
		return -1;
	for (size_t i = 0; i < n; i++)
	{
		char c = in[i];
		if (c == '-')
			buf[i] = '+';
		else if (c == '_')
			buf[i] = '/';
		else
			buf[i] = c;
	}
	size_t pad = (4 - (n % 4)) % 4;
	for (size_t i = 0; i < pad; i++)
		buf[n + i] = '=';
	buf[n + pad] = 0;
	return b64_decode(buf, out, out_size);
}

static int b64url_encode(const unsigned char *in, size_t in_len,
                         char *out, size_t out_size)
{
	int n = b64_encode(in, in_len, out, out_size);
	if (n <= 0)
		return -1;
	while (n > 0 && out[n - 1] == '=')
	{
		out[n - 1] = 0;
		n--;
	}
	for (int i = 0; i < n; i++)
	{
		if (out[i] == '+')
			out[i] = '-';
		else if (out[i] == '/')
			out[i] = '_';
	}
	return n;
}

/* ----- minimal CBOR decoder (RFC 8949 subset) ----- */

typedef struct {
	int major;	           /* 0..7 */
	uint64_t arg;                /* uint value, length, or count */
	const unsigned char *bytes;         /* for major 2/3: data start */
	size_t bytes_len;                   /* for major 2/3: data length */
	const unsigned char *items;         /* for major 4/5: inner data start */
	size_t items_len;                   /* for major 4/5: inner data length */
} CborItem;

static int cbor_read_one(const unsigned char **p,
                         const unsigned char *end, CborItem *out);

static int cbor_read_head(const unsigned char **p,
                          const unsigned char *end,
                          int *major, uint64_t *arg)
{
	if (*p >= end)
		return 0;
	unsigned char ib = *(*p)++;
	*major = (ib >> 5) & 0x07;
	int info = ib & 0x1F;
	if (info < 24)
	{
		*arg = info;
		return 1;
	}
	int extra;
	switch (info)
	{
		case 24:
			extra = 1;
			break;
		case 25:
			extra = 2;
			break;
		case 26:
			extra = 4;
			break;
		case 27:
			extra = 8;
			break;
		default:
			return 0;
	}
	if (*p + extra > end)
		return 0;
	uint64_t v = 0;
	for (int i = 0; i < extra; i++)
		v = (v << 8) | *(*p)++;
	*arg = v;
	return 1;
}

static int cbor_skip(const unsigned char **p, const unsigned char *end)
{
	CborItem it;
	return cbor_read_one(p, end, &it);
}

static int cbor_read_one(const unsigned char **p, const unsigned char *end,
                         CborItem *out)
{
	int major;
	uint64_t arg;
	const unsigned char *start;

	if (!cbor_read_head(p, end, &major, &arg))
		return 0;
	out->major = major;
	out->arg = arg;
	out->bytes = NULL;
	out->bytes_len = 0;
	out->items = NULL;
	out->items_len = 0;

	switch (major)
	{
		case 0:
		case 1:
		case 7:
			return 1;
		case 2:
		case 3:
			if (*p + arg > end)
				return 0;
			out->bytes = *p;
			out->bytes_len = (size_t)arg;
			*p += arg;
			return 1;
		case 4:
		{
			start = *p;
			for (uint64_t i = 0; i < arg; i++)
				if (!cbor_skip(p, end))
					return 0;
			out->items = start;
			out->items_len = (size_t)(*p - start);
			return 1;
		}
		case 5:
		{
			start = *p;
			for (uint64_t i = 0; i < arg; i++)
			{
				if (!cbor_skip(p, end))
					return 0;  /* key */
				if (!cbor_skip(p, end))
					return 0;  /* value */
			}
			out->items = start;
			out->items_len = (size_t)(*p - start);
			return 1;
		}
		default:
			return 0;
	}
}

/** Iterate a CBOR map and call cb(key_item, value_item) for each entry.
 *  cb returns 1 to keep iterating, 0 to stop with success. */
static int cbor_map_for_each(CborItem *map_item,
                             int (*cb)(CborItem *k, CborItem *v, void *ud),
                             void *ud)
{
	const unsigned char *p = map_item->items;
	const unsigned char *end = map_item->items + map_item->items_len;
	for (uint64_t i = 0; i < map_item->arg; i++)
	{
		CborItem k, v;
		if (!cbor_read_one(&p, end, &k))
			return 0;
		if (!cbor_read_one(&p, end, &v))
			return 0;
		int r = cb(&k, &v, ud);
		if (!r)
			return 1;  /* caller-requested early stop, still success */
	}
	return 1;
}

/* ----- COSE -> EVP_PKEY (ES256) ----- */

typedef struct {
	int kty;
	int alg;
	int crv;
	const unsigned char *x;
	size_t x_len;
	const unsigned char *y;
	size_t y_len;
} CoseEs256;

static int cose_es256_callback(CborItem *k, CborItem *v, void *ud)
{
	CoseEs256 *c = ud;
	int64_t key;
	if (k->major == 0)
		key = (int64_t)k->arg;
	else if (k->major == 1)
		key = -(int64_t)(k->arg + 1);
	else
		return 1;

	if (key == 1 && v->major == 0)
		c->kty = (int)v->arg;
	else if (key == 3 && v->major == 1)
		c->alg = -(int)(v->arg + 1);
	else if (key == -1 && v->major == 0)
		c->crv = (int)v->arg;
	else if (key == -2 && v->major == 2)
	{
		c->x = v->bytes;
		c->x_len = v->bytes_len;
	} else if (key == -3 && v->major == 2)
	{
		c->y = v->bytes;
		c->y_len = v->bytes_len;
	}
	return 1;
}

static EVP_PKEY *cose_to_evp_pkey_es256(const unsigned char *cose,
                                        size_t cose_len)
{
	const unsigned char *p = cose;
	CborItem map;
	if (!cbor_read_one(&p, cose + cose_len, &map) || map.major != 5)
		return NULL;

	CoseEs256 c = {0};
	cbor_map_for_each(&map, cose_es256_callback, &c);

	if (c.kty != 2 || c.alg != -7 || c.crv != 1 ||
	    c.x_len != 32 || c.y_len != 32)
		return NULL;

	EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (!ec)
		return NULL;
	BIGNUM *bx = BN_bin2bn(c.x, 32, NULL);
	BIGNUM *by = BN_bin2bn(c.y, 32, NULL);
	EVP_PKEY *pkey = NULL;
	if (bx && by &&
	    EC_KEY_set_public_key_affine_coordinates(ec, bx, by) == 1)
	{
		pkey = EVP_PKEY_new();
		if (pkey && !EVP_PKEY_assign_EC_KEY(pkey, ec))
		{
			EVP_PKEY_free(pkey);
			pkey = NULL;
			EC_KEY_free(ec);
		} else if (pkey)
		{
			ec = NULL; /* ownership transferred */
		}
	}
	if (ec)
		EC_KEY_free(ec);
	BN_free(bx);
	BN_free(by);
	return pkey;
}

/* ----- authenticatorData parser ----- */

typedef struct {
	unsigned char rp_id_hash[32];
	unsigned char flags;
	uint32_t sign_count;
    /* Attested credential data (only when AT bit set in flags) */
	int has_attested;
	unsigned char aaguid[16];
	const unsigned char *cred_id;
	size_t cred_id_len;
	const unsigned char *cose_pubkey;
	size_t cose_pubkey_len;
} WebAuthnAuthData;

#define AUTHFLAG_UP 0x01
#define AUTHFLAG_UV 0x04
#define AUTHFLAG_AT 0x40
#define AUTHFLAG_ED 0x80

static int parse_authenticator_data(const unsigned char *data, size_t len,
                                    WebAuthnAuthData *out)
{
	if (len < 37)
		return 0;
	memset(out, 0, sizeof(*out));
	memcpy(out->rp_id_hash, data, 32);
	out->flags = data[32];
	out->sign_count = ((uint32_t)data[33] << 24) |
	                  ((uint32_t)data[34] << 16) |
	                  ((uint32_t)data[35] << 8) |
	                  ((uint32_t)data[36]);
	if (!(out->flags & AUTHFLAG_AT))
		return 1;

	if (len < 37 + 16 + 2)
		return 0;
	memcpy(out->aaguid, data + 37, 16);
	size_t cred_id_len = ((size_t)data[53] << 8) | data[54];
	if (cred_id_len == 0 || cred_id_len > 1023)
		return 0;
	if (len < 37 + 16 + 2 + cred_id_len)
		return 0;
	out->cred_id = data + 55;
	out->cred_id_len = cred_id_len;

    /* COSE key: parse one CBOR value to determine its length. */
	const unsigned char *p = data + 55 + cred_id_len;
	const unsigned char *end = data + len;
	CborItem item;
	const unsigned char *ks = p;
	if (!cbor_read_one(&p, end, &item))
		return 0;
	out->cose_pubkey = ks;
	out->cose_pubkey_len = (size_t)(p - ks);
	out->has_attested = 1;
	return 1;
}

/* ----- ECDSA verify ----- */

static int webauthn_ecdsa_verify(EVP_PKEY *pkey,
                                 const unsigned char *msg, size_t msg_len,
                                 const unsigned char *sig, size_t sig_len)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	int ok = 0;
	if (ctx &&
	    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
	    EVP_DigestVerifyUpdate(ctx, msg, msg_len) == 1 &&
	    EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1)
	{
		ok = 1;
	}
	if (ctx)
		EVP_MD_CTX_free(ctx);
	return ok;
}

/* ----- WebAuthn credential record ----- */

typedef struct {
	char *credential_id_b64u;
	char *x_b64u;
	char *y_b64u;
	char *user_handle_b64u;
	long counter;
	long row_id;            /* DB rowid in account_2fa_credentials */
	long account_id;
	char *account_name;     /* loaded on demand */
} WebAuthnCred;

static void webauthn_cred_free(WebAuthnCred *c)
{
	if (!c)
		return;
	safe_free(c->credential_id_b64u);
	safe_free(c->x_b64u);
	safe_free(c->y_b64u);
	safe_free(c->user_handle_b64u);
	safe_free(c->account_name);
	safe_free(c);
}

/* The "secret" column of account_2fa_credentials holds a JSON blob:
 *   {"cid":"<b64u>","x":"<b64u>","y":"<b64u>","cnt":N,"uh":"<b64u>"}
 */
static char *webauthn_pack(const char *credential_id_b64u,
                           const char *x_b64u, const char *y_b64u,
                           const char *user_handle_b64u,
                           long counter)
{
	json_t *j = json_object();
	json_object_set_new(j, "cid", json_string(credential_id_b64u));
	json_object_set_new(j, "x", json_string(x_b64u));
	json_object_set_new(j, "y", json_string(y_b64u));
	json_object_set_new(j, "uh", json_string(user_handle_b64u ? user_handle_b64u : ""));
	json_object_set_new(j, "cnt", json_integer(counter));
	char *s = json_dumps(j, JSON_COMPACT);
	json_decref(j);
	return s;
}

static int webauthn_unpack(const char *blob, WebAuthnCred *out)
{
	json_error_t err;
	json_t *j = json_loads(blob, 0, &err);
	if (!j)
		return 0;
	const char *cid = json_string_value(json_object_get(j, "cid"));
	const char *x = json_string_value(json_object_get(j, "x"));
	const char *y = json_string_value(json_object_get(j, "y"));
	const char *uh = json_string_value(json_object_get(j, "uh"));
	json_t *jcnt = json_object_get(j, "cnt");

	if (!cid || !x || !y)
	{
		json_decref(j);
		return 0;
	}

	safe_strdup(out->credential_id_b64u, cid);
	safe_strdup(out->x_b64u, x);
	safe_strdup(out->y_b64u, y);
	if (uh && *uh)
		safe_strdup(out->user_handle_b64u, uh);
	out->counter = (jcnt && json_is_integer(jcnt))
	                   ? (long)json_integer_value(jcnt)
	                   : 0;

	json_decref(j);
	return 1;
}

/** Walk all WebAuthn credentials, optionally filtered by account_id (<=0
 *  for "all").  Caller frees with webauthn_free_list. */
typedef struct WebAuthnRow_ {
	long row_id;
	long account_id;
	char *secret_blob;
	struct WebAuthnRow_ *next;
} WebAuthnRow;

static void webauthn_free_rows(WebAuthnRow *head)
{
	while (head)
	{
		WebAuthnRow *n = head->next;
		safe_free(head->secret_blob);
		safe_free(head);
		head = n;
	}
}

static WebAuthnRow *webauthn_load_rows(long account_id_filter)
{
	sqlite3_stmt *stmt;
	const char *sql_a =
	    "SELECT id, account_id, secret FROM account_2fa_credentials"
	    " WHERE type = 'webauthn' AND account_id = ? ORDER BY id ASC";
	const char *sql_b =
	    "SELECT id, account_id, secret FROM account_2fa_credentials"
	    " WHERE type = 'webauthn' ORDER BY id ASC";

	if (!obsidian_db)
		return NULL;
	if (sqlite3_prepare_v2(obsidian_db,
	                       account_id_filter > 0 ? sql_a : sql_b,
	                       -1, &stmt, NULL) != SQLITE_OK)
		return NULL;
	if (account_id_filter > 0)
		sqlite3_bind_int(stmt, 1, (int)account_id_filter);

	WebAuthnRow *head = NULL, *tail = NULL;
	while (sqlite3_step(stmt) == SQLITE_ROW)
	{
		WebAuthnRow *r = safe_alloc(sizeof(*r));
		r->row_id = sqlite3_column_int(stmt, 0);
		r->account_id = sqlite3_column_int(stmt, 1);
		r->secret_blob = strdup((const char *)sqlite3_column_text(stmt, 2));
		r->next = NULL;
		if (tail)
			tail->next = r;
		else
			head = r;
		tail = r;
	}
	sqlite3_finalize(stmt);
	return head;
}

static int webauthn_update_secret(long row_id, const char *new_secret)
{
	const char *sql =
	    "UPDATE account_2fa_credentials SET secret = ? WHERE id = ?";
	sqlite3_stmt *stmt;
	int rc;
	if (!obsidian_db)
		return 0;
	if (sqlite3_prepare_v2(obsidian_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;
	sqlite3_bind_text(stmt, 1, new_secret, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 2, (int)row_id);
	rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return rc == SQLITE_DONE;
}

static char *account_name_by_id(long account_id)
{
	sqlite3_stmt *stmt;
	char *out = NULL;
	if (!obsidian_db)
		return NULL;
	if (sqlite3_prepare_v2(obsidian_db,
	                       "SELECT name FROM accounts WHERE id = ? LIMIT 1",
	                       -1, &stmt, NULL) != SQLITE_OK)
		return NULL;
	sqlite3_bind_int(stmt, 1, (int)account_id);
	if (sqlite3_step(stmt) == SQLITE_ROW)
	{
		const unsigned char *t = sqlite3_column_text(stmt, 0);
		if (t)
			out = strdup((const char *)t);
	}
	sqlite3_finalize(stmt);
	return out;
}

/* ----- WebAuthn registration parse (attestationObject -> cred fields) ----- */

typedef struct AttestationFindCtx_ {
	const unsigned char *auth_data;
	size_t auth_data_len;
} AttestationFindCtx;

static int attestation_cb(CborItem *k, CborItem *v, void *ud)
{
	AttestationFindCtx *ctx = ud;
	if (k->major == 3 && k->bytes_len == 8 &&
	    !memcmp(k->bytes, "authData", 8) && v->major == 2)
	{
		ctx->auth_data = v->bytes;
		ctx->auth_data_len = v->bytes_len;
	}
	return 1;
}

typedef struct {
	char *credential_id_b64u;
	char *x_b64u;
	char *y_b64u;
	long counter;
} WebAuthnRegistration;

static void webauthn_registration_free(WebAuthnRegistration *r)
{
	if (!r)
		return;
	safe_free(r->credential_id_b64u);
	safe_free(r->x_b64u);
	safe_free(r->y_b64u);
}

/** Parse the inner attestationObject CBOR + verify rpIdHash + UV + UP.
 *  On success populates *out with heap-owned base64url strings. */
static int parse_webauthn_registration(const unsigned char *attestation,
                                       size_t attestation_len,
                                       const char *expected_rp_id,
                                       WebAuthnRegistration *out)
{
	const unsigned char *p = attestation;
	CborItem map;
	if (!cbor_read_one(&p, attestation + attestation_len, &map) ||
	    map.major != 5)
		return 0;

	AttestationFindCtx ctx = {0};
	cbor_map_for_each(&map, attestation_cb, &ctx);
	if (!ctx.auth_data)
		return 0;

	WebAuthnAuthData ad;
	if (!parse_authenticator_data(ctx.auth_data, ctx.auth_data_len, &ad))
		return 0;
	if (!(ad.flags & AUTHFLAG_AT))
		return 0;
	if (!(ad.flags & AUTHFLAG_UP))
		return 0;
	if (!(ad.flags & AUTHFLAG_UV))
		return 0;

	unsigned char rp_id_hash[32];
	SHA256((const unsigned char *)expected_rp_id, strlen(expected_rp_id),
	       rp_id_hash);
	if (CRYPTO_memcmp(rp_id_hash, ad.rp_id_hash, 32) != 0)
		return 0;

    /* COSE key: must be ES256.  Validate by attempting to build EVP_PKEY. */
	EVP_PKEY *pkey = cose_to_evp_pkey_es256(ad.cose_pubkey, ad.cose_pubkey_len);
	if (!pkey)
		return 0;
	EVP_PKEY_free(pkey);

    /* Re-parse to extract x/y. */
	CoseEs256 c = {0};
	{
		const unsigned char *cp = ad.cose_pubkey;
		CborItem cosem;
		if (!cbor_read_one(&cp, ad.cose_pubkey + ad.cose_pubkey_len, &cosem) ||
		    cosem.major != 5)
			return 0;
		cbor_map_for_each(&cosem, cose_es256_callback, &c);
	}
	if (!c.x || !c.y || c.x_len != 32 || c.y_len != 32)
		return 0;

	char buf[256];
	if (b64url_encode(ad.cred_id, ad.cred_id_len, buf, sizeof(buf)) <= 0)
		return 0;
	out->credential_id_b64u = strdup(buf);
	if (b64url_encode(c.x, 32, buf, sizeof(buf)) <= 0 ||
	    !(out->x_b64u = strdup(buf)))
		return 0;
	if (b64url_encode(c.y, 32, buf, sizeof(buf)) <= 0 ||
	    !(out->y_b64u = strdup(buf)))
		return 0;
	out->counter = (long)ad.sign_count;
	return 1;
}

/* ----- Origin acceptance ----- */

static int webauthn_origin_acceptable(const char *origin, const char *rp_id)
{
	char buf[256];
	if (!origin || !rp_id)
		return 0;

	snprintf(buf, sizeof(buf), "ircs://%s", rp_id);
	if (!strcmp(origin, buf))
		return 1;
	snprintf(buf, sizeof(buf), "irc://%s", rp_id);
	if (!strcmp(origin, buf))
		return 1;
	snprintf(buf, sizeof(buf), "https://%s", rp_id);
	if (!strcmp(origin, buf))
		return 1;
	return 0;
}

/* ----- Top-level WebAuthn assertion verify -----
 *  Inputs are JSON-decoded base64url byte buffers + the expected challenge
 *  bytes the server issued earlier in this SASL exchange.
 *  On success, returns the matched account_id.  On failure returns 0 and
 *  writes a WebAuthn error code into *err_code (caller-owned static string,
 *  do not free). */
static long webauthn_verify_assertion(
    const unsigned char *credential_id, size_t credential_id_len,
    const unsigned char *authenticator_data, size_t authenticator_data_len,
    const unsigned char *client_data_json, size_t client_data_json_len,
    const unsigned char *signature, size_t signature_len,
    const unsigned char *user_handle, size_t user_handle_len,
    const unsigned char *expected_challenge, size_t expected_challenge_len,
    const char *username_hint,         /* NULL for resident-key flow */
    const char **err_code)
{
	*err_code = "WEBAUTHN_MALFORMED";

    /* 1. Parse clientDataJSON */
	char *cd = safe_alloc(client_data_json_len + 1);
	memcpy(cd, client_data_json, client_data_json_len);
	cd[client_data_json_len] = 0;
	json_error_t je;
	json_t *cj = json_loads(cd, 0, &je);
	safe_free(cd);
	if (!cj)
		return 0;

	const char *type = json_string_value(json_object_get(cj, "type"));
	const char *chal = json_string_value(json_object_get(cj, "challenge"));
	const char *origin = json_string_value(json_object_get(cj, "origin"));
	if (!type || strcmp(type, "webauthn.get") || !chal || !origin)
	{
		json_decref(cj);
		*err_code = "WEBAUTHN_MALFORMED";
		return 0;
	}

    /* 2. Verify challenge in clientDataJSON matches the server-issued one */
	{
		unsigned char buf[128];
		int n = b64url_decode(chal, buf, sizeof(buf));
		if (n != (int)expected_challenge_len ||
		    CRYPTO_memcmp(buf, expected_challenge, expected_challenge_len) != 0)
		{
			json_decref(cj);
			*err_code = "WEBAUTHN_INVALID_CHALLENGE";
			return 0;
		}
	}

    /* 3. Verify origin */
	if (!webauthn_origin_acceptable(origin, me.name))
	{
		json_decref(cj);
		*err_code = "WEBAUTHN_INVALID_ORIGIN";
		return 0;
	}
	json_decref(cj);

    /* 4. Parse authenticatorData */
	WebAuthnAuthData ad;
	if (!parse_authenticator_data(authenticator_data,
	                              authenticator_data_len, &ad))
	{
		*err_code = "WEBAUTHN_MALFORMED";
		return 0;
	}
	if (!(ad.flags & AUTHFLAG_UP))
	{
		*err_code = "WEBAUTHN_INVALID_SIGNATURE";
		return 0;
	}
	if (!(ad.flags & AUTHFLAG_UV))
	{
		*err_code = "WEBAUTHN_UV_REQUIRED";
		return 0;
	}
	{
		unsigned char rp_hash[32];
		SHA256((const unsigned char *)me.name, strlen(me.name), rp_hash);
		if (CRYPTO_memcmp(rp_hash, ad.rp_id_hash, 32) != 0)
		{
			*err_code = "WEBAUTHN_INVALID_ORIGIN";
			return 0;
		}
	}

    /* 5. Identify credential.  Walk all WebAuthn rows for the account
     * (or globally for resident-key flow), match credentialId. */
	long matched_account_id = 0;
	long matched_row_id = 0;
	long stored_counter = 0;
	char *stored_uh = NULL;
	char *stored_x = NULL, *stored_y = NULL;

	long account_filter = 0;
	if (username_hint && *username_hint)
	{
		Account *acct = find_account(username_hint);
		if (acct)
		{
			account_filter = acct->id;
			free_account(acct);
		}
		if (account_filter <= 0)
		{
			*err_code = "WEBAUTHN_UNKNOWN_CREDENTIAL";
			return 0;
		}
	}

	char cid_b64u[512];
	if (b64url_encode(credential_id, credential_id_len,
	                  cid_b64u, sizeof(cid_b64u)) <= 0)
	{
		*err_code = "WEBAUTHN_MALFORMED";
		return 0;
	}

	WebAuthnRow *rows = webauthn_load_rows(account_filter);
	for (WebAuthnRow *r = rows; r; r = r->next)
	{
		WebAuthnCred c = {0};
		if (!webauthn_unpack(r->secret_blob, &c))
			continue;
		if (!strcmp(c.credential_id_b64u, cid_b64u))
		{
            /* Resident-key flow: also match userHandle if supplied. */
			if (!username_hint && user_handle_len > 0 && c.user_handle_b64u)
			{
				char uh_b64u[256];
				if (b64url_encode(user_handle, user_handle_len,
				                  uh_b64u, sizeof(uh_b64u)) <= 0 ||
				    strcmp(uh_b64u, c.user_handle_b64u))
				{
					safe_free(c.credential_id_b64u);
					safe_free(c.x_b64u);
					safe_free(c.y_b64u);
					safe_free(c.user_handle_b64u);
					continue;
				}
			}
			matched_account_id = r->account_id;
			matched_row_id = r->row_id;
			stored_counter = c.counter;
			stored_x = c.x_b64u;
			c.x_b64u = NULL;
			stored_y = c.y_b64u;
			c.y_b64u = NULL;
			stored_uh = c.user_handle_b64u;
			c.user_handle_b64u = NULL;
			safe_free(c.credential_id_b64u);
			break;
		}
		safe_free(c.credential_id_b64u);
		safe_free(c.x_b64u);
		safe_free(c.y_b64u);
		safe_free(c.user_handle_b64u);
	}
	webauthn_free_rows(rows);

	if (!matched_account_id)
	{
		*err_code = "WEBAUTHN_UNKNOWN_CREDENTIAL";
		safe_free(stored_x);
		safe_free(stored_y);
		safe_free(stored_uh);
		return 0;
	}

    /* 6. Build pubkey from x,y and verify signature. */
	unsigned char x_raw[64], y_raw[64];
	int xlen = b64url_decode(stored_x, x_raw, sizeof(x_raw));
	int ylen = b64url_decode(stored_y, y_raw, sizeof(y_raw));
	safe_free(stored_x);
	safe_free(stored_y);
	safe_free(stored_uh);
	if (xlen != 32 || ylen != 32)
	{
		*err_code = "WEBAUTHN_INVALID_SIGNATURE";
		return 0;
	}

	EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	BIGNUM *bx = BN_bin2bn(x_raw, 32, NULL);
	BIGNUM *by = BN_bin2bn(y_raw, 32, NULL);
	EVP_PKEY *pkey = NULL;
	if (ec && bx && by &&
	    EC_KEY_set_public_key_affine_coordinates(ec, bx, by) == 1)
	{
		pkey = EVP_PKEY_new();
		if (pkey)
			EVP_PKEY_assign_EC_KEY(pkey, ec);
		else
			EC_KEY_free(ec);
	} else if (ec)
		EC_KEY_free(ec);
	BN_free(bx);
	BN_free(by);
	if (!pkey)
	{
		*err_code = "WEBAUTHN_INVALID_SIGNATURE";
		return 0;
	}

    /* 7. signed = authData || sha256(clientDataJSON) */
	unsigned char client_data_hash[32];
	SHA256(client_data_json, client_data_json_len, client_data_hash);
	size_t signed_len = authenticator_data_len + 32;
	unsigned char *signed_buf = safe_alloc(signed_len);
	memcpy(signed_buf, authenticator_data, authenticator_data_len);
	memcpy(signed_buf + authenticator_data_len, client_data_hash, 32);

	int sig_ok = webauthn_ecdsa_verify(pkey, signed_buf, signed_len,
	                                   signature, signature_len);
	safe_free(signed_buf);
	EVP_PKEY_free(pkey);
	if (!sig_ok)
	{
		*err_code = "WEBAUTHN_INVALID_SIGNATURE";
		return 0;
	}

    /* 8. Counter check. */
	if (stored_counter > 0 && ad.sign_count != 0 &&
	    ad.sign_count <= (uint32_t)stored_counter)
	{
		*err_code = "WEBAUTHN_COUNTER_REPLAY";
		return 0;
	}

    /* 9. Persist updated counter (only if authenticator supplies one). */
	if (ad.sign_count > 0)
	{
		WebAuthnRow *rows2 = webauthn_load_rows(matched_account_id);
		for (WebAuthnRow *r = rows2; r; r = r->next)
		{
			if (r->row_id != matched_row_id)
				continue;
			WebAuthnCred c = {0};
			if (webauthn_unpack(r->secret_blob, &c))
			{
				c.counter = (long)ad.sign_count;
				char *new_blob = webauthn_pack(c.credential_id_b64u,
				                               c.x_b64u, c.y_b64u,
				                               c.user_handle_b64u,
				                               c.counter);
				if (new_blob)
				{
					webauthn_update_secret(r->row_id, new_blob);
					free(new_blob);
				}
				safe_free(c.credential_id_b64u);
				safe_free(c.x_b64u);
				safe_free(c.y_b64u);
				safe_free(c.user_handle_b64u);
			}
			break;
		}
		webauthn_free_rows(rows2);
	}

	*err_code = NULL;
	return matched_account_id;
}

/* ----- WEBAUTHN-BIO SASL state -----
 * (struct + ModData macros forward-declared near top of file) */

static void webauthn_sasl_md_free(ModData *m)
{
	if (m->ptr)
	{
		safe_free(m->ptr);
		m->ptr = NULL;
	}
}
static void webauthn_sasl_clear(Client *c)
{
	WebAuthnSaslState *s = WebAuthnSaslGet(c);
	if (s)
	{
		safe_free(s);
		WebAuthnSaslSet(c, NULL);
	}
}

/* Send a FAIL AUTHENTICATE WEBAUTHN_* before 904 */
static void webauthn_sasl_fail_with_code(Client *client, const char *code)
{
	if (code)
		sendto_one(client, NULL,
		           ":%s FAIL AUTHENTICATE %s :WebAuthn authentication failed",
		           me.name, code);
	client->local->sasl_sent_time = 0;
	add_fake_lag(client, 5000);
	sendnumeric(client, ERR_SASLFAIL);
	DelSaslType(client);
	webauthn_sasl_clear(client);
}

/* ----- WEBAUTHN-BIO SASL handlers ----- */

static void webauthn_sasl_send_challenge(Client *client, WebAuthnSaslState *st)
{
	json_t *j = json_object();
	json_object_set_new(j, "version", json_integer(1));

	char chal_b64u[64];
	b64url_encode(st->challenge, sizeof(st->challenge),
	              chal_b64u, sizeof(chal_b64u));
	json_object_set_new(j, "challenge", json_string(chal_b64u));
	json_object_set_new(j, "rpId", json_string(me.name));
	json_object_set_new(j, "timeout", json_integer(60000));
	json_object_set_new(j, "userVerification", json_string("required"));

	if (*st->username_hint)
	{
		Account *acct = find_account(st->username_hint);
		if (acct)
		{
			WebAuthnRow *rows = webauthn_load_rows(acct->id);
			if (rows)
			{
				json_t *arr = json_array();
				for (WebAuthnRow *r = rows; r; r = r->next)
				{
					WebAuthnCred c = {0};
					if (webauthn_unpack(r->secret_blob, &c))
					{
						json_t *o = json_object();
						json_object_set_new(o, "type",
						                    json_string("public-key"));
						json_object_set_new(o, "id",
						                    json_string(c.credential_id_b64u));
						json_array_append_new(arr, o);
						safe_free(c.credential_id_b64u);
						safe_free(c.x_b64u);
						safe_free(c.y_b64u);
						safe_free(c.user_handle_b64u);
					}
				}
				json_object_set_new(j, "allowCredentials", arr);
			}
			webauthn_free_rows(rows);
			free_account(acct);
		}
	}

	char *jstr = json_dumps(j, JSON_COMPACT);
	json_decref(j);
	if (!jstr)
	{
		webauthn_sasl_fail_with_code(client, "WEBAUTHN_MALFORMED");
		return;
	}
	size_t jlen = strlen(jstr);
	size_t b64size = ((jlen + 2) / 3) * 4 + 1;
	char *b64 = safe_alloc(b64size);
	int n = b64_encode((const unsigned char *)jstr, jlen, b64, b64size);
	free(jstr);
	if (n <= 0 || n > 400)
	{
		safe_free(b64);
		webauthn_sasl_fail_with_code(client, "WEBAUTHN_MALFORMED");
		return;
	}
	sendto_one(client, NULL, ":%s AUTHENTICATE %s", me.name, b64);
	safe_free(b64);
	st->step = 1;
}

static void webauthn_sasl_handle_hello(Client *client, const char *param)
{
	WebAuthnSaslState *st = WebAuthnSaslGet(client);
	if (!st || st->step != 0)
	{
		webauthn_sasl_fail_with_code(client, "WEBAUTHN_MALFORMED");
		return;
	}

	if (!strcmp(param, "+"))
	{
        /* Discoverable-credential flow: no allowCredentials. */
		st->username_hint[0] = 0;
		webauthn_sasl_send_challenge(client, st);
		return;
	}

    /* Decode hello JSON */
	unsigned char buf[1024];
	int n = b64_decode(param, buf, sizeof(buf) - 1);
	if (n <= 0)
	{
		webauthn_sasl_fail_with_code(client, "WEBAUTHN_MALFORMED");
		return;
	}
	buf[n] = 0;
	json_error_t err;
	json_t *j = json_loads((const char *)buf, 0, &err);
	if (!j)
	{
		webauthn_sasl_fail_with_code(client, "WEBAUTHN_MALFORMED");
		return;
	}
	const char *uname = json_string_value(json_object_get(j, "username"));
	if (uname && *uname)
		strlcpy(st->username_hint, uname, sizeof(st->username_hint));
	else
		st->username_hint[0] = 0;
	json_decref(j);

	webauthn_sasl_send_challenge(client, st);
}

static void webauthn_sasl_handle_assertion(Client *client, const char *param)
{
	WebAuthnSaslState *st = WebAuthnSaslGet(client);
	if (!st || st->step != 1)
	{
		webauthn_sasl_fail_with_code(client, "WEBAUTHN_MALFORMED");
		return;
	}

	unsigned char buf[2048];
	int n = b64_decode(param, buf, sizeof(buf) - 1);
	if (n <= 0)
	{
		webauthn_sasl_fail_with_code(client, "WEBAUTHN_MALFORMED");
		return;
	}
	buf[n] = 0;

	json_error_t err;
	json_t *j = json_loads((const char *)buf, 0, &err);
	if (!j)
	{
		webauthn_sasl_fail_with_code(client, "WEBAUTHN_MALFORMED");
		return;
	}

	const char *cid_b = json_string_value(json_object_get(j, "credentialId"));
	const char *ad_b = json_string_value(json_object_get(j, "authenticatorData"));
	const char *cd_b = json_string_value(json_object_get(j, "clientDataJSON"));
	const char *sig_b = json_string_value(json_object_get(j, "signature"));
	const char *uh_b = json_string_value(json_object_get(j, "userHandle"));
	if (!cid_b || !ad_b || !cd_b || !sig_b)
	{
		json_decref(j);
		webauthn_sasl_fail_with_code(client, "WEBAUTHN_MALFORMED");
		return;
	}

	unsigned char cid_buf[512], ad_buf[1024], cd_buf[1024];
	unsigned char sig_buf[256], uh_buf[64];
	int cid_len = b64url_decode(cid_b, cid_buf, sizeof(cid_buf));
	int ad_len = b64url_decode(ad_b, ad_buf, sizeof(ad_buf));
	int cd_len = b64url_decode(cd_b, cd_buf, sizeof(cd_buf));
	int sig_len = b64url_decode(sig_b, sig_buf, sizeof(sig_buf));
	int uh_len = uh_b ? b64url_decode(uh_b, uh_buf, sizeof(uh_buf)) : 0;
	json_decref(j);
	if (cid_len <= 0 || ad_len <= 0 || cd_len <= 0 || sig_len <= 0)
	{
		webauthn_sasl_fail_with_code(client, "WEBAUTHN_MALFORMED");
		return;
	}

	const char *err_code = NULL;
	long account_id = webauthn_verify_assertion(
	    cid_buf, cid_len, ad_buf, ad_len, cd_buf, cd_len,
	    sig_buf, sig_len, uh_b ? uh_buf : NULL, uh_len > 0 ? (size_t)uh_len : 0,
	    st->challenge, sizeof(st->challenge),
	    *st->username_hint ? st->username_hint : NULL,
	    &err_code);

	if (!account_id)
	{
		webauthn_sasl_fail_with_code(client, err_code);
		return;
	}

	char *aname = account_name_by_id(account_id);
	if (!aname)
	{
		webauthn_sasl_fail_with_code(client, "WEBAUTHN_UNKNOWN_CREDENTIAL");
		return;
	}

	strlcpy(client->user->account, aname, sizeof(client->user->account));
	unreal_log(ULOG_INFO, "account", "SASL_LOGIN", client,
	           "SASL/WEBAUTHN-BIO login for $client.details [account: $account]",
	           log_data_string("account", aname));
	free(aname);
	user_account_login(NULL, client);
	if (!IsDead(client))
	{
		client->local->sasl_complete = 1;
		sendnumeric(client, RPL_SASLSUCCESS);
	}
	DelSaslType(client);
	webauthn_sasl_clear(client);
}

#pragma GCC diagnostic pop

/* ----- 2FA ADD webauthn integration -----
 * (called from twofa_cmd_add when type == "webauthn") */
static int webauthn_2fa_handle_add(Client *client, Account *acc,
                                   const char *name, const char *data_b64)
{
    /* data is base64-encoded JSON: clientDataJSON + attestationObject (both
     * base64url within the JSON). */
	unsigned char buf[2048];
	int n = b64_decode(data_b64, buf, sizeof(buf) - 1);
	if (n <= 0)
		return 0;
	buf[n] = 0;
	json_error_t je;
	json_t *j = json_loads((const char *)buf, 0, &je);
	if (!j)
		return 0;

	const char *cd_b = json_string_value(json_object_get(j, "clientDataJSON"));
	const char *ao_b = json_string_value(json_object_get(j, "attestationObject"));
	if (!cd_b || !ao_b)
	{
		json_decref(j);
		return 0;
	}

	unsigned char cd[2048], ao[2048];
	int cd_len = b64url_decode(cd_b, cd, sizeof(cd) - 1);
	int ao_len = b64url_decode(ao_b, ao, sizeof(ao));
	json_decref(j);
	if (cd_len <= 0 || ao_len <= 0)
		return 0;
	cd[cd_len] = 0;

    /* Verify clientDataJSON.type / challenge / origin against the pending
     * enrolment challenge (stored in TwoFAEnroll for this client). */
	TwoFAEnroll *e = TwoFAEnrollGet(client);
	if (!e || strcmp(e->type, "webauthn") || time(NULL) > e->expires_at ||
	    !e->secret_b32)
		return 0;

	json_t *cdj = json_loads((const char *)cd, 0, &je);
	if (!cdj)
		return 0;
	const char *type = json_string_value(json_object_get(cdj, "type"));
	const char *chal = json_string_value(json_object_get(cdj, "challenge"));
	const char *origin = json_string_value(json_object_get(cdj, "origin"));
	if (!type || strcmp(type, "webauthn.create") || !chal || !origin)
	{
		json_decref(cdj);
		return 0;
	}
    /* The enrolment "secret" carries the issued challenge as base64url. */
	if (strcmp(chal, e->secret_b32) ||
	    !webauthn_origin_acceptable(origin, me.name))
	{
		json_decref(cdj);
		return 0;
	}
	json_decref(cdj);

	WebAuthnRegistration reg = {0};
	if (!parse_webauthn_registration(ao, ao_len, me.name, &reg))
		return 0;

    /* User handle: stable per-account.  Use base64url(account_id-as-bigint
     * little-endian 8 bytes). */
	unsigned char uh_raw[8];
	long aid = acc->id;
	for (int i = 0; i < 8; i++)
	{
		uh_raw[i] = aid & 0xFF;
		aid >>= 8;
	}
	char uh_b64u[24];
	b64url_encode(uh_raw, sizeof(uh_raw), uh_b64u, sizeof(uh_b64u));

	char *blob = webauthn_pack(reg.credential_id_b64u, reg.x_b64u, reg.y_b64u,
	                           uh_b64u, reg.counter);
	webauthn_registration_free(&reg);
	if (!blob)
		return 0;

	long new_id = 0;
	int ok = twofa_insert_credential(acc->id, "webauthn", name, blob, &new_id);
	free(blob);
	if (!ok)
		return 0;

	char id_buf[TWOFA_ID_MAX + 1];
	format_cred_id(id_buf, sizeof(id_buf), new_id);
	sendto_one(client, NULL,
	           ":%s 2FA ADD SUCCESS webauthn %s :WebAuthn credential '%s' registered.",
	           me.name, id_buf, name);
	twofa_clear_enroll(client);
	return 1;
}

/* Called from twofa_cmd_challenge when type == "webauthn". */
static void webauthn_2fa_handle_challenge(Client *client, Account *acc)
{
	unsigned char chal[32];
	if (RAND_bytes(chal, sizeof(chal)) != 1)
	{
		twofa_fail(client, "TEMPORARILY_UNAVAILABLE", NULL,
		           "Could not generate challenge.");
		return;
	}
	char chal_b64u[64];
	b64url_encode(chal, sizeof(chal), chal_b64u, sizeof(chal_b64u));

    /* User handle (base64url of 8-byte account_id LE). */
	unsigned char uh_raw[8];
	long aid = acc->id;
	for (int i = 0; i < 8; i++)
	{
		uh_raw[i] = aid & 0xFF;
		aid >>= 8;
	}
	char uh_b64u[24];
	b64url_encode(uh_raw, sizeof(uh_raw), uh_b64u, sizeof(uh_b64u));

	json_t *j = json_object();
	json_object_set_new(j, "challenge", json_string(chal_b64u));
	json_object_set_new(j, "rpId", json_string(me.name));
	json_object_set_new(j, "rpName", json_string(me.name));
	json_object_set_new(j, "userId", json_string(uh_b64u));
	json_object_set_new(j, "userName", json_string(acc->name));
	json_object_set_new(j, "userVerification", json_string("required"));
	json_t *params = json_array();
	json_t *p1 = json_object();
	json_object_set_new(p1, "type", json_string("public-key"));
	json_object_set_new(p1, "alg", json_integer(-7));
	json_array_append_new(params, p1);
	json_object_set_new(j, "pubKeyCredParams", params);

	char *jstr = json_dumps(j, JSON_COMPACT);
	json_decref(j);
	if (!jstr)
	{
		twofa_fail(client, "TEMPORARILY_UNAVAILABLE", NULL,
		           "Could not encode challenge.");
		return;
	}

	size_t jlen = strlen(jstr);
	size_t b64size = ((jlen + 2) / 3) * 4 + 1;
	char *b64 = safe_alloc(b64size);
	int b64n = b64_encode((const unsigned char *)jstr, jlen, b64, b64size);
	free(jstr);
	if (b64n <= 0)
	{
		safe_free(b64);
		twofa_fail(client, "TEMPORARILY_UNAVAILABLE", NULL,
		           "Could not encode challenge.");
		return;
	}

	twofa_clear_enroll(client);
	TwoFAEnroll *e = safe_alloc(sizeof(*e));
	safe_strdup(e->type, "webauthn");
	safe_strdup(e->secret_b32, chal_b64u); /* stash issued challenge */
	e->expires_at = time(NULL) + TWOFA_CHALLENGE_LIFETIME;
	TwoFAEnrollSet(client, e);

	sendto_one(client, NULL,
	           ":%s NOTE 2FA REGISTRATION_CHALLENGE webauthn %s :"
	           "Perform a WebAuthn credential creation gesture, then run "
	           "/2FA ADD webauthn <name> <data>",
	           me.name, b64);
	safe_free(b64);
}

static const char *saslmechs(Client *client)
{
    /* OAUTHBEARER + IRCV3BEARER are only meaningful if at least one
     * oauth-provider {} is loaded; advertise both unconditionally so
     * clients can negotiate -- the dispatcher will reject with
     * ERR_SASLFAIL if no provider matches the token's issuer. */
	return "PLAIN,TOTP,EXTERNAL,DRAFT-WEBAUTHN-BIO,OAUTHBEARER,IRCV3BEARER,ANONYMOUS";
}

/* ===================================================================
 * CMD: REGISTER <name> <email> <password>
 * =================================================================== */
CMD_FUNC(register_account)
{
	const char *name, *email, *password;
	const char *password_hash;
	Account *acc;

	if (!obsidian_db && obsidian_open_database(OBSIDIAN_DB) != SQLITE_OK)
	{
		sendto_one(client, NULL,
		           ":%s FAIL REGISTER SERVER_BUG :Database unavailable.", me.name);
		return;
	}

	if (parc < 4)
	{
		sendto_one(client, NULL,
		           ":%s NOTE REGISTER INVALID_PARAMS "
		           ":Syntax: /REGISTER <name> <email> <password>",
		           me.name);
		return;
	}

	name = parv[1];
	email = parv[2];
	password = parv[3];

	if ((int)strlen(name) < MyConf.min_name_length ||
	    (int)strlen(name) > MyConf.max_name_length)
	{
		sendto_one(client, NULL,
		           ":%s FAIL REGISTER BAD_ACCOUNT_NAME %s "
		           ":Account name must be between %d and %d characters.",
		           me.name, name, MyConf.min_name_length, MyConf.max_name_length);
		return;
	}

	if ((int)strlen(password) < MyConf.min_password_length ||
	    (int)strlen(password) > MyConf.max_password_length)
	{
		sendto_one(client, NULL,
		           ":%s FAIL REGISTER BAD_PASSWORD %s "
		           ":Password must be between %d and %d characters.",
		           me.name, name, MyConf.min_password_length, MyConf.max_password_length);
		return;
	}

	if (MyConf.require_email &&
	    (strlen(email) < 5 || !strcmp(email, "*") ||
	     !strchr(email, '@') || !strchr(email, '.')))
	{
		sendto_one(client, NULL,
		           ":%s FAIL REGISTER BAD_EMAIL %s "
		           ":A valid email address is required.",
		           me.name, name);
		return;
	}

    /* Nick in use by another client */
	{
		Client *found = find_client(name, NULL);
		if (found && found != client)
		{
			if (client->name[0])
				sendto_one(client, NULL,
				           ":%s FAIL REGISTER BAD_ACCOUNT_NAME %s "
				           ":That account name is currently in use.",
				           me.name, name);
			else
				sendto_one(client, NULL,
				           ":%s FAIL REGISTER BAD_ACCOUNT_NAME %s "
				           ":That account name is banned.",
				           me.name, name);
			return;
		}
	}

    /* Nameban check */
	if (my_find_tkl_nameban(name))
	{
		sendto_one(client, NULL,
		           ":%s FAIL REGISTER BAD_ACCOUNT_NAME %s "
		           ":That account name is banned.",
		           me.name, name);
		return;
	}

    /* Already registered? */
	{
		Account *existing = find_account(name);
		if (existing)
		{
			sendto_one(client, NULL,
			           ":%s FAIL REGISTER ACCOUNT_EXISTS %s "
			           ":That account name is already registered.",
			           me.name, name);
			free_account(existing);
			return;
		}
	}

    /* Hash the password with Argon2id */
	password_hash = Auth_Hash(AUTHTYPE_ARGON2, password);
	if (!password_hash)
	{
		sendto_one(client, NULL,
		           ":%s FAIL REGISTER SERVER_BUG %s "
		           ":Password hashing failed. Contact an administrator.",
		           me.name, name);
		return;
	}

    /* Build and save the account */
	acc = safe_alloc(sizeof(Account));
	acc->name = strdup(name);
	acc->email = strdup(email);
	acc->password = strdup(password_hash);
	acc->time_registered = time(NULL);
	acc->verified = 0;
	acc->channels = NULL;
	acc->metadata_head = NULL;

    /* SCRAM-SHA-256 credentials.  Failure here is non-fatal: argon2 still
     * works for PLAIN, and we'll backfill on the next successful login. */
	scram_make_credentials(acc, password);

    /* Email verification path: if enabled, generate a code and try to send
     * it via the smtp hook BEFORE we log the user in. */
	int wants_verify = MyConf.verify_email && try_send_email_loaded();
	if (wants_verify)
	{
		char code[VERIFY_CODE_LENGTH + 1];
		gen_random_alnum(code, VERIFY_CODE_LENGTH);
		code[VERIFY_CODE_LENGTH] = '\0';
		acc->verify_code = strdup(code);
		acc->verify_expires = time(NULL) + MyConf.verify_code_lifetime;
	}

	if (write_account_to_db(acc))
	{
		unreal_log(ULOG_INFO, "account", "REGISTER", client,
		           "New account registered by $client.details "
		           "[account: $account] [email: $email]",
		           log_data_string("account", acc->name),
		           log_data_string("email", acc->email));

		if (wants_verify)
		{
			int sent = send_verify_email(acc);
			if (sent)
			{
				sendto_one(client, NULL,
				           ":%s REGISTER VERIFICATION_REQUIRED %s :"
				           "Account created.  Check %s for a verification code, "
				           "then run /VERIFY %s <code>",
				           me.name, name, acc->email, name);
                /* Do NOT log in yet; verification happens via /VERIFY. */
				RunHook(HOOKTYPE_ACCOUNT_REGISTER, acc, client);
				free_account(acc);
				return;
			}
            /* Email send couldn't be queued -- fall through to old behavior
             * (account exists, verify_code stays valid in DB).  Log warning.
             */
			unreal_log(ULOG_WARNING, "account", "VERIFY_EMAIL_NOT_QUEUED",
			           client,
			           "Could not queue verification email for $account; "
			           "smtp module unavailable or misconfigured.  "
			           "Account created without verification.",
			           log_data_string("account", acc->name));
		}

		sendto_one(client, NULL,
		           ":%s REGISTER SUCCESS %s :Account registered successfully.",
		           me.name, name);
        /* CMD_UNREGISTERED: no User struct until cmd_user runs. */
		if (!client->user)
			make_user(client);
		strlcpy(client->user->account, name, sizeof(client->user->account));
		user_account_login(NULL, client);
		RunHook(HOOKTYPE_ACCOUNT_REGISTER, acc, client);
	} else
	{
		sendto_one(client, NULL,
		           ":%s FAIL REGISTER INTERNAL_ERROR "
		           ":Failed to register account.",
		           me.name);
	}
	free_account(acc);
}

/* ===================================================================
 * CMD: LISTACC [<name>]  (oper-only)
 * =================================================================== */
CMD_FUNC(list_accounts)
{
	Account **accounts;
	size_t i;

	if (!obsidian_db && obsidian_open_database(OBSIDIAN_DB) != SQLITE_OK)
	{
		sendto_one(client, NULL,
		           ":%s LISTACC SERVER_BUG :Database unavailable.", me.name);
		return;
	}

	accounts = read_accounts_from_db(!BadPtr(parv[1]) ? parv[1] : NULL);
	if (!accounts || !accounts[0])
	{
		sendto_one(client, NULL,
		           ":%s LISTACC NO_ACCOUNTS :No accounts registered.", me.name);
		free(accounts);
		return;
	}

	for (i = 0; accounts[i]; i++)
	{
		int member_count = 0;
		AccountMember *m = accounts[i]->members;
		while (m)
		{
			member_count++;
			m = m->next;
		}

		sendto_one(client, NULL,
		           ":%s LISTACC ACCOUNT %ld %s %s %ld %d %d",
		           me.name,
		           accounts[i]->id,
		           accounts[i]->name,
		           accounts[i]->email,
		           (long)accounts[i]->time_registered,
		           accounts[i]->verified,
		           member_count);
		free_account(accounts[i]);
	}
	free(accounts);
}

/* ===================================================================
 * CMD: IDENTIFY <account> <password>
 * Fallback for clients without SASL support.
 * =================================================================== */
CMD_FUNC(cmd_identify)
{
	const char *account_name, *password;
	Account *acc;

	if (!obsidian_db && obsidian_open_database(OBSIDIAN_DB) != SQLITE_OK)
	{
		sendto_one(client, NULL,
		           ":%s FAIL IDENTIFY SERVER_BUG :Database unavailable.", me.name);
		return;
	}

	if (parc < 3)
	{
		sendto_one(client, NULL,
		           ":%s NOTE IDENTIFY INVALID_PARAMS "
		           ":Syntax: /IDENTIFY <account> <password>",
		           me.name);
		return;
	}

	account_name = parv[1];
	password = parv[2];

	if (!account_name || !*account_name)
	{
		sendto_one(client, NULL,
		           ":%s FAIL IDENTIFY INVALID_ACCOUNT :Account name cannot be empty.",
		           me.name);
		return;
	}

	if (!strcasecmp(account_name, client->user->account))
	{
		sendto_one(client, NULL,
		           ":%s FAIL IDENTIFY ALREADY_IDENTIFIED "
		           ":You are already identified to account %s.",
		           me.name, account_name);
		return;
	}

    /* Nick collision check */
	{
		Client *found = find_client(account_name, NULL);
		if (found && found != client)
		{
			sendto_one(client, NULL,
			           ":%s FAIL IDENTIFY INVALID_ACCOUNT "
			           ":That account name is currently in use.",
			           me.name);
			return;
		}
	}

	if (my_find_tkl_nameban(account_name))
	{
		sendto_one(client, NULL,
		           ":%s FAIL IDENTIFY INVALID_ACCOUNT :That account name is banned.",
		           me.name);
		return;
	}

	if (!password || !*password)
	{
		sendto_one(client, NULL,
		           ":%s FAIL IDENTIFY INVALID_PASSWORD :Password cannot be empty.",
		           me.name);
		return;
	}

	acc = find_account(account_name);
	if (!acc)
	{
		sendto_one(client, NULL,
		           ":%s FAIL IDENTIFY ACCOUNT_NOT_FOUND :Account %s not found.",
		           me.name, account_name);
		return;
	}

	if (verify_password_for_scheme(acc->password_scheme, acc->password, password))
	{
        /* Always regenerate SCRAM here: a migrated account's
         * scram_stored_key may be from a different SCRAM derivation
         * (e.g. Ergo) that obbyircd's verifier won't accept. Rederiving
         * locally from the freshly-verified plaintext password
         * guarantees the SCRAM blob is consistent with how this server
         * verifies it. */
		if (scram_make_credentials(acc, password))
			update_account_scram(acc);
        /* Roll forward migrated non-argon2id accounts. */
		if (acc->password_scheme && strcmp(acc->password_scheme, "argon2id"))
		{
			const char *new_hash = Auth_Hash(AUTHTYPE_ARGON2, password);
			if (new_hash)
			{
				free(acc->password);
				acc->password = strdup(new_hash);
				free(acc->password_scheme);
				acc->password_scheme = strdup("argon2id");
				update_account_password(acc);
			}
		}

		sendto_one(client, NULL,
		           ":%s IDENTIFY SUCCESS %s :You have been successfully identified.",
		           me.name, acc->name);
		strlcpy(client->user->account, acc->name, sizeof(client->user->account));
		user_account_login(NULL, client);
		DelSaslType(client);
		unreal_log(ULOG_INFO, "account", "IDENTIFY", client,
		           "User $client.details identified [account: $account] [email: $email]",
		           log_data_string("account", acc->name),
		           log_data_string("email", acc->email));
	} else
	{
		sendto_one(client, NULL,
		           ":%s FAIL IDENTIFY INVALID_PASSWORD :Invalid password for account %s.",
		           me.name, acc->name);
		client->local->sasl_sent_time = 0;
		add_fake_lag(client, 7000);
	}
	free_account(acc);
}

/* ===================================================================
 * CMD: LOGOUT
 * =================================================================== */
CMD_FUNC(cmd_logout)
{
	if (!IsLoggedIn(client))
	{
		sendto_one(client, NULL,
		           ":%s FAIL LOGOUT NOT_LOGGED_IN :You are not logged in.", me.name);
		return;
	}
	strlcpy(client->user->account, "0", sizeof(client->user->account));
	user_account_login(NULL, client);
	sendto_one(client, NULL,
	           ":%s LOGOUT SUCCESS :You have been logged out successfully.", me.name);
}

/* ===================================================================
 * Email verification helpers
 * =================================================================== */

/** Returns 1 if any module is registered for HOOKTYPE_SEND_EMAIL. */
static int try_send_email_loaded(void)
{
	return Hooks[HOOKTYPE_SEND_EMAIL] != NULL;
}

/** Walk HOOKTYPE_SEND_EMAIL handlers; return 1 if any returns nonzero
 *  (meaning the email was queued by some backend). */
static int try_send_email(const char *to, const char *subject,
                          const char *body)
{
	Hook *h;
	for (h = Hooks[HOOKTYPE_SEND_EMAIL]; h; h = h->next)
	{
		int rc = h->func.intfunc(to, subject, body, NULL, NULL);
		if (rc)
			return 1;
	}
	return 0;
}

static int send_verify_email(const Account *acc)
{
	char subject[256];
	char body[2048];

	if (!acc || !acc->email || !acc->verify_code)
		return 0;

	snprintf(subject, sizeof(subject),
	         "Verify your %s account", me.name);
	snprintf(body, sizeof(body),
	         "Hi %s,\n"
	         "\n"
	         "Someone (hopefully you) registered the account '%s' on %s\n"
	         "with this email address.\n"
	         "\n"
	         "To complete registration, run this command on IRC:\n"
	         "\n"
	         "    /VERIFY %s %s\n"
	         "\n"
	         "This code expires in %ld minutes.\n"
	         "\n"
	         "If you didn't request this, you can ignore this message.\n",
	         acc->name, acc->name, me.name,
	         acc->name, acc->verify_code,
	         (long)(MyConf.verify_code_lifetime / 60));

	return try_send_email(acc->email, subject, body);
}

/* ===================================================================
 * CMD: VERIFY <account> <code>
 * =================================================================== */
CMD_FUNC(cmd_verify)
{
	const char *name;
	const char *code;
	Account *acc;

	if (!obsidian_db && obsidian_open_database(OBSIDIAN_DB) != SQLITE_OK)
	{
		sendto_one(client, NULL,
		           ":%s FAIL VERIFY SERVER_BUG :Database unavailable.", me.name);
		return;
	}

	if (parc < 3 || BadPtr(parv[1]) || BadPtr(parv[2]))
	{
		sendto_one(client, NULL,
		           ":%s NOTE VERIFY INVALID_PARAMS "
		           ":Syntax: /VERIFY <account> <code>",
		           me.name);
		return;
	}

	name = parv[1];
	code = parv[2];

	acc = find_account(name);
	if (!acc)
	{
		sendto_one(client, NULL,
		           ":%s FAIL VERIFY UNKNOWN_ACCOUNT %s "
		           ":No such account.",
		           me.name, name);
		return;
	}

	if (acc->verified)
	{
		sendto_one(client, NULL,
		           ":%s FAIL VERIFY ALREADY_VERIFIED %s "
		           ":Account is already verified.",
		           me.name, name);
		free_account(acc);
		return;
	}

	if (!acc->verify_code)
	{
		sendto_one(client, NULL,
		           ":%s FAIL VERIFY NO_PENDING %s "
		           ":No verification is pending for this account.",
		           me.name, name);
		free_account(acc);
		return;
	}

	if (acc->verify_expires && time(NULL) > acc->verify_expires)
	{
		sendto_one(client, NULL,
		           ":%s FAIL VERIFY CODE_EXPIRED %s "
		           ":The verification code has expired.  Re-register the "
		           "account.",
		           me.name, name);
		free_account(acc);
		return;
	}

	if (strcmp(acc->verify_code, code))
	{
		add_fake_lag(client, 5000);
		sendto_one(client, NULL,
		           ":%s FAIL VERIFY BAD_CODE %s "
		           ":Incorrect verification code.",
		           me.name, name);
		free_account(acc);
		return;
	}

    /* Success: clear code, mark verified, persist. */
	free(acc->verify_code);
	acc->verify_code = NULL;
	acc->verify_expires = 0;
	acc->verified = 1;

	if (!update_account_verification(acc))
	{
		sendto_one(client, NULL,
		           ":%s FAIL VERIFY INTERNAL_ERROR %s "
		           ":Could not persist verification.",
		           me.name, name);
		free_account(acc);
		return;
	}

	sendto_one(client, NULL,
	           ":%s VERIFY SUCCESS %s :Account verified.  You are now logged in.",
	           me.name, name);
	unreal_log(ULOG_INFO, "account", "VERIFY", client,
	           "Account $account verified by $client.details",
	           log_data_string("account", acc->name));

    /* Auto-login the verifying client. */
	if (!client->user)
		make_user(client);
	strlcpy(client->user->account, acc->name, sizeof(client->user->account));
	user_account_login(NULL, client);

	free_account(acc);
}

/* ===================================================================
 * RPC helpers
 * =================================================================== */
static json_t *account2json(const Account *acc)
{
	json_t *j = json_object();
	json_t *jchannels = json_array();
	json_t *jmeta = json_array();
	json_t *jmembers = json_object();

	json_object_set_new(j, "id", acc->id ? json_integer(acc->id) : json_null());
	json_object_set_new(j, "name", json_string(acc->name));
	json_object_set_new(j, "email", json_string(acc->email));
	json_object_set_new(j, "time_registered", json_integer(acc->time_registered));
	json_object_set_new(j, "verified", json_integer(acc->verified));

	if (acc->channels)
		for (char **c = acc->channels; *c; c++)
			json_array_append_new(jchannels, json_string(*c));
	json_object_set_new(j, "channels", jchannels);

	for (Metadata *m = acc->metadata_head; m; m = m->next)
	{
		json_t *mj = json_object();
		json_object_set_new(mj, "key", json_string(m->key));
		json_object_set_new(mj, "value", json_string(m->value));
		json_array_append_new(jmeta, mj);
	}
	json_object_set_new(j, "metadata", jmeta);

	for (AccountMember *m = acc->members; m; m = m->next)
		json_expand_client(jmembers, m->client->id, m->client, 2);
	json_object_set_new(j, "online_clients", jmembers);

	return j;
}

RPC_CALL_FUNC(rpc_list_accounts)
{
	Account **accounts;
	json_t *jaccounts, *result;

	if (!obsidian_db)
	{
		rpc_error(client, request, JSON_RPC_ERROR_INTERNAL_ERROR,
		          "Database is not available.");
		return;
	}

	accounts = read_accounts_from_db(NULL);
	if (!accounts || !accounts[0])
	{
		free(accounts);
		rpc_error(client, request, JSON_RPC_ERROR_NOT_FOUND,
		          "No accounts registered.");
		return;
	}

	jaccounts = json_array();
	result = json_object();
	for (size_t i = 0; accounts[i]; i++)
	{
		json_array_append_new(jaccounts, account2json(accounts[i]));
		free_account(accounts[i]);
	}
	free(accounts);
	json_object_set_new(result, "accounts", jaccounts);
	rpc_response(client, request, result);
	json_decref(result);
}

RPC_CALL_FUNC(rpc_accounts_find)
{
	const char *name;
	Account *acc;
	json_t *jacc;

	if (!obsidian_db)
	{
		rpc_error(client, request, JSON_RPC_ERROR_INTERNAL_ERROR,
		          "Database is not available.");
		return;
	}

	REQUIRE_PARAM_STRING("name", name);

	acc = find_account(name);
	if (!acc)
	{
		rpc_error(client, request, JSON_RPC_ERROR_NOT_FOUND, "Account not found.");
		return;
	}

	jacc = account2json(acc);
	rpc_response(client, request, jacc);
	json_decref(jacc);
	free_account(acc);
}
