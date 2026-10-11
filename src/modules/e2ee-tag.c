/*
 * src/modules/e2ee-tag.c
 *
 * Relays the +obby.world/e2ee client-only tag, the transport for Obby-native
 * end-to-end encryption. The tag value is opaque (base64 of an encrypted blob)
 * and the server never inspects it; it only validates the shape and forwards it
 * to recipients, exactly as it does for +obby.world/invoked-by and +draft/reply.
 *
 * License: GPLv3 or later
 * Copyright (c) 2026 obbyworld Team
 */

#include "unrealircd.h"

ModuleHeader MOD_HEADER = {
    "e2ee-tag",
    "1.0",
    "+obby.world/e2ee client tag (Obby-native end-to-end encryption)",
    "ObbyIRCd Team",
    "unrealircd-6",
};

#define E2EE_TAG "+obby.world/e2ee"
/* Client message-tag data caps at 4094 bytes (IRCv3 message-tags); the value is
 * the only tag we add, so the whole budget is available to it. */
#define E2EE_MAX_VALUE 4094

int e2ee_mtag_is_ok(Client *client, const char *name, const char *value);
void mtag_add_e2ee(Client *client, MessageTag *recv_mtags, MessageTag **mtag_list, const char *signature);

MOD_INIT()
{
	MessageTagHandlerInfo mtag;

	MARK_AS_OFFICIAL_MODULE(modinfo);

	memset(&mtag, 0, sizeof(mtag));
	mtag.name = E2EE_TAG;
	mtag.is_ok = e2ee_mtag_is_ok;
	mtag.flags = MTAG_HANDLER_FLAGS_NO_CAP_NEEDED;
	MessageTagHandlerAdd(modinfo->handle, &mtag);

	HookAddVoid(modinfo->handle, HOOKTYPE_NEW_MESSAGE, 0, mtag_add_e2ee);

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

/** Accept the tag from any client if the value is a non-empty, length-bounded
 *  base64 string. The contents are end-to-end encrypted, so the server cannot
 *  and must not interpret them beyond this sanity check.
 */
int e2ee_mtag_is_ok(Client *client, const char *name, const char *value)
{
	const char *p;

	if (BadPtr(value))
		return 0;

	if (strlen(value) > E2EE_MAX_VALUE)
		return 0;

	for (p = value; *p; p++)
	{
		if (!isalnum((unsigned char)*p) && *p != '+' && *p != '/' && *p != '=')
			return 0;
	}

	return 1;
}

void mtag_add_e2ee(Client *client, MessageTag *recv_mtags, MessageTag **mtag_list, const char *signature)
{
	MessageTag *m;

	if (IsUser(client))
	{
		m = find_mtag(recv_mtags, E2EE_TAG);
		if (m)
		{
			m = duplicate_mtag(m);
			AddListItem(m, *mtag_list);
		}
	}
}
