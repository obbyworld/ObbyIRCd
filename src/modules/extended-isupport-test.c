/*
 * extended-isupport-test.c
 *
 * Test scaffold for draft/extended-isupport-0.2's `+=` append form.
 * Registers a batch of dummy client-prefixed message-tag handlers via
 * MessageTagHandlerAdd() so the CLIENTTAGDENY ISUPPORT value overflows
 * one RPL_ISUPPORT line, which then exercises the v0.2 line-splitting
 * path in isupport.c.
 *
 * Load with:  loadmodule "extended-isupport-test";
 *
 * Once loaded, connecting with `draft/extended-isupport-0.2` + `batch`
 * caps and issuing the ISUPPORT command should produce multiple
 * RPL_ISUPPORT replies for CLIENTTAGDENY: one `KEY=chunk1` line
 * followed by one or more `KEY+=chunk2` lines, all inside a single
 * draft/isupport batch.
 */

#include "unrealircd.h"

#define EIST_NUM_TAGS   80
#define EIST_TAG_PREFIX "+draft/eist-"

static MessageTagHandler *eist_handlers[EIST_NUM_TAGS];
static char *eist_names[EIST_NUM_TAGS];

ModuleHeader MOD_HEADER = {
    "extended-isupport-test",
    "0.1",
    "Test module: register many client tag handlers to exercise CLIENTTAGDENY overflow",
    "Valerie Pond",
    "unrealircd-6",
};

/* Always-accept validator: this is a test, the value side of these
 * tags is never consulted by any code path that matters. */
static int eist_is_ok(Client *c, const char *name, const char *value)
{
	return 1;
}

MOD_INIT()
{
	int i;
	MARK_AS_OFFICIAL_MODULE(modinfo);

	for (i = 0; i < EIST_NUM_TAGS; i++)
	{
		MessageTagHandlerInfo info;
		char buf[32];
		snprintf(buf, sizeof(buf), "%s%d", EIST_TAG_PREFIX, i);
		eist_names[i] = strdup(buf);
		memset(&info, 0, sizeof(info));
		info.name = eist_names[i];
		info.is_ok = eist_is_ok;
		info.flags = MTAG_HANDLER_FLAGS_NO_CAP_NEEDED;
		eist_handlers[i] = MessageTagHandlerAdd(modinfo->handle, &info);
	}
	return MOD_SUCCESS;
}

MOD_LOAD()
{
	return MOD_SUCCESS;
}

MOD_UNLOAD()
{
	int i;
	for (i = 0; i < EIST_NUM_TAGS; i++)
	{
		if (eist_names[i])
		{
			free(eist_names[i]);
			eist_names[i] = NULL;
		}
	}
	return MOD_SUCCESS;
}
