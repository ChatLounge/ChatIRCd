/* m_listenoff.c: Borrowed from ircd-seven, adapted for use with ChatIRCd.
 *
 *     Provides the LISTENOFF command.  When executed, turns off all the
 * listeners on the target server.  To turn it off locally, requires
 * Admin with the oper:local_routing flag.  To turn it off remotely,
 * additionally requires NetAdmin and the oper:routing flag.  Could also
 * be used by services, if supported.
 *
 *     Ben
 *
 */

#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_newconf.h"
#include "numeric.h"
#include "s_serv.h"
#include "s_conf.h"
#include "listener.h"

static int mo_listenoff(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int me_listenoff(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message listenoff_msgtab = {
  "LISTENOFF", 0, 0, 0, MFLG_SLOW,
  { mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_listenoff, 0}, {mo_listenoff, 0}
  }
};

mapi_clist_av1 listenoff_clist[] = { &listenoff_msgtab, NULL };


DECLARE_MODULE_AV1(listenoff, NULL, NULL, listenoff_clist, NULL, NULL, "Revision 0.43");


static int
mo_listenoff(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
    const char *target_server;

    if (!HasPrivilege(source_p, "oper:local_routing") && !IsAdmin(source_p))
    {
        sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "local_routing");
        return 0;
    }

    if (parc > 1)
    {
        target_server = parv[1];

		if(!HasPrivilege(source_p, "oper:routing") && !IsNetAdmin(source_p) && match(target_server, me.name) != 0)
		{
			sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "routing");
			return 0;
		}

        sendto_match_servs(source_p, target_server, CAP_ENCAP, NOCAPS,
                "ENCAP %s LISTENOFF", target_server);

        if (match(target_server, me.name) == 0)
            return 0;
    }
	sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s is closing listeners on: %s",
		get_oper_name(source_p), me.name);
	close_listeners();
	sendto_one_notice(source_p, ":*** Listeners have been closed.");

    return 0;
}

static int
me_listenoff(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
    sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s is closing listeners on: %s",
		get_oper_name(source_p), me.name);
    close_listeners();
    sendto_one_notice(source_p, ":*** Listeners have been closed.");

    return 0;
}

