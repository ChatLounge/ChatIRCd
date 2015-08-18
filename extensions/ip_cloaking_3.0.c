/* $Id: ip_cloaking.c 3526 2007-07-06 07:56:14Z nenolod $ */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_serv.h"
#include "numeric.h"

/* if you're modifying this module, you'll probably to change this */
#define KEY 0x13748cfa

static int
_modinit(void)
{
	/* add the usermode to the available slot */
	user_modes['h'] = find_umode_slot();
	construct_umodebuf();

	return 0;
}

static void
_moddeinit(void)
{
	/* disable the umode and remove it from the available list */
	user_modes['h'] = 0;
	construct_umodebuf();
}

static void check_umode_change(void *data);
static void check_new_user(void *data);
mapi_hfn_list_av1 ip_cloaking_hfnlist[] = {
	{ "umode_changed", (hookfn) check_umode_change },
	{ "new_local_user", (hookfn) check_new_user },
	{ NULL, NULL }
};

DECLARE_MODULE_AV1(ip_cloaking, _modinit, _moddeinit, NULL, NULL,
			ip_cloaking_hfnlist, "$Revision: 3526 $");

static void
distribute_hostchange(struct Client *client_p, char *newhost)
{
	if (newhost != client_p->orighost)
		sendto_one_numeric(client_p, RPL_HOSTHIDDEN, "%s :is now your hidden host",
			newhost);
	else
		sendto_one_numeric(client_p, RPL_HOSTHIDDEN, "%s :hostname reset",
			newhost);

	sendto_server(NULL, NULL,
		CAP_EUID | CAP_TS6, NOCAPS, ":%s CHGHOST %s :%s",
		use_id(&me), use_id(client_p), newhost);
	sendto_server(NULL, NULL,
		CAP_TS6, CAP_EUID, ":%s ENCAP * CHGHOST %s :%s",
		use_id(&me), use_id(client_p), newhost);

	change_nick_user_host(client_p, client_p->name, client_p->username, newhost, 0, "Changing host");

	if (newhost != client_p->orighost)
		SetDynSpoof(client_p);
	else
		ClearDynSpoof(client_p);
}

#define Nval 0x8c3a48ac
#define HOSTLEN 63
#define INITDATA "98fwqefnoiqefv03f423t34gbv3vb89tg432t3b8" /* change this */

static inline unsigned int
get_string_entropy(const char *inbuf)
{
	unsigned int accum = 1;

	while(*inbuf != '\0')
		accum += *inbuf++;

	return accum;
}

/* calls get_string_entropy() and toasts it against INITDATA */
static inline unsigned int
get_string_weighted_entropy(const char *inbuf)
{
	static int base_entropy = 0;
        unsigned int accum = get_string_entropy(inbuf);

	/* initialize the algorithm if it is not yet ready */
	if (base_entropy == 0)
		base_entropy = get_string_entropy(INITDATA);

        return (Nval * accum) ^ base_entropy;
}

static void
do_host_cloak_ip(const char *inbuf, char *outbuf)
{
	char *tptr;
	unsigned int accum = get_string_weighted_entropy(inbuf);
	char buf[HOSTLEN];
	int ipv6 = 0;

	strncpy(buf, inbuf, HOSTLEN);
	tptr = strrchr(buf, '.');

	if (tptr == NULL)
	{
		tptr = strrchr(buf, ':');
		ipv6 = 1;
	}

	if (tptr == NULL)
	{
		strncpy(outbuf, inbuf, HOSTLEN);
		return;
	}

	*tptr++ = '\0';

	if(ipv6)
	{
	    rb_snprintf(outbuf, HOSTLEN, "%s:%x", buf, accum);
	}
	else
	{
	    rb_snprintf(outbuf, HOSTLEN, "%s.%x", buf, accum);
	}
}

static void
do_host_cloak_host(const char *inbuf, char *outbuf)
{
	char b26_alphabet[] = "abcdefghijklmnopqrstuvwxyz";
	char *tptr;
	unsigned int accum = get_string_weighted_entropy(inbuf);

	strncpy(outbuf, inbuf, HOSTLEN);

	/* pass 1: scramble first section of hostname using base26 
	 * alphabet toasted against the weighted entropy of the string.
	 *
	 * numbers are not changed at this time, only letters.
	 */
	for (tptr = outbuf; *tptr != '\0'; tptr++)
	{
		if (*tptr == '.')
			break;

		if (isdigit((unsigned char)*tptr) || *tptr == '-')
			continue;

		*tptr = b26_alphabet[(*tptr * accum) % 26];
	}

	/* pass 2: scramble each number in the address */
	for (tptr = outbuf; *tptr != '\0'; tptr++)
	{
		if (isdigit((unsigned char)*tptr))
		{
			*tptr = 48 + ((*tptr * accum) % 10);
		}
	}	
}

static void
check_umode_change(void *vdata)
{
	hook_data_umode_changed *data = (hook_data_umode_changed *)vdata;
	struct Client *source_p = data->client;

	if (!MyClient(source_p))
		return;

	/* didn't change +h umode, we don't need to do anything */
	if (!((data->oldumodes ^ source_p->umodes) & user_modes['h']))
		return;

	if (source_p->umodes & user_modes['h'])
	{
		if (IsIPSpoof(source_p) || source_p->localClient->mangledhost == NULL || (IsDynSpoof(source_p) && strcmp(source_p->host, source_p->localClient->mangledhost)))
		{
			source_p->umodes &= ~user_modes['h'];
			return;
		}
		if (strcmp(source_p->host, source_p->localClient->mangledhost))
		{
			distribute_hostchange(source_p, source_p->localClient->mangledhost);
		}
		else /* not really nice, but we need to send this numeric here */
			sendto_one_numeric(source_p, RPL_HOSTHIDDEN, "%s :is now your hidden host",
				source_p->host);
	}
	else if (!(source_p->umodes & user_modes['h']))
	{
		if (source_p->localClient->mangledhost != NULL &&
				!strcmp(source_p->host, source_p->localClient->mangledhost))
		{
			distribute_hostchange(source_p, source_p->orighost);
		}
	}
}

static void
check_new_user(void *vdata)
{
	struct Client *source_p = (void *)vdata;

	if (IsIPSpoof(source_p))
	{
		source_p->umodes &= ~user_modes['h'];
		return;
	}
	source_p->localClient->mangledhost = rb_malloc(HOSTLEN);
	if (!irccmp(source_p->orighost, source_p->sockhost))
		do_host_cloak_ip(source_p->orighost, source_p->localClient->mangledhost);
	else
		do_host_cloak_host(source_p->orighost, source_p->localClient->mangledhost);
	if (IsDynSpoof(source_p))
		source_p->umodes &= ~user_modes['h'];
	if (source_p->umodes & user_modes['h'])
	{
		rb_strlcpy(source_p->host, source_p->localClient->mangledhost, sizeof(source_p->host));
		if (irccmp(source_p->host, source_p->orighost))
			SetDynSpoof(source_p);
	}
}
