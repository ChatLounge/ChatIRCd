/*
 * Copyright (c) 2012 William Pitcock <nenolod@dereferenced.org>.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice is present in all copies.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "stdinc.h"
#include "client.h"
#include "common.h"
#include "match.h"
#include "hash.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "msg.h"
#include "modules.h"
#include "sslproc.h"

static int mr_starttls(struct Client *, struct Client *, int, const char **);

struct Message starttls_msgtab = {
	"STARTTLS", 0, 0, 0, MFLG_SLOW,
	{{mr_starttls, 0}, mg_ignore, mg_ignore, mg_ignore, mg_ignore, mg_ignore}
};

mapi_clist_av1 starttls_clist[] = { &starttls_msgtab, NULL };

DECLARE_MODULE_AV1(starttls, NULL, NULL, starttls_clist, NULL, NULL, "$Revision$");

static int
mr_starttls(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
#ifdef HAVE_LIBCRYPTO
	ssl_ctl_t *ctl;
	rb_fde_t *F[2];

	if (!MyConnect(client_p))
		return 0;

	if (rb_socketpair(AF_UNIX, SOCK_STREAM, 0, &F[0], &F[1], "STARTTLS ssld session") == -1)
	{
		ilog_error("error creating SSL/TLS socketpair for ssld slave");
		sendto_one_numeric(client_p, ERR_STARTTLS, form_str(ERR_STARTTLS), "Unable to create SSL/TLS socketpair for ssld offload slave");
		return 1;
	}

	s_assert(client_p->localClient != NULL);

	/* clear out any remaining plaintext lines */
	rb_linebuf_donebuf(&client_p->localClient->buf_recvq);

	sendto_one_numeric(client_p, RPL_STARTTLS, form_str(RPL_STARTTLS));
	send_queued(client_p);

	ctl = start_ssld_accept(client_p->localClient->F, F[1], rb_get_fd(F[0]));
	if (ctl != NULL)
	{
		client_p->localClient->F = F[0];
		client_p->localClient->ssl_ctl = ctl;
		SetSSL(client_p);
	}
	else
		return 1;

#endif
	return 0;
}
