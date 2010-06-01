/* VTY interface for our GPRS LLC implementation */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include <arpa/inet.h>

#include <openbsc/gsm_data.h>
#include <osmocore/msgb.h>
#include <osmocore/tlv.h>
#include <osmocore/talloc.h>
#include <osmocore/select.h>
#include <osmocore/rate_ctr.h>
#include <openbsc/debug.h>
#include <openbsc/signal.h>
#include <openbsc/gprs_llc.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>

struct value_string gprs_llc_state_strs[] = {
	{ GPRS_LLES_UNASSIGNED, 	"TLLI Unassigned" },
	{ GPRS_LLES_ASSIGNED_ADM,	"TLLI Assigned" },
	{ GPRS_LLES_LOCAL_EST,		"Local Establishment" },
	{ GPRS_LLES_REMOTE_EST,		"Remote Establishment" },
	{ GPRS_LLES_ABM,		"Asynchronous Balanced Mode" },
	{ GPRS_LLES_LOCAL_REL,		"Local Release" },
	{ GPRS_LLES_TIMER_REC,		"Timer Recovery" },
};

static void vty_dump_lle(struct vty *vty, struct gprs_llc_lle *lle)
{
	vty_out(vty, " SAPI %2u State %s VUsend=%u, VUrecv=%u", lle->sapi, 
		get_value_string(gprs_llc_state_strs, lle->state),
		lle->vu_send, lle->vu_recv);
	vty_out(vty, " Vsent=%u Vack=%u Vrecv=%u, N200=%u, RetransCtr=%u%s",
		lle->v_sent, lle->v_ack, lle->v_recv, lle->n200,
		lle->retrans_ctr, VTY_NEWLINE);
}

static void vty_dump_llme(struct vty *vty, struct gprs_llc_llme *llme)
{
	unsigned int i;

	vty_out(vty, "TLLI %08x (Old TLLI %08x) BVCI=%u NSEI=%u: State %s%s",
		llme->tlli, llme->old_tlli, llme->bvci, llme->nsei,
		get_value_string(gprs_llc_state_strs, llme->state), VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(llme->lle); i++) {
		struct gprs_llc_lle *lle = &llme->lle[i];
		vty_dump_lle(vty, lle);
	}
}


DEFUN(show_llc, show_llc_cmd,
	"show llc",
	SHOW_STR "Display information about the LLC protocol")
{
	struct gprs_llc_llme *llme;

	vty_out(vty, "State of LLC Entities%s", VTY_NEWLINE);
	llist_for_each_entry(llme, &gprs_llc_llmes, list) {
		vty_dump_llme(vty, llme);
	}
	return CMD_SUCCESS;
}

int gprs_llc_vty_init(void)
{
	install_element_ve(&show_llc_cmd);

	return 0;
}
