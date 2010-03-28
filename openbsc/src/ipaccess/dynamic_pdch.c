/* ip.access nanoBTS dynamic PDCH allocator */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves ehf, Reykjavik
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

#include <unistd.h>
#include <stdlib.h>

#include <openbsc/signal.h>
#include <openbsc/gsm_data.h>

#define NUM_MIN_PDCH	1
#define NUM_MIN_TCHF	2

struct dyn_pdch_params {
	/* how many PDCHs (static+dynamic) should be active as
	 * a minimum at any given point in time */
	unsigned int num_min_pdch;
	/* how many TCHFs should be available and unused as a
	 * minimum at any given point in time */
	unsigned int num_min_tchf;
};

static struct dyn_pdch_params params = {
	.num_min_pdch = NUM_MIN_PDCH,
	.num_min_tchf = NUM_MIN_TCHF,
};

/* count the number of physical channels with given pchan config
 * (and optionally flags) within the given BTS */
static unsigned int num_pchan_in_bts(struct gsm_bts *bts,
				     enum gsm_phys_chan_config pchan,
				     unsigned int flags)
{
	struct gsm_bts_trx *trx;
	unsigned int num = 0;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		unsigned int i;

		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			if (ts->pchan == pchan) {
				if (flags && !(ts->flags & flags))
					continue;
				num++;
			}
		}
	}

	return num;
}

/* attempt to deactivate one currently active dynamic PDCH */
static int try_deact_one_pdch(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	/* try to deactivate one PDCH */
	llist_for_each_entry(trx, &bts->trx_list, list) {
		int i;
		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			if (ts->pchan != GSM_PCHAN_TCH_F_PDCH)
				continue;
			if (!(ts->flags & TS_F_PDCH_MODE))
				continue;
			/* deactivate PDCH mode and turn it into a TCH/F */
			rsl_ipacc_pdch_activate(&ts->lchan[0], 0);
			return 1;
		}
	}

	return 0;
}

static int try_act_one_pdch(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	/* try to deactivate one PDCH */
	llist_for_each_entry(trx, &bts->trx_list, list) {
		int i;
		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			if (ts->pchan != GSM_PCHAN_TCH_F_PDCH)
				continue;
			if (ts->flags & TS_F_PDCH_MODE)
				continue;
			/* activate PDCH mode */
			rsl_ipacc_pdch_activate(&ts->lchan[0], 1);
			return 1;
		}
	}

	return 0;
}

/* activate number of dynamic PDCH's withing constraints */
void ipac_dyn_pdch_equalize(struct gsm_bts *bts)
{
	unsigned int num_static_tchf, num_static_pdch;
	unsigned int num_dyn_pdch;
	unsigned int num_dyn_pdch_act, num_dyn_tchf_act;
	unsigned int i;
	int tchf_required;

	if (!bts->gprs.enabled)
		return;

	num_static_tchf = num_pchan_in_bts(bts, GSM_PCHAN_TCH_F, 0);
	num_static_pdch = num_pchan_in_bts(bts, GSM_PCHAN_PDCH, 0);
	num_dyn_pdch =
		num_pchan_in_bts(bts, GSM_PCHAN_TCH_F_PDCH, 0);
	num_dyn_pdch_act =
		num_pchan_in_bts(bts, GSM_PCHAN_TCH_F_PDCH, TS_F_PDCH_MODE);
	num_dyn_tchf_act = num_dyn_pdch - num_dyn_pdch_act;

	tchf_required = params.num_min_tchf - (num_static_tchf + num_dyn_tchf_act);
	if (tchf_required > 0) {
		/* we need to release some more TCH/F */
		/* make sure we always keep the minimum number of PDCH
		 * around */
		int max = (num_dyn_pdch_act + num_static_pdch) -
							params.num_min_pdch;
		if (tchf_required > max)
			tchf_required = max;
		for (i = 0; i < tchf_required; i++)
			try_deact_one_pdch(bts);
	} else if (tchf_required < 0 && num_dyn_tchf_act) {
		/* we can activate some more PDCH */
		for (i = 0; i < abs(tchf_required); i++)
			try_act_one_pdch(bts);
	}
}

/* A channel allocation has been failed, which might be indication
 * for a shortage of circuit switched channel, which in turn means
 * that we could deactivte some PDCH to make space for more TCH/F's */
static void handle_challoc_fail(struct gsm_bts *bts,
				enum gsm_chan_t type)
{
	unsigned int num_stat_pdch;
	unsigned int num_dyn_pdch_act;

	if (!bts->gprs.enabled)
		return;

	/* we can only increase the amount of available TCH/F's */
	if (type != GSM_LCHAN_TCH_F)
		return;

	num_stat_pdch = num_pchan_in_bts(bts, GSM_PCHAN_PDCH, 0);
	num_dyn_pdch_act =
		num_pchan_in_bts(bts, GSM_PCHAN_TCH_F_PDCH, TS_F_PDCH_MODE);

	/* we have to keep at least num_min_pdch dynamic PDCH's alive */
	if (num_dyn_pdch_act + num_stat_pdch <= params.num_min_pdch)
		return;

	try_deact_one_pdch(bts);
}

/* A lchan has been free()d by the channel allocator, we can consider
 * activating that timeslot in PDCH mode again now */
static void handle_lchan_freed(struct gsm_lchan *lchan,
				enum gsm_chan_t type)
{
	if (!lchan->ts->trx->bts->gprs.enabled)
		return;

	if (type != GSM_LCHAN_TCH_F)
		return;

	if (lchan->ts->pchan != GSM_PCHAN_TCH_F_PDCH)
		return;

	/* activate the channel in PDCH mode while it is
	 * not used as a TCH/F */
	rsl_ipacc_pdch_activate(lchan, 1);
}

/* signal callback for signals from the channel allocator */
static int dyn_pdch_sig_cb(unsigned int subsys, unsigned int signal,
			   void *handler_data, void *signal_data)
{
	struct challoc_signal_data *sig = signal_data;

	if (subsys != SS_CHALLOC)
		return 0;

	switch (signal) {
	case S_CHALLOC_ALLOC_FAIL:
		handle_challoc_fail(sig->bts, sig->type);
		break;
	case S_CHALLOC_FREED:
		handle_lchan_freed(sig->lchan, sig->type);
		break;
	}

	return 0;
}

void on_dso_load_ipac_dyn_pdch(void)
{
	register_signal_handler(SS_CHALLOC, dyn_pdch_sig_cb, NULL);
}
