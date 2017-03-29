/* Implementation of RANAP messages to/from an MSC via an Iu-CS interface.
 * This keeps direct RANAP dependencies out of libmsc. */

/* (C) 2016 by sysmocom s.m.f.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include <osmocom/core/logging.h>

#include <osmocom/ranap/ranap_ies_defs.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/iu.h>
#include <openbsc/iucs.h>
#include <openbsc/vlr.h>
#include <openbsc/iucs_ranap.h>
#include <openbsc/osmo_msc.h>

/* To continue authorization after a Security Mode Complete */
int gsm0408_authorize(struct gsm_subscriber_connection *conn);

static int iucs_rx_rab_assign(struct gsm_subscriber_connection *conn,
			      RANAP_RAB_SetupOrModifiedItemIEs_t *setup_ies)
{
	uint8_t rab_id;
	RANAP_RAB_SetupOrModifiedItem_t *item = &setup_ies->raB_SetupOrModifiedItem;

	rab_id = item->rAB_ID.buf[0];

	LOGP(DIUCS, LOGL_NOTICE,
	     "Received RAB assignment event for %s rab_id=%hhd\n",
	     vlr_subscr_name(conn->vsub), rab_id);

	return 0;
}

int iucs_rx_sec_mode_compl(struct gsm_subscriber_connection *conn,
			   RANAP_SecurityModeCompleteIEs_t *ies)
{
	OSMO_ASSERT(conn->via_ran == RAN_UTRAN_IU);

	/* TODO evalute ies */

	if (conn->iu.integrity_protection)
		LOGP(DIUCS, LOGL_NOTICE, "Integrity Protection"
		     " was already enabled for %s\n",
		     vlr_subscr_name(conn->vsub));

	conn->iu.integrity_protection = INTEGRITY_PROTECTION_IK;

	msc_rx_sec_mode_compl(conn);
	return 0;
}

int iucs_rx_ranap_event(struct gsm_network *network,
			struct ue_conn_ctx *ue_ctx, int type, void *data)
{
	struct gsm_subscriber_connection *conn;

	conn = subscr_conn_lookup_iu(network, ue_ctx);

	if (!conn) {
		LOGP(DRANAP, LOGL_ERROR, "Cannot find subscriber for IU event %u\n", type);
		return -1;
	}

	switch (type) {
	case IU_EVENT_IU_RELEASE:
	case IU_EVENT_LINK_INVALIDATED:
		LOGP(DIUCS, LOGL_INFO, "IuCS release for %s\n",
		     vlr_subscr_name(conn->vsub));
		msc_subscr_conn_close(conn, 0);
		return 0;

	case IU_EVENT_SECURITY_MODE_COMPLETE:
		LOGP(DIUCS, LOGL_INFO, "IuCS security mode complete for %s\n",
		     vlr_subscr_name(conn->vsub));
		return iucs_rx_sec_mode_compl(conn,
					      (RANAP_SecurityModeCompleteIEs_t*)data);
	case IU_EVENT_RAB_ASSIGN:
		return iucs_rx_rab_assign(conn,
				(RANAP_RAB_SetupOrModifiedItemIEs_t*)data);
	default:
		LOGP(DIUCS, LOGL_NOTICE, "Unknown message received:"
		     " RANAP event: %i\n", type);
		return -1;
	}
}
