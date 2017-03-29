/* MSC subscriber connection implementation */

/*
 * (C) 2016 by sysmocom s.m.f.c. <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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
#include <osmocom/core/fsm.h>
#include <osmocom/core/signal.h>

#include <openbsc/osmo_msc.h>
#include <openbsc/vlr.h>
#include <openbsc/debug.h>
#include <openbsc/transaction.h>
#include <openbsc/signal.h>

#define SUBSCR_CONN_TIMEOUT 5 /* seconds */

static const struct value_string subscr_conn_fsm_event_names[] = {
	OSMO_VALUE_STRING(SUBSCR_CONN_E_INVALID),
	OSMO_VALUE_STRING(SUBSCR_CONN_E_START),
	OSMO_VALUE_STRING(SUBSCR_CONN_E_ACCEPTED),
	OSMO_VALUE_STRING(SUBSCR_CONN_E_COMMUNICATING),
	OSMO_VALUE_STRING(SUBSCR_CONN_E_BUMP),
	OSMO_VALUE_STRING(SUBSCR_CONN_E_MO_CLOSE),
	OSMO_VALUE_STRING(SUBSCR_CONN_E_CN_CLOSE),
	{ 0, NULL }
};

const struct value_string subscr_conn_from_names[] = {
	OSMO_VALUE_STRING(SUBSCR_CONN_FROM_INVALID),
	OSMO_VALUE_STRING(SUBSCR_CONN_FROM_LU),
	OSMO_VALUE_STRING(SUBSCR_CONN_FROM_CM_SERVICE_REQ),
	OSMO_VALUE_STRING(SUBSCR_CONN_FROM_PAGING_RESP),
	{ 0, NULL }
};

static void paging_resp(struct gsm_subscriber_connection *conn,
			       enum gsm_paging_event pe)
{
	subscr_paging_dispatch(GSM_HOOK_RR_PAGING, pe, NULL, conn, conn->vsub);
}

void subscr_conn_fsm_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	OSMO_ASSERT(event == SUBSCR_CONN_E_START);
	osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_S_NEW,
				SUBSCR_CONN_TIMEOUT, 0);
}

void subscr_conn_fsm_new(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	enum subscr_conn_from from = SUBSCR_CONN_FROM_INVALID;
	bool success;

	if (data) {
		from = *(enum subscr_conn_from*)data;
		LOGPFSM(fi, "%s\n", subscr_conn_from_name(from));
	}

	/* If accepted, transition the state, all other cases mean failure. */
	switch (event) {
	case SUBSCR_CONN_E_ACCEPTED:
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_S_ACCEPTED,
					SUBSCR_CONN_TIMEOUT, 0);
		break;

	case SUBSCR_CONN_E_MO_CLOSE:
	case SUBSCR_CONN_E_CN_CLOSE:
		break;

	default:
		LOGPFSM(fi, "Unexpected event: %d %s\n",
			event, osmo_fsm_event_name(fi->fsm, event));
		break;
	}

	success = (fi->state == SUBSCR_CONN_S_ACCEPTED);

	if (from == SUBSCR_CONN_FROM_LU)
		rate_ctr_inc(&conn->network->msc_ctrs->ctr[
		             	success ? MSC_CTR_LOC_UPDATE_COMPLETED
					: MSC_CTR_LOC_UPDATE_FAILED]);

	/* signal paging success or failure in case this was a paging */
	if (from == SUBSCR_CONN_FROM_PAGING_RESP)
		paging_resp(conn,
			    success ? GSM_PAGING_SUCCEEDED
			    	    : GSM_PAGING_EXPIRED);

	/* On failure, discard the conn */
	if (!success) {
		/* TODO: on MO_CLOSE or CN_CLOSE, first go to RELEASING and
		 * await BSC confirmation? */
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_S_RELEASED, 0, 0);
		return;
	}

	if (from == SUBSCR_CONN_FROM_CM_SERVICE_REQ) {
		conn->received_cm_service_request = true;
		LOGPFSM(fi, "received_cm_service_request = true\n");
	}

	osmo_fsm_inst_dispatch(fi, SUBSCR_CONN_E_BUMP, data);
}

static void subscr_conn_fsm_bump(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	if (conn->silent_call)
		return;

	if (conn->received_cm_service_request)
		return;

	if (conn->vsub && !llist_empty(&conn->vsub->cs.requests))
		return;

	if (trans_has_conn(conn))
		return;

	osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_S_RELEASED, 0, 0);
}

static void subscr_conn_fsm_accepted_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_ATTACHED, conn->vsub);
}

static void subscr_conn_fsm_accepted(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SUBSCR_CONN_E_COMMUNICATING:
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_S_COMMUNICATING, 0, 0);
		return;

	case SUBSCR_CONN_E_BUMP:
		subscr_conn_fsm_bump(fi, event, data);
		return;

	default:
		break;
	}
	/* Whatever unexpected happens in the accepted state, it means release.
	 * Even if an unexpected event is passed, the safest thing to do is
	 * discard the conn. We don't expect another SUBSCR_CONN_E_ACCEPTED. */
	osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_S_RELEASED, 0, 0);
}

static void subscr_conn_fsm_communicating(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SUBSCR_CONN_E_COMMUNICATING:
		/* no-op */
		return;

	case SUBSCR_CONN_E_BUMP:
		subscr_conn_fsm_bump(fi, event, data);
		return;

	default:
		break;
	}
	/* Whatever unexpected happens in the accepted state, it means release.
	 * Even if an unexpected event is passed, the safest thing to do is
	 * discard the conn. We don't expect another SUBSCR_CONN_E_ACCEPTED. */
	osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_S_RELEASED, 0, 0);
}

static void subscr_conn_fsm_cleanup(struct osmo_fsm_inst *fi,
				    enum osmo_fsm_term_cause cause)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	fi->priv = NULL;

	if (!conn)
		return;

	if (conn->in_release)
		return;
	conn->in_release = true;
	conn->conn_fsm = NULL;

	/* If we're closing in a middle of a trans, we need to clean up */
	trans_conn_closed(conn);

	msc_subscr_conn_put(conn);
}

int subscr_conn_fsm_timeout(struct osmo_fsm_inst *fi)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	if (conn)
		vlr_subscr_conn_timeout(conn->vsub);
	osmo_fsm_inst_dispatch(fi, SUBSCR_CONN_E_CN_CLOSE, NULL);
	return 0;
}

static void subscr_conn_fsm_release(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state subscr_conn_fsm_states[] = {
	[SUBSCR_CONN_S_INIT] = {
		.name = OSMO_STRINGIFY(SUBSCR_CONN_S_INIT),
		.in_event_mask = S(SUBSCR_CONN_E_START),
		.out_state_mask = S(SUBSCR_CONN_S_NEW),
		.action = subscr_conn_fsm_init,
	},
	[SUBSCR_CONN_S_NEW] = {
		.name = OSMO_STRINGIFY(SUBSCR_CONN_S_NEW),
		.in_event_mask = S(SUBSCR_CONN_E_ACCEPTED) |
				 S(SUBSCR_CONN_E_MO_CLOSE) |
				 S(SUBSCR_CONN_E_CN_CLOSE),
		.out_state_mask = S(SUBSCR_CONN_S_ACCEPTED) |
				  S(SUBSCR_CONN_S_RELEASED),
		.action = subscr_conn_fsm_new,
	},
	[SUBSCR_CONN_S_ACCEPTED] = {
		.name = OSMO_STRINGIFY(SUBSCR_CONN_S_ACCEPTED),
		/* allow everything to release for any odd behavior */
		.in_event_mask = S(SUBSCR_CONN_E_COMMUNICATING) |
		                 S(SUBSCR_CONN_E_BUMP) |
				 S(SUBSCR_CONN_E_ACCEPTED) |
				 S(SUBSCR_CONN_E_MO_CLOSE) |
				 S(SUBSCR_CONN_E_CN_CLOSE),
		.out_state_mask = S(SUBSCR_CONN_S_RELEASED) |
				  S(SUBSCR_CONN_S_COMMUNICATING),
		.onenter = subscr_conn_fsm_accepted_enter,
		.action = subscr_conn_fsm_accepted,
	},
	[SUBSCR_CONN_S_COMMUNICATING] = {
		.name = OSMO_STRINGIFY(SUBSCR_CONN_S_COMMUNICATING),
		/* allow everything to release for any odd behavior */
		.in_event_mask = S(SUBSCR_CONN_E_BUMP) |
				 S(SUBSCR_CONN_E_ACCEPTED) |
				 S(SUBSCR_CONN_E_COMMUNICATING) |
				 S(SUBSCR_CONN_E_MO_CLOSE) |
				 S(SUBSCR_CONN_E_CN_CLOSE),
		.out_state_mask = S(SUBSCR_CONN_S_RELEASED),
		.action = subscr_conn_fsm_communicating,
	},
	[SUBSCR_CONN_S_RELEASED] = {
		.name = OSMO_STRINGIFY(SUBSCR_CONN_S_RELEASED),
		.onenter = subscr_conn_fsm_release,
	},
};

static struct osmo_fsm subscr_conn_fsm = {
	.name = "Subscr_Conn",
	.states = subscr_conn_fsm_states,
	.num_states = ARRAY_SIZE(subscr_conn_fsm_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DVLR,
	.event_names = subscr_conn_fsm_event_names,
	.cleanup = subscr_conn_fsm_cleanup,
	.timer_cb = subscr_conn_fsm_timeout,
};

int msc_create_conn_fsm(struct gsm_subscriber_connection *conn, const char *id)
{
	struct osmo_fsm_inst *fi;
	OSMO_ASSERT(conn);

	if (conn->conn_fsm) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: Error: connection already in use\n", id);
		return -EINVAL;
	}

	/* Allocate the FSM not with the subscr_conn. Semantically it would
	 * make sense, but in subscr_conn_fsm_cleanup(), we want to discard the
	 * subscriber connection. If the FSM is freed along with the subscriber
	 * connection, then in _osmo_fsm_inst_term() the osmo_fsm_inst_free()
	 * that follows the cleanup() call would run into a double free. */
	fi = osmo_fsm_inst_alloc(&subscr_conn_fsm, conn->network,
				 msc_subscr_conn_get(conn),
				 LOGL_DEBUG, id);

	if (!fi) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: Failed to allocate subscr conn master FSM\n", id);
		return -ENOMEM;
	}
	conn->conn_fsm = fi;
	osmo_fsm_inst_dispatch(conn->conn_fsm, SUBSCR_CONN_E_START, NULL);
	return 0;
}

bool msc_subscr_conn_is_accepted(struct gsm_subscriber_connection *conn)
{
	if (!conn)
		return false;
	if (!conn->vsub)
		return false;
	if (!conn->conn_fsm)
		return false;
	if (!(conn->conn_fsm->state == SUBSCR_CONN_S_ACCEPTED
	      || conn->conn_fsm->state == SUBSCR_CONN_S_COMMUNICATING))
		return false;
	return true;
}

void msc_subscr_conn_communicating(struct gsm_subscriber_connection *conn)
{
	OSMO_ASSERT(conn);
	osmo_fsm_inst_dispatch(conn->conn_fsm, SUBSCR_CONN_E_COMMUNICATING,
			       NULL);
}

void msc_subscr_conn_init(void)
{
	osmo_fsm_register(&subscr_conn_fsm);
}
