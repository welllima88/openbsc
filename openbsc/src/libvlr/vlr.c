/* MS subscriber data handling */

/* (C) 2014 by sysmocom s.f.m.c. GmbH
 * (C) 2015 by Holger Hans Peter Freyther
 * (C) 2016 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/gsup.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gprs_gsup_client.h>
#include <openbsc/vlr.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/debug.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define SGSN_SUBSCR_MAX_RETRIES 3
#define SGSN_SUBSCR_RETRY_INTERVAL 10

/***********************************************************************
 * Convenience functions
 ***********************************************************************/

#define LOGGSUPP(level, gsup, fmt, args...) \
	LOGP(DVLR, level, "GSUP(%s) " fmt, \
	     (gsup)->imsi, \
	     ## args)

#define LOGVSUBP(level, vsub, fmt, args...) \
	LOGP(DVLR, level, "SUBSCR(%s) " fmt, \
		vlr_sub_name(vsub), ## args)

static const struct value_string vlr_sub_auth_state_names[] = {
	{ VLR_SUB_AS_NEEDS_AUTH,		"NEEDS-AUTH" },
	{ VLR_SUB_AS_NEEDS_AUTH_WAIT_AI,	"NEEDS-AUTH(WAIT-AI)" },
	{ VLR_SUB_AS_WAIT_RESP,		"WAIT-RESP" },
	{ VLR_SUB_AS_AUTHENTICATED,	"AUTHENTICATED" },
	{ VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC,
					"NEEDS-AUTH(WAIT-SAI-RESYNC)" },
	{ VLR_SUB_AS_WAIT_RESP_RESYNC,	"NEEDS-AUTH(WAIT-RESP-RESYNC)" },
	{ VLR_SUB_AS_WAIT_ID_IMSI,	"WAIT-IMSI" },
	{ VLR_SUB_AS_AUTH_FAILED,	"AUTH-FAILED" },
	{ 0, NULL }
};

/* return static buffer with printable name of VLR subscriber */
static const char *vlr_sub_name(struct vlr_subscriber *vsub)
{
	static char buf[32];
	if (vsub->imsi[0])
		strncpy(buf, vsub->imsi, sizeof(buf));
	else
		snprintf(buf, sizeof(buf), "0x%08x", vsub->tmsi);
	buf[sizeof(buf)-1] = '\0';
	return buf;
}

/* change the authentication state of given VLR subscriber */
static void vlr_sub_set_auth_state(struct vlr_subscriber *vsub,
				   enum vlr_sub_auth_state astate)
{
	DEBUGP(DVLR, "%s: auth_state %s -> ", vlr_sub_name(vsub),
		get_value_string(vlr_sub_auth_state_names, vsub->auth_state));
	DEBUGPC(DVLR, "%s\n",
		get_value_string(vlr_sub_auth_state_names, astate));
	vsub->auth_state = astate;
}

static struct vlr_subscriber *
vlr_subscr_find_by_imsi(struct vlr_instance *vlr, const char *imsi)
{
	struct vlr_subscriber *vsub;

	llist_for_each_entry(vsub, &vlr->subscribers, list) {
		if (!strcmp(vsub->imsi, imsi))
			return vsub;
	}
	return NULL;
}

static struct vlr_subscriber *
vlr_subscr_find_by_tmsi(struct vlr_instance *vlr, uint32_t tmsi)
{
	struct vlr_subscriber *vsub;

	llist_for_each_entry(vsub, &vlr->subscribers, list) {
		if (vsub->tmsi == tmsi)
			return vsub;
	}
	return NULL;
}

/* Transmit GSUP message to HLR */
static int vlr_tx_gsup_message(struct vlr_instance *vlr,
			       struct osmo_gsup_message *gsup_msg)
{
	struct msgb *msg = gprs_gsup_msgb_alloc();

	osmo_gsup_encode(msg, gsup_msg);

	LOGP(DVLR, LOGL_DEBUG,
		    "Sending GSUP, will send: %s\n", msgb_hexdump(msg));

	if (!vlr->gsup_client) {
		msgb_free(msg);
		return -ENOTSUP;
	}

	return gprs_gsup_client_send(vlr->gsup_client, msg);
}

/* Transmit GSUP message for subscriber to HLR, using IMSI from subscriber */
static int vlr_subscr_tx_gsup_message(struct vlr_subscriber *vsub,
				      struct osmo_gsup_message *gsup_msg)
{
	struct vlr_instance *vlr = vsub->vlr;

	if (strlen(gsup_msg->imsi) == 0)
		strncpy(gsup_msg->imsi, vsub->imsi, sizeof(gsup_msg->imsi) - 1);

	return vlr_tx_gsup_message(vlr, gsup_msg);
}

/* Transmit GSUP error in response to original message */
static int vlr_tx_gsup_error_reply(struct vlr_instance *vlr,
				   struct osmo_gsup_message *gsup_orig,
				   enum gsm48_gmm_cause cause)
{
	struct osmo_gsup_message gsup_reply = {0};

	strncpy(gsup_reply.imsi, gsup_orig->imsi, sizeof(gsup_reply.imsi) - 1);
	gsup_reply.cause = cause;
	gsup_reply.message_type =
		OSMO_GSUP_TO_MSGT_ERROR(gsup_orig->message_type);

	return vlr_tx_gsup_message(vlr, &gsup_reply);
}

struct gsm_auth_tuple *vlr_sub_get_auth_tuple(struct vlr_subscriber *vsub,
					  unsigned int key_seq)
{
	unsigned int count;
	unsigned int idx;
	struct gsm_auth_tuple *at = NULL;

	if (!vsub)
		return NULL;

	if (key_seq == GSM_KEY_SEQ_INVAL)
		/* Start with 0 after increment moduleo array size */
		idx = ARRAY_SIZE(vsub->auth_tuples) - 1;
	else
		idx = key_seq;

	for (count = ARRAY_SIZE(vsub->auth_tuples); count > 0; count--) {
		idx = (idx + 1) % ARRAY_SIZE(vsub->auth_tuples);

		if (vsub->auth_tuples[idx].key_seq == GSM_KEY_SEQ_INVAL)
			continue;

		if (vsub->auth_tuples[idx].use_count == 0) {
			at = &vsub->auth_tuples[idx];
			at->use_count++;
			return at;
		}
	}
	return NULL;
}

/* Allocate a new subscriber and insert it into list */
struct vlr_subscriber *vlr_sub_alloc(struct vlr_instance *vlr)
{
	struct vlr_subscriber *vsub;
	int i;

	vsub = talloc_zero(vlr, struct vlr_subscriber);

	for (i = 0; i < ARRAY_SIZE(vsub->auth_tuples); i++)
		vsub->auth_tuples[i].key_seq = GSM_KEY_SEQ_INVAL;

	INIT_LLIST_HEAD(&vsub->ps.pdp_list);

	llist_add(&vsub->list, &vlr->subscribers);

	return vsub;
}

void vlr_sub_cleanup(struct vlr_subscriber *vsub)
{
	if (vsub->flags & GPRS_SUBSCRIBER_ENABLE_PURGE) {
		vlr_sub_purge(vsub);
		vsub->flags &= ~GPRS_SUBSCRIBER_ENABLE_PURGE;
	}
}

void vlr_sub_cancel(struct vlr_subscriber *vsub)
{
	vsub->authorized = 0;
	vsub->flags |= GPRS_SUBSCRIBER_CANCELLED;
	vsub->flags &= ~GPRS_SUBSCRIBER_ENABLE_PURGE;

	vsub->vlr.ops->subscr_update(vsub);
	vlr_sub_cleanup(vsub);
}

/***********************************************************************
 * PDP context data
 ***********************************************************************/

struct sgsn_subscriber_pdp_data *
vlr_sub_pdp_data_alloc(struct vlr_subscriber *vsub)
{
	struct sgsn_subscriber_pdp_data* pdata;

	pdata = talloc_zero(vsub, struct sgsn_subscriber_pdp_data);

	llist_add_tail(&pdata->list, &vsub->ps.pdp_list);

	return pdata;
}

static int vlr_sub_pdp_data_clear(struct vlr_subscriber *vsub)
{
	struct sgsn_subscriber_pdp_data *pdp, *pdp2;
	int count = 0;

	llist_for_each_entry_safe(pdp, pdp2, &vsub->ps.pdp_list, list) {
		llist_del(&pdp->list);
		talloc_free(pdp);
		count += 1;
	}

	return count;
}

static struct sgsn_subscriber_pdp_data *
vlr_sub_pdp_data_get_by_id(struct vlr_subscriber *vsub, unsigned context_id)
{
	struct sgsn_subscriber_pdp_data *pdp;

	llist_for_each_entry(pdp, &vsub->ps.pdp_list, list) {
		if (pdp->context_id == context_id)
			return pdp;
	}

	return NULL;
}

/***********************************************************************
 * Actual Implementation
 ***********************************************************************/

static int vlr_rx_gsup_unknown_imsi(struct vlr_instance *vlr,
				   struct osmo_gsup_message *gsup_msg)
{
	if (OSMO_GSUP_IS_MSGT_REQUEST(gsup_msg->message_type)) {
		vlr_tx_gsup_error_reply(vlr, gsup_msg,
					GMM_CAUSE_IMSI_UNKNOWN);
		LOGP(DVLR, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP request "
		     "of type 0x%02x\n",
		     gsup_msg->imsi, gsup_msg->message_type);
	} else if (OSMO_GSUP_IS_MSGT_ERROR(gsup_msg->message_type)) {
		LOGP(DVLR, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP error "
		     "of type 0x%02x, cause '%s' (%d)\n",
		     gsup_msg->imsi, gsup_msg->message_type,
		     get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
		     gsup_msg->cause);
	} else {
		LOGP(DVLR, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP response "
		     "of type 0x%02x\n",
		     gsup_msg->imsi, gsup_msg->message_type);
	}

	return -GMM_CAUSE_IMSI_UNKNOWN;
}

static int vlr_rx_gsup_purge_no_subscr(struct osmo_gsup_message *gsup_msg)
{
	if (OSMO_GSUP_IS_MSGT_ERROR(gsup_msg->message_type)) {
		LOGGSUPP(LOGL_NOTICE, gsup_msg,
			 "Purge MS has failed with cause '%s' (%d)\n",
			 get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
			 gsup_msg->cause);
		return -gsup_msg->cause;
	}
	LOGGSUPP(LOGL_INFO, gsup_msg, "Completing purge MS\n");
	return 0;
}

/* back-end function transmitting authentication. Caller ensures we have valid
 * tuple */
static int _vlr_sub_authenticate(struct vlr_subscriber *vsub,
				 enum vlr_sub_auth_state next_state)
{
	struct gsm_auth_tuple *at;
	unsigned int last_keyseq = GSM_KEY_SEQ_INVAL;

	if (vsub->last_tuple)
		last_keyseq = vsub->last_tuple->key_seq;

	/* Check if we have vectors available */
	at = vlr_sub_get_auth_tuple(vsub, last_keyseq);
	OSMO_ASSERT(at);

	/* Transmit auth req to subscriber */
	vsub->vlr.ops->tx_auth_req(vsub, at);
	vlr_sub_set_auth_state(vsub, next_state);
	vsub->last_tuple = at;

	return 0;
}

/* VLR internal call to request tuples from HLR */
static int vlr_sub_req_sai(struct vlr_subscriber *vsub,
		   	   const uint8_t *auts, const uint8_t *auts_rand)
{
	struct osmo_gsup_message gsup_msg = {0};
	int rc;

	gsup_msg.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST;

	switch (vsub->auth_state) {
	case VLR_SUB_AS_NEEDS_AUTH:
		break;
	case VLR_SUB_AS_NEEDS_RESYNC:
		gsup_msg.auts = auts;
		gsup_msg.rand = auts_rand;
		break;
	default:
		return -1;
	}

	rc = vlr_subscr_tx_gsup_message(vsub, &gsup_msg);

	switch (vsub->auth_state) {
	case VLR_SUB_AS_NEEDS_AUTH:
		vlr_sub_set_auth_state(vsub, VLR_SUB_AS_NEEDS_AUTH_WAIT_AI);
		break;
	case VLR_SUB_AS_NEEDS_RESYNC:
		vlr_sub_set_auth_state(vsub, VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC);
		break;
	}
	/* FIXME: do we want some timer? */

	return rc;
}

/* Update the subscriber with GSUP-received auth tuples */
static void vlr_sub_update_tuples(struct vlr_subscriber *vsub,
				 const struct osmo_gsup_message *gsup)
{
	unsigned int i;

	LOGVSUBP(LOGL_DEBUG, vsub, "Adding %zu auth tuples\n",
		 gsup->num_auth_vectors);

	if (gsup->num_auth_vectors) {
		memset(&vsub->auth_tuples, 0, sizeof(vsub->auth_tuples));
		for (i = 0; i < ARRAY_SIZE(vsub->auth_tuples); i++)
			vsub->auth_tuples[i].key_seq = GSM_KEY_SEQ_INVAL;
	}

	for (i = 0; i < gsup->num_auth_vectors; i++) {
		size_t key_seq = i;

		if (key_seq >= ARRAY_SIZE(vsub->auth_tuples)) {
			LOGVSUBP(LOGL_NOTICE, vsub,
				"Skipping auth tuple wih invalid cksn %zu\n",
				key_seq);
			continue;
		}
		vsub->auth_tuples[i].vec = gsup->auth_vectors[i];
		vsub->auth_tuples[i].key_seq = key_seq;
	}

	vsub->auth_tuples_updated = true;
	vsub->auth_error_cause = SGSN_ERROR_CAUSE_NONE;
}

/* Handle SendAuthInfo Result/Error from HLR */
static int vlr_sub_handle_sai_res(struct vlr_subscriber *vsub,
				  const struct osmo_gsup_message *gsup)
{
	switch (gsup->message_type) {
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT:
		vlr_sub_update_tuples(vsub, gsup);
		switch (vsub->auth_state) {
		case VLR_SUB_AS_NEEDS_AUTH_WAIT_AI:
			_vlr_sub_authenticate(vsub, VLR_SUB_AS_WAIT_RESP);
			break;
		case VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC:
			_vlr_sub_authenticate(vsub, VLR_SUB_AS_WAIT_RESP_RESYNC);
			break;
		default:
			LOGVSUBP(LOGL_ERROR, vsub, "SendAuthInfo.res in invalid "
				"state %s\n",
				get_value_string(vlr_sub_auth_state_names,
						 vsub->auth_state));
			break;
		}
		break;
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR:
		/* FIXME: differentiate real error and IMSI unknown in HLR */
		break;
	}

	return 0;
}

static void vlr_sub_gsup_insert_data(struct vlr_subscriber *vsub,
					struct osmo_gsup_message *gsup_msg)
{
	unsigned idx;
	int rc;

	if (gsup_msg->msisdn_enc) {
		if (gsup_msg->msisdn_enc_len > sizeof(vsub->msisdn)) {
			LOGP(DVLR, LOGL_ERROR, "MSISDN too long (%zu)\n",
				gsup_msg->msisdn_enc_len);
			sdata->msisdn_len = 0;
		} else {
			memcpy(sdata->msisdn, gsup_msg->msisdn_enc,
				gsup_msg->msisdn_enc_len);
			sdata->msisdn_len = gsup_msg->msisdn_enc_len;
		}
	}

	if (gsup_msg->hlr_enc) {
		if (gsup_msg->hlr_enc_len > sizeof(sdata->hlr)) {
			LOGP(DVLR, LOGL_ERROR, "HLR-Number too long (%zu)\n",
				gsup_msg->hlr_enc_len);
			sdata->hlr_len = 0;
		} else {
			memcpy(sdata->hlr, gsup_msg->hlr_enc,
				gsup_msg->hlr_enc_len);
			sdata->hlr_len = gsup_msg->hlr_enc_len;
		}
	}

	if (gsup_msg->pdp_info_compl) {
		rc = vlr_sub_pdp_data_clear(vsub);
		if (rc > 0)
			LOGP(DVLR, LOGL_INFO, "Cleared existing PDP info\n");
	}

	for (idx = 0; idx < gsup_msg->num_pdp_infos; idx++) {
		struct osmo_gsup_pdp_info *pdp_info = &gsup_msg->pdp_infos[idx];
		size_t ctx_id = pdp_info->context_id;
		struct sgsn_subscriber_pdp_data *pdp_data;

		if (pdp_info->apn_enc_len >= sizeof(pdp_data->apn_str)-1) {
			LOGVSUBP(LOGL_ERROR, vsub,
			     "APN too long, context id = %zu, APN = %s\n",
			     ctx_id, osmo_hexdump(pdp_info->apn_enc,
						  pdp_info->apn_enc_len));
			continue;
		}

		if (pdp_info->qos_enc_len > sizeof(pdp_data->qos_subscribed)) {
			LOGVSUBP(LOGL_ERROR, vsub,
				"QoS info too long (%zu)\n",
				pdp_info->qos_enc_len);
			continue;
		}

		LOGVSUBP(LOGL_INFO, vsub,
		     "Will set PDP info, context id = %zu, APN = %s\n",
		     ctx_id, osmo_hexdump(pdp_info->apn_enc, pdp_info->apn_enc_len));

		/* Set PDP info [ctx_id] */
		pdp_data = vlr_sub_pdp_data_get_by_id(vsub, ctx_id);
		if (!pdp_data) {
			pdp_data = vlr_sub_pdp_data_alloc(vsub);
			pdp_data->context_id = ctx_id;
		}

		OSMO_ASSERT(pdp_data != NULL);
		pdp_data->pdp_type = pdp_info->pdp_type;
		gprs_apn_to_str(pdp_data->apn_str,
				pdp_info->apn_enc, pdp_info->apn_enc_len);
		memcpy(pdp_data->qos_subscribed, pdp_info->qos_enc, pdp_info->qos_enc_len);
		pdp_data->qos_subscribed_len = pdp_info->qos_enc_len;
	}
}


/* Handle InsertSubscrData Result from HLR */
static int vlr_sub_handle_isd_req(struct vlr_subscriber *vsub,
				  const struct osmo_gsup_message *gsup)
{
	struct osmo_gsup_message gsup_reply = {0};

	vlr_sub_gsup_insert_data(vsub, gsup_msg);

	vsub->authorized = 1;
	vsub->auth_error_cause = SGSN_ERROR_CAUSE_NONE;
	vsub->flags |= GPRS_SUBSCRIBER_ENABLE_PURGE;
	vsub->vlr.ops->subscr_update(vsub);

	gsup_reply.message_type = OSMO_GSUP_MSGT_INSERT_DATA_RESULT;
	return vlr_subscr_tx_gsup_message(subscr, &gsup_reply);
}

/* Handle UpdateLocation Result from HLR */
static int vlr_sub_handle_lu_res(struct vlr_subscriber *vsub,
				 const struct osmo_gsup_message *gsup)
{
	/* contrary to MAP, we allow piggy-backing subscriber data onto the
	 * UPDATE LOCATION RESULT, and don't mandate the use of a separate
	 * nested INSERT SUBSCRIBER DATA transaction */
	vlr_sub_gsup_insert_data(vsub, gsup);
	vsub->authorized = 1;
	vsub->auth_error_cause = SGSN_ERROR_CAUSE_NONE;
	vsub->flags |= GPRS_SUBSCRIBER_ENABLE_PURGE;
	vsub->vlr.ops->subscr_update(vsub);

	return 0;
}

/* Handle UpdateLocation Result from HLR */
static int vlr_sub_handle_lu_err(struct vlr_subscriber *vsub,
				 const struct osmo_gsup_message *gsup)
{
	int cause_err = check_cause(gsup->cause);

	LOGVSUBP(LOGL_DEBUG, vsub, "UpdateLocation failed; gmm_cause: %s\n",
		 get_value_string(gsm48_gmm_cause_names, gsup->cause));
	vsub->authorized = 0;
	vsub->auth_error_cause = gsup->cause;
	vsub->vlr.ops->tx_lu_rej(vsub, gsup->cause);

	return 0;
}

static int vlr_sub_handle_cancel_req(struct vlr_subscriber *vsub,
				     struct osmo_gsup_message *gsup_msg)
{
	struct osmo_gsup_message gsup_reply = {0};
	int is_update_procedure = !gsup_msg->cancel_type ||
		gsup_msg->cancel_type == OSMO_GSUP_CANCEL_TYPE_UPDATE;

	LOGVSUBP(LOGL_INFO, vsub, "Cancelling MS subscriber (%s)\n",
		 is_update_procedure ?
		 "update procedure" : "subscription withdraw");

	gsup_reply.message_type = OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT;
	vlr_sub_tx_gsup_message(vsub, &gsup_reply);

	if (is_update_procedure)
		vsub->auth_error_cause = SGSN_ERROR_CAUSE_NONE;
	else
		/* Since a withdraw cause is not specified, just abort the
		 * current attachment. The following re-attachment should then
		 * be rejected with a proper cause value.
		 */
		vsub->auth_error_cause = GMM_CAUSE_IMPL_DETACHED;

	vlr_sub_cancel(vsub);

	return 0;
}

static int vlr_sub_handle_upd_loc_res(struct vlr_subscriber *vsub,
				      struct osmo_gsup_message *gsup_msg)
{
	/* contrary to MAP, we allow piggy-backing subscriber data onto
	 * the UPDATE LOCATION RESULT, and don't mandate the use of a
	 * separate nested INSERT SUBSCRIBER DATA transaction */
	vlr_sub_gsup_insert_data(vsub, gsup_msg);

	subscr->authorized = 1;
	vsub->auth_error_cause = SGSN_ERROR_CAUSE_NONE;

	subscr->flags |= GPRS_SUBSCRIBER_ENABLE_PURGE;

	vsub->vlr.ops->subscr_update(vsub);
	return 0;
}


/* Incoming handler for GSUP from HLR */
static int vlr_gsupc_read_cb(struct gprs_gsup_client *gsupc, struct msgb *msg)
{
	struct vlr_instance *vlr = (struct vlr_instance *) gsupc->data;
	struct vlr_subscriber *vsub;
	struct osmo_gsup_message gsup;
	int rc;

	rc = osmo_gsup_decode(msgb_l2(msg), msgb_l2len(msg), &gsup);
	if (rc < 0) {
		LOGP(DVLR, LOGL_ERROR,
			"decoding GSUP message fails with error '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, -rc), -rc);
		return rc;
	}

	if (gsup.imsi[0]) {
		LOGP(DVLR, LOGL_ERROR, "Missing IMSI in GSUP message\n");
		if (OSMO_GSUP_IS_MSGT_REQUEST(gsup.message_type))
			vlr_tx_gsup_error_reply(vlr, &gsup,
						GMM_CAUSE_INV_MAND_INFO);
		return -GMM_CAUSE_INV_MAND_INFO;
	}

	vsub = vlr_subscr_find_by_imsi(vlr, gsup.imsi);
	if (!vsub) {
		switch (gsup.message_type) {
		case OSMO_GSUP_MSGT_PURGE_MS_RESULT:
		case OSMO_GSUP_MSGT_PURGE_MS_ERROR:
			return vlr_rx_gsup_purge_no_subscr(vlr, &gsup);
		default:
			return vlr_rx_gsup_unknown_imsi(vlr, &gsup);
		}
	}

	switch (gsup.message_type) {
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT:
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR:
		rc = vlr_sub_handle_sai_res(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_INSERT_DATA_REQUEST:
		rc = vlr_sub_handle_isd_req(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_REQUEST:
		rc = vlr_sub_handle_cancel_req(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT:
		rc = vlr_sub_handle_lu_res(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR:
		rc = vlr_sub_handle_lu_err(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_PURGE_MS_ERROR:
	case OSMO_GSUP_MSGT_PURGE_MS_RESULT:
	case OSMO_GSUP_MSGT_DELETE_DATA_REQUEST:
		LOGVSUBP(LOGL_ERROR, vsub,
			"Rx GSUP msg_type=%d not yet implemented\n",
			gsup.message_type);
		rc = -GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL;
		break;
	default:
		LOGVSUBP(LOGL_ERROR, vsub,
			"Rx GSUP msg_type=%d not valid at VLR/SGSN side\n",
			gsup.message_type);
		rc = -GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL;
		break;
	}

	return rc;
}

/***********************************************************************
 * User API (for SGSN/MSC code)
 ***********************************************************************/

/* Start Procedure Authenticate_VLR (TS 23.012 Ch. 4.1.2.2) */
int vlr_sub_authenticate(struct vlr_subscriber *vsub)
{
	struct gsm_auth_tuple *at;
	unsigned int last_keyseq = GSM_KEY_SEQ_INVAL;

	if (vsub->last_tuple)
		last_keyseq = vsub->last_tuple->key_seq;

	/* Check if we have vectors available */
	at = vlr_sub_get_auth_tuple(vsub, last_keyseq);
	if (!at) {
		vlr_sub_req_sai(vsub, NULL, NULL);
	} else {
		/* Transmit auth req to subscriber */
		_vlr_sub_authenticate(vsub, VLR_SUB_AS_WAIT_RESP);
	}
	return 0;
}

/* Receive Authentication Failure from Subscriber */
int vlr_sub_rx_auth_fail(struct vlr_subscriber *vsub, const uint8_t *auts)
{
	switch (vsub->auth_state) {
	case VLR_SUB_AS_WAIT_RESP:
		vlr_sub_set_auth_state(vsub, VLR_SUB_AS_NEEDS_RESYMC);
		if (!vsub->last_tuple)
			break;
		vlr_sub_req_sai(vsub, auts, vsub->last_tuple->vec.rand);
		break;
	case VLR_SUB_AS_WAIT_RESP_RESYNC:
		/* Failure despite alredy re-synced: Abort! */
		vlr_sub_set_auth_state(vsub, VLR_SUB_AS_AUTH_FAILED);
		break;
	default:
		return -1;
	}
	return 0;
}

static bool check_auth_resp(struct vlr_subscriber *vsub, bool is_r99,
			    bool is_utran, const uint8_t *res,
			    uint8_t res_len)
{
	struct gsm_auth_tuple *at = vsub->last_tuple;
	struct osmo_auth_vector *vec = &at->vec;
	OSMO_ASSERT(at);

	/* RES must be present and at leat 32bit */
	if (!res || res_len < 4)
		goto out_false;

	if (is_r99 && vec->auth_types & OSMO_AUTH_TYPE_UMTS) {
		/* We have a R99 capable UE and have a UMTS AKA capable USIM.
		 * However, the ME may still chose to only perform GSM AKA, as
		 * long as the bearer is GERAN */
		if (is_utran && res_len != vec->res_len)
			goto out_false;
	}

	if (res_len == vec->res_len && !memcmp(res, vec->res, res_len)) {
		/* We have established a UMTS Security Context */
		vsub->sec_ctx = VLR_SEC_CTX_UMTS;
		return true;
	} else if (res_len == 4 && !memcmp(res, vec->sres, 4)) {
		/* We have establieshed a GSM Security Context */
		vsub->sec_ctx = VLR_SEC_CTX_GSM;
		return true;
	}

out_false:
	vsub->sec_ctx = VLR_SEC_CTX_NONE;
	return false;
}

/* Receive Authentication Response from MS */
int vlr_sub_rx_auth_resp(struct vlr_subscriber *vsub, bool is_r99,
			 bool is_utran, const uint8_t *res, uint8_t res_len)
{
	return check_auth_resp(vsub, is_r99, is_utran, res, res_len);
	/* FIXME: Request ID if IMSI was resolved by TMSI? */
}

#if 0
/***********************************************************************
 * Location updating, TS 23.012 Chapter 4.1.2.1
 ***********************************************************************/

static const struct value_string vlr_sub_lu_state_names[] = {
	{ VLR_SUB_LS_WAIT_PVLR,	"WAIT-ID-PREV-VLR" },
	{ VLR_SUB_LS_WAIT_AUTH,	"WAIT-AUTH" },
	{ VLR_SUB_LS_WAIT_IMSI,	"WAIT-IMSI" },
	{ VLR_SUB_LS_WAIT_HLR_UPD, "WAIT-HLR-UPD" },
	{ VLR_SUB_LS_WAIT_IMEI_TMSI, "WAIT-IMEI (new TMSI)" },
	{ VLR_SUB_LS_WAIT_IMEI,	"WAIT-IMEI" },
};

/* change the LU state of given VLR subscriber */
static void vlr_sub_set_lu_state(struct vlr_subscriber *vsub,
				 enum vlr_sub_lu_state astate)
{
	DEBUGP(DVLR, "%s: lu_state %s -> ", vlr_sub_name(vsub),
		get_value_string(vlr_sub_lu_state_names, vsub->lu_state));
	DEBUGPC(DVLR, "%s\n",
		get_value_string(vlr_sub_lu_state_names, astate));
	vsub->lu_state = astate;
}

/* 4.1.2.1 End of Authenticate_VLR */
static int vlr_loc_upd_auth_compl(struct vlr_subscriber *vsub)
{
	if (pass) {
		vlr_loc_upd_post_auth(vsub);
	} else {
		/* FIXME: Differentiate based on result cause */
	}
}

/* 4.1.2.1 Node 4 */
static void vlr_loc_upd_node_4(struct vlr_subscriber *vsub)
{
	if (hlr_unknown) {
		/* Delete subscriber record */
		/* LU REJ: Roaming not allowed */
		vlr->ops.tx_lu_rej(vsub, cause);
	} else {
		/* Update_HLR_VLR */
		vlr_sub_set_lu_state(vsub, VLR_SUB_LS_WAIT_HLR_UPD);
	}
}

/* 4.1.2.1 Node B */
static void vlr_loc_upd_node_b(struct vlr_subscriber *vsub)
{
	if (0) { /* IMEISV or PgA to send */
		vlr_loc_upd_node_4(vsub);
	} else {
		/* Location_Update_Completion */
		vlr_loc_upd_compl(vsub);
	}
}

/* 4.1.2.1 after Authentication successful (or no auth rqd) */
static void vlr_loc_upd_post_auth(struct vlr_subscriber *vsub)
{
	vsub->conf_by_radio_contact_ind = true;
	/* FIXME: Update LAI */
	vsub->dormant_ind = false;
	vsub->cancel_loc_ind = false;
	if (hlr_update_needed) {
		vlr_loc_upd_node_4(vsub);
	} else {
		/* TODO: ADD Support */
		/* TODO: Node A: PgA Support */
		vlr_loc_upd_node_b(vsub);
	}
}

/* 4.2.1.3 after VLR_IMEI_CHECK completes */
static void vlr_loc_upd_compl_post_imei_check(struct vlr_subscriber *vsub)
{
	switch (vsub->lu_state) {
	case VLR_SUB_LS_WAIT_IMEI_TMSI:
		if (success) {
			/* Tx New TMSI */
			/* Tx LU ACK */
			vsub->vlr.ops.tx_lu_ack(vsub);
			/* Wait for TMSI conf */
			/* Rx Forward new TMSI ack */
			vlr_sub_set_lu_state(vsub, VLR_SUB_LS_DONE);
		}
		break;
	case VLR_SUB_LS_WAIT_IMEI:
		if (success) {
			/* Tx LU ACK */
			vsub->vlr.ops.tx_lu_ack(vsub);
			vlr_sub_set_lu_state(vsub, VLR_SUB_LS_DONE);
		}
		break;
	default:
		LOGVSUBP(LOGL_ERROR, "post_imei_check in state %s\n",
			get_value_string(vlr_lu_state_names, vsub->lu_state));
		break;
	}
}

/* TS 23.012 Chapter 4.2.1.3 */
static void vlr_loc_upd_compl(struct vlr_subscriber *vsub)
{
	/* TODO: National Roaming restrictions? */
	/* TODO: Roaming restriction due to unsupported feature in subscriber
	 * data? */
	/* TODO: Regional subscription restriction? */
	/* TODO: Administrative restriction of subscribres' access feature? */
	/* TODO: AccessRestrictuionData parameter available? */
	/* TODO: AccessRestrictionData permits RAT? */
	/* Node 1 */
	/* TODO: Autonomous CSG supported in VPLMN and allowed by HPLMN? */
	/* TODO: Hybrid Cel / CSG Cell */
	/* Node 2 */
	vsub->la_allowed = true;
	vsub->imsi_detached = false;
	vlr_sub_present_in_vlr(vsub);
	/* TODO: trace */
	if (vlr->cfg.alloc_tmsi) {
		/* Set Ciphering Mode */
		vlr->ops.set_ciph_mode(vsub);
		/* FIXME: wait for completion? SDL is wrong? */
		if (vlr->cfg.check_imei_rqd) {
			/* TODO: Check IMEI VLR */
			vlr_sub_set_lu_state(vsub, VLR_SUB_LS_WAIT_IMEI_TMSI);
		} else {
			/* FIXME: New TMSI.ind to MSC */
			/* Update Location Area Ack */
			vsub->vlr.ops.tx_lu_ack(vsub);
			/* FIXME: WAIT_FOR_TMSI_Cnf */
			/* FIXME: Rx Forard new TMSI ack
			vlr_sub_set_lu_state(vsub, VLR_SUB_LS_DONE);
		}
	} else {
		if (vlr->cfg.check_imei_rqd) {
			/* TODO: Check IMEI VLR */
			vlr_sub_set_lu_state(vsub, VLR_SUB_LS_WAIT_IMEI);
		} else {
			vsub->vlr.ops.tx_lu_ack(vsub);
			vlr_sub_set_lu_state(vsub, VLR_SUB_LS_DONE);
		}
	}
}

/* 4.1.2.1: Subscriber (via MSC/SGSN) requests location update */
int vlr_loc_update(struct vlr_instance *vlr, uint32_t tmsi,
		   const char *imsi, old_lai, new_lai)
{
	struct vlr_subscriber *vsub;	/* FIXME caller/callee allocated? */
	bool lai_in_this_vlr = true;	/* FIXME */

	/* TODO: PUESBINE related handling */

	if (!imsi) {
		/* TMSI was used */
		/* Is previous LAI in this VLR? */
		if (!lai_in_this_vlr(old_lai)) {
			vsub = vlr_sub_alloc(vlr);
			vsub->tmsi = tmsi;	/* FIXME: what if clash? */
			vsub->sub_dataconf_by_hlr_ind = false;
#if 0
			/* FIXME: check previous VLR, (3) */
			vlr_sub_set_lu_state(vsub, VLR_SUB_LS_WAIT_PVLR);
#endif
			goto node2;
		} else {
			/* Is TMSI known */
			vsub = vlr_sub_find_by_tmsi(tmsi);
			if (!vsub) {
				vsub = vlr_sub_alloc(vlr);
				vsub->tmsi = tmsi;	/* FIXME: what if clash? */
				vsub->sub_dataconf_by_hlr_ind = false;
				goto node2;
			} else {
				/* We cannot have MSC area change, as the VLR
				 * serves only one MSC */
				goto node1;
			}
		}
	} else {
		/* IMSI was used */
		/* Is subscriber known in VLR? */
		vsub = vlr_sub_find_by_imsi(vlr, imsi);
		if (!vsub) {
			vsub = vlr_sub_alloc(vlr);
			strncpy(vsub->imsi, imsi, sizeof(vsub->imsi));
			vsub->imsi[sizeof(vsub->imsi)-1] = '\0';
		}
		vsub->sub_dataconf_by_hlr_ind = false;
		goto node1;
	}

	return 0;

node1:
	if (auth_required) {
		/* Authenticate_VLR */
		vlr_sub_set_lu_state(vsub, VLR_SUB_LS_WAIT_AUTH);
		vlr_sub_authenticate(vsub);
	} else {
		/* no need for authentication */
		vlr_sub_post_auth(vsub);
	}

	return 0;

node2:
	/* Obtain_IMSI_VLR */
	vlr->ops.obtain_imsi(vsub);
	vlr_sub_set_lu_state(vsub, VLR_SUB_LS_WAIT_IMSI);
	goto node1;
}
#endif
