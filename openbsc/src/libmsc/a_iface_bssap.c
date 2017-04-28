/* (C) 2017 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sccp/sccp_types.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/a_iface_bssap.h>
#include <openbsc/iu.h>
#include <openbsc/osmo_msc.h>

/* Addresses of all BSCs which have been registered to this MSC */
static LLIST_HEAD(bsc_addr_list);

/*
 * Helper functions to lookup and allocate subscribers
 */

/* Allocate a new subscriber connection */
static struct gsm_subscriber_connection *subscr_conn_allocate_a(struct gsm_network *network, struct ue_conn_ctx *ue,
								uint16_t lac, struct osmo_sccp_user *scu, int conn_id)
{
	struct gsm_subscriber_connection *conn;

	LOGP(DMSC, LOGL_NOTICE, "Allocating A-Interface subscriber conn: lac %i, conn_id %i\n", lac, ue->conn_id);

	conn = talloc_zero(ue, struct gsm_subscriber_connection);
	if (!conn)
		return NULL;

	conn->network = network;
	conn->via_ran = RAN_GERAN_A;
	conn->iu.ue_ctx = ue;
	conn->iu.ue_ctx->rab_assign_addr_enc = network->iu.rab_assign_addr_enc;
	conn->lac = lac;

	conn->a.conn_id = conn_id;
	conn->a.scu = scu;

	llist_add_tail(&conn->entry, &network->subscr_conns);
	LOGP(DMSC, LOGL_NOTICE, "A-Interface subscriber connection successfully allocated!\n");
	return conn;
}

/* Return an existing A subscriber connection record for the given
 * connection IDs, or return NULL if not found. */
struct gsm_subscriber_connection *subscr_conn_lookup_a(struct gsm_network *network, int conn_id)
{
	struct gsm_subscriber_connection *conn;

	DEBUGP(DMSC, "Looking for A subscriber: conn_id %i\n", conn_id);

	/* FIXME: log_subscribers() is defined in iucs.c as static inline, if
	 * maybe this function should be public to reach it from here? */
	/* log_subscribers(network); */

	llist_for_each_entry(conn, &network->subscr_conns, entry) {
		if (conn->via_ran == RAN_GERAN_A && conn->a.conn_id == conn_id) {
			DEBUGP(DIUCS, "Found A subscriber for conn_id %i\n", conn_id);
			return conn;
		}
	}
	DEBUGP(DMSC, "No A subscriber found for conn_id %i\n", conn_id);
	return NULL;
}

/*
 * BSSMAP handling for UNITDATA
 */

/* Endpoint to handle BSSMAP reset */
static void bssmap_handle_reset(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg)
{
	struct a_bsc_addr *addr;
	struct a_bsc_addr *known_addr;
	bool addr_unknown = true;

	LOGP(DMSC, LOGL_NOTICE, "Rx RESET from BSC %s\n", osmo_sccp_addr_dump(a_conn_info->calling_addr));
	osmo_sccp_tx_unitdata_msg(scu, a_conn_info->called_addr, a_conn_info->calling_addr, gsm0808_create_reset_ack());

	/* Check if we know this BSC already, if yes, refresh its item */
	llist_for_each_entry(known_addr, &bsc_addr_list, list) {
		if (memcmp(&known_addr->calling_addr, a_conn_info->calling_addr, sizeof(*a_conn_info->calling_addr)) == 0) {
			LOGP(DMSC, LOGL_NOTICE, "This BSC is already known to this MSC, refreshing its list item\n");
			llist_del(&known_addr->list);
			talloc_free(known_addr);
			addr_unknown = false;
			break;
		}
	}
	if (addr_unknown)
		LOGP(DMSC, LOGL_NOTICE, "This BSC is not known to this MSC yet, adding it to list\n");

	addr = talloc_zero(NULL, struct a_bsc_addr);
	memcpy(&addr->calling_addr, a_conn_info->calling_addr, sizeof(addr->calling_addr));
	memcpy(&addr->called_addr, a_conn_info->called_addr, sizeof(addr->called_addr));
	addr->scu = scu;
	llist_add(&addr->list, &bsc_addr_list);

	msgb_free(msg);
}

/* Handle UNITDATA BSSMAP messages */
static void bssmap_rcvmsg_udt(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg)
{
	/* Note: When in the MSC role, RESET ACK is the only valid message that
	 * can be received via UNITDATA */

	if (msgb_l3len(msg) < 1) {
		LOGP(DMSC, LOGL_NOTICE, "Error: No data received -- discarding message!\n");
		return;
	}

	LOGP(DMSC, LOGL_NOTICE, "Rx BSC UDT BSSMAP %s\n", gsm0808_bssmap_name(msg->l3h[0]));

	switch (msg->l3h[0]) {
	case BSS_MAP_MSG_RESET:
		bssmap_handle_reset(scu, a_conn_info, msg);
		break;
	default:
		LOGP(DMSC, LOGL_NOTICE, "Unimplemented message format: %s -- message discarded!\n",
		     gsm0808_bssmap_name(msg->l3h[0]));
		msgb_free(msg);
	}
}

/* Handle incoming connection less data messages */
void msc_handle_udt(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg)
{
	/* Note: The only valid message type that can be received
	 * via UNITDATA are BSS Management messages */
	struct bssmap_header *bs;

	LOGP(DMSC, LOGL_NOTICE, "Rx BSC UDT: %s\n", osmo_hexdump(msgb_l2(msg), msgb_l2len(msg)));

	if (msgb_l2len(msg) < sizeof(*bs)) {
		LOGP(DMSC, LOGL_ERROR, "Error: Header is too short -- discarding message!\n");
		msgb_free(msg);
		return;
	}

	bs = (struct bssmap_header *)msgb_l2(msg);
	if (bs->length < msgb_l2len(msg) - sizeof(*bs)) {
		LOGP(DMSC, LOGL_ERROR, "Error: Message is too short -- discarding message!\n");
		msgb_free(msg);
		return;
	}

	switch (bs->type) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		msg->l3h = &msg->l2h[sizeof(struct bssmap_header)];
		bssmap_rcvmsg_udt(scu, a_conn_info, msg);
		break;
	default:
		LOGP(DMSC, LOGL_ERROR,
		     "Error: Unimplemented message type: %s -- message discarded!\n", gsm0808_bssmap_name(bs->type));
		msgb_free(msg);
	}
}

/*
 * BSSMAP handling for connection oriented data
 */

/* Endpoint to handle BSSMAP clear request */
static int bssmap_handle_clear_rqst(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg)
{
	struct gsm_network *network = a_conn_info->network;
	struct tlv_parsed tp;
	int rc;
	struct msgb *msg_resp;
	uint8_t cause;
	struct gsm_subscriber_connection *conn;

	LOGP(DMSC, LOGL_NOTICE, "BSC requested to clear connection (conn_id=%i)\n", a_conn_info->conn_id);

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CAUSE)) {
		LOGP(DMSC, LOGL_ERROR, "Cause code is missing -- discarding message!\n");
		goto fail;
	}
	cause = TLVP_VAL(&tp, GSM0808_IE_CAUSE)[0];

	/* Respond with clear command */
	msg_resp = gsm0808_create_clear_command(GSM0808_CAUSE_CALL_CONTROL);
	rc = osmo_sccp_tx_data_msg(scu, a_conn_info->conn_id, msg_resp);

	/* If possible, inform the MSC about the clear request */
	conn = subscr_conn_lookup_a(network, a_conn_info->conn_id);
	if (!conn)
		goto fail;
	msc_clear_request(conn, cause);

	msgb_free(msg);
	return rc;

fail:
	msgb_free(msg);
	return -EINVAL;
}

/* Endpoint to handle BSSMAP clear complete */
static int bssmap_handle_clear_complete(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg)
{
	int rc;

	LOGP(DMSC, LOGL_NOTICE, "Releasing connection (conn_id=%i)\n", a_conn_info->conn_id);
	rc = osmo_sccp_tx_disconn(scu, a_conn_info->conn_id,
				  a_conn_info->called_addr, SCCP_RELEASE_CAUSE_END_USER_ORIGINATED);

	msgb_free(msg);
	return rc;
}

/* Endpoint to handle layer 3 complete messages */
static int bssmap_handle_l3_compl(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg)
{
	struct tlv_parsed tp;
	struct {
		uint8_t ident;
		struct gsm48_loc_area_id lai;
		uint16_t ci;
	} __attribute__ ((packed)) lai_ci;
	uint16_t mcc;
	uint16_t mnc;
	uint16_t lac;
	uint8_t data_length;
	const uint8_t *data;
	int rc;

	struct gsm_network *network = a_conn_info->network;
	struct ue_conn_ctx *ue;
	struct gsm_subscriber_connection *conn;

	LOGP(DMSC, LOGL_NOTICE, "BSC has completed layer 3 connection (conn_id=%i)\n", a_conn_info->conn_id);

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CELL_IDENTIFIER)) {
		LOGP(DMSC, LOGL_ERROR, "Mandatory CELL IDENTIFIER not present -- discarding message!\n");
		goto fail;
	}
	if (!TLVP_PRESENT(&tp, GSM0808_IE_LAYER_3_INFORMATION)) {
		LOGP(DMSC, LOGL_ERROR, "Mandatory LAYER 3 INFORMATION not present -- discarding message!\n");
		goto fail;
	}

	/* Parse Cell ID element */
	/* FIXME: Encapsulate this in a parser/generator function inside
	 * libosmocore, add support for all specified cell identification
	 * discriminators (see 3GPP ts 3.2.2.17 Cell Identifier) */
	data_length = TLVP_LEN(&tp, GSM0808_IE_CELL_IDENTIFIER);
	data = TLVP_VAL(&tp, GSM0808_IE_CELL_IDENTIFIER);
	if (sizeof(lai_ci) != data_length) {
		LOGP(DMSC, LOGL_ERROR,
		     "Unable to parse element CELL IDENTIFIER (wrong field length) -- discarding message!\n");
		goto fail;
	}
	memcpy(&lai_ci, data, sizeof(lai_ci));
	if (lai_ci.ident != CELL_IDENT_WHOLE_GLOBAL) {
		LOGP(DMSC, LOGL_ERROR,
		     "Unable to parse element CELL IDENTIFIER (wrong cell identification discriminator) -- discarding message!\n");
		goto fail;
	}
	if (gsm48_decode_lai(&lai_ci.lai, &mcc, &mnc, &lac) != 0) {
		LOGP(DMSC, LOGL_ERROR,
		     "Unable to parse element CELL IDENTIFIER (lai decoding failed) -- discarding message!\n");
		goto fail;
	}

	/* Parse Layer 3 Information element */
	/* FIXME: This is probably to hackish, compiler also complains "assignment discards ‘const’ qualifier..." */
	msg->l3h = TLVP_VAL(&tp, GSM0808_IE_LAYER_3_INFORMATION);
	msg->tail = msg->l3h + TLVP_LEN(&tp, GSM0808_IE_LAYER_3_INFORMATION);

	/* Create new subscriber context */
	ue = ue_conn_ctx_alloc(a_conn_info->calling_addr, a_conn_info->conn_id);
	conn = subscr_conn_allocate_a(network, ue, lac, scu, a_conn_info->conn_id);

	/* Handover location update to the MSC code */
	/* msc_compl_l3() takes ownership of dtap_msg
	 * message buffer */
	rc = msc_compl_l3(conn, msg, 0);
	if (rc == MSC_CONN_ACCEPT) {
		LOGP(DMSC, LOGL_NOTICE, "User has been accepted by MSC.\n");
		return 0;
	} else if (rc == MSC_CONN_REJECT)
		LOGP(DMSC, LOGL_NOTICE, "User has been rejected by MSC.\n");
	else
		LOGP(DMSC, LOGL_NOTICE, "User has been rejected by MSC (unknown error)\n");

	return -EINVAL;

fail:
	msgb_free(msg);
	return -EINVAL;
}

/* Endpoint to handle BSSMAP classmark update */
static int bssmap_classmark_upd(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg)
{
	struct gsm_network *network = a_conn_info->network;
	struct gsm_subscriber_connection *conn;
	struct tlv_parsed tp;
	const uint8_t *cm2 = NULL;
	const uint8_t *cm3 = NULL;
	uint8_t cm2_len = 0;
	uint8_t cm3_len = 0;

	conn = subscr_conn_lookup_a(network, a_conn_info->conn_id);
	if (!conn)
		goto fail;

	LOGP(DMSC, LOGL_NOTICE, "BSC sends clasmark update (conn_id=%i)\n", conn->a.conn_id);

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CLASSMARK_INFORMATION_T2)) {
		LOGP(DMSC, LOGL_ERROR, "Mandatory Classmark Information Type 2 not present -- discarding message!\n");
		goto fail;
	}

	cm2 = TLVP_VAL(&tp, GSM0808_IE_CLASSMARK_INFORMATION_T2);
	cm2_len = TLVP_LEN(&tp, GSM0808_IE_CLASSMARK_INFORMATION_T2);

	if (TLVP_PRESENT(&tp, GSM0808_IE_CLASSMARK_INFORMATION_T3)) {
		cm3 = TLVP_VAL(&tp, GSM0808_IE_CLASSMARK_INFORMATION_T3);
		cm3_len = TLVP_LEN(&tp, GSM0808_IE_CLASSMARK_INFORMATION_T3);
	}

	/* Inform MSC about the classmark change */
	msc_classmark_chg(conn, cm2, cm2_len, cm3, cm3_len);

	msgb_free(msg);
	return 0;

fail:
	msgb_free(msg);
	return -EINVAL;
}

/* Endpoint to handle BSSMAP cipher mode complete */
static int bssmap_ciph_compl(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg)
{
	/* FIXME: The field GSM0808_IE_LAYER_3_MESSAGE_CONTENTS is optional by
	 * means of the specification. So there can be messages without L3 info.
	 * In this case, the code will crash becrause msc_cipher_mode_compl()
	 * is not able to deal with msg = NULL and apperently
	 * msc_cipher_mode_compl() was never meant to be used without L3 data.
	 * This needs to be discussed further! */

	struct gsm_network *network = a_conn_info->network;
	struct gsm_subscriber_connection *conn;
	struct tlv_parsed tp;
	uint8_t alg_id = 1;

	conn = subscr_conn_lookup_a(network, a_conn_info->conn_id);
	if (!conn)
		goto fail;

	LOGP(DMSC, LOGL_NOTICE, "BSC sends cipher mode complete (conn_id=%i)\n", conn->a.conn_id);

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);

	if (TLVP_PRESENT(&tp, GSM0808_IE_CHOSEN_ENCR_ALG)) {
		alg_id = TLVP_VAL(&tp, GSM0808_IE_CHOSEN_ENCR_ALG)[0] - 1;
	}

	if (TLVP_PRESENT(&tp, GSM0808_IE_LAYER_3_MESSAGE_CONTENTS)) {
		msg->l3h = TLVP_VAL(&tp, GSM0808_IE_LAYER_3_MESSAGE_CONTENTS);
		msg->tail = msg->l3h + TLVP_LEN(&tp, GSM0808_IE_LAYER_3_MESSAGE_CONTENTS);
	} else {
		msgb_free(msg);
		msg = NULL;
	}

	/* Hand over cipher mode complete message to the MSC,
	 * msc_cipher_mode_compl() takes ownership for msg */
	msc_cipher_mode_compl(conn, msg, alg_id);

	return 0;
fail:
	msgb_free(msg);
	return -EINVAL;
}

/* Endpoint to handle BSSMAP cipher mode reject */
static int bssmap_ciph_rej(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg)
{
	struct gsm_network *network = a_conn_info->network;
	struct gsm_subscriber_connection *conn;
	struct tlv_parsed tp;
	uint8_t cause;

	conn = subscr_conn_lookup_a(network, a_conn_info->conn_id);
	if (!conn)
		goto fail;

	LOGP(DMSC, LOGL_NOTICE, "BSC sends cipher mode reject (conn_id=%i)\n", conn->a.conn_id);

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, BSS_MAP_MSG_CIPHER_MODE_REJECT)) {
		LOGP(DMSC, LOGL_ERROR, "Cause code is missing -- discarding message!\n");
		goto fail;
	}

	cause = TLVP_VAL(&tp, BSS_MAP_MSG_CIPHER_MODE_REJECT)[0];
	LOGP(DMSC, LOGL_NOTICE, "Cipher mode rejection cause: %i\n", cause);

	/* FIXME: Can we do something meaningful here? e.g. report to the
	 * msc code somehow that the cipher mode command has failed. */

	msgb_free(msg);
	return 0;
fail:
	msgb_free(msg);
	return -EINVAL;
}

/* Endpoint to handle BSSMAP assignment failure */
static int bssmap_ass_fail(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg)
{
	struct gsm_network *network = a_conn_info->network;
	struct gsm_subscriber_connection *conn;
	struct tlv_parsed tp;
	uint8_t cause;
	uint8_t *rr_cause_ptr = NULL;
	uint8_t rr_cause;

	conn = subscr_conn_lookup_a(network, a_conn_info->conn_id);
	if (!conn)
		goto fail;

	LOGP(DMSC, LOGL_NOTICE, "BSC sends assignment failure message (conn_id=%i)\n", conn->a.conn_id);

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CAUSE)) {
		LOGP(DMSC, LOGL_ERROR, "Cause code is missing -- discarding message!\n");
		goto fail;
	}
	cause = TLVP_VAL(&tp, GSM0808_IE_CAUSE)[0];

	if (TLVP_PRESENT(&tp, GSM0808_IE_RR_CAUSE)) {
		rr_cause = TLVP_VAL(&tp, GSM0808_IE_RR_CAUSE)[0];
		rr_cause_ptr = &rr_cause;
	}

	/* FIXME: In AoIP, the Assignment failure will carry also an optional
	 * Codec List (BSS Supported) element. It has to be discussed if we
	 * can ignore this element. If not, The msc_assign_fail() function
	 * call has to change. However msc_assign_fail() does nothing in the
	 * end. So probably we can just leave it as it is. Even for AoIP */

	/* Inform the MSC about the assignment failure event */
	msc_assign_fail(conn, cause, rr_cause_ptr);

	msgb_free(msg);
	return 0;
fail:
	msgb_free(msg);
	return -EINVAL;
}

/* Endpoint to handle sapi "n" reject */
static int bssmap_sapi_n_rej(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg)
{
	struct gsm_network *network = a_conn_info->network;
	struct gsm_subscriber_connection *conn;
	struct tlv_parsed tp;
	uint8_t dlci;

	conn = subscr_conn_lookup_a(network, a_conn_info->conn_id);
	if (!conn)
		goto fail;

	LOGP(DMSC, LOGL_NOTICE, "BSC sends sapi \"n\" reject message (conn_id=%i)\n", conn->a.conn_id);

	/* Note: The MSC code seems not to care about the cause code, but by
	 * the specification it is mandatory, so we check its presence. See
	 * also 3GPP TS 48.008 3.2.1.34 SAPI "n" REJECT */
	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CAUSE)) {
		LOGP(DMSC, LOGL_ERROR, "Cause code is missing -- discarding message!\n");
		goto fail;
	}

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_DLCI)) {
		LOGP(DMSC, LOGL_ERROR, "DLCI is missing -- discarding message!\n");
		goto fail;
	}
	dlci = TLVP_VAL(&tp, GSM0808_IE_DLCI)[0];

	/* Inform the MSC about the sapi "n" reject event */
	msc_sapi_n_reject(conn, dlci);

	msgb_free(msg);
	return 0;
fail:
	msgb_free(msg);
	return -EINVAL;
}

/* Endpoint to handle assignment complete */
static int bssmap_ass_compl(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg)
{
	struct gsm_network *network = a_conn_info->network;
	struct gsm_subscriber_connection *conn;

	conn = subscr_conn_lookup_a(network, a_conn_info->conn_id);
	if (!conn)
		goto fail;

	LOGP(DMSC, LOGL_NOTICE, "BSC sends assignment complete message (conn_id=%i)\n", conn->a.conn_id);

	/* Inform the MSC about the assignment completion event */
	msc_rx_sec_mode_compl(conn);

	msgb_free(msg);
	return 0;
fail:
	msgb_free(msg);
	return -EINVAL;
}

/* Handle incoming connection oriented BSSMAP messages */
static int bssmap_rcvmsg_dt1(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg)
{
	if (msgb_l3len(msg) < 1) {
		LOGP(DMSC, LOGL_NOTICE, "Error: No data received -- discarding message!\n");
		msgb_free(msg);
		return -1;
	}

	LOGP(DMSC, LOGL_NOTICE, "Rx MSC DT1 BSSMAP %s\n", gsm0808_bssmap_name(msg->l3h[0]));

	switch (msg->l3h[0]) {
	case BSS_MAP_MSG_CLEAR_RQST:
		return bssmap_handle_clear_rqst(scu, a_conn_info, msg);
		break;
	case BSS_MAP_MSG_CLEAR_COMPLETE:
		return bssmap_handle_clear_complete(scu, a_conn_info, msg);
		break;
	case BSS_MAP_MSG_COMPLETE_LAYER_3:
		return bssmap_handle_l3_compl(scu, a_conn_info, msg);
		break;
	case BSS_MAP_MSG_CLASSMARK_UPDATE:
		return bssmap_classmark_upd(scu, a_conn_info, msg);
		break;
	case BSS_MAP_MSG_CIPHER_MODE_COMPLETE:
		return bssmap_ciph_compl(scu, a_conn_info, msg);
		break;
	case BSS_MAP_MSG_CIPHER_MODE_REJECT:
		return bssmap_ciph_rej(scu, a_conn_info, msg);
		break;
	case BSS_MAP_MSG_ASSIGMENT_FAILURE:
		return bssmap_ass_fail(scu, a_conn_info, msg);
		break;
	case BSS_MAP_MSG_SAPI_N_REJECT:
		return bssmap_sapi_n_rej(scu, a_conn_info, msg);
		break;
	case BSS_MAP_MSG_ASSIGMENT_COMPLETE:
		return bssmap_ass_compl(scu, a_conn_info, msg);
		break;
	default:
		LOGP(DMSC, LOGL_ERROR, "Unimplemented msg type: %s\n", gsm0808_bssmap_name(msg->l3h[0]));
		msgb_free(msg);
		return -EINVAL;
	}

	return -EINVAL;
}

/* Endpoint to handle regular BSSAP DTAP messages */
static int dtap_rcvmsg(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg)
{
	struct gsm_network *network = a_conn_info->network;
	struct gsm_subscriber_connection *conn;

	conn = subscr_conn_lookup_a(network, a_conn_info->conn_id);
	if (!conn) {
		msgb_free(msg);
		return -EINVAL;
	}

	LOGP(DMSC, LOGL_NOTICE, "BSC sends layer 3 dtap (conn_id=%i)\n", conn->a.conn_id);

	/* msc_dtap expects the dtap payload in l3h */
	msg->l3h = msg->l2h + 3;

	/* Forward dtap payload into the msc,
	 * msc_dtap() takes ownership for msg */
	msc_dtap(conn, conn->a.conn_id, msg);

	return 0;
}

/* Handle incoming connection oriented messages */
int msc_handle_dt1(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg)
{
	if (msgb_l2len(msg) < sizeof(struct bssmap_header)) {
		LOGP(DMSC, LOGL_NOTICE, "The header is too short -- discarding message!\n");
		msgb_free(msg);
	}

	switch (msg->l2h[0]) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		msg->l3h = &msg->l2h[sizeof(struct bssmap_header)];
		return bssmap_rcvmsg_dt1(scu, a_conn_info, msg);
		break;
	case BSSAP_MSG_DTAP:
		return dtap_rcvmsg(scu, a_conn_info, msg);
		break;
	default:
		LOGP(DMSC, LOGL_ERROR, "Unimplemented BSSAP msg type: %s\n", gsm0808_bssap_name(msg->l2h[0]));
		msgb_free(msg);
		return -EINVAL;
	}

	return -EINVAL;
}

/* Get a list with all known BSCs */
struct llist_head *get_bsc_addr_list(void)
{
	return &bsc_addr_list;
}
