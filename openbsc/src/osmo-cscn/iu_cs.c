#include <openbsc/gsm_data.h>
#include <openbsc/iu.h>

/* Return an existing Iu-CS subscriber connection record for the given link and
 * connection IDs, or return NULL if not found. */
static struct gsm_subscriber_connection *subscr_conn_lookup_iu(struct gsm_network *network,
							       uint8_t link_id,
							       uint32_t conn_id)
{
	struct gsm_subscriber_connection *conn;
	llist_for_each_entry(conn, &network->subscr_conns, entry) {
		if (conn->via_iface != IFACE_IUCS)
			continue;
		if (conn->iu.link_id != link_id)
			continue;
		if (conn->iu.conn_id != conn_id)
			continue;
		return conn;
	}
	return NULL;
}

/* Receive MM/CC/... message from Iu-CS (SCCP user SAP).
 * msg->dst must reference a struct ue_conn_ctx. link_id identifies the SCTP
 * peer that sent the msg.
 *
 * For A-interface see libbsc/bsc_api.c gsm0408_rcvmsg(). */
int gsm0408_rcvmsg_iucs(struct gsm_network *network, struct msgb *msg, uint8_t link_id)
{
	int rc;
	struct ue_conn_ctx *ue_ctx;
	struct gsm_subscriber_connection *conn;

	ue_ctx = (struct ue_conn_ctx*)msg->dst;

	/* TODO: are there message types that could allow us to skip this
	 * search? */
	conn = subscr_conn_lookup_iu(network, link_id, ue_ctx->conn_id);

	if (conn) {
		/* if we already have a connection, handle DTAP.
		   gsm0408_dispatch() is aka msc_dtap() */

		/* Make sure we don't receive RR over Iu-CS; otherwise all
		 * messages handled by gsm0408_dispatch() are of interest (CC,
		 * MM, SMS, NS_SS, maybe even MM_GPRS and SM_GPRS). */
		struct gsm48_hdr *gh = msgb_l3(msg);
		uint8_t pdisc = gh->proto_discr & 0x0f;
		OSMO_ASSERT(pdisc != GSM48_PDISC_RR);

		gsm0408_dispatch(conn, msg);
	} else {
		/* allocate a new connection */

		/* TODO */

#if 0
		rc = BSC_API_CONN_POL_REJECT;
		conn = subscr_conn_allocate_iu(msg->lchan);
		if (!lchan->conn) {
			lchan_release(lchan, 1, RSL_REL_NORMAL);
			return -1;
		}

		/* fwd via bsc_api to send COMPLETE L3 INFO to MSC */
		rc = api->compl_l3(lchan->conn, msg, 0);

		if (rc != BSC_API_CONN_POL_ACCEPT) {
			lchan->conn->lchan = NULL;
			subscr_con_free(lchan->conn);
			lchan_release(lchan, 1, RSL_REL_NORMAL);
		}
#endif
	}

	return 0;
}

/* For A-interface see libbsc/bsc_api.c subscr_con_allocate() */
struct gsm_subscriber_connection *subscr_conn_allocate_iu(struct gsm_bts *bts)
	/* TODO "bts"? this is an hNodeB, really. */
{
	struct gsm_subscriber_connection *conn;

	conn = talloc_zero(bts->network, struct gsm_subscriber_connection);
	if (!conn)
		return NULL;

	conn->via_iface = IFACE_IUCS;
	conn->bts = bts;
	llist_add_tail(&conn->entry, &bts->network->subscr_conns);
	return conn;
}