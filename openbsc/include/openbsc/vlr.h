#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <openbsc/gsm_data.h>

/* VLR subscriber authentication state */
enum vlr_sub_auth_state {
	/* subscriber needs to be autenticated */
	VLR_SUB_AS_NEEDS_AUTH,
	/* waiting for AuthInfo from HLR/AUC */
	VLR_SUB_AS_NEEDS_AUTH_WAIT_AI,
	/* waiting for response from subscriber */
	VLR_SUB_AS_WAIT_RESP,
	/* successfully authenticated */
	VLR_SUB_AS_AUTHENTICATED,
	/* subscriber needs re-sync */
	VLR_SUB_AS_NEEDS_RESYMC,
	/* waiting for AuthInfo with ReSync */
	VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC,
	/* waiting for response from subscr, resync case */
	VLR_SUB_AS_WAIT_RESP_RESYNC,
	/* waiting for IMSI from subscriber */
	VLR_SUB_AS_WAIT_ID_IMSI,
	/* authentication has failed */
	VLR_SUB_AS_AUTH_FAILED,
};

enum vlr_sub_lu_state {
	VLR_SUB_LS_WAIT_PVLR,	/* Waiting for ID from PVLR */
	VLR_SUB_LS_WAIT_AUTH,	/* Waiting for Authentication */
	VLR_SUB_LS_WAIT_IMSI,	/* Waiting for IMSI from MS */
	VLR_SUB_LS_WAIT_HLR_UPD,	/* Waiting for end of HLR update */
	VLR_SUB_LS_WAIT_IMEI_TMSI,/* Waiting for IMEI, TMSI allocated */
	VLR_SUB_LS_WAIT_IMEI,	/* Waiting for IMEI, no TMSI allocated */
};

enum vlr_sub_security_context {
	VLR_SEC_CTX_NONE,
	VLR_SEC_CTX_GSM,
	VLR_SEC_CTX_UMTS,
};


#define OSMO_LBUF_DECL(name, xlen) 		\
	struct {				\
		uint8_t buf[xlen];		\
		size_t len;			\
	} name

struct vlr_instance;

/* The VLR subscriber is the part of the GSM subscirber state in VLR (CS) or
 * SGSN (PS), particularly while interacting with the HLR via GSUP */
struct vlr_subscriber {
	struct llist_head list;
	struct vlr_instance *vlr;

	/* Data from HLR */
	char imsi[GSM23003_IMSI_MAX_DIGITS+1];		/* 2.1.1.1 */
	char msisdn[15+1];				/* 2.1.2 */
	OSMO_LBUF_DECL(hlr, 16);				/* 2.4.7 */
	uint32_t periodic_lu_timer;			/* 2.4.24 */
	uint32_t age_indicator;				/* 2.17.1 */

	/* Authentication Data */
	struct gsm_auth_tuple	auth_tuples[5];		/* 2.3.1-2.3.4 */
	enum vlr_sub_auth_state auth_state;
	struct gsm_auth_tuple *last_tuple;
	enum vlr_sub_security_context sec_ctx;

	char name[GSM_NAME_LENGTH];			/* proprietary */

	/* Data local to VLR is below */
	uint32_t tmsi;					/* 2.1.4 */

	/* some redundancy in information below? */
	struct cell_global_id cgi;			/* 2.4.16 */
	uint16_t lac;					/* 2.4.2 */

	char imeisv[GSM23003_IMEISV_NUM_DIGITS+1];	/* 2.2.3 */
	char imei[GSM23003_IMEISV_NUM_DIGITS+1];	/* 2.1.9 */
	bool imsi_detached_flag;			/* 2.7.1 */
	bool conf_by_radio_contact_ind;			/* 2.7.4.1 */
	bool sub_dataconf_by_hlr_ind;			/* 2.7.4.2 */
	bool loc_conf_in_hlr_ind;			/* 2.7.4.3 */
	bool dormant_ind;				/* 2.7.8 */
	bool cancel_loc_rx;				/* 2.7.8A */
	bool ms_not_reachable_flag;			/* 2.10.2 (MNRF) */

	/* PS (SGSN) specific parts */
	struct {
		struct llist_head pdp_list;
		uint8_t rac;
		uint8_t sac;
	} ps;
	/* VLR specific parts */
	struct {
	} cs;
};

struct vlr_ops {
	int (*tx_auth_req)(struct vlr_subscriber *vsub,
			   struct gsm_auth_tuple *at);
	int (*tx_auth_rej)(struct vlr_subscriber *vsub, uint8_t cause);
	void (*subscr_update)(struct vlr_subscriber *vsub);
};

struct vlr_instance {
	struct llist_head subscribers;
	struct gprs_gsup_client *gsup_client;
	struct vlr_ops ops;
};



