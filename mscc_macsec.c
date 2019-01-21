/* Copyright (c) 2018 Microchip  */
#include <stdio.h>
#include <errno.h>
#include "internal.h"

#define INGR 0x38
#define EGR  0x3c
#define HOST 0x5
#define LINE 0x6

#define MACSEC_DISP_REG(ctx, d, a, b, v) \
	macsec_read_reg(ctx, a, b, v);       \
	printf("%-10s %-40s 0x%-10x 0x%-12x\n", ctx->devname, d, a, *v)

#define MACSEC_DISP_CNT(ctx, d, a, b, v) \
	macsec_read_reg(ctx, a, b, v);       \
	printf("%-40s %-12d\n", d, *v)

#define MAX_RECORDS 16
#define REV_B 1
#define MACSEC_BYPASS_TAG_ONE 1
#define MACSEC_BYPASS_TAG_TWO 2
#define MACSEC_VALIDATE_FRAMES_DISABLE 0
#define MACSEC_VALIDATE_FRAMES_CHECK   1
#define MACSEC_VALIDATE_FRAMES_STRICT  2

// Need to fix
static u8 macsec_ver = 1;
static u8 encoding_sa = 0;
static u8 always_include_sci = 1;

typedef struct {
	u64 out_pkts_protected;
	u64 out_pkts_encrypted;
} macsec_txsa_counters_t;

typedef struct {
	u64 in_pkts_ok;
	u64 in_pkts_invalid;
	u64 in_pkts_not_valid;
	u64 in_pkts_not_using_sa;
	u64 in_pkts_unused_sa;
	u64 in_pkts_unchecked;
	u64 in_pkts_delayed;
	u64 in_pkts_late;
} macsec_rxsa_counters_t;

typedef struct {
	u64 out_pkts_protected;
	u64 out_pkts_encrypted;
	u64 out_octets_protected;
	u64 out_octets_encrypted;
	u64 out_octets_untagged;
} macsec_txsc_counters_t;

typedef struct {
	u64 in_pkts_unchecked;
	u64 in_pkts_delayed;
	u64 in_pkts_late;
	u64 in_pkts_ok;
	u64 in_pkts_invalid;
	u64 in_pkts_not_valid;
	u64 in_pkts_not_using_sa;
	u64 in_pkts_unused_sa;
	u64 in_octets_validated;
	u64 in_octets_decrypted;
	u64 in_octets_validation_disabled; /* Note: Add new variable */
} macsec_rxsc_counters_t;

typedef struct {
	u64 in_pkts_untagged;
	u64 in_pkts_no_tag;
	u64 in_pkts_bad_tag;
	u64 in_pkts_unknown_sci;
	u64 in_pkts_no_sci;
	u64 in_pkts_overrun;
	u64 in_octets_validated;
	u64 in_octets_decrypted;
	u64 out_pkts_untagged;
	u64 out_pkts_too_long;
	u64 out_octets_protected;
	u64 out_octets_encrypted;
} macsec_secy_counters_t;

typedef struct {
	u64 if_in_octets;
	u64 if_in_pkts;
	u64 if_in_ucast_pkts;
	u64 if_in_multicast_pkts;
	u64 if_in_broadcast_pkts;
	u64 if_in_discards;
	u64 if_in_errors;
	u64 if_out_octets;
	u64 if_out_pkts;
	u64 if_out_errors;
	u64 if_out_ucast_pkts;
	u64 if_out_multicast_pkts;
	u64 if_out_broadcast_pkts;
} macsec_port_counters_t;  /* i.e. vtss_macsec_secy_port_counters_t */

typedef struct {
	macsec_txsa_counters_t txsa_counter[MAX_RECORDS];
	macsec_rxsa_counters_t rxsa_counter[MAX_RECORDS];
	macsec_txsc_counters_t txsc_counter;
	macsec_rxsc_counters_t rxsc_counter;
	macsec_secy_counters_t secy_counter;
	macsec_port_counters_t controlled_counter;
	macsec_port_counters_t uncontrolled_counter;
	macsec_port_counters_t common_counter;
} macsec_all_counters_t;
static macsec_all_counters_t macsec_all_counters;

int macsec_txsc_counters_dump(struct cmd_context *ctx);
int macsec_rxsc_counters_dump(struct cmd_context *ctx);
int macsec_secy_counters_dump(struct cmd_context *ctx);
int macsec_controlled_counters_dump(struct cmd_context *ctx);
int macsec_uncontrolled_counters_dump(struct cmd_context *ctx);
int macsec_common_counters_dump(struct cmd_context *ctx);

u8 macsec_rxsa_confidentiality_offset_get(struct cmd_context *ctx, u16 record)
{
	u32 value;
	macsec_read_reg(ctx, (u16)(0x1c00 | (record * 32)), INGR, &value);
	return (value & 0x70000000 >> 24);
}

u8 macsec_txsa_confidentiality_offset_get(struct cmd_context *ctx, u16 record)
{
	u32 value;
	macsec_read_reg(ctx, (u16)(0x9c00 | (record * 32)), EGR, &value);
	return (value & 0x70000000 >> 24);
}

bool macsec_txsa_confidentiality_get(struct cmd_context *ctx, u16 record)
{
	u32 value;
	macsec_read_reg(ctx, (u16)(0x9c00 | (record * 32)), EGR, &value);
	if (value & 0x80000000)
		return true;
	else
		return false;
}

bool macsec_txsa_protect_frame_get(struct cmd_context *ctx, u16 record)
{
	u32 value;
	macsec_read_reg(ctx, (u16)(0x9c00 | (record * 32)), EGR, &value);
	if (value & 0x10000)
		return true;
	else
		return false;
}

int macsec_rxsa_validate_frame_get(struct cmd_context *ctx, u16 record)
{
	u32 value;
	macsec_read_reg(ctx, (u16)(0x1c00 | (record * 32)), INGR, &value);
	return ((value & 0x180000) >> 19);
}

int macsec_ctrl_reg_dump(struct cmd_context *ctx)
{
	u32 value;
	printf("\nMACSEC_CTL_REGS MACsec Ingress Control registers\n\n");
	MACSEC_DISP_REG(ctx, "MACSEC_ENA_CFG", (u16)(0x800), INGR, &value);
	MACSEC_DISP_REG(ctx, "MACSEC_CTL_CFG", (u16)(0x801), INGR, &value);
	MACSEC_DISP_REG(ctx, "MACSEC_STICKY", (u16)(0x802), INGR, &value);
	MACSEC_DISP_REG(ctx, "MACSEC_STICKY_MASK", (u16)(0x803), INGR, &value);
	MACSEC_DISP_REG(ctx, "MACSEC_IGR_LATENCY_CFG", (u16)(0x804), INGR, &value);

	printf("\nMACSEC_CTL_REGS MACsec Egress Control registers\n\n");
	MACSEC_DISP_REG(ctx, "MACSEC_ENA_CFG", (u16)(0x8800), EGR, &value);
	MACSEC_DISP_REG(ctx, "MACSEC_CTL_CFG", (u16)(0x8801), EGR, &value);
	MACSEC_DISP_REG(ctx, "MACSEC_STICKY", (u16)(0x8802), EGR, &value);
	MACSEC_DISP_REG(ctx, "MACSEC_STICKY_MASK", (u16)(0x8803), EGR, &value);
	MACSEC_DISP_REG(ctx, "MACSEC_IGR_LATENCY_CFG", (u16)(0x8804), EGR, &value);

	return 0;
}

int macsec_sa_ctrl_reg_dump(struct cmd_context *ctx)
{
	u32 value;

	printf("\nSA_MATCH_CTL_PARAMS - Ingress SA compare parameters\n\n");
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_ENABLE1",    (u16)(0x1800), INGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_ENABLE2",    (u16)(0x1801), INGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_TOGGLE1",    (u16)(0x1804), INGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_TOGGLE2",    (u16)(0x1805), INGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_SET1",       (u16)(0x1808), INGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_SET2",       (u16)(0x1809), INGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_CLEAR1",     (u16)(0x180C), INGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_CLEAR2",     (u16)(0x180D), INGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_IN_FLIGHT",        (u16)(0x1810), INGR, &value);

	printf("\nSA_MATCH_CTL_PARAMS - Egress SA compare parameters\n\n");
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_ENABLE1",    (u16)(0x9800), EGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_ENABLE2",    (u16)(0x9801), EGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_TOGGLE1",    (u16)(0x9804), EGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_TOGGLE2",    (u16)(0x9805), EGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_SET1",       (u16)(0x9808), EGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_SET2",       (u16)(0x9809), EGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_CLEAR1",     (u16)(0x980C), EGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_ENTRY_CLEAR2",     (u16)(0x980D), EGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_IN_FLIGHT",        (u16)(0x9810), EGR, &value);

	return 0;
}

int macsec_sa_flow_ctrl_reg_dump(struct cmd_context *ctx)
{
	const u8 no_entries = 16;
	u16 idx;
	u32 value;
	
	printf("\nIngress SA_MATCH_FLOW_CONTROL_PARAMS_IGR - 16/64 flow control words SA parameter set\n\n");
	for (idx = 0; idx < no_entries; idx++) {
		MACSEC_DISP_REG(ctx, "SA MATCH FLOW CONTROL",  (u16)(0x1C00 + idx), INGR, &value);
	}

	printf("\nEgress SA_MATCH_FLOW_CONTROL_PARAMS_EGR - 16/64 flow control words SA parameter set\n\n");
	for (idx = 0; idx < no_entries; idx++) {
		MACSEC_DISP_REG(ctx, "SA MATCH FLOW CONTROL",  (u16)(0x9C00 + idx), EGR, &value);
	}

	return 0;
}

int macsec_ctrl_pkt_class_reg_dump(struct cmd_context *ctx)
{
	u16 idx;
	u32 value;

	printf("\nIngress CTL_PACKET_CLASS_PARAMS - Control packet classification parameters\n\n");
	for (idx = 0; idx < 10; idx++) {
		MACSEC_DISP_REG(ctx, "CP_MAC_DA_MATCH",  (u16)(0x1E00 + (2 * idx)), INGR, &value);
		MACSEC_DISP_REG(ctx, "CP_MAC_DA_ET_MATCH",  (u16)(0x1E01 + (2 * idx)), INGR, &value);
	}
	for (idx = 0; idx < 8; idx++) {
		MACSEC_DISP_REG(ctx, "CP_MAC_ET_MATCH",  (u16)(0x1E14 + idx), INGR, &value);
	}

	printf("\nEgress CTL_PACKET_CLASS_PARAMS - Control packet classification parameters\n\n");
	for (idx = 0; idx < 10; idx++) {
		MACSEC_DISP_REG(ctx, "CP_MAC_DA_MATCH",  (u16)(0x9E00 + (2 * idx)), EGR, &value);
		MACSEC_DISP_REG(ctx, "CP_MAC_DA_ET_MATCH",  (u16)(0x9E01 + (2 * idx)), EGR, &value);
	}
	for (idx = 0; idx < 8; idx++) {
		MACSEC_DISP_REG(ctx, "CP_MAC_ET_MATCH",  (u16)(0x9E14 + idx), EGR, &value);
	}

	return 0;
}

int macsec_ctrl_pkt_class2_reg_dump(struct cmd_context *ctx)
{
	u32 value;

	printf("\nIngress CTL_PACKET_CLASS_PARAMS2 - Control packet classification parameters\n\n");
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_START_LO",      (u16)(0x1E20), INGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_START_HI",      (u16)(0x1E21), INGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_END_LO",        (u16)(0x1E22), INGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_END_HI",        (u16)(0x1E23), INGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_44_BITS_LO",    (u16)(0x1E24), INGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_44_BITS_HI",    (u16)(0x1E25), INGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_48_BITS_LO",    (u16)(0x1E26), INGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_48_BITS_HI",    (u16)(0x1E27), INGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MATCH_MODE",           (u16)(0x1E3E), INGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MATCH_ENABLE",         (u16)(0x1E3F), INGR, &value);

	printf("\nEgress CTL_PACKET_CLASS_PARAMS2 - Control packet classification parameters\n\n");
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_START_LO",      (u16)(0x9E20), EGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_START_HI",      (u16)(0x9E21), EGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_END_LO",        (u16)(0x9E22), EGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_END_HI",        (u16)(0x9E23), EGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_44_BITS_LO",    (u16)(0x9E24), EGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_44_BITS_HI",    (u16)(0x9E25), EGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_48_BITS_LO",    (u16)(0x9E26), EGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MAC_DA_48_BITS_HI",    (u16)(0x9E27), EGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MATCH_MODE",           (u16)(0x9E3E), EGR, &value);
	MACSEC_DISP_REG(ctx, "CP_MATCH_ENABLE",         (u16)(0x9E3F), EGR, &value);

	return 0;
}

int macsec_ctrl_frame_reg_dump(struct cmd_context *ctx)
{
	u32 value;

	printf("\nIngress FRAME_MATCHING_HANDLING_CTRL - Frame matching and handling control registers\n\n");
	MACSEC_DISP_REG(ctx, "SAM_CP_TAG",          (u16)(0x1E40), INGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_PP_TAGS",         (u16)(0x1E41), INGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_PP_TAGS2",        (u16)(0x1E42), INGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_CP_TAG2",         (u16)(0x1E43), INGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_NM_PARAMS",       (u16)(0x1E50), INGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_NM_FLOW_NCP",     (u16)(0x1E51), INGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_NM_FLOW_CP",      (u16)(0x1E52), INGR, &value);
	MACSEC_DISP_REG(ctx, "MISC_CONTROL",        (u16)(0x1E5F), INGR, &value);
	MACSEC_DISP_REG(ctx, "HDR_EXT_CTRL",        (u16)(0x1E60), INGR, &value);
	MACSEC_DISP_REG(ctx, "CRYPT_AUTH_CTRL",     (u16)(0x1E61), INGR, &value);

	printf("\nEgress FRAME_MATCHING_HANDLING_CTRL - Frame matching and handling control registers\n\n");
	MACSEC_DISP_REG(ctx, "SAM_CP_TAG",          (u16)(0x9E40), EGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_PP_TAGS",         (u16)(0x9E41), EGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_PP_TAGS2",        (u16)(0x9E42), EGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_CP_TAG2",         (u16)(0x9E43), EGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_NM_PARAMS",       (u16)(0x9E50), EGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_NM_FLOW_NCP",     (u16)(0x9E51), EGR, &value);
	MACSEC_DISP_REG(ctx, "SAM_NM_FLOW_CP",      (u16)(0x9E52), EGR, &value);
	MACSEC_DISP_REG(ctx, "MISC_CONTROL",        (u16)(0x9E5F), EGR, &value);
	MACSEC_DISP_REG(ctx, "HDR_EXT_CTRL",        (u16)(0x9E60), EGR, &value);
	MACSEC_DISP_REG(ctx, "CRYPT_AUTH_CTRL",     (u16)(0x9E61), EGR, &value);

	return 0;
}

int macsec_sa_reg_dump(struct cmd_context *ctx)
{
	const u8 no_entries = 16;
	u16 idx;
	u32 value;

	printf("\nSA: Ingress SA Match Params\n\n");
	for (idx = 0; idx < no_entries; idx++) {
		MACSEC_DISP_REG(ctx, "SAM_MAC_SA_MATCH_LO",  (u16)(0x1000 + (0x10 * idx)), INGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_MAC_SA_MATCH_HI",  (u16)(0x1000 + (0x10 * idx) + 1), INGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_MAC_DA_MATCH_LO",  (u16)(0x1000 + (0x10 * idx) + 2), INGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_MAC_DA_MATCH_HI",  (u16)(0x1000 + (0x10 * idx) + 3), INGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_MISC_MATCH",       (u16)(0x1000 + (0x10 * idx) + 4), INGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_SCI_MATCH_LO",     (u16)(0x1000 + (0x10 * idx) + 5), INGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_SCI_MATCH_HI",     (u16)(0x1000 + (0x10 * idx) + 6), INGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_MASK",             (u16)(0x1000 + (0x10 * idx) + 7), INGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_EXT_MATCH",        (u16)(0x1000 + (0x10 * idx) + 8), INGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_HDR_BYPASS_MATCH1", (u16)(0x1000 + (0x10 * idx) + 9), INGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_HDR_BYPASS_MATCH2", (u16)(0x1000 + (0x10 * idx) + 0xA), INGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_HDR_BYPASS_MASK1", (u16)(0x1000 + (0x10 * idx) + 0xB), INGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_HDR_BYPASS_MASK2", (u16)(0x1000 + (0x10 * idx) + 0xC), INGR, &value);
	}

	printf("\nSA: Egress SA Match Params\n\n");
	for (idx = 0; idx < no_entries; idx++) {
		MACSEC_DISP_REG(ctx, "SAM_MAC_SA_MATCH_LO",  (u16)(0x9000 + (0x10 * idx)), EGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_MAC_SA_MATCH_HI",  (u16)(0x9000 + (0x10 * idx) + 1), EGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_MAC_DA_MATCH_LO",  (u16)(0x9000 + (0x10 * idx) + 2), EGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_MAC_DA_MATCH_HI",  (u16)(0x9000 + (0x10 * idx) + 3), EGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_MISC_MATCH",       (u16)(0x9000 + (0x10 * idx) + 4), EGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_SCI_MATCH_LO",     (u16)(0x9000 + (0x10 * idx) + 5), EGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_SCI_MATCH_HI",     (u16)(0x9000 + (0x10 * idx) + 6), EGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_MASK",             (u16)(0x9000 + (0x10 * idx) + 7), EGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_EXT_MATCH",        (u16)(0x9000 + (0x10 * idx) + 8), EGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_HDR_BYPASS_MATCH1", (u16)(0x9000 + (0x10 * idx) + 9), EGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_HDR_BYPASS_MATCH2", (u16)(0x9000 + (0x10 * idx) + 0xA), EGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_HDR_BYPASS_MASK1", (u16)(0x9000 + (0x10 * idx) + 0xB), EGR, &value);
		MACSEC_DISP_REG(ctx, "SAM_HDR_BYPASS_MASK2", (u16)(0x9000 + (0x10 * idx) + 0xC), EGR, &value);
	}

	return 0;
}

int macsec_xform_reg_dump(struct cmd_context *ctx)
{
	const u8 no_entries = 16;
	u8 rec_size = 0, reg_num = 0;
	u16 base_addr, addr;
	u16 idx, reg;
	u32 value, value1, value2, value3;

	printf("\nIngress XFORM_RECORD_REGS - Transform context records\n\n");
	macsec_read_reg(ctx, (u16)0x1E5F, INGR, &value);
	rec_size = (value & 0x03000000) >> 24;
	reg_num =(rec_size == 1) ? 20 : ((rec_size == 2) ? 24 : 16);
	for (idx = 0; idx < no_entries; idx++) {
		printf("Ingress XFORM Record -%u\n", (u32)(idx + 1));
		base_addr = (0x20 * idx);
		for (reg = 0; reg < reg_num; reg += 4) {
			addr = base_addr + reg;
			macsec_read_reg(ctx, (u16)addr, INGR, &value);
			macsec_read_reg(ctx, (u16)(addr + 1), INGR, &value1);
			macsec_read_reg(ctx, (u16)(addr + 2), INGR, &value2);
			macsec_read_reg(ctx, (u16)(addr + 3), INGR, &value3);
			printf("[ \t0x%-6x - 0x%-6x ] 0x%-12x  0x%-12x  0x%-12x  0x%-12x \n", addr, addr+3, value, value1, value2, value3);
		}
	}

	printf("\nEgress XFORM_RECORD_REGS - Transform context records\n\n");
	macsec_read_reg(ctx, (u16)0x9E5F, EGR, &value);
	rec_size = (value & 0x03000000) >> 24;
	reg_num =(rec_size == 1) ? 20 : ((rec_size == 2) ? 24 : 16);
	for (idx = 0; idx < no_entries; idx++) {
		printf("Egress XFORM Record -%u\n", (u32)(idx + 1));
		base_addr = 0x8000 + (0x20 * idx);
		for (reg = 0; reg < reg_num; reg += 4) {
			addr = base_addr + reg;
			macsec_read_reg(ctx, (u16)addr, EGR, &value);
			macsec_read_reg(ctx, (u16)(addr + 1), EGR, &value1);
			macsec_read_reg(ctx, (u16)(addr + 2), EGR, &value2);
			macsec_read_reg(ctx, (u16)(addr + 3), EGR, &value3);
			printf("[ \t0x%-6x - 0x%-6x ] 0x%-12x  0x%-12x  0x%-12x  0x%-12x \n", addr, addr+3, value, value1, value2, value3);
		}
	}

	return 0;
}

int macsec_rmon_hmac_reg_dump(struct cmd_context *ctx)
{
	u32 value;
	u64 count64 = 0;
	u64 stats_pkts = 0;

	printf("\nMACSEC HOST MAC statistics\n\n");

	macsec_read_reg(ctx, (u16)(0x13b), HOST, &value);
	count64 = (u64)value;
	macsec_read_reg(ctx, (u16)(0x13c), HOST, &value);
	count64 += (u64)value;
	macsec_read_reg(ctx, (u16)(0x139), HOST, &value);
	count64 += (u64)value;
	macsec_read_reg(ctx, (u16)(0x13a), HOST, &value);
	count64 += (u64)value;
	printf("%-40s %-12llu\n", "if_rx_octets", count64);
	macsec_read_reg(ctx, (u16)(0x13d), HOST, &value);
	count64 = (u64)value;
	macsec_read_reg(ctx, (u16)(0x13e), HOST, &value);
	count64 += (u64)value;
	printf("%-40s %-12llu\n", "if_rx_in_bytes", count64);
	MACSEC_DISP_CNT(ctx, "if_rx_pause_pkts", (u16)(0x11a), HOST, &value);
	MACSEC_DISP_CNT(ctx, "if_rx_ucast_pkts", (u16)(0x11c), HOST, &value);
	MACSEC_DISP_CNT(ctx, "if_rx_multicast_pkts", (u16)(0x11d), HOST, &value);
	MACSEC_DISP_CNT(ctx, "if_rx_broadcast_pkts", (u16)(0x11e), HOST, &value);
	macsec_read_reg(ctx, (u16)(0x13b), HOST, &value);
	count64 = (u64)value;
	macsec_read_reg(ctx, (u16)(0x139), HOST, &value);
	count64 += (u64)value;
	printf("%-40s %-12llu\n", "if_rx_in_bytes", count64);
	MACSEC_DISP_CNT(ctx, "if_rx_CRCAlignErrors", (u16)(0x11f), HOST, &value);
	count64 = (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_UndersizePkts", (u16)(0x120), HOST, &value);
	count64 += (u64)value;
	stats_pkts = (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Fragments", (u16)(0x121), HOST, &value);
	count64 += (u64)value;
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Jabbers", (u16)(0x125), HOST, &value);
	count64 += (u64)value;
	stats_pkts += (u64)value;
	printf("%-40s %-12llu\n", "if_rx_errors", count64);
	MACSEC_DISP_CNT(ctx, "if_rx_OversizePkts", (u16)(0x124), HOST, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Pkts64Octets", (u16)(0x126), HOST, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Pkts65to127Octets", (u16)(0x127), HOST, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Pkts128to255Octets", (u16)(0x128), HOST, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Pkts256to511Octets", (u16)(0x129), HOST, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Pkts512to1023Octets", (u16)(0x12a), HOST, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Pkts1024to1518Octets", (u16)(0x12b), HOST, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Pkts1519toMaxOctets", (u16)(0x12c), HOST, &value);
	stats_pkts += (u64)value;
	printf("%-40s %-12llu\n", "if_rx_StatsPkts", stats_pkts);
	macsec_read_reg(ctx, (u16)(0x13f), HOST, &value);
	count64 = (u64)value;
	macsec_read_reg(ctx, (u16)(0x140), HOST, &value);
	count64 += (u64)value;
	printf("%-40s %-12llu\n", "if_tx_octets", count64);
	MACSEC_DISP_CNT(ctx, "if_tx_pause_pkts", (u16)(0x12e), HOST, &value);
	MACSEC_DISP_CNT(ctx, "if_tx_ucast_pkts", (u16)(0x12f), HOST, &value);
	MACSEC_DISP_CNT(ctx, "if_tx_multicast_pkts", (u16)(0x130), HOST, &value);
	MACSEC_DISP_CNT(ctx, "if_tx_broadcast_pkts", (u16)(0x131), HOST, &value);
	MACSEC_DISP_CNT(ctx, "if_tx_Pkts64Octets", (u16)(0x132), HOST, &value);
	stats_pkts = (u64)value;
	MACSEC_DISP_CNT(ctx, "if_tx_Pkts65to127Octets", (u16)(0x133), HOST, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_tx_Pkts128to255Octets", (u16)(0x134), HOST, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_tx_Pkts256to511Octets", (u16)(0x135), HOST, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_tx_Pkts512to1023Octets", (u16)(0x136), HOST, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_tx_Pkts1024to1518Octets", (u16)(0x137), HOST, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_tx_Pkts1519toMaxOctets", (u16)(0x138), HOST, &value);
	stats_pkts += (u64)value;
	printf("%-40s %-12llu\n", "if_tx_StatsPkts", stats_pkts);

	printf("\n");

	return 0;
}

int macsec_rmon_hmac_reg_clear(struct cmd_context *ctx)
{
	u32 value = 0;

	macsec_write_reg(ctx, (u16)(0x138), HOST, value);
	macsec_write_reg(ctx, (u16)(0x139), HOST, value);
	macsec_write_reg(ctx, (u16)(0x13a), HOST, value);
	macsec_write_reg(ctx, (u16)(0x13b), HOST, value);
	macsec_write_reg(ctx, (u16)(0x13c), HOST, value);
	macsec_write_reg(ctx, (u16)(0x13d), HOST, value);
	macsec_write_reg(ctx, (u16)(0x13e), HOST, value);
	macsec_write_reg(ctx, (u16)(0x11a), HOST, value);
	macsec_write_reg(ctx, (u16)(0x11c), HOST, value);
	macsec_write_reg(ctx, (u16)(0x11d), HOST, value);
	macsec_write_reg(ctx, (u16)(0x11e), HOST, value);
	macsec_write_reg(ctx, (u16)(0x11f), HOST, value);
	macsec_write_reg(ctx, (u16)(0x120), HOST, value);
	macsec_write_reg(ctx, (u16)(0x121), HOST, value);
	macsec_write_reg(ctx, (u16)(0x124), HOST, value);
	macsec_write_reg(ctx, (u16)(0x125), HOST, value);
	macsec_write_reg(ctx, (u16)(0x126), HOST, value);
	macsec_write_reg(ctx, (u16)(0x127), HOST, value);
	macsec_write_reg(ctx, (u16)(0x128), HOST, value);
	macsec_write_reg(ctx, (u16)(0x129), HOST, value);
	macsec_write_reg(ctx, (u16)(0x12a), HOST, value);
	macsec_write_reg(ctx, (u16)(0x12b), HOST, value);
	macsec_write_reg(ctx, (u16)(0x12c), HOST, value);

	macsec_write_reg(ctx, (u16)(0x12e), HOST, value);
	macsec_write_reg(ctx, (u16)(0x12f), HOST, value);
	macsec_write_reg(ctx, (u16)(0x130), HOST, value);
	macsec_write_reg(ctx, (u16)(0x131), HOST, value);
	macsec_write_reg(ctx, (u16)(0x132), HOST, value);
	macsec_write_reg(ctx, (u16)(0x133), HOST, value);
	macsec_write_reg(ctx, (u16)(0x134), HOST, value);
	macsec_write_reg(ctx, (u16)(0x135), HOST, value);
	macsec_write_reg(ctx, (u16)(0x136), HOST, value);
	macsec_write_reg(ctx, (u16)(0x137), HOST, value);
	macsec_write_reg(ctx, (u16)(0x138), HOST, value);
	macsec_write_reg(ctx, (u16)(0x13f), HOST, value);
	macsec_write_reg(ctx, (u16)(0x140), HOST, value);

	printf("MACSEC HOST MAC statistics cleared\n");

	return 0;
}

int macsec_rmon_lmac_reg_dump(struct cmd_context *ctx)
{
	u32 value;
	u64 count64 = 0;
	u64 stats_pkts = 0;

	printf("\nMACSEC LINE MAC statistics\n\n");

	macsec_read_reg(ctx, (u16)(0x23b), LINE, &value);
	count64 = (u64)value;
	macsec_read_reg(ctx, (u16)(0x23c), LINE, &value);
	count64 += (u64)value;
	macsec_read_reg(ctx, (u16)(0x239), LINE, &value);
	count64 += (u64)value;
	macsec_read_reg(ctx, (u16)(0x23a), LINE, &value);
	count64 += (u64)value;
	printf("%-40s %-12llu\n", "if_rx_octets", count64);
	macsec_read_reg(ctx, (u16)(0x23d), LINE, &value);
	count64 = (u64)value;
	macsec_read_reg(ctx, (u16)(0x23e), LINE, &value);
	count64 += (u64)value;
	printf("%-40s %-12llu\n", "if_rx_in_bytes", count64);
	MACSEC_DISP_CNT(ctx, "if_rx_pause_pkts", (u16)(0x21a), LINE, &value);
	MACSEC_DISP_CNT(ctx, "if_rx_ucast_pkts", (u16)(0x21c), LINE, &value);
	MACSEC_DISP_CNT(ctx, "if_rx_multicast_pkts", (u16)(0x21d), LINE, &value);
	MACSEC_DISP_CNT(ctx, "if_rx_broadcast_pkts", (u16)(0x21e), LINE, &value);
	macsec_read_reg(ctx, (u16)(0x23b), LINE, &value);
	count64 = (u64)value;
	macsec_read_reg(ctx, (u16)(0x239), LINE, &value);
	count64 += (u64)value;
	printf("%-40s %-12llu\n", "if_rx_in_bytes", count64);
	MACSEC_DISP_CNT(ctx, "if_rx_CRCAlignErrors", (u16)(0x21f), LINE, &value);
	count64 = (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_UndersizePkts", (u16)(0x220), LINE, &value);
	count64 += (u64)value;
	stats_pkts = (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Fragments", (u16)(0x221), LINE, &value);
	count64 += (u64)value;
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Jabbers", (u16)(0x225), LINE, &value);
	count64 += (u64)value;
	stats_pkts += (u64)value;
	printf("%-40s %-12llu\n", "if_rx_errors", count64);
	MACSEC_DISP_CNT(ctx, "if_rx_OversizePkts", (u16)(0x224), LINE, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Pkts64Octets", (u16)(0x226), LINE, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Pkts65to127Octets", (u16)(0x227), LINE, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Pkts128to255Octets", (u16)(0x228), LINE, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Pkts256to511Octets", (u16)(0x229), LINE, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Pkts512to1023Octets", (u16)(0x22a), LINE, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Pkts1024to1518Octets", (u16)(0x22b), LINE, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_rx_Pkts1519toMaxOctets", (u16)(0x22c), LINE, &value);
	stats_pkts += (u64)value;
	printf("%-40s %-12llu\n", "if_rx_StatsPkts", stats_pkts);
	macsec_read_reg(ctx, (u16)(0x23f), LINE, &value);
	count64 = (u64)value;
	macsec_read_reg(ctx, (u16)(0x240), LINE, &value);
	count64 += (u64)value;
	printf("%-40s %-12llu\n", "if_tx_octets", count64);
	MACSEC_DISP_CNT(ctx, "if_tx_pause_pkts", (u16)(0x22e), LINE, &value);
	MACSEC_DISP_CNT(ctx, "if_tx_ucast_pkts", (u16)(0x22f), LINE, &value);
	MACSEC_DISP_CNT(ctx, "if_tx_multicast_pkts", (u16)(0x230), LINE, &value);
	MACSEC_DISP_CNT(ctx, "if_tx_broadcast_pkts", (u16)(0x131), LINE, &value);
	MACSEC_DISP_CNT(ctx, "if_tx_Pkts64Octets", (u16)(0x232), LINE, &value);
	stats_pkts = (u64)value;
	MACSEC_DISP_CNT(ctx, "if_tx_Pkts65to127Octets", (u16)(0x233), LINE, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_tx_Pkts128to255Octets", (u16)(0x234), LINE, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_tx_Pkts256to511Octets", (u16)(0x235), LINE, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_tx_Pkts512to1023Octets", (u16)(0x236), LINE, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_tx_Pkts1024to1518Octets", (u16)(0x237), LINE, &value);
	stats_pkts += (u64)value;
	MACSEC_DISP_CNT(ctx, "if_tx_Pkts1519toMaxOctets", (u16)(0x238), LINE, &value);
	stats_pkts += (u64)value;
	printf("%-40s %-12llu\n", "if_tx_StatsPkts", stats_pkts);

	printf("\n");

	return 0;
}

int macsec_rmon_lmac_reg_clear(struct cmd_context *ctx)
{
	u32 value = 0;

	macsec_write_reg(ctx, (u16)(0x238), LINE, value);
	macsec_write_reg(ctx, (u16)(0x239), LINE, value);
	macsec_write_reg(ctx, (u16)(0x23a), LINE, value);
	macsec_write_reg(ctx, (u16)(0x23b), LINE, value);
	macsec_write_reg(ctx, (u16)(0x23c), LINE, value);
	macsec_write_reg(ctx, (u16)(0x23d), LINE, value);
	macsec_write_reg(ctx, (u16)(0x23e), LINE, value);
	macsec_write_reg(ctx, (u16)(0x21a), LINE, value);
	macsec_write_reg(ctx, (u16)(0x21c), LINE, value);
	macsec_write_reg(ctx, (u16)(0x21d), LINE, value);
	macsec_write_reg(ctx, (u16)(0x21e), LINE, value);
	macsec_write_reg(ctx, (u16)(0x21f), LINE, value);
	macsec_write_reg(ctx, (u16)(0x220), LINE, value);
	macsec_write_reg(ctx, (u16)(0x221), LINE, value);
	macsec_write_reg(ctx, (u16)(0x224), LINE, value);
	macsec_write_reg(ctx, (u16)(0x225), LINE, value);
	macsec_write_reg(ctx, (u16)(0x226), LINE, value);
	macsec_write_reg(ctx, (u16)(0x227), LINE, value);
	macsec_write_reg(ctx, (u16)(0x228), LINE, value);
	macsec_write_reg(ctx, (u16)(0x229), LINE, value);
	macsec_write_reg(ctx, (u16)(0x22a), LINE, value);
	macsec_write_reg(ctx, (u16)(0x22b), LINE, value);
	macsec_write_reg(ctx, (u16)(0x22c), LINE, value);

	macsec_write_reg(ctx, (u16)(0x22e), LINE, value);
	macsec_write_reg(ctx, (u16)(0x22f), LINE, value);
	macsec_write_reg(ctx, (u16)(0x230), LINE, value);
	macsec_write_reg(ctx, (u16)(0x231), LINE, value);
	macsec_write_reg(ctx, (u16)(0x232), LINE, value);
	macsec_write_reg(ctx, (u16)(0x233), LINE, value);
	macsec_write_reg(ctx, (u16)(0x234), LINE, value);
	macsec_write_reg(ctx, (u16)(0x235), LINE, value);
	macsec_write_reg(ctx, (u16)(0x236), LINE, value);
	macsec_write_reg(ctx, (u16)(0x237), LINE, value);
	macsec_write_reg(ctx, (u16)(0x238), LINE, value);
	macsec_write_reg(ctx, (u16)(0x23f), LINE, value);
	macsec_write_reg(ctx, (u16)(0x240), LINE, value);

	printf("MACSEC LINE MAC statistics cleared\n");

	return 0;
}

int macsec_store_counters()
{
	FILE *f;
	char *file = "/dev/macsec_counters";
	size_t bytes;

	f = fopen(file, "wb+");
	if ( !f) {
		fprintf(stderr, "Can't open '%s': %s\n", file, strerror(errno));
		return 1;
	}

	bytes = fwrite(&macsec_all_counters, 1, sizeof(macsec_all_counters_t), f);
	if (bytes !=  sizeof(macsec_all_counters_t)) {
		fprintf(stderr, "Can not write all data\n");
		return 1;
	}
	if (fclose(f)) {
		fprintf(stderr, "Can't close file %s: %s\n", file, strerror(errno));
		return 1;
	}

	return 0;
}

int macsec_restore_counters()
{
	FILE *f;
	char *file = "/dev/macsec_counters";
	size_t bytes;

	f = fopen(file, "rb");
	if ( !f) {
		fprintf(stderr, "Can't open '%s': %s\n", file, strerror(errno));
		return 1;
	}
	bytes = fread(&macsec_all_counters, 1, sizeof(macsec_all_counters_t), f);
	if (bytes !=  sizeof(macsec_all_counters_t)) {
		fprintf(stderr, "Can not read all data\n");
		return 1;
	}
	if (fclose(f)) {
		fprintf(stderr, "Can't close file %s: %s\n", file, strerror(errno));
		return 1;
	}

	return 0;
}

int macsec_counters_clear(struct cmd_context *ctx)
{
	memset(&macsec_all_counters, 0, sizeof(macsec_all_counters_t));
	macsec_store_counters();
	macsec_rmon_hmac_reg_clear(ctx);
	macsec_rmon_lmac_reg_clear(ctx);
	printf("MACSEC statistics cleared\n");

	return 0;
}

int macsec_tx_sa_counters_dump(struct cmd_context *ctx, const u16 record)
{
	u32 value;
	u64 out_pkts_cnt = 0;
	macsec_txsa_counters_t *txsa_cnts;
	macsec_txsc_counters_t *txsc_cnts;
	macsec_secy_counters_t *secy_cnts;
	macsec_port_counters_t *cntl_cnts;

	memset(&macsec_all_counters, 0, sizeof(macsec_all_counters_t));
	macsec_restore_counters();
	txsa_cnts = &macsec_all_counters.txsa_counter[record];
	macsec_read_reg(ctx, (u16)(0xa005 | (record * 32)), EGR, &value);
	out_pkts_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0xa004 | (record * 32)), EGR, &value);
	out_pkts_cnt |= (u64) value;
	if (macsec_txsa_confidentiality_get(ctx, record)) {
		txsa_cnts->out_pkts_encrypted += out_pkts_cnt;
		txsa_cnts->out_pkts_protected = 0;
	} else {
		txsa_cnts->out_pkts_encrypted = 0;
		txsa_cnts->out_pkts_protected += out_pkts_cnt;
	}
	printf("\nTX SA Counters: Record(%d) \n", record);
	printf("Packets protected\t: %llu\n", txsa_cnts->out_pkts_protected);
	printf("Packets encrypted\t: %llu\n", txsa_cnts->out_pkts_encrypted);

	txsc_cnts = &macsec_all_counters.txsc_counter;
	macsec_read_reg(ctx, (u16)(0xa001 | (record * 32)), EGR, &value);
	out_pkts_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0xa000 | (record * 32)), EGR, &value);
	out_pkts_cnt |= (u64) value;
	if (!macsec_txsa_protect_frame_get(ctx, record) && macsec_ver == REV_B) {
		txsc_cnts->out_octets_untagged += out_pkts_cnt;
	} else if (macsec_txsa_confidentiality_get(ctx, record)) {
		u8 offset = macsec_txsa_confidentiality_offset_get(ctx, record);
		if (out_pkts_cnt > txsa_cnts->out_pkts_encrypted * offset) {
			txsc_cnts->out_octets_encrypted += (out_pkts_cnt - (txsa_cnts->out_pkts_encrypted * offset));
			txsc_cnts->out_octets_protected += (txsa_cnts->out_pkts_encrypted * offset);
		} else {
			txsc_cnts->out_octets_protected += out_pkts_cnt;
		}
	} else {
		txsc_cnts->out_octets_protected += out_pkts_cnt;
	}

	// SecY Too Log counters:
	secy_cnts = &macsec_all_counters.secy_counter;
	macsec_read_reg(ctx, (u16)(0xa007 | (record * 32)), EGR, &value);
	out_pkts_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0xa006 | (record * 32)), EGR, &value);
	out_pkts_cnt |= (u64) value;
	secy_cnts->out_pkts_too_long += out_pkts_cnt;

	// Controlled Port counters for Rev B
	cntl_cnts = &macsec_all_counters.controlled_counter;
	if (macsec_ver == REV_B) {
		macsec_read_reg(ctx, (u16)(0xa009 | (record * 32)), EGR, &value);
		out_pkts_cnt = (u64) value << 32;
		macsec_read_reg(ctx, (u16)(0xa008 | (record * 32)), EGR, &value);
		out_pkts_cnt |= (u64) value;
		cntl_cnts->if_out_ucast_pkts += out_pkts_cnt;
		macsec_read_reg(ctx, (u16)(0xa00b | (record * 32)), EGR, &value);
		out_pkts_cnt = (u64) value << 32;
		macsec_read_reg(ctx, (u16)(0xa00a | (record * 32)), EGR, &value);
		out_pkts_cnt |= (u64) value;
		cntl_cnts->if_out_multicast_pkts += out_pkts_cnt;
		macsec_read_reg(ctx, (u16)(0xa00d | (record * 32)), EGR, &value);
		out_pkts_cnt = (u64) value << 32;
		macsec_read_reg(ctx, (u16)(0xa00c | (record * 32)), EGR, &value);
		out_pkts_cnt |= (u64) value;
		cntl_cnts->if_out_broadcast_pkts += out_pkts_cnt;
	}

	macsec_store_counters();
	// TBD
	macsec_txsc_counters_dump(ctx);
	macsec_secy_counters_dump(ctx);

	return 0;
}

int macsec_rx_sa_counters_dump(struct cmd_context *ctx, const u16 record)
{
	u8 ev_bit = 0;
	u8 validate_frame = 0;
	u32 value;
	u64 in_pkts_cnt = 0;
	macsec_rxsa_counters_t *rxsa_cnts;
	macsec_rxsc_counters_t *rxsc_cnts;
	macsec_port_counters_t *cntl_cnts;

	memset(&macsec_all_counters, 0, sizeof(macsec_all_counters_t));
	macsec_restore_counters();
	rxsa_cnts = &macsec_all_counters.rxsa_counter[record];
	macsec_read_reg(ctx, (u16)(0x200b | (record * 32)), INGR, &value);
	in_pkts_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x200a | (record * 32)), INGR, &value);
	in_pkts_cnt |= (u64) value;
	rxsa_cnts->in_pkts_ok += in_pkts_cnt;
	macsec_read_reg(ctx, (u16)(0x200d | (record * 32)), INGR, &value);
	in_pkts_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x200c | (record * 32)), INGR, &value);
	in_pkts_cnt |= (u64) value;
	rxsa_cnts->in_pkts_invalid += in_pkts_cnt;
	macsec_read_reg(ctx, (u16)(0x200f | (record * 32)), INGR, &value);
	in_pkts_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x200e | (record * 32)), INGR, &value);
	in_pkts_cnt |= (u64) value;
	rxsa_cnts->in_pkts_not_valid += in_pkts_cnt;
	macsec_read_reg(ctx, (u16)(0x2011 | (record * 32)), INGR, &value);
	in_pkts_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x2010 | (record * 32)), INGR, &value);
	in_pkts_cnt |= (u64) value;
	rxsa_cnts->in_pkts_not_using_sa += in_pkts_cnt;
	macsec_read_reg(ctx, (u16)(0x2013 | (record * 32)), INGR, &value);
	in_pkts_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x2012 | (record * 32)), INGR, &value);
	in_pkts_cnt |= (u64) value;
	rxsa_cnts->in_pkts_unused_sa += in_pkts_cnt;
	macsec_read_reg(ctx, (u16)(0x2005 | (record * 32)), INGR, &value);
	in_pkts_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x2004 | (record * 32)), INGR, &value);
	in_pkts_cnt |= (u64) value;
	rxsa_cnts->in_pkts_unchecked += in_pkts_cnt;
	macsec_read_reg(ctx, (u16)(0x2007 | (record * 32)), INGR, &value);
	in_pkts_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x2006 | (record * 32)), INGR, &value);
	in_pkts_cnt |= (u64) value;
	rxsa_cnts->in_pkts_delayed += in_pkts_cnt;
	macsec_read_reg(ctx, (u16)(0x2009 | (record * 32)), INGR, &value);
	in_pkts_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x2008 | (record * 32)), INGR, &value);
	in_pkts_cnt |= (u64) value;
	rxsa_cnts->in_pkts_late += in_pkts_cnt;

	// Need to fix here:
	// Update SC Specific  counters
	rxsc_cnts = &macsec_all_counters.rxsc_counter;
	macsec_read_reg(ctx, (u16)(0x2001 | (record * 32)), INGR, &value);
	in_pkts_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x2000 | (record * 32)), INGR, &value);
	in_pkts_cnt |= (u64) value;
	validate_frame = macsec_rxsa_validate_frame_get(ctx, record);
	ev_bit = macsec_txsa_confidentiality_get(ctx, encoding_sa);
	if (validate_frame != MACSEC_VALIDATE_FRAMES_DISABLE && !ev_bit) {
		rxsc_cnts->in_octets_validated += in_pkts_cnt;
	}

	if (validate_frame != MACSEC_VALIDATE_FRAMES_DISABLE && ev_bit) {
		u8 offset = macsec_rxsa_confidentiality_offset_get(ctx, record);
		if (in_pkts_cnt > (rxsa_cnts->in_pkts_ok * offset)) {
			rxsc_cnts->in_octets_decrypted += in_pkts_cnt - (rxsa_cnts->in_pkts_ok * offset);
			rxsc_cnts->in_octets_validated += rxsa_cnts->in_pkts_ok * offset;
		} else {
			rxsc_cnts->in_octets_validated += in_pkts_cnt;
		}
	}

	if (validate_frame == MACSEC_VALIDATE_FRAMES_DISABLE && macsec_ver == REV_B) {
		rxsc_cnts->in_octets_validation_disabled += in_pkts_cnt;
	}

	// Controlled Port counters for Rev B
	cntl_cnts = &macsec_all_counters.controlled_counter;
	if (macsec_ver == REV_B) {
		macsec_read_reg(ctx, (u16)(0x2017 | (record * 32)), INGR, &value);
		in_pkts_cnt = (u64) value << 32;
		macsec_read_reg(ctx, (u16)(0x2016 | (record * 32)), INGR, &value);
		in_pkts_cnt |= (u64) value;
		cntl_cnts->if_in_ucast_pkts += in_pkts_cnt;
		macsec_read_reg(ctx, (u16)(0x2019 | (record * 32)), INGR, &value);
		in_pkts_cnt = (u64) value << 32;
		macsec_read_reg(ctx, (u16)(0x2018 | (record * 32)), INGR, &value);
		in_pkts_cnt |= (u64) value;
		cntl_cnts->if_in_multicast_pkts += in_pkts_cnt;
		macsec_read_reg(ctx, (u16)(0x201b | (record * 32)), INGR, &value);
		in_pkts_cnt = (u64) value << 32;
		macsec_read_reg(ctx, (u16)(0x201a | (record * 32)), INGR, &value);
		in_pkts_cnt |= (u64) value;
		cntl_cnts->if_in_broadcast_pkts += in_pkts_cnt;
	}
	macsec_store_counters();

	printf("\nRX SA Counters: Record(%d):\n", record);
	printf("Packets Ok\t\t: %llu\n", rxsa_cnts->in_pkts_ok);
	printf("Packets Invalid\t\t: %llu\n", rxsa_cnts->in_pkts_invalid);
	printf("Packets Not valid\t: %llu\n", rxsa_cnts->in_pkts_not_valid);
	printf("Packets Not using SA\t: %llu\n", rxsa_cnts->in_pkts_not_using_sa);
	printf("Packets Unused SA\t: %llu\n", rxsa_cnts->in_pkts_unused_sa);

	// TBD
	macsec_rxsc_counters_dump(ctx);
	macsec_secy_counters_dump(ctx);

	return 0;
}

int macsec_txsc_counters_dump(struct cmd_context *ctx)
{
	u16 record;
	macsec_txsa_counters_t *txsa_cnts;
	macsec_txsc_counters_t *txsc_cnts;

	memset(&macsec_all_counters, 0, sizeof(macsec_all_counters_t));
	macsec_restore_counters();
	txsc_cnts = &macsec_all_counters.txsc_counter;
	txsc_cnts->out_pkts_protected = 0;
	txsc_cnts->out_pkts_encrypted = 0;
	for (record = 0; record < MAX_RECORDS; record++) {
		txsa_cnts = &macsec_all_counters.txsa_counter[record];
		txsc_cnts->out_pkts_protected += txsa_cnts->out_pkts_protected;
		txsc_cnts->out_pkts_encrypted += txsa_cnts->out_pkts_encrypted;
	}
	macsec_store_counters();

	printf("\nTX SC Counters: \n");
	printf("Packets protected\t: %llu\n", txsc_cnts->out_pkts_protected);
	printf("Packets encrypted\t: %llu\n", txsc_cnts->out_pkts_encrypted);
	printf("Octects protected\t: %llu\n", txsc_cnts->out_octets_protected);
	printf("Octects encrypted\t: %llu\n", txsc_cnts->out_octets_encrypted);

	return 0;
}

int macsec_rxsc_counters_dump(struct cmd_context *ctx)
{
	u16 record;
	macsec_rxsa_counters_t *rxsa_cnts;
	macsec_rxsc_counters_t *rxsc_cnts;

	memset(&macsec_all_counters, 0, sizeof(macsec_all_counters_t));
	macsec_restore_counters();
	rxsc_cnts = &macsec_all_counters.rxsc_counter;
	rxsc_cnts->in_pkts_ok = 0;
	rxsc_cnts->in_pkts_invalid = 0;
	rxsc_cnts->in_pkts_not_valid = 0;
	rxsc_cnts->in_pkts_not_using_sa = 0;
	rxsc_cnts->in_pkts_unused_sa = 0;
	rxsc_cnts->in_pkts_unchecked = 0;
	rxsc_cnts->in_pkts_delayed = 0;
	rxsc_cnts->in_pkts_late = 0;
	for (record = 0; record < MAX_RECORDS; record++) {
		rxsa_cnts = &macsec_all_counters.rxsa_counter[record];
		rxsc_cnts->in_pkts_ok += rxsa_cnts->in_pkts_ok;
		rxsc_cnts->in_pkts_invalid += rxsa_cnts->in_pkts_invalid;
		rxsc_cnts->in_pkts_not_valid += rxsa_cnts->in_pkts_not_valid;
		rxsc_cnts->in_pkts_not_using_sa += rxsa_cnts->in_pkts_not_using_sa;
		rxsc_cnts->in_pkts_unused_sa += rxsa_cnts->in_pkts_unused_sa;
		rxsc_cnts->in_pkts_unchecked += rxsa_cnts->in_pkts_unchecked;
		rxsc_cnts->in_pkts_delayed += rxsa_cnts->in_pkts_delayed;
		rxsc_cnts->in_pkts_late += rxsa_cnts->in_pkts_late;
	}
	macsec_store_counters();

	printf("\nRX SC Counters: \n");
	printf("Packets unchecked\t: %llu\n", rxsc_cnts->in_pkts_unchecked);
	printf("Packets delayed \t: %llu\n", rxsc_cnts->in_pkts_delayed);
	printf("Packets Late\t\t: %llu\n", rxsc_cnts->in_pkts_late);
	printf("Packets Ok \t\t: %llu\n", rxsc_cnts->in_pkts_ok);
	printf("Packets Invalid \t: %llu\n", rxsc_cnts->in_pkts_invalid);
	printf("Packets Not valid \t: %llu\n", rxsc_cnts->in_pkts_not_valid);
	printf("Packets Not using SA \t: %llu\n", rxsc_cnts->in_pkts_not_using_sa);
	printf("Packets Unused SA \t: %llu\n", rxsc_cnts->in_pkts_unused_sa);
	printf("Octets Validated \t: %llu\n", rxsc_cnts->in_octets_validated);
	printf("Octets Decrypted \t: %llu\n", rxsc_cnts->in_octets_decrypted);

	return 0;
}

int macsec_secy_counters_dump(struct cmd_context *ctx)
{
	u32 value;
	u64 secy_cnt;
	macsec_txsc_counters_t *txsc_cnts;
	macsec_rxsc_counters_t *rxsc_cnts;
	macsec_secy_counters_t *secy_cnts;

	memset(&macsec_all_counters, 0, sizeof(macsec_all_counters_t));
	macsec_restore_counters();
	secy_cnts = &macsec_all_counters.secy_counter;
	macsec_read_reg(ctx, (u16)0x310f, INGR, &value);
	secy_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)0x310e, INGR, &value);
	secy_cnt |= (u64) value;
	secy_cnts->in_pkts_no_sci += secy_cnt;
	macsec_read_reg(ctx, (u16)0x3111, INGR, &value);
	secy_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)0x3110, INGR, &value);
	secy_cnt |= (u64) value;
	secy_cnts->in_pkts_unknown_sci += secy_cnt;
	macsec_read_reg(ctx, (u16)0x310b, INGR, &value);
	secy_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)0x310a, INGR, &value);
	secy_cnt |= (u64) value;
	secy_cnts->in_pkts_bad_tag += secy_cnt;
	macsec_read_reg(ctx, (u16)0x3107, INGR, &value);
	secy_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)0x3106, INGR, &value);
	secy_cnt |= (u64) value;
	if (macsec_ver == REV_B)
		secy_cnts->out_pkts_untagged += secy_cnt;
	macsec_read_reg(ctx, (u16)0x3105, INGR, &value);
	secy_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)0x3104, INGR, &value);
	secy_cnt |= (u64) value;
	secy_cnts->in_pkts_no_tag += secy_cnt;
	macsec_read_reg(ctx, (u16)0x3107, INGR, &value);
	secy_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)0x3106, INGR, &value);
	secy_cnt |= (u64) value;
	secy_cnts->in_pkts_untagged += secy_cnt;
	// Overrun - condition does not occur, report as zero
	secy_cnts->in_pkts_overrun = 0;

	txsc_cnts = &macsec_all_counters.txsc_counter;
	secy_cnts->out_octets_encrypted = txsc_cnts->out_octets_encrypted;
	secy_cnts->out_octets_protected = txsc_cnts->out_octets_protected;

	// Need to fix for Multiplex RxSCs:
	rxsc_cnts = &macsec_all_counters.rxsc_counter;
	secy_cnts->in_octets_validated = rxsc_cnts->in_octets_validated;
	secy_cnts->in_octets_decrypted = rxsc_cnts->in_octets_decrypted;

	macsec_store_counters();

	printf("\nSecY Counters:\n");
	printf("Rx Packets untagged in\t: %llu\n", secy_cnts->in_pkts_untagged);
	printf("Rx Packets no tag\t: %llu\n", secy_cnts->in_pkts_no_tag);
	printf("Rx Packets bad tag\t: %llu\n", secy_cnts->in_pkts_bad_tag);
	printf("Rx Packets unknown sci\t: %llu\n", secy_cnts->in_pkts_unknown_sci);
	printf("Rx Packets no sci\t: %llu\n", secy_cnts->in_pkts_no_sci);
	printf("Rx Packets overrun\t: %llu\n", secy_cnts->in_pkts_overrun);
	printf("Rx Octets validated\t: %llu\n", secy_cnts->in_octets_validated);
	printf("Rx Octets decrypted\t: %llu\n", secy_cnts->in_octets_decrypted);
	printf("Tx Packets untagged out\t: %llu\n", secy_cnts->out_pkts_untagged);
	printf("Tx Packets too long\t: %llu\n", secy_cnts->out_pkts_too_long);
	printf("Tx protected\t\t: %llu\n", secy_cnts->out_octets_protected);
	printf("Tx Octets encrypted\t: %llu\n", secy_cnts->out_octets_encrypted);

	// Need to remove:
	macsec_controlled_counters_dump(ctx);
	macsec_common_counters_dump(ctx);
	macsec_uncontrolled_counters_dump(ctx);
	return 0;
}

int macsec_controlled_counters_dump(struct cmd_context *ctx)
{
	macsec_txsc_counters_t *txsc_cnts;
	macsec_rxsc_counters_t *rxsc_cnts;
	macsec_secy_counters_t *secy_cnts;
	macsec_port_counters_t *cntl_cnts;
	u8 octets_add = 12;
	u8 bypass_mode = 0;

	memset(&macsec_all_counters, 0, sizeof(macsec_all_counters_t));
	macsec_restore_counters();
	cntl_cnts = &macsec_all_counters.controlled_counter;
	secy_cnts = &macsec_all_counters.secy_counter;
	txsc_cnts = &macsec_all_counters.txsc_counter;
	rxsc_cnts = &macsec_all_counters.rxsc_counter;
	cntl_cnts->if_out_octets = secy_cnts->out_octets_protected +
				   secy_cnts->out_octets_encrypted;
	if (macsec_ver == REV_B)
		cntl_cnts->if_out_octets += txsc_cnts->out_octets_untagged;

	// Need to fix for Multiple RxSCs
	cntl_cnts->if_in_errors = secy_cnts->in_pkts_bad_tag +
				  secy_cnts->in_pkts_no_sci +
				  rxsc_cnts->in_pkts_not_valid +
				  rxsc_cnts->in_pkts_not_using_sa;
	cntl_cnts->if_in_pkts = rxsc_cnts->in_pkts_ok +
				rxsc_cnts->in_pkts_invalid +
				rxsc_cnts->in_pkts_not_using_sa +
				rxsc_cnts->in_pkts_unused_sa +
				rxsc_cnts->in_pkts_unchecked +
				rxsc_cnts->in_pkts_delayed +
				rxsc_cnts->in_pkts_late;
	// Need to fix:
	cntl_cnts->if_in_octets = 0;
	cntl_cnts->if_out_errors = secy_cnts->out_pkts_too_long;
	cntl_cnts->if_in_discards = secy_cnts->in_pkts_no_tag +
				    secy_cnts->in_pkts_overrun +
				    rxsc_cnts->in_pkts_late;
	cntl_cnts->if_out_pkts = txsc_cnts->out_pkts_encrypted +
				 txsc_cnts->out_pkts_protected;
	if (macsec_ver == REV_B)
		cntl_cnts->if_out_pkts += secy_cnts->out_pkts_untagged;

	// Need to fix:
	bypass_mode = 0; //Fix me: macsec_bypass_mode_get(ctx, record);
	if (bypass_mode == MACSEC_BYPASS_TAG_ONE)
		octets_add += 4;
	else if (bypass_mode == MACSEC_BYPASS_TAG_TWO)
		octets_add += 8;
	// Next to fix - Many be wrong calcuation:
	cntl_cnts->if_out_octets += cntl_cnts->if_out_pkts * octets_add;

	macsec_store_counters();

	printf("\nControlled Port Counters:\n");
	printf("In Octets\t\t: %llu\n", cntl_cnts->if_in_octets);
	printf("In Packets\t\t: %llu\n", cntl_cnts->if_in_pkts);
	if (macsec_ver == REV_B) {
		printf("In Ucast Packets\t: %llu\n", cntl_cnts->if_in_ucast_pkts);
		printf("In Mcast Packets\t: %llu\n", cntl_cnts->if_in_multicast_pkts);
		printf("In Bcast Packets\t: %llu\n", cntl_cnts->if_in_broadcast_pkts);
	}
	printf("In Discards\t\t: %llu\n", cntl_cnts->if_in_discards);
	printf("In Errors\t\t: %llu\n", cntl_cnts->if_in_errors);
	printf("Out Octets\t\t: %llu\n", cntl_cnts->if_out_octets);
	printf("Out Packets\t\t: %llu\n", cntl_cnts->if_out_pkts);
	printf("Out Errors\t\t: %llu\n", cntl_cnts->if_out_errors);
	if (macsec_ver == REV_B) {
		printf("Out Ucast Packets\t: %llu\n", cntl_cnts->if_out_ucast_pkts);
		printf("Out Mcast Packets\t: %llu\n", cntl_cnts->if_out_multicast_pkts);
		printf("Out Bcast Packets\t: %llu\n", cntl_cnts->if_out_broadcast_pkts);
	}

	return 0;
}

int macsec_common_counters_dump(struct cmd_context *ctx)
{
	u32 value;
	u64 count64 = 0;
	macsec_rxsc_counters_t *rxsc_cnts;
	macsec_secy_counters_t *secy_cnts;
	macsec_port_counters_t *comm_cnts;

	memset(&macsec_all_counters, 0, sizeof(macsec_all_counters_t));
	macsec_restore_counters();
	rxsc_cnts = &macsec_all_counters.rxsc_counter;
	secy_cnts = &macsec_all_counters.secy_counter;
	comm_cnts = &macsec_all_counters.common_counter;
	// Line MAC Rx Counters
	macsec_read_reg(ctx, (u16)(0x23c), LINE, &value);
	count64 = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x23b), LINE, &value);
	count64 |= (u64) value;
	// Need to fix:
	comm_cnts->if_in_octets = count64;
	macsec_read_reg(ctx, (u16)(0x21c), LINE, &value);
	comm_cnts->if_in_ucast_pkts = (u64) value;
	macsec_read_reg(ctx, (u16)(0x21d), LINE, &value);
	comm_cnts->if_in_multicast_pkts = (u64) value;
	macsec_read_reg(ctx, (u16)(0x21e), LINE, &value);
	comm_cnts->if_in_broadcast_pkts = (u64) value;
	// Need to fix for Multiple RxSCs
	comm_cnts->if_in_errors = secy_cnts->in_pkts_bad_tag +
				  secy_cnts->in_pkts_no_sci +
				  rxsc_cnts->in_pkts_not_valid +
				  rxsc_cnts->in_pkts_not_using_sa;
	comm_cnts->if_in_discards = secy_cnts->in_pkts_no_tag +
				    secy_cnts->in_pkts_overrun +
				    rxsc_cnts->in_pkts_late;

	// Line MAC Tx Counters
	macsec_read_reg(ctx, (u16)(0x240), LINE, &value);
	count64 = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x23f), LINE, &value);
	count64 |= (u64) value;
	// Need to fix:
	comm_cnts->if_out_octets = count64;
	macsec_read_reg(ctx, (u16)(0x22f), LINE, &value);
	comm_cnts->if_out_ucast_pkts = (u64) value;
	macsec_read_reg(ctx, (u16)(0x230), LINE, &value);
	comm_cnts->if_out_multicast_pkts = (u64) value;
	macsec_read_reg(ctx, (u16)(0x231), LINE, &value);
	comm_cnts->if_out_broadcast_pkts = (u64) value;
	comm_cnts->if_out_errors = secy_cnts->out_pkts_too_long;

	macsec_store_counters();

	printf("\nCommon Port Counters:\n");
	printf("In Octets\t\t: %llu\n", comm_cnts->if_in_octets);
	printf("In Ucast Packets\t: %llu\n", comm_cnts->if_in_ucast_pkts);
	printf("In Mcast Packets\t: %llu\n", comm_cnts->if_in_multicast_pkts);
	printf("In Bcast Packets\t: %llu\n", comm_cnts->if_in_broadcast_pkts);
	printf("In Discards\t\t: %llu\n", comm_cnts->if_in_discards);
	printf("In Errors\t\t: %llu\n", comm_cnts->if_in_errors);
	printf("Out Octets\t\t: %llu\n", comm_cnts->if_out_octets);
	printf("Out Errors\t\t: %llu\n", comm_cnts->if_out_errors);
	printf("Out Ucast Packets\t: %llu\n", comm_cnts->if_out_ucast_pkts);
	printf("Out Mcast Packets\t: %llu\n", comm_cnts->if_out_multicast_pkts);
	printf("Out Bcast Packets\t: %llu\n", comm_cnts->if_out_broadcast_pkts);

	return 0;
}

int macsec_uncontrolled_counters_dump(struct cmd_context *ctx)
{
	u32 value;
	macsec_rxsc_counters_t *rxsc_cnts;
	macsec_secy_counters_t *secy_cnts;
	macsec_port_counters_t *cntl_cnts;
	macsec_port_counters_t *uncntl_cnts;
	macsec_port_counters_t *comm_cnts;

	memset(&macsec_all_counters, 0, sizeof(macsec_all_counters_t));
	macsec_restore_counters();
	rxsc_cnts = &macsec_all_counters.rxsc_counter;
	secy_cnts = &macsec_all_counters.secy_counter;
	cntl_cnts = &macsec_all_counters.controlled_counter;
	comm_cnts = &macsec_all_counters.common_counter;
	uncntl_cnts = &macsec_all_counters.uncontrolled_counter;
	// Line MAC Rx Counters
	uncntl_cnts->if_in_octets = cntl_cnts->if_in_octets +
				    (36 * cntl_cnts->if_in_pkts);
	macsec_read_reg(ctx, (u16)(0x21c), LINE, &value);
	uncntl_cnts->if_in_ucast_pkts = (u64) value;
	macsec_read_reg(ctx, (u16)(0x21d), LINE, &value);
	uncntl_cnts->if_in_multicast_pkts = (u64) value;
	macsec_read_reg(ctx, (u16)(0x21e), LINE, &value);
	uncntl_cnts->if_in_broadcast_pkts = (u64) value;
	// Need to fix for Multiple RxSCs
	uncntl_cnts->if_in_errors = secy_cnts->in_pkts_bad_tag +
				    secy_cnts->in_pkts_no_sci +
				    rxsc_cnts->in_pkts_not_valid +
				    rxsc_cnts->in_pkts_not_using_sa;
	uncntl_cnts->if_in_discards = secy_cnts->in_pkts_no_tag +
				      secy_cnts->in_pkts_overrun +
				      rxsc_cnts->in_pkts_late;

	// Line MAC Tx Counters
	// Need to fix for Multiplex SecYs, record = 0:
	if (!macsec_txsa_protect_frame_get(ctx, 0) && macsec_ver == REV_B) {
		uncntl_cnts->if_out_octets = cntl_cnts->if_out_octets +
					     (cntl_cnts->if_in_pkts * 4);
	} else if (always_include_sci) { // Need to fix: always_include_sci
		// Sectag = 16, ICV = 16, CRC = 4
		uncntl_cnts->if_out_octets = cntl_cnts->if_out_octets +
					     (cntl_cnts->if_in_pkts * (16+16+4));
	} else {
		// Sectag = 8, ICV = 16, CRC = 4
		uncntl_cnts->if_out_octets = cntl_cnts->if_out_octets +
					     (cntl_cnts->if_in_pkts * (8+16+4));
	}
	if (comm_cnts->if_out_octets > uncntl_cnts->if_out_octets) {
		uncntl_cnts->if_out_octets = (comm_cnts->if_out_octets -
					      uncntl_cnts->if_out_octets);
	} else {
		uncntl_cnts->if_out_octets = comm_cnts->if_out_octets;
	}

	macsec_read_reg(ctx, (u16)(0x22f), LINE, &value);
	uncntl_cnts->if_out_ucast_pkts = (u64) value;
	macsec_read_reg(ctx, (u16)(0x230), LINE, &value);
	uncntl_cnts->if_out_multicast_pkts = (u64) value;
	macsec_read_reg(ctx, (u16)(0x231), LINE, &value);
	uncntl_cnts->if_out_broadcast_pkts = (u64) value;
	uncntl_cnts->if_out_errors = secy_cnts->out_pkts_too_long;

	macsec_store_counters();

	printf("\nUncontrolled Port Counters:\n");
	printf("In Octets\t\t: %llu\n", uncntl_cnts->if_in_octets);
	printf("In Ucast Packets\t: %llu\n", uncntl_cnts->if_in_ucast_pkts);
	printf("In Mcast Packets\t: %llu\n", uncntl_cnts->if_in_multicast_pkts);
	printf("In Bcast Packets\t: %llu\n", uncntl_cnts->if_in_broadcast_pkts);
	printf("In Discards\t\t: %llu\n", uncntl_cnts->if_in_discards);
	printf("In Errors\t\t: %llu\n", uncntl_cnts->if_in_errors);
	printf("Out Octets\t\t: %llu\n", uncntl_cnts->if_out_octets);
	printf("Out Errors\t\t: %llu\n", uncntl_cnts->if_out_errors);
	printf("Out Ucast Packets\t: %llu\n", uncntl_cnts->if_out_ucast_pkts);
	printf("Out Mcast Packets\t: %llu\n", uncntl_cnts->if_out_multicast_pkts);
	printf("Out Bcast Packets\t: %llu\n", uncntl_cnts->if_out_broadcast_pkts);

	return 0;
}
