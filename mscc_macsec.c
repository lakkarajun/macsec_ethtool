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
} macsec_controlled_counters_t;

typedef struct {
	u64 if_in_octets;
	u64 if_in_ucast_pkts;
	u64 if_in_multicast_pkts;
	u64 if_in_broadcast_pkts;
	u64 if_in_discards;
	u64 if_in_errors;
	u64 if_out_octets;
	u64 if_out_ucast_pkts;
	u64 if_out_broadcast_pkts;
	u64 if_out_errors;
} macsec_common_counters_t;

typedef struct {
	macsec_txsa_counters_t txsa_counter[MAX_RECORDS];
	macsec_rxsa_counters_t rxsa_counter[MAX_RECORDS];
	macsec_txsc_counters_t txsc_counter;
	macsec_rxsc_counters_t rxsc_counter;
	macsec_secy_counters_t secy_counter;
	macsec_controlled_counters_t macsec_controlled_counter;
	macsec_common_counters_t macsec_common_counter;
	macsec_common_counters_t macsec_uncontrolled_counter;
} macsec_all_counters_t;
static macsec_all_counters_t macsec_all_counters;

static macsec_common_counters_t macsec_common_counters;
static macsec_common_counters_t macsec_uncontrolled_counters;

int macsec_txsc_counters_dump(struct cmd_context *ctx);
int macsec_rxsc_counters_dump(struct cmd_context *ctx);
int macsec_secy_counters_dump(struct cmd_context *ctx);

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
	printf("%-40s %-12lld\n", "if_rx_octets", count64);
	macsec_read_reg(ctx, (u16)(0x13d), HOST, &value);
	count64 = (u64)value;
	macsec_read_reg(ctx, (u16)(0x13e), HOST, &value);
	count64 += (u64)value;
	printf("%-40s %-12lld\n", "if_rx_in_bytes", count64);
	MACSEC_DISP_CNT(ctx, "if_rx_pause_pkts", (u16)(0x11a), HOST, &value);
	MACSEC_DISP_CNT(ctx, "if_rx_ucast_pkts", (u16)(0x11c), HOST, &value);
	MACSEC_DISP_CNT(ctx, "if_rx_multicast_pkts", (u16)(0x11d), HOST, &value);
	MACSEC_DISP_CNT(ctx, "if_rx_broadcast_pkts", (u16)(0x11e), HOST, &value);
	macsec_read_reg(ctx, (u16)(0x13b), HOST, &value);
	count64 = (u64)value;
	macsec_read_reg(ctx, (u16)(0x139), HOST, &value);
	count64 += (u64)value;
	printf("%-40s %-12lld\n", "if_rx_in_bytes", count64);
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
	printf("%-40s %-12lld\n", "if_rx_errors", count64);
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
	printf("%-40s %-12lld\n", "if_rx_StatsPkts", stats_pkts);
	macsec_read_reg(ctx, (u16)(0x13f), HOST, &value);
	count64 = (u64)value;
	macsec_read_reg(ctx, (u16)(0x140), HOST, &value);
	count64 += (u64)value;
	printf("%-40s %-12lld\n", "if_tx_octets", count64);
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
	printf("%-40s %-12lld\n", "if_tx_StatsPkts", stats_pkts);

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

	printf("\nMACSEC HOST MAC statistics cleared\n\n");

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
	printf("%-40s %-12lld\n", "if_rx_octets", count64);
	macsec_read_reg(ctx, (u16)(0x23d), LINE, &value);
	count64 = (u64)value;
	macsec_read_reg(ctx, (u16)(0x23e), LINE, &value);
	count64 += (u64)value;
	printf("%-40s %-12lld\n", "if_rx_in_bytes", count64);
	MACSEC_DISP_CNT(ctx, "if_rx_pause_pkts", (u16)(0x21a), LINE, &value);
	MACSEC_DISP_CNT(ctx, "if_rx_ucast_pkts", (u16)(0x21c), LINE, &value);
	MACSEC_DISP_CNT(ctx, "if_rx_multicast_pkts", (u16)(0x21d), LINE, &value);
	MACSEC_DISP_CNT(ctx, "if_rx_broadcast_pkts", (u16)(0x21e), LINE, &value);
	macsec_read_reg(ctx, (u16)(0x23b), LINE, &value);
	count64 = (u64)value;
	macsec_read_reg(ctx, (u16)(0x239), LINE, &value);
	count64 += (u64)value;
	printf("%-40s %-12lld\n", "if_rx_in_bytes", count64);
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
	printf("%-40s %-12lld\n", "if_rx_errors", count64);
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
	printf("%-40s %-12lld\n", "if_rx_StatsPkts", stats_pkts);
	macsec_read_reg(ctx, (u16)(0x23f), LINE, &value);
	count64 = (u64)value;
	macsec_read_reg(ctx, (u16)(0x240), LINE, &value);
	count64 += (u64)value;
	printf("%-40s %-12lld\n", "if_tx_octets", count64);
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
	printf("%-40s %-12lld\n", "if_tx_StatsPkts", stats_pkts);

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

	printf("\nMACSEC LINE MAC statistics cleared\n\n");

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
	printf("\nMACSEC statistics cleared\n\n");

	return 0;
}

int macsec_tx_sa_counters_dump(struct cmd_context *ctx, const u16 record)
{
	u32 value;
	u64 out_pkts_cnt = 0;

	memset(&macsec_all_counters, 0, sizeof(macsec_all_counters_t));
	macsec_restore_counters();
	macsec_read_reg(ctx, (u16)(0xa005 | (record * 32)), EGR, &value);
	out_pkts_cnt = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0xa004 | (record * 32)), EGR, &value);
	out_pkts_cnt |= (u64) value;
	if (macsec_txsa_confidentiality_get(ctx, record)) {
		macsec_all_counters.txsa_counter[record].out_pkts_encrypted += out_pkts_cnt;
		macsec_all_counters.txsa_counter[record].out_pkts_protected = 0;
	} else {
		macsec_all_counters.txsa_counter[record].out_pkts_encrypted = 0;
		macsec_all_counters.txsa_counter[record].out_pkts_protected += out_pkts_cnt;
	}
	printf("\nTX SA Counters: Record(%d) \n", record);
	printf("Packets encrypted\t: %lld\n", macsec_all_counters.txsa_counter[record].out_pkts_encrypted);
	printf("Packets protected\t: %lld\n", macsec_all_counters.txsa_counter[record].out_pkts_protected);
	macsec_store_counters();
	// TBD
	macsec_txsc_counters_dump(ctx);
	macsec_secy_counters_dump(ctx);

	return 0;
}

int macsec_rx_sa_counters_dump(struct cmd_context *ctx, const u16 record)
{
	u32 value;
	u64 in_pkts_ok = 0;
	u64 in_pkts_invalid = 0;
	u64 in_pkts_not_valid = 0;
    u64 in_pkts_not_using_sa = 0;
	u64 in_pkts_unused_sa = 0;
	u64 in_pkts_unchecked = 0;
	u64 in_pkts_delayed = 0;
	u64 in_pkts_late = 0;
	u64 in_octets_decrypted = 0;
//	u64 if_in_ucast_pkts = 0;    // Adress: 0x2016-17   Rev B
//	u64 if_in_multicast_pkt = 0;  // Address: 0x2018-19 Rev B
//	u64 if_in_broadcast_pkts = 0; // Address: 0x201a-1b Rev B

	memset(&macsec_all_counters, 0, sizeof(macsec_all_counters_t));
	macsec_restore_counters();
	macsec_read_reg(ctx, (u16)(0x200b | (record * 32)), INGR, &value);
	in_pkts_ok = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x200a | (record * 32)), INGR, &value);
	in_pkts_ok |= (u64) value;
	macsec_all_counters.rxsa_counter[record].in_pkts_ok += in_pkts_ok;
	macsec_read_reg(ctx, (u16)(0x200d | (record * 32)), INGR, &value);
	in_pkts_invalid = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x200c | (record * 32)), INGR, &value);
	in_pkts_invalid |= (u64) value;
	macsec_all_counters.rxsa_counter[record].in_pkts_invalid += in_pkts_invalid;
	macsec_read_reg(ctx, (u16)(0x200f | (record * 32)), INGR, &value);
	in_pkts_not_valid = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x200e | (record * 32)), INGR, &value);
	in_pkts_not_valid |= (u64) value;
	macsec_all_counters.rxsa_counter[record].in_pkts_not_valid += in_pkts_not_valid;
	macsec_read_reg(ctx, (u16)(0x2011 | (record * 32)), INGR, &value);
	in_pkts_not_using_sa = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x2010 | (record * 32)), INGR, &value);
	in_pkts_not_using_sa |= (u64) value;
	macsec_all_counters.rxsa_counter[record].in_pkts_not_using_sa += in_pkts_not_using_sa;
	macsec_read_reg(ctx, (u16)(0x2013 | (record * 32)), INGR, &value);
	in_pkts_unused_sa = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x2012 | (record * 32)), INGR, &value);
	in_pkts_unused_sa |= (u64) value;
	macsec_all_counters.rxsa_counter[record].in_pkts_unused_sa += in_pkts_unused_sa;
	macsec_read_reg(ctx, (u16)(0x2005 | (record * 32)), INGR, &value);
	in_pkts_unchecked = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x2004 | (record * 32)), INGR, &value);
	in_pkts_unchecked |= (u64) value;
	macsec_all_counters.rxsa_counter[record].in_pkts_unchecked += in_pkts_unchecked;
	macsec_read_reg(ctx, (u16)(0x2007 | (record * 32)), INGR, &value);
	in_pkts_delayed = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x2006 | (record * 32)), INGR, &value);
	in_pkts_delayed |= (u64) value;
	macsec_all_counters.rxsa_counter[record].in_pkts_delayed += in_pkts_delayed;
	macsec_read_reg(ctx, (u16)(0x2009 | (record * 32)), INGR, &value);
	in_pkts_late = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x2008 | (record * 32)), INGR, &value);
	in_pkts_late |= (u64) value;
	macsec_all_counters.rxsa_counter[record].in_pkts_late += in_pkts_late;
    // Need to fix here:
	macsec_read_reg(ctx, (u16)(0x2001 | (record * 32)), INGR, &value);
    in_octets_decrypted = (u64) value << 32;
	macsec_read_reg(ctx, (u16)(0x2000 | (record * 32)), INGR, &value);
    in_octets_decrypted |= (u64) value;
	macsec_all_counters.rxsc_counter.in_octets_decrypted += in_octets_decrypted;

	printf("\nRX SA Counters: Record(%d):\n", record);
	printf("Packets Ok\t\t: %lld\n", macsec_all_counters.rxsa_counter[record].in_pkts_ok);
	printf("Packets Invalid\t\t: %lld\n", macsec_all_counters.rxsa_counter[record].in_pkts_invalid);
	printf("Packets Not valid\t: %lld\n", macsec_all_counters.rxsa_counter[record].in_pkts_not_valid);
	printf("Packets Not using SA\t: %lld\n", macsec_all_counters.rxsa_counter[record].in_pkts_not_using_sa);
	printf("Packets Unused SA\t: %lld\n", macsec_all_counters.rxsa_counter[record].in_pkts_unused_sa);

	printf("\nRX SC Counters: Record(%d):\n", record);
	printf("Packets unchecked\t: %lld\n", macsec_all_counters.rxsa_counter[record].in_pkts_unchecked);
	printf("Packets delayed\t\t: %lld\n", macsec_all_counters.rxsa_counter[record].in_pkts_delayed);
	printf("Packets Late\t\t: %lld\n", macsec_all_counters.rxsa_counter[record].in_pkts_late);
	printf("Octets Decrypted\t: %lld\n", macsec_all_counters.rxsc_counter.in_octets_decrypted);
	macsec_store_counters();
	// TBD
	macsec_rxsc_counters_dump(ctx);
	macsec_secy_counters_dump(ctx);

	return 0;
}

int macsec_txsc_counters_dump(struct cmd_context *ctx)
{
	u16 record;

	memset(&macsec_all_counters, 0, sizeof(macsec_all_counters_t));
	macsec_restore_counters();
	for (record = 0; record < MAX_RECORDS; record++) {
		macsec_all_counters.txsc_counter.out_pkts_protected += macsec_all_counters.txsa_counter[record].out_pkts_protected;
		macsec_all_counters.txsc_counter.out_pkts_encrypted += macsec_all_counters.txsa_counter[record].out_pkts_encrypted;
	}

	printf("\nTX SC Counters: \n");
	printf("Packets protected\t: %lld\n", macsec_all_counters.txsc_counter.out_pkts_protected);
	printf("Packets encrypted\t: %lld\n", macsec_all_counters.txsc_counter.out_pkts_encrypted);
	printf("\nOctects protected\t: %lld\n", macsec_all_counters.txsc_counter.out_octets_protected);
	printf("Octects encrypted\t: %lld\n", macsec_all_counters.txsc_counter.out_octets_encrypted);

	return 0;
}

int macsec_rxsc_counters_dump(struct cmd_context *ctx)
{
	u16 record;

	memset(&macsec_all_counters, 0, sizeof(macsec_all_counters_t));
	macsec_restore_counters();
	for (record = 0; record < MAX_RECORDS; record++) {
		macsec_all_counters.rxsc_counter.in_pkts_ok += macsec_all_counters.rxsa_counter[record].in_pkts_ok;
		macsec_all_counters.rxsc_counter.in_pkts_invalid += macsec_all_counters.rxsa_counter[record].in_pkts_invalid;
		macsec_all_counters.rxsc_counter.in_pkts_not_valid += macsec_all_counters.rxsa_counter[record].in_pkts_not_valid;
		macsec_all_counters.rxsc_counter.in_pkts_not_using_sa += macsec_all_counters.rxsa_counter[record].in_pkts_not_using_sa;
		macsec_all_counters.rxsc_counter.in_pkts_unused_sa += macsec_all_counters.rxsa_counter[record].in_pkts_unused_sa;
		macsec_all_counters.rxsc_counter.in_pkts_unchecked += macsec_all_counters.rxsa_counter[record].in_pkts_unchecked;
		macsec_all_counters.rxsc_counter.in_pkts_delayed += macsec_all_counters.rxsa_counter[record].in_pkts_delayed;
		macsec_all_counters.rxsc_counter.in_pkts_late += macsec_all_counters.rxsa_counter[record].in_pkts_late;
	}

	printf("\nRX SC Counters: \n");
	printf("Packets unchecked\t: %lld\n", macsec_all_counters.rxsc_counter.in_pkts_unchecked);
	printf("Packets delayed \t: %lld\n", macsec_all_counters.rxsc_counter.in_pkts_delayed);
	printf("Packets Late\t\t: %lld\n", macsec_all_counters.rxsc_counter.in_pkts_late);
	printf("Packets Ok \t\t: %lld\n", macsec_all_counters.rxsc_counter.in_pkts_ok);
	printf("Packets Invalid \t: %lld\n", macsec_all_counters.rxsc_counter.in_pkts_invalid);
	printf("Packets Not valid \t: %lld\n", macsec_all_counters.rxsc_counter.in_pkts_not_valid);
	printf("Packets Not using SA \t: %lld\n", macsec_all_counters.rxsc_counter.in_pkts_not_using_sa);
	printf("Packets Unused SA \t: %lld\n", macsec_all_counters.rxsc_counter.in_pkts_unused_sa);
	printf("Octets Validated \t: %lld\n", macsec_all_counters.rxsc_counter.in_octets_validated);
	printf("Octets Decrypted \t: %lld\n", macsec_all_counters.rxsc_counter.in_octets_decrypted);

	// Need to remove from here
	macsec_rxsa_validate_frame_get(ctx, 0);
	return 0;
}

int macsec_secy_counters_dump(struct cmd_context *ctx)
{
	u32 value;
	u64 out_pkts_too_long;
	u64 cnt;
	//u64 out_octets_protected;
	// u64 out_octets_encrypted;
	u16 record;

	memset(&macsec_all_counters, 0, sizeof(macsec_all_counters_t));
	macsec_restore_counters();
	for (record = 0; record < MAX_RECORDS; record++) {
		macsec_read_reg(ctx, (u16)(0xa007 | (record * 32)), INGR, &value);
		out_pkts_too_long = (u64) value << 32;
		macsec_read_reg(ctx, (u16)(0xa006 | (record * 32)), INGR, &value);
		out_pkts_too_long |= (u64) value;
		macsec_all_counters.secy_counter.out_pkts_too_long += out_pkts_too_long;
		macsec_read_reg(ctx, (u16)(0xa001 | (record * 32)), INGR, &value);
		cnt = (u64) value << 32;
		macsec_read_reg(ctx, (u16)(0xa000 | (record * 32)), INGR, &value);
		cnt |= (u64) value;
		if (!macsec_txsa_protect_frame_get(ctx, record)) {
			macsec_all_counters.secy_counter.out_pkts_untagged += cnt;
		} else if(macsec_txsa_confidentiality_get(ctx, record)) {

		}
	}

	for (record = 0; record < MAX_RECORDS; record++) {
		macsec_all_counters.secy_counter.out_octets_protected +=
			(macsec_all_counters.txsa_counter[record].out_pkts_encrypted +
             macsec_all_counters.txsa_counter[record].out_pkts_protected);
	}

	printf("\nSecY Counters:\n");
	return 0;
}

