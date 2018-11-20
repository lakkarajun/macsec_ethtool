/* Copyright (c) 2018 Microchip  */
#include <stdio.h>
#include "internal.h"

#define INGR 0x38
#define EGR  0x3c

#define MACSEC_DISP_REG(ctx, d, a, b, v) \
	macsec_read_reg(ctx, a, b, v);       \
	printf("%-10s %-40s 0x%-10x 0x%-12x\n", ctx->devname, d, a, *v)

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
