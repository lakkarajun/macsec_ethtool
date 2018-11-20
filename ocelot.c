/* Copyright (c) 2018 Microchip  */
#include <stdio.h>
#include "internal.h"

/* Register Bit Masks */
/* ANA:ANAGEFIL */
#define OCELOT_B_DOM_EN           (1 << 22)
#define OCELOT_B_DOM_VAL          (1 << 21)
#define OCELOT_AGE_LOCKED         (1 << 20)
#define OCELOT_PID_EN             (1 << 19)
#define OCELOT_PID_VAL            (0x1F << 18)
#define OCELOT_VID_EN             (1 << 13)
#define OCELOT_VID_VAL            (0xfff)

/* ANA:ANEVENTS */
#define OCELOT_MSTI_DROP          (1 << 27)
#define OCELOT_ACLKILL            (1 << 26)
#define OCELOT_ACLUSED            (1 << 25)
#define OCELOT_AUTOAGE            (1 << 24)

int
ocelot_dump_regs(struct ethtool_drvinfo *info, struct ethtool_regs *regs)
{
	u32 *regs_buff = (u32 *)regs->data;
	u32 reg;
	u8 version = (u8)(regs->version);

    printf("Raju:%d:%s: version:%d\n", __LINE__, __func__, regs->version);
	if (version != 1)
		return -1;

	/* ANA ANAGEFIL register */
	reg = regs_buff[0];
	fprintf(stdout,
		"0x88_2403: ANAGEFIL(register)                         0x%08X\n"
		"       B-domain:                                      %s\n"
		"       B-domain flag used:                            %s\n"
		"       Locked entries aged:                           %s\n"
		"       PID VAL aged:                                  %s\n"
		"       PID VALs:                                      0x%x\n"
		"       VID:                                           %s\n"
		"       VIDs:                                          0x%x\n",
		reg,
		reg & OCELOT_B_DOM_EN ? "enabled"  : "disabled",
		reg & OCELOT_B_DOM_VAL ? "yes" : "no",
		reg & OCELOT_AGE_LOCKED ? "yes" : "no",
		reg & OCELOT_PID_EN ? "enabled" : "disabled",
		(reg & OCELOT_PID_VAL >> 18),
		reg & OCELOT_VID_EN ? "enabled" : "disabled",
		reg & OCELOT_PID_VAL);

	/* ANA ANEVENTS register */
	reg = regs_buff[1];
	fprintf(stdout,
		"0x88_2404: ANEVENTS (register)                        0x%08X\n"
		"       Frame discarded due to block MSTI:             %s\n"
		"       Frame discarded due to an ACL rule:            %s\n"
		"       ACL action done:                               %s\n"
		"       AUTOAGE done:                                  %s\n",
		reg,
		reg & OCELOT_MSTI_DROP ? "yes"      : "no",
		reg & OCELOT_ACLKILL ? "yes"  : "no",
		reg & OCELOT_ACLUSED ? "yes"  : "no",
		reg & OCELOT_AUTOAGE ? "yes"  : "no");

	return 0;
}

