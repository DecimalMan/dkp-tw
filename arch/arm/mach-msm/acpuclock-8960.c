/* Copyright (c) 2011, Code Aurora Forum. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define ALLOW_OC_STEPS
#define FREQ_TABLE_SIZE 33
#define MAX_BUS_LVL 7
//#define ENABLE_VMIN
//#define EXTRA_TABLES

static unsigned int final_vmin = 700000;

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/cpufreq.h>
#include <linux/cpu.h>
#include <linux/regulator/consumer.h>

#include <asm/mach-types.h>
#include <asm/cpu.h>

#include <mach/board.h>
#include <mach/msm_iomap.h>
#include <mach/rpm-regulator.h>
#include <mach/msm_bus.h>
#include <mach/msm_bus_board.h>
#include <mach/socinfo.h>
#include <mach/msm-krait-l2-accessors.h>
#include <mach/rpm-regulator.h>

#include "acpuclock.h"
#if defined(CONFIG_SEC_DEBUG_DCVS_LOG) || defined(CONFIG_SEC_L1_DCACHE_PANIC_CHK)
#include <mach/sec_debug.h>
#endif

/*
 * Source IDs.
 * These must be negative to not overlap with the source IDs
 * used by the 8x60 local clock driver.
 */
#define PLL_8			 0
#define HFPLL			-1
#define QSB			-2

/* Mux source selects. */
#define PRI_SRC_SEL_SEC_SRC	0
#define PRI_SRC_SEL_HFPLL	1
#define PRI_SRC_SEL_HFPLL_DIV2	2
#define SEC_SRC_SEL_QSB		0
#define SEC_SRC_SEL_AUX		2

/* HFPLL registers offsets. */
#define HFPLL_MODE		0x00
#define HFPLL_CONFIG_CTL	0x04
#define HFPLL_L_VAL		0x08
#define HFPLL_M_VAL		0x0C
#define HFPLL_N_VAL		0x10
#define HFPLL_DROOP_CTL		0x14

/* CP15 L2 indirect addresses. */
#define L2CPMR_IADDR		0x500
#define L2CPUCPMR_IADDR		0x501

#define STBY_KHZ		1

#define HFPLL_NOMINAL_VDD	1050000
#define HFPLL_LOW_VDD		 850000
#define HFPLL_LOW_VDD_PLL_L_MAX	0x28

#define SECCLKAGD		BIT(4)

/* PTE EFUSE register. */
#define QFPROM_PTE_ROW0_MSB	(MSM_QFPROM_BASE + 0x00BC)
#define QFPROM_PTE_ROW1_LSB	(MSM_QFPROM_BASE + 0x00C0)

enum scalables {
	CPU0 = 0,
	CPU1,
	CPU2,
	CPU3,
	L2,
	NUM_SCALABLES
};

enum vregs {
	VREG_CORE,
	VREG_MEM,
	VREG_DIG,
	VREG_HFPLL_A,
	VREG_HFPLL_B,
	NUM_VREG
};

/* max_vdd gets written to for slow/nominal */
struct vreg {
	const char name[15];
	/*const*/ unsigned int max_vdd;
	const int rpm_vreg_voter;
	const int rpm_vreg_id;
	struct regulator *reg;
	unsigned int cur_vdd;
};

struct core_speed {
	unsigned int		khz;
	int			src;
	unsigned int		pri_src_sel;
	unsigned int		sec_src_sel;
	unsigned int		pll_l_val;
};

struct l2_level {
	struct core_speed	speed;
	unsigned int		vdd_dig;
	unsigned int		vdd_mem;
	unsigned int		bw_level;
};

struct acpu_level {
	unsigned int		use_for_scaling;
	struct core_speed	speed;
	struct l2_level		*l2_level;
	unsigned int		vdd_core;
};

struct scalable {
	void * __iomem const hfpll_base;
	void * __iomem const aux_clk_sel;
	const uint32_t l2cpmr_iaddr;
	struct core_speed *current_speed;
	struct l2_level *l2_vote;
	struct vreg vreg[NUM_VREG];
	bool first_set_call;
};

static struct scalable scalable_8960[] = {
	[CPU0] = {
			.hfpll_base      = MSM_HFPLL_BASE + 0x200,
			.aux_clk_sel     = MSM_ACC0_BASE  + 0x014,
			.l2cpmr_iaddr    = L2CPUCPMR_IADDR,
			.vreg[VREG_CORE] = { "krait0",     1300000 },
			.vreg[VREG_MEM]  = { "krait0_mem", 1150000,
					     RPM_VREG_VOTER1,
					     RPM_VREG_ID_PM8921_L24 },
			.vreg[VREG_DIG]  = { "krait0_dig", 1150000,
					     RPM_VREG_VOTER1,
					     RPM_VREG_ID_PM8921_S3 },
			.vreg[VREG_HFPLL_A] = { "hfpll", 2100000,
					     RPM_VREG_VOTER1,
					     RPM_VREG_ID_PM8921_S8 },
			.vreg[VREG_HFPLL_B] = { "hfpll", 1800000,
					     RPM_VREG_VOTER1,
					     RPM_VREG_ID_PM8921_L23 },
		},
	[CPU1] = {
			.hfpll_base      = MSM_HFPLL_BASE + 0x300,
			.aux_clk_sel     = MSM_ACC1_BASE  + 0x014,
			.l2cpmr_iaddr    = L2CPUCPMR_IADDR,
			.vreg[VREG_CORE] = { "krait1",     1300000 },
			.vreg[VREG_MEM]  = { "krait0_mem", 1150000,
					     RPM_VREG_VOTER2,
					     RPM_VREG_ID_PM8921_L24 },
			.vreg[VREG_DIG]  = { "krait0_dig", 1150000,
					     RPM_VREG_VOTER2,
					     RPM_VREG_ID_PM8921_S3 },
			.vreg[VREG_HFPLL_A] = { "hfpll", 2100000,
					     RPM_VREG_VOTER2,
					     RPM_VREG_ID_PM8921_S8 },
			.vreg[VREG_HFPLL_B] = { "hfpll", 1800000,
					     RPM_VREG_VOTER2,
					     RPM_VREG_ID_PM8921_L23 },
		},
	[L2] = {
			.hfpll_base   = MSM_HFPLL_BASE    + 0x400,
			.aux_clk_sel  = MSM_APCS_GCC_BASE + 0x028,
			.l2cpmr_iaddr = L2CPMR_IADDR,
			.vreg[VREG_HFPLL_A] = { "hfpll", 2100000,
					     RPM_VREG_VOTER6,
					     RPM_VREG_ID_PM8921_S8 },
			.vreg[VREG_HFPLL_B] = { "hfpll", 1800000,
					     RPM_VREG_VOTER6,
					     RPM_VREG_ID_PM8921_L23 },
		},
};

static DEFINE_MUTEX(driver_lock);
static DEFINE_SPINLOCK(l2_lock);

#ifdef EXTRA_TABLES
static struct scalable scalable_8064[] = {
	[CPU0] = {
			.hfpll_base      = MSM_HFPLL_BASE + 0x200,
			.aux_clk_sel     = MSM_ACC0_BASE  + 0x014,
			.l2cpmr_iaddr    = L2CPUCPMR_IADDR,
			.vreg[VREG_CORE] = { "krait0",     1150000 },
			.vreg[VREG_MEM]  = { "krait0_mem", 1150000,
					     RPM_VREG_VOTER1,
					     RPM_VREG_ID_PM8921_L24 },
			.vreg[VREG_DIG]  = { "krait0_dig", 1150000,
					     RPM_VREG_VOTER1,
					     RPM_VREG_ID_PM8921_S3 },
		},
	[CPU1] = {
			.hfpll_base      = MSM_HFPLL_BASE + 0x240,
			.aux_clk_sel     = MSM_ACC1_BASE  + 0x014,
			.l2cpmr_iaddr    = L2CPUCPMR_IADDR,
			.vreg[VREG_CORE] = { "krait1",     1150000 },
			.vreg[VREG_MEM]  = { "krait0_mem", 1150000,
					     RPM_VREG_VOTER2,
					     RPM_VREG_ID_PM8921_L24 },
			.vreg[VREG_DIG]  = { "krait0_dig", 1150000,
					     RPM_VREG_VOTER2,
					     RPM_VREG_ID_PM8921_S3 },
		},
	[CPU2] = {
			.hfpll_base      = MSM_HFPLL_BASE + 0x280,
			.aux_clk_sel     = MSM_ACC2_BASE  + 0x014,
			.l2cpmr_iaddr    = L2CPUCPMR_IADDR,
			.vreg[VREG_CORE] = { "krait2",     1150000 },
			.vreg[VREG_MEM]  = { "krait0_mem", 1150000,
					     RPM_VREG_VOTER4,
					     RPM_VREG_ID_PM8921_L24 },
			.vreg[VREG_DIG]  = { "krait0_dig", 1150000,
					     RPM_VREG_VOTER4,
					     RPM_VREG_ID_PM8921_S3 },
		},
	[CPU3] = {
			.hfpll_base      = MSM_HFPLL_BASE + 0x2C0,
			.aux_clk_sel     = MSM_ACC3_BASE  + 0x014,
			.l2cpmr_iaddr    = L2CPUCPMR_IADDR,
			.vreg[VREG_CORE] = { "krait3",     1150000 },
			.vreg[VREG_MEM]  = { "krait0_mem", 1150000,
					     RPM_VREG_VOTER5,
					     RPM_VREG_ID_PM8921_L24 },
			.vreg[VREG_DIG]  = { "krait0_dig", 1150000,
					     RPM_VREG_VOTER5,
					     RPM_VREG_ID_PM8921_S3 },
		},
	[L2] = {
			.hfpll_base   = MSM_HFPLL_BASE    + 0x300,
			.aux_clk_sel  = MSM_APCS_GCC_BASE + 0x028,
			.l2cpmr_iaddr = L2CPMR_IADDR,
		},
};

/*TODO: Update the rpm vreg id when the rpm driver is ready */
static struct scalable scalable_8930[] = {
	[CPU0] = {
			.hfpll_base      = MSM_HFPLL_BASE + 0x200,
			.aux_clk_sel     = MSM_ACC0_BASE  + 0x014,
			.l2cpmr_iaddr    = L2CPUCPMR_IADDR,
			.vreg[VREG_CORE] = { "krait0",     1300000 },
			.vreg[VREG_MEM]  = { "krait0_mem", 1150000,
					     RPM_VREG_VOTER1,
					     RPM_VREG_ID_PM8921_L24 },
			.vreg[VREG_DIG]  = { "krait0_dig", 1150000,
					     RPM_VREG_VOTER1,
					     RPM_VREG_ID_PM8921_S3 },
			.vreg[VREG_HFPLL_A] = { "hfpll", 2100000,
					     RPM_VREG_VOTER1,
					     RPM_VREG_ID_PM8921_S8 },
			.vreg[VREG_HFPLL_B] = { "hfpll", 1800000,
					     RPM_VREG_VOTER1,
					     RPM_VREG_ID_PM8921_L23 },
		},
	[CPU1] = {
			.hfpll_base      = MSM_HFPLL_BASE + 0x300,
			.aux_clk_sel     = MSM_ACC1_BASE  + 0x014,
			.l2cpmr_iaddr    = L2CPUCPMR_IADDR,
			.vreg[VREG_CORE] = { "krait1",     1300000 },
			.vreg[VREG_MEM]  = { "krait0_mem", 1150000,
					     RPM_VREG_VOTER2,
					     RPM_VREG_ID_PM8921_L24 },
			.vreg[VREG_DIG]  = { "krait0_dig", 1150000,
					     RPM_VREG_VOTER2,
					     RPM_VREG_ID_PM8921_S3 },
			.vreg[VREG_HFPLL_A] = { "hfpll", 2100000,
					     RPM_VREG_VOTER2,
					     RPM_VREG_ID_PM8921_S8 },
			.vreg[VREG_HFPLL_B] = { "hfpll", 1800000,
					     RPM_VREG_VOTER2,
					     RPM_VREG_ID_PM8921_L23 },
		},
	[L2] = {
			.hfpll_base   = MSM_HFPLL_BASE    + 0x400,
			.aux_clk_sel  = MSM_APCS_GCC_BASE + 0x028,
			.l2cpmr_iaddr = L2CPMR_IADDR,
			.vreg[VREG_HFPLL_A] = { "hfpll", 2100000,
					     RPM_VREG_VOTER6,
					     RPM_VREG_ID_PM8921_S8 },
			.vreg[VREG_HFPLL_B] = { "hfpll", 1800000,
					     RPM_VREG_VOTER6,
					     RPM_VREG_ID_PM8921_L23 },
		},
};

/*TODO: Update the rpm vreg id when the rpm driver is ready */
static struct scalable scalable_8627[] = {
	[CPU0] = {
			.hfpll_base      = MSM_HFPLL_BASE + 0x200,
			.aux_clk_sel     = MSM_ACC0_BASE  + 0x014,
			.l2cpmr_iaddr    = L2CPUCPMR_IADDR,
			.vreg[VREG_CORE] = { "krait0",     1300000 },
			.vreg[VREG_MEM]  = { "krait0_mem", 1150000,
					     RPM_VREG_VOTER1,
					     RPM_VREG_ID_PM8921_L24 },
			.vreg[VREG_DIG]  = { "krait0_dig", 1150000,
					     RPM_VREG_VOTER1,
					     RPM_VREG_ID_PM8921_S3 },
			.vreg[VREG_HFPLL_A] = { "hfpll", 2100000,
					     RPM_VREG_VOTER1,
					     RPM_VREG_ID_PM8921_S8 },
			.vreg[VREG_HFPLL_B] = { "hfpll", 1800000,
					     RPM_VREG_VOTER1,
					     RPM_VREG_ID_PM8921_L23 },
		},
	[CPU1] = {
			.hfpll_base      = MSM_HFPLL_BASE + 0x300,
			.aux_clk_sel     = MSM_ACC1_BASE  + 0x014,
			.l2cpmr_iaddr    = L2CPUCPMR_IADDR,
			.vreg[VREG_CORE] = { "krait1",     1300000 },
			.vreg[VREG_MEM]  = { "krait0_mem", 1150000,
					     RPM_VREG_VOTER2,
					     RPM_VREG_ID_PM8921_L24 },
			.vreg[VREG_DIG]  = { "krait0_dig", 1150000,
					     RPM_VREG_VOTER2,
					     RPM_VREG_ID_PM8921_S3 },
			.vreg[VREG_HFPLL_A] = { "hfpll", 2100000,
					     RPM_VREG_VOTER2,
					     RPM_VREG_ID_PM8921_S8 },
			.vreg[VREG_HFPLL_B] = { "hfpll", 1800000,
					     RPM_VREG_VOTER2,
					     RPM_VREG_ID_PM8921_L23 },
		},
	[L2] = {
			.hfpll_base   = MSM_HFPLL_BASE    + 0x400,
			.aux_clk_sel  = MSM_APCS_GCC_BASE + 0x028,
			.l2cpmr_iaddr = L2CPMR_IADDR,
			.vreg[VREG_HFPLL_A] = { "hfpll", 2100000,
					     RPM_VREG_VOTER6,
					     RPM_VREG_ID_PM8921_S8 },
			.vreg[VREG_HFPLL_B] = { "hfpll", 1800000,
					     RPM_VREG_VOTER6,
					     RPM_VREG_ID_PM8921_L23 },
		},
};
#endif /* EXTRA_TABLES */

static struct scalable *scalable;
static struct l2_level *l2_freq_tbl;
static struct acpu_level *acpu_freq_tbl;
static int l2_freq_tbl_size;
uint32_t global_pvs; /*  This code is temporary code */

/* Instantaneous bandwidth requests in MB/s. */
#define BW_MBPS(_bw) \
	{ \
		.vectors = (struct msm_bus_vectors[]){ \
			{\
				.src = MSM_BUS_MASTER_AMPSS_M0, \
				.dst = MSM_BUS_SLAVE_EBI_CH0, \
				.ib = (_bw) * 1000000ULL, \
				.ab = (_bw) *  100000ULL, \
			}, \
			{ \
				.src = MSM_BUS_MASTER_AMPSS_M1, \
				.dst = MSM_BUS_SLAVE_EBI_CH0, \
				.ib = (_bw) * 1000000ULL, \
				.ab = (_bw) *  100000ULL, \
			}, \
		}, \
		.num_paths = 2, \
	}
static struct msm_bus_paths bw_level_tbl[] = {
	[0] =  BW_MBPS(640), /* At least  80 MHz on bus. */
	[1] = BW_MBPS(1064), /* At least 133 MHz on bus. */
	[2] = BW_MBPS(1600), /* At least 200 MHz on bus. */
	[3] = BW_MBPS(2128), /* At least 266 MHz on bus. */
	[4] = BW_MBPS(3200), /* At least 400 MHz on bus. */
	[5] = BW_MBPS(3600), /* At least 450 MHz on bus. */
	[6] = BW_MBPS(3936), /* At least 492 MHz on bus. */
	[7] = BW_MBPS(4264), /* At least 533 MHz on bus. */
};

static struct msm_bus_scale_pdata bus_client_pdata = {
	.usecase = bw_level_tbl,
	.num_usecases = ARRAY_SIZE(bw_level_tbl),
	.active_only = 1,
	.name = "acpuclock",
};

static uint32_t bus_perf_client;

#ifdef EXTRA_TABLES
/* TODO: Update vdd_dig and vdd_mem when voltage data is available. */
#define L2(x) (&l2_freq_tbl_8960_kraitv1[(x)])
static struct l2_level l2_freq_tbl_8960_kraitv1[] = {
	[0]  = { {STBY_KHZ, QSB,   0, 0, 0x00 }, 1050000, 1050000, 0 },
	[1]  = { {  384000, PLL_8, 0, 2, 0x00 }, 1050000, 1050000, 1 },
	[2]  = { {  432000, HFPLL, 2, 0, 0x20 }, 1050000, 1050000, 1 },
	[3]  = { {  486000, HFPLL, 2, 0, 0x24 }, 1050000, 1050000, 1 },
	[4]  = { {  540000, HFPLL, 2, 0, 0x28 }, 1050000, 1050000, 1 },
	[5]  = { {  594000, HFPLL, 1, 0, 0x16 }, 1050000, 1050000, 2 },
	[6]  = { {  648000, HFPLL, 1, 0, 0x18 }, 1050000, 1050000, 2 },
	[7]  = { {  702000, HFPLL, 1, 0, 0x1A }, 1050000, 1050000, 2 },
	[8]  = { {  756000, HFPLL, 1, 0, 0x1C }, 1150000, 1150000, 2 },
	[9]  = { {  810000, HFPLL, 1, 0, 0x1E }, 1150000, 1150000, 3 },
	[10] = { {  864000, HFPLL, 1, 0, 0x20 }, 1150000, 1150000, 3 },
	[11] = { {  918000, HFPLL, 1, 0, 0x22 }, 1150000, 1150000, 3 },
};

static struct acpu_level acpu_freq_tbl_8960_kraitv1_slow[] = {
	{ 0, {STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   900000 },
	{ 1, {  384000, PLL_8, 0, 2, 0x00 }, L2(1),   900000 },
	{ 1, {  432000, HFPLL, 2, 0, 0x20 }, L2(6),   925000 },
	{ 1, {  486000, HFPLL, 2, 0, 0x24 }, L2(6),   925000 },
	{ 1, {  540000, HFPLL, 2, 0, 0x28 }, L2(6),   937500 },
	{ 1, {  594000, HFPLL, 1, 0, 0x16 }, L2(6),   962500 },
	{ 1, {  648000, HFPLL, 1, 0, 0x18 }, L2(6),   987500 },
	{ 1, {  702000, HFPLL, 1, 0, 0x1A }, L2(6),  1000000 },
	{ 1, {  756000, HFPLL, 1, 0, 0x1C }, L2(11), 1025000 },
	{ 1, {  810000, HFPLL, 1, 0, 0x1E }, L2(11), 1062500 },
	{ 1, {  864000, HFPLL, 1, 0, 0x20 }, L2(11), 1062500 },
	{ 1, {  918000, HFPLL, 1, 0, 0x22 }, L2(11), 1087500 },
	{ 0, { 0 } }
};

static struct acpu_level acpu_freq_tbl_8960_kraitv1_nom_fast[] = {
	{ 0, {STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   862500 },
	{ 1, {  384000, PLL_8, 0, 2, 0x00 }, L2(1),   862500 },
	{ 1, {  432000, HFPLL, 2, 0, 0x20 }, L2(6),   862500 },
	{ 1, {  486000, HFPLL, 2, 0, 0x24 }, L2(6),   887500 },
	{ 1, {  540000, HFPLL, 2, 0, 0x28 }, L2(6),   900000 },
	{ 1, {  594000, HFPLL, 1, 0, 0x16 }, L2(6),   925000 },
	{ 1, {  648000, HFPLL, 1, 0, 0x18 }, L2(6),   925000 },
	{ 1, {  702000, HFPLL, 1, 0, 0x1A }, L2(6),   937500 },
	{ 1, {  756000, HFPLL, 1, 0, 0x1C }, L2(11),  962500 },
	{ 1, {  810000, HFPLL, 1, 0, 0x1E }, L2(11), 1012500 },
	{ 1, {  864000, HFPLL, 1, 0, 0x20 }, L2(11), 1025000 },
	{ 1, {  918000, HFPLL, 1, 0, 0x22 }, L2(11), 1025000 },
	{ 0, { 0 } }
};
#else
#define acpu_freq_tbl_8960_kraitv1_slow NULL
#define acpu_freq_tbl_8960_kraitv1_nom_fast NULL
#endif /* EXTRA_TABLES */

#undef L2
#define L2(x) (&l2_freq_tbl_8960_kraitv2[(x)])

#if defined(CONFIG_MSM_CPU_MAX_CLK_1DOT2GHZ)

static struct l2_level l2_freq_tbl_8960_kraitv2[] = {
	[0]  = { {STBY_KHZ, QSB,   0, 0, 0x00 }, 1050000, 1050000, 0 },
	[1]  = { {  384000, PLL_8, 0, 2, 0x00 }, 1050000, 1050000, 1 },
	[2]  = { {  432000, HFPLL, 2, 0, 0x20 }, 1050000, 1050000, 2 },
	[3]  = { {  486000, HFPLL, 2, 0, 0x24 }, 1050000, 1050000, 2 },
	[4]  = { {  540000, HFPLL, 2, 0, 0x28 }, 1050000, 1050000, 2 },
	[5]  = { {  594000, HFPLL, 1, 0, 0x16 }, 1050000, 1050000, 2 },
	[6]  = { {  648000, HFPLL, 1, 0, 0x18 }, 1050000, 1050000, 4 },
	[7]  = { {  702000, HFPLL, 1, 0, 0x1A }, 1050000, 1050000, 4 },
	[8]  = { {  756000, HFPLL, 1, 0, 0x1C }, 1150000, 1150000, 4 },
	[9]  = { {  810000, HFPLL, 1, 0, 0x1E }, 1150000, 1150000, 4 },
	[10] = { {  864000, HFPLL, 1, 0, 0x20 }, 1150000, 1150000, 4 },
	[11] = { {  918000, HFPLL, 1, 0, 0x22 }, 1150000, 1150000, 6 },
	[12] = { {  972000, HFPLL, 1, 0, 0x24 }, 1150000, 1150000, 6 },
	[13] = { { 1026000, HFPLL, 1, 0, 0x26 }, 1150000, 1150000, 6 },
	[14] = { { 1080000, HFPLL, 1, 0, 0x28 }, 1150000, 1150000, 6 },
	[15] = { { 1134000, HFPLL, 1, 0, 0x2A }, 1150000, 1150000, 6 },
	[16] = { { 1188000, HFPLL, 1, 0, 0x2C }, 1150000, 1150000, 6 },
	[17] = { { 1242000, HFPLL, 1, 0, 0x2E }, 1150000, 1150000, 6 },
	[18] = { { 1296000, HFPLL, 1, 0, 0x30 }, 1150000, 1150000, 6 },
	[19] = { { 1350000, HFPLL, 1, 0, 0x32 }, 1150000, 1150000, 6 },
};

static struct acpu_level acpu_freq_tbl_8960_kraitv2_slow[] = {
	{ 0, { STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   950000 },
	{ 1, {   384000, PLL_8, 0, 2, 0x00 }, L2(1),   950000 },
	{ 0, {   432000, HFPLL, 2, 0, 0x20 }, L2(7),   975000 },
	{ 1, {   486000, HFPLL, 2, 0, 0x24 }, L2(7),   975000 },
	{ 0, {   540000, HFPLL, 2, 0, 0x28 }, L2(7),  1000000 },
	{ 1, {   594000, HFPLL, 1, 0, 0x16 }, L2(7),  1000000 },
	{ 0, {   648000, HFPLL, 1, 0, 0x18 }, L2(7),  1025000 },
	{ 1, {   702000, HFPLL, 1, 0, 0x1A }, L2(7),  1025000 },
	{ 0, {   756000, HFPLL, 1, 0, 0x1C }, L2(7),  1075000 },
	{ 1, {   810000, HFPLL, 1, 0, 0x1E }, L2(7),  1075000 },
	{ 0, {   864000, HFPLL, 1, 0, 0x20 }, L2(7),  1100000 },
	{ 1, {   918000, HFPLL, 1, 0, 0x22 }, L2(7),  1100000 },
	{ 0, {   972000, HFPLL, 1, 0, 0x24 }, L2(7),  1125000 },
	{ 1, {  1026000, HFPLL, 1, 0, 0x26 }, L2(7),  1125000 },
	{ 0, {  1080000, HFPLL, 1, 0, 0x28 }, L2(16), 1175000 },
	{ 1, {  1134000, HFPLL, 1, 0, 0x2A }, L2(16), 1175000 },
	{ 1, {  1188000, HFPLL, 1, 0, 0x2C }, L2(16), 1200000 },
#if 0
	/* This part is commented out only to MSM8960(1.2GHz) model */
	{ 1, {  1242000, HFPLL, 1, 0, 0x2E }, L2(16), 1200000 },
	{ 0, {  1296000, HFPLL, 1, 0, 0x30 }, L2(16), 1225000 },
	{ 1, {  1350000, HFPLL, 1, 0, 0x32 }, L2(16), 1225000 },
	{ 0, {  1404000, HFPLL, 1, 0, 0x34 }, L2(16), 1237500 },
	{ 1, {  1458000, HFPLL, 1, 0, 0x36 }, L2(16), 1237500 },
	{ 1, {  1512000, HFPLL, 1, 0, 0x38 }, L2(16), 1250000 },
#endif
	{ 0, { 0 } }
};

static struct acpu_level acpu_freq_tbl_8960_kraitv2_nom[] = {
	{ 0, { STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   900000 },
	{ 1, {   384000, PLL_8, 0, 2, 0x00 }, L2(1),   900000 },
	{ 0, {   432000, HFPLL, 2, 0, 0x20 }, L2(7),   925000 },
	{ 1, {   486000, HFPLL, 2, 0, 0x24 }, L2(7),   925000 },
	{ 0, {   540000, HFPLL, 2, 0, 0x28 }, L2(7),   950000 },
	{ 1, {   594000, HFPLL, 1, 0, 0x16 }, L2(7),   950000 },
	{ 0, {   648000, HFPLL, 1, 0, 0x18 }, L2(7),   975000 },
	{ 1, {   702000, HFPLL, 1, 0, 0x1A }, L2(7),   975000 },
	{ 0, {   756000, HFPLL, 1, 0, 0x1C }, L2(7),  1025000 },
	{ 1, {   810000, HFPLL, 1, 0, 0x1E }, L2(7),  1025000 },
	{ 0, {   864000, HFPLL, 1, 0, 0x20 }, L2(7),  1050000 },
	{ 1, {   918000, HFPLL, 1, 0, 0x22 }, L2(7),  1050000 },
	{ 0, {   972000, HFPLL, 1, 0, 0x24 }, L2(7),  1075000 },
	{ 1, {  1026000, HFPLL, 1, 0, 0x26 }, L2(7),  1075000 },
	{ 0, {  1080000, HFPLL, 1, 0, 0x28 }, L2(16), 1125000 },
	{ 1, {  1134000, HFPLL, 1, 0, 0x2A }, L2(16), 1125000 },
	{ 1, {  1188000, HFPLL, 1, 0, 0x2C }, L2(16), 1150000 },
#if 0
	/* This part is commented out only to MSM8960(1.2GHz) model */
	{ 1, {  1242000, HFPLL, 1, 0, 0x2E }, L2(16), 1150000 },
	{ 0, {  1296000, HFPLL, 1, 0, 0x30 }, L2(16), 1175000 },
	{ 1, {  1350000, HFPLL, 1, 0, 0x32 }, L2(16), 1175000 },
	{ 0, {  1404000, HFPLL, 1, 0, 0x34 }, L2(16), 1187500 },
	{ 1, {  1458000, HFPLL, 1, 0, 0x36 }, L2(16), 1187500 },
	{ 1, {  1512000, HFPLL, 1, 0, 0x38 }, L2(16), 1200000 },
#endif
	{ 0, { 0 } }
};

static struct acpu_level acpu_freq_tbl_8960_kraitv2_fast[] = {
	{ 0, { STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   850000 },
	{ 1, {   384000, PLL_8, 0, 2, 0x00 }, L2(1),   850000 },
	{ 0, {   432000, HFPLL, 2, 0, 0x20 }, L2(7),   875000 },
	{ 1, {   486000, HFPLL, 2, 0, 0x24 }, L2(7),   875000 },
	{ 0, {   540000, HFPLL, 2, 0, 0x28 }, L2(7),   900000 },
	{ 1, {   594000, HFPLL, 1, 0, 0x16 }, L2(7),   900000 },
	{ 0, {   648000, HFPLL, 1, 0, 0x18 }, L2(7),   925000 },
	{ 1, {   702000, HFPLL, 1, 0, 0x1A }, L2(7),   925000 },
	{ 0, {   756000, HFPLL, 1, 0, 0x1C }, L2(7),   975000 },
	{ 1, {   810000, HFPLL, 1, 0, 0x1E }, L2(7),   975000 },
	{ 0, {   864000, HFPLL, 1, 0, 0x20 }, L2(7),  1000000 },
	{ 1, {   918000, HFPLL, 1, 0, 0x22 }, L2(7),  1000000 },
	{ 0, {   972000, HFPLL, 1, 0, 0x24 }, L2(7),  1025000 },
	{ 1, {  1026000, HFPLL, 1, 0, 0x26 }, L2(7),  1025000 },
	{ 0, {  1080000, HFPLL, 1, 0, 0x28 }, L2(16), 1075000 },
	{ 1, {  1134000, HFPLL, 1, 0, 0x2A }, L2(16), 1075000 },
	{ 1, {  1188000, HFPLL, 1, 0, 0x2C }, L2(16), 1100000 },
#if 0
	/* This part is commented out only to MSM8960(1.2GHz) model */
	{ 1, {  1242000, HFPLL, 1, 0, 0x2E }, L2(16), 1100000 },
	{ 0, {  1296000, HFPLL, 1, 0, 0x30 }, L2(16), 1125000 },
	{ 1, {  1350000, HFPLL, 1, 0, 0x32 }, L2(16), 1125000 },
	{ 0, {  1404000, HFPLL, 1, 0, 0x34 }, L2(16), 1137500 },
	{ 1, {  1458000, HFPLL, 1, 0, 0x36 }, L2(16), 1137500 },
	{ 1, {  1512000, HFPLL, 1, 0, 0x38 }, L2(16), 1150000 },
#endif
	{ 0, { 0 } }
};

static struct acpu_level acpu_freq_tbl_8960_kraitv2_f3[] = {
	{ 0, { STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   850000 },
	{ 1, {   384000, PLL_8, 0, 2, 0x00 }, L2(1),   850000 },
	{ 0, {   432000, HFPLL, 2, 0, 0x20 }, L2(7),   875000 },
	{ 1, {   486000, HFPLL, 2, 0, 0x24 }, L2(7),   875000 },
	{ 0, {   540000, HFPLL, 2, 0, 0x28 }, L2(7),   900000 },
	{ 1, {   594000, HFPLL, 1, 0, 0x16 }, L2(7),   900000 },
	{ 0, {   648000, HFPLL, 1, 0, 0x18 }, L2(7),   925000 },
	{ 1, {   702000, HFPLL, 1, 0, 0x1A }, L2(7),   925000 },
	{ 0, {   756000, HFPLL, 1, 0, 0x1C }, L2(7),   975000 },
	{ 1, {   810000, HFPLL, 1, 0, 0x1E }, L2(7),   975000 },
	{ 0, {   864000, HFPLL, 1, 0, 0x20 }, L2(7),  1000000 },
	{ 1, {   918000, HFPLL, 1, 0, 0x22 }, L2(7),  1000000 },
	{ 0, {   972000, HFPLL, 1, 0, 0x24 }, L2(7),  1012500 },
	{ 1, {  1026000, HFPLL, 1, 0, 0x26 }, L2(7),  1012500 },
	{ 0, {  1080000, HFPLL, 1, 0, 0x28 }, L2(16), 1050000 },
	{ 1, {  1134000, HFPLL, 1, 0, 0x2A }, L2(16), 1050000 },
	{ 0, {  1188000, HFPLL, 1, 0, 0x2C }, L2(16), 1075000 },
#if 0
	{ 1, {  1242000, HFPLL, 1, 0, 0x2E }, L2(16), 1075000 },
	{ 0, {  1296000, HFPLL, 1, 0, 0x30 }, L2(16), 1100000 },
	{ 1, {  1350000, HFPLL, 1, 0, 0x32 }, L2(16), 1100000 },
	{ 0, {  1404000, HFPLL, 1, 0, 0x34 }, L2(16), 1112500 },
	{ 1, {  1458000, HFPLL, 1, 0, 0x36 }, L2(16), 1112500 },
	{ 1, {  1512000, HFPLL, 1, 0, 0x38 }, L2(16), 1125000 },
#endif
	{ 0, { 0 } }
};
#elif defined(CONFIG_MSM_DCVS_FOR_MSM8260A)

static struct l2_level l2_freq_tbl_8960_kraitv2[] = {
	[0]  = { {STBY_KHZ, QSB,   0, 0, 0x00 }, 1050000, 1050000, 0 },
	[1]  = { {  384000, PLL_8, 0, 2, 0x00 }, 1050000, 1050000, 1 },
	[2]  = { {  432000, HFPLL, 2, 0, 0x20 }, 1050000, 1050000, 2 },
	[3]  = { {  486000, HFPLL, 2, 0, 0x24 }, 1050000, 1050000, 2 },
	[4]  = { {  540000, HFPLL, 2, 0, 0x28 }, 1050000, 1050000, 2 },
	[5]  = { {  594000, HFPLL, 1, 0, 0x16 }, 1050000, 1050000, 2 },
	[6]  = { {  648000, HFPLL, 1, 0, 0x18 }, 1050000, 1050000, 4 },
	[7]  = { {  702000, HFPLL, 1, 0, 0x1A }, 1050000, 1050000, 4 },
	[8]  = { {  756000, HFPLL, 1, 0, 0x1C }, 1150000, 1150000, 4 },
	[9]  = { {  810000, HFPLL, 1, 0, 0x1E }, 1150000, 1150000, 4 },
	[10] = { {  864000, HFPLL, 1, 0, 0x20 }, 1150000, 1150000, 4 },
	[11] = { {  918000, HFPLL, 1, 0, 0x22 }, 1150000, 1150000, 6 },
	[12] = { {  972000, HFPLL, 1, 0, 0x24 }, 1150000, 1150000, 6 },
	[13] = { { 1026000, HFPLL, 1, 0, 0x26 }, 1150000, 1150000, 6 },
	[14] = { { 1080000, HFPLL, 1, 0, 0x28 }, 1150000, 1150000, 6 },
	[15] = { { 1134000, HFPLL, 1, 0, 0x2A }, 1150000, 1150000, 6 },
	[16] = { { 1188000, HFPLL, 1, 0, 0x2C }, 1150000, 1150000, 6 },
	[17] = { { 1242000, HFPLL, 1, 0, 0x2E }, 1150000, 1150000, 6 },
	[18] = { { 1296000, HFPLL, 1, 0, 0x30 }, 1150000, 1150000, 6 },
	[19] = { { 1350000, HFPLL, 1, 0, 0x32 }, 1150000, 1150000, 6 },
};

static struct acpu_level acpu_freq_tbl_8960_kraitv2_slow[] = {
	{ 0, { STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   950000 },
	{ 1, {   384000, PLL_8, 0, 2, 0x00 }, L2(1),   950000 },
	{ 0, {   432000, HFPLL, 2, 0, 0x20 }, L2(7),   975000 },
	{ 1, {   486000, HFPLL, 2, 0, 0x24 }, L2(7),   975000 },
	{ 0, {   540000, HFPLL, 2, 0, 0x28 }, L2(7),  1000000 },
	{ 1, {   594000, HFPLL, 1, 0, 0x16 }, L2(7),  1000000 },
	{ 0, {   648000, HFPLL, 1, 0, 0x18 }, L2(7),  1025000 },
	{ 1, {   702000, HFPLL, 1, 0, 0x1A }, L2(7),  1025000 },
	{ 0, {   756000, HFPLL, 1, 0, 0x1C }, L2(7),  1075000 },
	{ 1, {   810000, HFPLL, 1, 0, 0x1E }, L2(7),  1075000 },
	{ 0, {   864000, HFPLL, 1, 0, 0x20 }, L2(7),  1100000 },
	{ 1, {   918000, HFPLL, 1, 0, 0x22 }, L2(7),  1100000 },
	{ 0, {   972000, HFPLL, 1, 0, 0x24 }, L2(7),  1125000 },
	{ 1, {  1026000, HFPLL, 1, 0, 0x26 }, L2(7),  1125000 },
	{ 0, {  1080000, HFPLL, 1, 0, 0x28 }, L2(16), 1175000 },
	{ 1, {  1134000, HFPLL, 1, 0, 0x2A }, L2(16), 1175000 },
	{ 0, {  1188000, HFPLL, 1, 0, 0x2C }, L2(16), 1200000 },
	{ 1, {  1242000, HFPLL, 1, 0, 0x2E }, L2(16), 1200000 },
	{ 0, {  1296000, HFPLL, 1, 0, 0x30 }, L2(16), 1225000 },
	{ 1, {  1350000, HFPLL, 1, 0, 0x32 }, L2(16), 1225000 },
	{ 0, {  1404000, HFPLL, 1, 0, 0x34 }, L2(16), 1237500 },
	{ 1, {  1458000, HFPLL, 1, 0, 0x36 }, L2(16), 1237500 },
	{ 1, {  1512000, HFPLL, 1, 0, 0x38 }, L2(16), 1250000 },
	{ 0, { 0 } }
};

static struct acpu_level acpu_freq_tbl_8960_kraitv2_nom[] = {
	{ 0, { STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   950000 },
	{ 1, {   384000, PLL_8, 0, 2, 0x00 }, L2(1),   950000 },
	{ 0, {   432000, HFPLL, 2, 0, 0x20 }, L2(7),   975000 },
	{ 1, {   486000, HFPLL, 2, 0, 0x24 }, L2(7),   975000 },
	{ 0, {   540000, HFPLL, 2, 0, 0x28 }, L2(7),  1000000 },
	{ 1, {   594000, HFPLL, 1, 0, 0x16 }, L2(7),  1000000 },
	{ 0, {   648000, HFPLL, 1, 0, 0x18 }, L2(7),  1025000 },
	{ 1, {   702000, HFPLL, 1, 0, 0x1A }, L2(7),  1025000 },
	{ 0, {   756000, HFPLL, 1, 0, 0x1C }, L2(7),  1075000 },
	{ 1, {   810000, HFPLL, 1, 0, 0x1E }, L2(7),  1075000 },
	{ 0, {   864000, HFPLL, 1, 0, 0x20 }, L2(7),  1100000 },
	{ 1, {   918000, HFPLL, 1, 0, 0x22 }, L2(7),  1100000 },
	{ 0, {   972000, HFPLL, 1, 0, 0x24 }, L2(7),  1125000 },
	{ 1, {  1026000, HFPLL, 1, 0, 0x26 }, L2(7),  1125000 },
	{ 0, {  1080000, HFPLL, 1, 0, 0x28 }, L2(16), 1175000 },
	{ 1, {  1134000, HFPLL, 1, 0, 0x2A }, L2(16), 1175000 },
	{ 0, {  1188000, HFPLL, 1, 0, 0x2C }, L2(16), 1200000 },
	{ 1, {  1242000, HFPLL, 1, 0, 0x2E }, L2(16), 1200000 },
	{ 0, {  1296000, HFPLL, 1, 0, 0x30 }, L2(16), 1225000 },
	{ 1, {  1350000, HFPLL, 1, 0, 0x32 }, L2(16), 1225000 },
	{ 0, {  1404000, HFPLL, 1, 0, 0x34 }, L2(16), 1237500 },
	{ 1, {  1458000, HFPLL, 1, 0, 0x36 }, L2(16), 1237500 },
	{ 1, {  1512000, HFPLL, 1, 0, 0x38 }, L2(16), 1250000 },
	{ 0, { 0 } }
};

static struct acpu_level acpu_freq_tbl_8960_kraitv2_fast[] = {
	{ 0, { STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   900000 },
	{ 1, {   384000, PLL_8, 0, 2, 0x00 }, L2(1),   900000 },
	{ 0, {   432000, HFPLL, 2, 0, 0x20 }, L2(7),   925000 },
	{ 1, {   486000, HFPLL, 2, 0, 0x24 }, L2(7),   925000 },
	{ 0, {   540000, HFPLL, 2, 0, 0x28 }, L2(7),   950000 },
	{ 1, {   594000, HFPLL, 1, 0, 0x16 }, L2(7),   950000 },
	{ 0, {   648000, HFPLL, 1, 0, 0x18 }, L2(7),   975000 },
	{ 1, {   702000, HFPLL, 1, 0, 0x1A }, L2(7),   975000 },
	{ 0, {   756000, HFPLL, 1, 0, 0x1C }, L2(7),  1025000 },
	{ 1, {   810000, HFPLL, 1, 0, 0x1E }, L2(7),  1025000 },
	{ 0, {   864000, HFPLL, 1, 0, 0x20 }, L2(7),  1050000 },
	{ 1, {   918000, HFPLL, 1, 0, 0x22 }, L2(7),  1050000 },
	{ 0, {   972000, HFPLL, 1, 0, 0x24 }, L2(7),  1075000 },
	{ 1, {  1026000, HFPLL, 1, 0, 0x26 }, L2(7),  1075000 },
	{ 0, {  1080000, HFPLL, 1, 0, 0x28 }, L2(16), 1125000 },
	{ 1, {  1134000, HFPLL, 1, 0, 0x2A }, L2(16), 1125000 },
	{ 0, {  1188000, HFPLL, 1, 0, 0x2C }, L2(16), 1150000 },
	{ 1, {  1242000, HFPLL, 1, 0, 0x2E }, L2(16), 1150000 },
	{ 0, {  1296000, HFPLL, 1, 0, 0x30 }, L2(16), 1175000 },
	{ 1, {  1350000, HFPLL, 1, 0, 0x32 }, L2(16), 1175000 },
	{ 0, {  1404000, HFPLL, 1, 0, 0x34 }, L2(16), 1187500 },
	{ 1, {  1458000, HFPLL, 1, 0, 0x36 }, L2(16), 1187500 },
	{ 1, {  1512000, HFPLL, 1, 0, 0x38 }, L2(16), 1200000 },
	{ 0, { 0 } }
};

static struct acpu_level acpu_freq_tbl_8960_kraitv2_f3[] = {
	{ 0, { STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   850000 },
	{ 1, {   384000, PLL_8, 0, 2, 0x00 }, L2(1),   850000 },
	{ 0, {   432000, HFPLL, 2, 0, 0x20 }, L2(7),   875000 },
	{ 1, {   486000, HFPLL, 2, 0, 0x24 }, L2(7),   875000 },
	{ 0, {   540000, HFPLL, 2, 0, 0x28 }, L2(7),   900000 },
	{ 1, {   594000, HFPLL, 1, 0, 0x16 }, L2(7),   900000 },
	{ 0, {   648000, HFPLL, 1, 0, 0x18 }, L2(7),   925000 },
	{ 1, {   702000, HFPLL, 1, 0, 0x1A }, L2(7),   925000 },
	{ 0, {   756000, HFPLL, 1, 0, 0x1C }, L2(7),   975000 },
	{ 1, {   810000, HFPLL, 1, 0, 0x1E }, L2(7),   975000 },
	{ 0, {   864000, HFPLL, 1, 0, 0x20 }, L2(7),  1000000 },
	{ 1, {   918000, HFPLL, 1, 0, 0x22 }, L2(7),  1000000 },
	{ 0, {   972000, HFPLL, 1, 0, 0x24 }, L2(7),  1012500 },
	{ 1, {  1026000, HFPLL, 1, 0, 0x26 }, L2(7),  1012500 },
	{ 0, {  1080000, HFPLL, 1, 0, 0x28 }, L2(16), 1050000 },
	{ 1, {  1134000, HFPLL, 1, 0, 0x2A }, L2(16), 1050000 },
	{ 0, {  1188000, HFPLL, 1, 0, 0x2C }, L2(16), 1075000 },
	{ 1, {  1242000, HFPLL, 1, 0, 0x2E }, L2(16), 1075000 },
	{ 0, {  1296000, HFPLL, 1, 0, 0x30 }, L2(16), 1100000 },
	{ 1, {  1350000, HFPLL, 1, 0, 0x32 }, L2(16), 1100000 },
	{ 0, {  1404000, HFPLL, 1, 0, 0x34 }, L2(16), 1112500 },
	{ 1, {  1458000, HFPLL, 1, 0, 0x36 }, L2(16), 1112500 },
	{ 1, {  1512000, HFPLL, 1, 0, 0x38 }, L2(16), 1125000 },
	{ 0, { 0 } }
};
#else

static struct l2_level l2_freq_tbl_8960_kraitv2[] = {
	[0]  = { {STBY_KHZ, QSB,   0, 0, 0x00 }, 1050000, 1050000, 0 },
	[1]  = { {  384000, PLL_8, 0, 2, 0x00 }, 1050000, 1050000, 1 },
	[2]  = { {  432000, HFPLL, 2, 0, 0x20 }, 1050000, 1050000, 2 },
	[3]  = { {  486000, HFPLL, 2, 0, 0x24 }, 1050000, 1050000, 2 },
	[4]  = { {  540000, HFPLL, 2, 0, 0x28 }, 1050000, 1050000, 2 },
	[5]  = { {  594000, HFPLL, 1, 0, 0x16 }, 1050000, 1050000, 2 },
	[6]  = { {  648000, HFPLL, 1, 0, 0x18 }, 1050000, 1050000, 4 },
	[7]  = { {  702000, HFPLL, 1, 0, 0x1A }, 1050000, 1050000, 4 },
	[8]  = { {  756000, HFPLL, 1, 0, 0x1C }, 1150000, 1150000, 4 },
	[9]  = { {  810000, HFPLL, 1, 0, 0x1E }, 1150000, 1150000, 4 },
	[10] = { {  864000, HFPLL, 1, 0, 0x20 }, 1150000, 1150000, 4 },
	[11] = { {  918000, HFPLL, 1, 0, 0x22 }, 1150000, 1150000, 6 },
	[12] = { {  972000, HFPLL, 1, 0, 0x24 }, 1150000, 1150000, 6 },
	[13] = { { 1026000, HFPLL, 1, 0, 0x26 }, 1150000, 1150000, 6 },
	[14] = { { 1080000, HFPLL, 1, 0, 0x28 }, 1150000, 1150000, 6 },
	[15] = { { 1134000, HFPLL, 1, 0, 0x2A }, 1150000, 1150000, 6 },
	[16] = { { 1188000, HFPLL, 1, 0, 0x2C }, 1150000, 1150000, 6 },
	[17] = { { 1242000, HFPLL, 1, 0, 0x2E }, 1150000, 1150000, 6 },
	[18] = { { 1296000, HFPLL, 1, 0, 0x30 }, 1150000, 1150000, 6 },
	[19] = { { 1350000, HFPLL, 1, 0, 0x32 }, 1150000, 1150000, 6 },
};

static struct acpu_level acpu_freq_tbl_8960_kraitv2_slow[] = {
	{ 0, { STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   950000 },
	{ 1, {   384000, PLL_8, 0, 2, 0x00 }, L2(1),   950000 },
	{ 1, {   432000, HFPLL, 2, 0, 0x20 }, L2(7),   975000 },
	{ 1, {   486000, HFPLL, 2, 0, 0x24 }, L2(7),   975000 },
	{ 1, {   540000, HFPLL, 2, 0, 0x28 }, L2(7),  1000000 },
	{ 1, {   594000, HFPLL, 1, 0, 0x16 }, L2(7),  1000000 },
	{ 1, {   648000, HFPLL, 1, 0, 0x18 }, L2(7),  1025000 },
	{ 1, {   702000, HFPLL, 1, 0, 0x1A }, L2(7),  1025000 },
	{ 1, {   756000, HFPLL, 1, 0, 0x1C }, L2(7),  1075000 },
	{ 1, {   810000, HFPLL, 1, 0, 0x1E }, L2(7),  1075000 },
	{ 1, {   864000, HFPLL, 1, 0, 0x20 }, L2(7),  1100000 },
	{ 1, {   918000, HFPLL, 1, 0, 0x22 }, L2(7),  1100000 },
	{ 1, {   972000, HFPLL, 1, 0, 0x24 }, L2(7),  1125000 },
	{ 1, {  1026000, HFPLL, 1, 0, 0x26 }, L2(7),  1125000 },
	{ 1, {  1080000, HFPLL, 1, 0, 0x28 }, L2(19), 1175000 },
	{ 1, {  1134000, HFPLL, 1, 0, 0x2A }, L2(19), 1175000 },
	{ 1, {  1188000, HFPLL, 1, 0, 0x2C }, L2(19), 1200000 },
	{ 1, {  1242000, HFPLL, 1, 0, 0x2E }, L2(19), 1200000 },
	{ 1, {  1296000, HFPLL, 1, 0, 0x30 }, L2(19), 1225000 },
	{ 1, {  1350000, HFPLL, 1, 0, 0x32 }, L2(19), 1225000 },
	{ 1, {  1404000, HFPLL, 1, 0, 0x34 }, L2(19), 1237500 },
	{ 1, {  1458000, HFPLL, 1, 0, 0x36 }, L2(19), 1237500 },
	{ 1, {  1512000, HFPLL, 1, 0, 0x38 }, L2(19), 1250000 },
#ifdef ALLOW_OC_STEPS
	{ 0, {  1566000, HFPLL, 1, 0, 0x3A }, L2(19), 1250000 },
	{ 0, {  1620000, HFPLL, 1, 0, 0x3C }, L2(19), 1262500 },
	{ 0, {  1674000, HFPLL, 1, 0, 0x3E }, L2(19), 1262500 },
	{ 0, {  1728000, HFPLL, 1, 0, 0x40 }, L2(19), 1275000 },
	{ 0, {  1782000, HFPLL, 1, 0, 0x42 }, L2(19), 1275000 },
	{ 0, {  1836000, HFPLL, 1, 0, 0x44 }, L2(19), 1287500 },
	{ 0, {  1890000, HFPLL, 1, 0, 0x46 }, L2(19), 1300000 },
	{ 0, {  1944000, HFPLL, 1, 0, 0x48 }, L2(19), 1325000 },
	{ 0, {  1998000, HFPLL, 1, 0, 0x4A }, L2(19), 1350000 },
	{ 0, {  2052000, HFPLL, 1, 0, 0x4C }, L2(19), 1375000 },
	{ 0, {  2106000, HFPLL, 1, 0, 0x4E }, L2(19), 1400000 },
#endif
	{ 0, { 0 } }
};

static struct acpu_level acpu_freq_tbl_8960_kraitv2_nom[] = {
	{ 0, { STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   900000 },
	{ 1, {   384000, PLL_8, 0, 2, 0x00 }, L2(1),   900000 },
	{ 1, {   432000, HFPLL, 2, 0, 0x20 }, L2(7),   925000 },
	{ 1, {   486000, HFPLL, 2, 0, 0x24 }, L2(7),   925000 },
	{ 1, {   540000, HFPLL, 2, 0, 0x28 }, L2(7),   950000 },
	{ 1, {   594000, HFPLL, 1, 0, 0x16 }, L2(7),   950000 },
	{ 1, {   648000, HFPLL, 1, 0, 0x18 }, L2(7),   975000 },
	{ 1, {   702000, HFPLL, 1, 0, 0x1A }, L2(7),   975000 },
	{ 1, {   756000, HFPLL, 1, 0, 0x1C }, L2(7),  1025000 },
	{ 1, {   810000, HFPLL, 1, 0, 0x1E }, L2(7),  1025000 },
	{ 1, {   864000, HFPLL, 1, 0, 0x20 }, L2(7),  1050000 },
	{ 1, {   918000, HFPLL, 1, 0, 0x22 }, L2(7),  1050000 },
	{ 1, {   972000, HFPLL, 1, 0, 0x24 }, L2(7),  1075000 },
	{ 1, {  1026000, HFPLL, 1, 0, 0x26 }, L2(7),  1075000 },
	{ 1, {  1080000, HFPLL, 1, 0, 0x28 }, L2(19), 1125000 },
	{ 1, {  1134000, HFPLL, 1, 0, 0x2A }, L2(19), 1125000 },
	{ 1, {  1188000, HFPLL, 1, 0, 0x2C }, L2(19), 1150000 },
	{ 1, {  1242000, HFPLL, 1, 0, 0x2E }, L2(19), 1150000 },
	{ 1, {  1296000, HFPLL, 1, 0, 0x30 }, L2(19), 1175000 },
	{ 1, {  1350000, HFPLL, 1, 0, 0x32 }, L2(19), 1175000 },
	{ 1, {  1404000, HFPLL, 1, 0, 0x34 }, L2(19), 1187500 },
	{ 1, {  1458000, HFPLL, 1, 0, 0x36 }, L2(19), 1187500 },
	{ 1, {  1512000, HFPLL, 1, 0, 0x38 }, L2(19), 1200000 },
#ifdef ALLOW_OC_STEPS
	{ 0, {  1566000, HFPLL, 1, 0, 0x3A }, L2(19), 1200000 },
	{ 0, {  1620000, HFPLL, 1, 0, 0x3C }, L2(19), 1212500 },
	{ 0, {  1674000, HFPLL, 1, 0, 0x3E }, L2(19), 1212500 },
	{ 0, {  1728000, HFPLL, 1, 0, 0x40 }, L2(19), 1225000 },
	{ 0, {  1782000, HFPLL, 1, 0, 0x42 }, L2(19), 1225000 },
	{ 0, {  1836000, HFPLL, 1, 0, 0x44 }, L2(19), 1237500 },
	{ 0, {  1890000, HFPLL, 1, 0, 0x46 }, L2(19), 1250000 },
	{ 0, {  1944000, HFPLL, 1, 0, 0x48 }, L2(19), 1275000 },
	{ 0, {  1998000, HFPLL, 1, 0, 0x4A }, L2(19), 1300000 },
	{ 0, {  2052000, HFPLL, 1, 0, 0x4C }, L2(19), 1325000 },
	{ 0, {  2106000, HFPLL, 1, 0, 0x4E }, L2(19), 1350000 },
#endif
	{ 0, { 0 } }
};

static struct acpu_level acpu_freq_tbl_8960_kraitv2_fast[] = {
	{ 0, { STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   850000 },
	{ 1, {   384000, PLL_8, 0, 2, 0x00 }, L2(1),   850000 },
	{ 1, {   432000, HFPLL, 2, 0, 0x20 }, L2(7),   875000 },
	{ 1, {   486000, HFPLL, 2, 0, 0x24 }, L2(7),   875000 },
	{ 1, {   540000, HFPLL, 2, 0, 0x28 }, L2(7),   900000 },
	{ 1, {   594000, HFPLL, 1, 0, 0x16 }, L2(7),   900000 },
	{ 1, {   648000, HFPLL, 1, 0, 0x18 }, L2(7),   925000 },
	{ 1, {   702000, HFPLL, 1, 0, 0x1A }, L2(7),   925000 },
	{ 1, {   756000, HFPLL, 1, 0, 0x1C }, L2(7),   975000 },
	{ 1, {   810000, HFPLL, 1, 0, 0x1E }, L2(7),   975000 },
	{ 1, {   864000, HFPLL, 1, 0, 0x20 }, L2(7),  1000000 },
	{ 1, {   918000, HFPLL, 1, 0, 0x22 }, L2(7),  1000000 },
	{ 1, {   972000, HFPLL, 1, 0, 0x24 }, L2(7),  1025000 },
	{ 1, {  1026000, HFPLL, 1, 0, 0x26 }, L2(7),  1025000 },
	{ 1, {  1080000, HFPLL, 1, 0, 0x28 }, L2(19), 1075000 },
	{ 1, {  1134000, HFPLL, 1, 0, 0x2A }, L2(19), 1075000 },
	{ 1, {  1188000, HFPLL, 1, 0, 0x2C }, L2(19), 1100000 },
	{ 1, {  1242000, HFPLL, 1, 0, 0x2E }, L2(19), 1100000 },
	{ 1, {  1296000, HFPLL, 1, 0, 0x30 }, L2(19), 1125000 },
	{ 1, {  1350000, HFPLL, 1, 0, 0x32 }, L2(19), 1125000 },
	{ 1, {  1404000, HFPLL, 1, 0, 0x34 }, L2(19), 1137500 },
	{ 1, {  1458000, HFPLL, 1, 0, 0x36 }, L2(19), 1137500 },
	{ 1, {  1512000, HFPLL, 1, 0, 0x38 }, L2(19), 1150000 },
#ifdef ALLOW_OC_STEPS
	{ 0, {  1566000, HFPLL, 1, 0, 0x3A }, L2(19), 1150000 },
	{ 0, {  1620000, HFPLL, 1, 0, 0x3C }, L2(19), 1162500 },
	{ 0, {  1674000, HFPLL, 1, 0, 0x3E }, L2(19), 1162500 },
	{ 0, {  1728000, HFPLL, 1, 0, 0x40 }, L2(19), 1175000 },
	{ 0, {  1782000, HFPLL, 1, 0, 0x42 }, L2(19), 1175000 },
	{ 0, {  1836000, HFPLL, 1, 0, 0x44 }, L2(19), 1187500 },
	{ 0, {  1890000, HFPLL, 1, 0, 0x46 }, L2(19), 1200000 },
	{ 0, {  1944000, HFPLL, 1, 0, 0x48 }, L2(19), 1225000 },
	{ 0, {  1998000, HFPLL, 1, 0, 0x4A }, L2(19), 1250000 },
	{ 0, {  2052000, HFPLL, 1, 0, 0x4C }, L2(19), 1275000 },
	{ 0, {  2106000, HFPLL, 1, 0, 0x4E }, L2(19), 1300000 },
#endif
	{ 0, { 0 } }
};

static struct acpu_level acpu_freq_tbl_8960_kraitv2_f3[] = {
	{ 0, { STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   850000 },
	{ 1, {   384000, PLL_8, 0, 2, 0x00 }, L2(1),   850000 },
	{ 1, {   432000, HFPLL, 2, 0, 0x20 }, L2(7),   875000 },
	{ 1, {   486000, HFPLL, 2, 0, 0x24 }, L2(7),   875000 },
	{ 1, {   540000, HFPLL, 2, 0, 0x28 }, L2(7),   900000 },
	{ 1, {   594000, HFPLL, 1, 0, 0x16 }, L2(7),   900000 },
	{ 1, {   648000, HFPLL, 1, 0, 0x18 }, L2(7),   925000 },
	{ 1, {   702000, HFPLL, 1, 0, 0x1A }, L2(7),   925000 },
	{ 1, {   756000, HFPLL, 1, 0, 0x1C }, L2(7),   975000 },
	{ 1, {   810000, HFPLL, 1, 0, 0x1E }, L2(7),   975000 },
	{ 1, {   864000, HFPLL, 1, 0, 0x20 }, L2(7),  1000000 },
	{ 1, {   918000, HFPLL, 1, 0, 0x22 }, L2(7),  1000000 },
	{ 1, {   972000, HFPLL, 1, 0, 0x24 }, L2(7),  1012500 },
	{ 1, {  1026000, HFPLL, 1, 0, 0x26 }, L2(7),  1012500 },
	{ 1, {  1080000, HFPLL, 1, 0, 0x28 }, L2(16), 1050000 },
	{ 1, {  1134000, HFPLL, 1, 0, 0x2A }, L2(16), 1050000 },
	{ 1, {  1188000, HFPLL, 1, 0, 0x2C }, L2(16), 1075000 },
	{ 1, {  1242000, HFPLL, 1, 0, 0x2E }, L2(16), 1075000 },
	{ 1, {  1296000, HFPLL, 1, 0, 0x30 }, L2(16), 1100000 },
	{ 1, {  1350000, HFPLL, 1, 0, 0x32 }, L2(16), 1100000 },
	{ 1, {  1404000, HFPLL, 1, 0, 0x34 }, L2(16), 1112500 },
	{ 1, {  1458000, HFPLL, 1, 0, 0x36 }, L2(16), 1112500 },
	{ 1, {  1512000, HFPLL, 1, 0, 0x38 }, L2(16), 1125000 },
#ifdef ALLOW_OC_STEPS
	{ 0, {  1566000, HFPLL, 1, 0, 0x3A }, L2(19), 1125000 },
	{ 0, {  1620000, HFPLL, 1, 0, 0x3C }, L2(19), 1137500 },
	{ 0, {  1674000, HFPLL, 1, 0, 0x3E }, L2(19), 1137500 },
	{ 0, {  1728000, HFPLL, 1, 0, 0x40 }, L2(19), 1150000 },
	{ 0, {  1782000, HFPLL, 1, 0, 0x42 }, L2(19), 1150000 },
	{ 0, {  1836000, HFPLL, 1, 0, 0x44 }, L2(19), 1162500 },
	{ 0, {  1890000, HFPLL, 1, 0, 0x46 }, L2(19), 1175000 },
	{ 0, {  1944000, HFPLL, 1, 0, 0x48 }, L2(19), 1200000 },
	{ 0, {  1998000, HFPLL, 1, 0, 0x4A }, L2(19), 1225000 },
	{ 0, {  2052000, HFPLL, 1, 0, 0x4C }, L2(19), 1250000 },
	{ 0, {  2106000, HFPLL, 1, 0, 0x4E }, L2(19), 1275000 },
#endif
	{ 0, { 0 } }
};

#endif

#ifdef EXTRA_TABLES
/* TODO: Update vdd_dig and vdd_mem when voltage data is available. */
#undef L2
#define L2(x) (&l2_freq_tbl_8064[(x)])
static struct l2_level l2_freq_tbl_8064[] = {
	[0]  = { {STBY_KHZ, QSB,   0, 0, 0x00 }, 1050000, 1050000, 0 },
	[1]  = { {  384000, PLL_8, 0, 2, 0x00 }, 1050000, 1050000, 0 },
	[2]  = { {  432000, HFPLL, 2, 0, 0x20 }, 1050000, 1050000, 1 },
	[3]  = { {  486000, HFPLL, 2, 0, 0x24 }, 1050000, 1050000, 1 },
	[4]  = { {  540000, HFPLL, 2, 0, 0x28 }, 1050000, 1050000, 1 },
	[5]  = { {  594000, HFPLL, 1, 0, 0x16 }, 1050000, 1050000, 2 },
	[6]  = { {  648000, HFPLL, 1, 0, 0x18 }, 1050000, 1050000, 2 },
	[7]  = { {  702000, HFPLL, 1, 0, 0x1A }, 1050000, 1050000, 2 },
	[8]  = { {  756000, HFPLL, 1, 0, 0x1C }, 1150000, 1150000, 3 },
	[9]  = { {  810000, HFPLL, 1, 0, 0x1E }, 1150000, 1150000, 3 },
	[10] = { {  864000, HFPLL, 1, 0, 0x20 }, 1150000, 1150000, 3 },
	[11] = { {  918000, HFPLL, 1, 0, 0x22 }, 1150000, 1150000, 3 },
	[12] = { {  972000, HFPLL, 1, 0, 0x24 }, 1150000, 1150000, 3 },
	[13] = { { 1026000, HFPLL, 1, 0, 0x26 }, 1150000, 1150000, 3 },
	[14] = { { 1080000, HFPLL, 1, 0, 0x28 }, 1150000, 1150000, 4 },
	[15] = { { 1134000, HFPLL, 1, 0, 0x2A }, 1150000, 1150000, 4 },
	[16] = { { 1188000, HFPLL, 1, 0, 0x2C }, 1150000, 1150000, 4 },
	[17] = { { 1242000, HFPLL, 1, 0, 0x2E }, 1150000, 1150000, 4 },
	[18] = { { 1296000, HFPLL, 1, 0, 0x30 }, 1150000, 1150000, 4 },
	[19] = { { 1350000, HFPLL, 1, 0, 0x32 }, 1150000, 1150000, 4 },
	[20] = { { 1404000, HFPLL, 1, 0, 0x34 }, 1150000, 1150000, 4 },
	[21] = { { 1458000, HFPLL, 1, 0, 0x36 }, 1150000, 1150000, 5 },
	[22] = { { 1512000, HFPLL, 1, 0, 0x38 }, 1150000, 1150000, 5 },
	[23] = { { 1566000, HFPLL, 1, 0, 0x3A }, 1150000, 1150000, 5 },
	[24] = { { 1620000, HFPLL, 1, 0, 0x3C }, 1150000, 1150000, 5 },
	[25] = { { 1674000, HFPLL, 1, 0, 0x3E }, 1150000, 1150000, 5 },
};

/* TODO: Update core voltages when data is available. */
static struct acpu_level acpu_freq_tbl_8064[] = {
	{ 0, {STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),  1050000 },
	{ 1, {  384000, PLL_8, 0, 2, 0x00 }, L2(1),  1050000 },
	{ 1, {  432000, HFPLL, 2, 0, 0x20 }, L2(2),  1050000 },
	{ 1, {  486000, HFPLL, 2, 0, 0x24 }, L2(3),  1050000 },
	{ 1, {  540000, HFPLL, 2, 0, 0x28 }, L2(4),  1050000 },
	{ 1, {  594000, HFPLL, 1, 0, 0x16 }, L2(5),  1050000 },
	{ 1, {  648000, HFPLL, 1, 0, 0x18 }, L2(6),  1050000 },
	{ 1, {  702000, HFPLL, 1, 0, 0x1A }, L2(7),  1050000 },
	{ 1, {  756000, HFPLL, 1, 0, 0x1C }, L2(8),  1150000 },
	{ 1, {  810000, HFPLL, 1, 0, 0x1E }, L2(9),  1150000 },
	{ 1, {  864000, HFPLL, 1, 0, 0x20 }, L2(10), 1150000 },
	{ 1, {  918000, HFPLL, 1, 0, 0x22 }, L2(11), 1150000 },
	{ 0, { 0 } }
};

/* TODO: Update vdd_dig, vdd_mem and bw when data is available. */
#undef L2
#define L2(x) (&l2_freq_tbl_8930[(x)])
static struct l2_level l2_freq_tbl_8930[] = {
	[0]  = { {STBY_KHZ, QSB,   0, 0, 0x00 }, 1050000, 1050000, 0 },
	[1]  = { {  384000, PLL_8, 0, 2, 0x00 }, 1050000, 1050000, 1 },
	[2]  = { {  432000, HFPLL, 2, 0, 0x20 }, 1050000, 1050000, 1 },
	[3]  = { {  486000, HFPLL, 2, 0, 0x24 }, 1050000, 1050000, 1 },
	[4]  = { {  540000, HFPLL, 2, 0, 0x28 }, 1050000, 1050000, 1 },
	[5]  = { {  594000, HFPLL, 1, 0, 0x16 }, 1050000, 1050000, 2 },
	[6]  = { {  648000, HFPLL, 1, 0, 0x18 }, 1050000, 1050000, 2 },
	[7]  = { {  702000, HFPLL, 1, 0, 0x1A }, 1050000, 1050000, 2 },
	[8]  = { {  756000, HFPLL, 1, 0, 0x1C }, 1150000, 1150000, 2 },
	[9]  = { {  810000, HFPLL, 1, 0, 0x1E }, 1150000, 1150000, 3 },
	[10] = { {  864000, HFPLL, 1, 0, 0x20 }, 1150000, 1150000, 3 },
	[11] = { {  918000, HFPLL, 1, 0, 0x22 }, 1150000, 1150000, 3 },
	[12] = { {  972000, HFPLL, 1, 0, 0x24 }, 1150000, 1150000, 3 },
	[13] = { { 1026000, HFPLL, 1, 0, 0x26 }, 1150000, 1150000, 4 },
	[14] = { { 1080000, HFPLL, 1, 0, 0x28 }, 1150000, 1150000, 4 },
	[15] = { { 1134000, HFPLL, 1, 0, 0x2A }, 1150000, 1150000, 4 },
	[16] = { { 1188000, HFPLL, 1, 0, 0x2C }, 1150000, 1150000, 4 },
};

/* TODO: Update core voltages when data is available. */
static struct acpu_level acpu_freq_tbl_8930[] = {
	{ 0, { STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   900000 },
	{ 1, {   384000, PLL_8, 0, 2, 0x00 }, L2(1),   900000 },
	{ 1, {   432000, HFPLL, 2, 0, 0x20 }, L2(6),   925000 },
	{ 1, {   486000, HFPLL, 2, 0, 0x24 }, L2(6),   925000 },
	{ 1, {   540000, HFPLL, 2, 0, 0x28 }, L2(6),   937500 },
	{ 1, {   594000, HFPLL, 1, 0, 0x16 }, L2(6),   962500 },
	{ 1, {   648000, HFPLL, 1, 0, 0x18 }, L2(6),   987500 },
	{ 1, {   702000, HFPLL, 1, 0, 0x1A }, L2(6),  1000000 },
	{ 1, {   756000, HFPLL, 1, 0, 0x1C }, L2(11), 1025000 },
	{ 1, {   810000, HFPLL, 1, 0, 0x1E }, L2(11), 1062500 },
	{ 1, {   864000, HFPLL, 1, 0, 0x20 }, L2(11), 1062500 },
	{ 1, {   918000, HFPLL, 1, 0, 0x22 }, L2(11), 1087500 },
	{ 1, {   972000, HFPLL, 1, 0, 0x24 }, L2(16), 1100000 },
	{ 1, {  1026000, HFPLL, 1, 0, 0x26 }, L2(16), 1100000 },
	{ 1, {  1080000, HFPLL, 1, 0, 0x28 }, L2(16), 1100000 },
	{ 1, {  1134000, HFPLL, 1, 0, 0x2A }, L2(16), 1100000 },
	{ 1, {  1188000, HFPLL, 1, 0, 0x2C }, L2(16), 1125000 },
	{ 0, { 0 } }
};

/* TODO: Update vdd_dig, vdd_mem and bw when data is available. */
#undef L2
#define L2(x) (&l2_freq_tbl_8627[(x)])
static struct l2_level l2_freq_tbl_8627[] = {
	[0]  = { {STBY_KHZ, QSB,   0, 0, 0x00 }, 1050000, 1050000, 0 },
	[1]  = { {  384000, PLL_8, 0, 2, 0x00 }, 1050000, 1050000, 1 },
	[2]  = { {  432000, HFPLL, 2, 0, 0x20 }, 1050000, 1050000, 1 },
	[3]  = { {  486000, HFPLL, 2, 0, 0x24 }, 1050000, 1050000, 1 },
	[4]  = { {  540000, HFPLL, 2, 0, 0x28 }, 1050000, 1050000, 2 },
	[5]  = { {  594000, HFPLL, 1, 0, 0x16 }, 1050000, 1050000, 2 },
	[6]  = { {  648000, HFPLL, 1, 0, 0x18 }, 1050000, 1050000, 2 },
	[7]  = { {  702000, HFPLL, 1, 0, 0x1A }, 1050000, 1050000, 3 },
	[8]  = { {  756000, HFPLL, 1, 0, 0x1C }, 1150000, 1150000, 3 },
	[9]  = { {  810000, HFPLL, 1, 0, 0x1E }, 1150000, 1150000, 3 },
	[10] = { {  864000, HFPLL, 1, 0, 0x20 }, 1150000, 1150000, 4 },
	[11] = { {  918000, HFPLL, 1, 0, 0x22 }, 1150000, 1150000, 4 },
	[12] = { {  972000, HFPLL, 1, 0, 0x24 }, 1150000, 1150000, 4 },
};

/* TODO: Update core voltages when data is available. */
static struct acpu_level acpu_freq_tbl_8627[] = {
	{ 0, { STBY_KHZ, QSB,   0, 0, 0x00 }, L2(0),   900000 },
	{ 1, {   384000, PLL_8, 0, 2, 0x00 }, L2(1),   900000 },
	{ 1, {   432000, HFPLL, 2, 0, 0x20 }, L2(5),   925000 },
	{ 1, {   486000, HFPLL, 2, 0, 0x24 }, L2(5),   925000 },
	{ 1, {   540000, HFPLL, 2, 0, 0x28 }, L2(5),   937500 },
	{ 1, {   594000, HFPLL, 1, 0, 0x16 }, L2(5),   962500 },
	{ 1, {   648000, HFPLL, 1, 0, 0x18 }, L2(9),   987500 },
	{ 1, {   702000, HFPLL, 1, 0, 0x1A }, L2(9),  1000000 },
	{ 1, {   756000, HFPLL, 1, 0, 0x1C }, L2(9),  1025000 },
	{ 1, {   810000, HFPLL, 1, 0, 0x1E }, L2(9),  1062500 },
	{ 1, {   864000, HFPLL, 1, 0, 0x20 }, L2(12), 1062500 },
	{ 1, {   918000, HFPLL, 1, 0, 0x22 }, L2(12), 1087500 },
	{ 1, {   972000, HFPLL, 1, 0, 0x24 }, L2(12), 1100000 },
	{ 0, { 0 } }
};
#endif /* EXTRA_TABLES */

static unsigned long acpuclk_8960_get_rate(int cpu)
{
	return scalable[cpu].current_speed->khz;
}

/* Get the selected source on primary MUX. */
static int get_pri_clk_src(struct scalable *sc)
{
	uint32_t regval;

	regval = get_l2_indirect_reg(sc->l2cpmr_iaddr);
	return regval & 0x3;
}

/* Set the selected source on primary MUX. */
static void set_pri_clk_src(struct scalable *sc, uint32_t pri_src_sel)
{
	uint32_t regval;

	regval = get_l2_indirect_reg(sc->l2cpmr_iaddr);
	regval &= ~0x3;
	regval |= (pri_src_sel & 0x3);
	set_l2_indirect_reg(sc->l2cpmr_iaddr, regval);
	/* Wait for switch to complete. */
	mb();
	udelay(1);
}

/* Get the selected source on secondary MUX. */
static int get_sec_clk_src(struct scalable *sc)
{
	uint32_t regval;

	regval = get_l2_indirect_reg(sc->l2cpmr_iaddr);
	return (regval >> 2) & 0x3;
}

/* Set the selected source on secondary MUX. */
static void set_sec_clk_src(struct scalable *sc, uint32_t sec_src_sel)
{
	uint32_t regval;

	/* Disable secondary source clock gating during switch. */
	regval = get_l2_indirect_reg(sc->l2cpmr_iaddr);
	regval |= SECCLKAGD;
	set_l2_indirect_reg(sc->l2cpmr_iaddr, regval);

	/* Program the MUX. */
	regval &= ~(0x3 << 2);
	regval |= ((sec_src_sel & 0x3) << 2);
	set_l2_indirect_reg(sc->l2cpmr_iaddr, regval);

	/* Wait for switch to complete. */
	mb();
	udelay(1);

	/* Re-enable secondary source clock gating. */
	regval &= ~SECCLKAGD;
	set_l2_indirect_reg(sc->l2cpmr_iaddr, regval);
}

/* Enable an already-configured HFPLL. */
static void hfpll_enable(struct scalable *sc)
{
	int rc;

	if (cpu_is_msm8960() || cpu_is_msm8930() || cpu_is_msm8627()) {
		rc = rpm_vreg_set_voltage(sc->vreg[VREG_HFPLL_A].rpm_vreg_id,
				sc->vreg[VREG_HFPLL_A].rpm_vreg_voter, 2100000,
				sc->vreg[VREG_HFPLL_A].max_vdd, 0);
		if (rc)
			pr_err("%s regulator enable failed (%d)\n",
				sc->vreg[VREG_HFPLL_A].name, rc);
		rc = rpm_vreg_set_voltage(sc->vreg[VREG_HFPLL_B].rpm_vreg_id,
				sc->vreg[VREG_HFPLL_B].rpm_vreg_voter, 1800000,
				sc->vreg[VREG_HFPLL_B].max_vdd, 0);
		if (rc)
			pr_err("%s regulator enable failed (%d)\n",
				sc->vreg[VREG_HFPLL_B].name, rc);
	}

	/* Disable PLL bypass mode. */
	writel_relaxed(0x2, sc->hfpll_base + HFPLL_MODE);

	/*
	 * H/W requires a 5us delay between disabling the bypass and
	 * de-asserting the reset. Delay 10us just to be safe.
	 */
	mb();
	udelay(10);

	/* De-assert active-low PLL reset. */
	writel_relaxed(0x6, sc->hfpll_base + HFPLL_MODE);

	/* Wait for PLL to lock. */
	mb();
	udelay(60);

	/* Enable PLL output. */
	writel_relaxed(0x7, sc->hfpll_base + HFPLL_MODE);
}

/* Disable a HFPLL for power-savings or while its being reprogrammed. */
static void hfpll_disable(struct scalable *sc)
{
	int rc;

	/*
	 * Disable the PLL output, disable test mode, enable
	 * the bypass mode, and assert the reset.
	 */
	writel_relaxed(0, sc->hfpll_base + HFPLL_MODE);

	if (cpu_is_msm8960() || cpu_is_msm8930() || cpu_is_msm8627()) {
		rc = rpm_vreg_set_voltage(sc->vreg[VREG_HFPLL_B].rpm_vreg_id,
				sc->vreg[VREG_HFPLL_B].rpm_vreg_voter, 0,
				0, 0);
		if (rc)
			pr_err("%s regulator enable failed (%d)\n",
				sc->vreg[VREG_HFPLL_B].name, rc);
		rc = rpm_vreg_set_voltage(sc->vreg[VREG_HFPLL_A].rpm_vreg_id,
				sc->vreg[VREG_HFPLL_A].rpm_vreg_voter, 0,
				0, 0);
		if (rc)
			pr_err("%s regulator enable failed (%d)\n",
				sc->vreg[VREG_HFPLL_A].name, rc);
	}
}

/* Program the HFPLL rate. Assumes HFPLL is already disabled. */
static void hfpll_set_rate(struct scalable *sc, struct core_speed *tgt_s)
{
	writel_relaxed(tgt_s->pll_l_val, sc->hfpll_base + HFPLL_L_VAL);
}

/* Return the L2 speed that should be applied. */
static struct l2_level *compute_l2_level(struct scalable *sc,
					 struct l2_level *vote_l)
{
	struct l2_level *new_l;
	int cpu;

	/* Bounds check. */
	BUG_ON(vote_l >= (l2_freq_tbl + l2_freq_tbl_size));

	/* Find max L2 speed vote. */
	sc->l2_vote = vote_l;
	new_l = l2_freq_tbl;
	for_each_present_cpu(cpu)
		new_l = max(new_l, scalable[cpu].l2_vote);

	return new_l;
}

/* Update the bus bandwidth request. */
static void set_bus_bw(unsigned int bw)
{
	int ret;

	/* Bounds check. */
	if (bw >= ARRAY_SIZE(bw_level_tbl)) {
		pr_err("invalid bandwidth request (%d)\n", bw);
		return;
	}

	/* Update bandwidth if request has changed. This may sleep. */
	ret = msm_bus_scale_client_update_request(bus_perf_client, bw);
	if (ret)
		pr_err("bandwidth request failed (%d)\n", ret);
}

/* Set the CPU or L2 clock speed. */
static void set_speed(struct scalable *sc, struct core_speed *tgt_s,
		      enum setrate_reason reason)
{
	struct core_speed *strt_s = sc->current_speed;

	if (tgt_s == strt_s)
		return;

	if (strt_s->src == HFPLL && tgt_s->src == HFPLL) {
		/*
		 * Move to an always-on source running at a frequency that does
		 * not require an elevated CPU voltage. PLL8 is used here.
		 */
		set_sec_clk_src(sc, SEC_SRC_SEL_AUX);
		set_pri_clk_src(sc, PRI_SRC_SEL_SEC_SRC);

		/* Program CPU HFPLL. */
		hfpll_disable(sc);
		hfpll_set_rate(sc, tgt_s);
		hfpll_enable(sc);

		/* Move CPU to HFPLL source. */
		set_pri_clk_src(sc, tgt_s->pri_src_sel);
	} else if (strt_s->src == HFPLL && tgt_s->src != HFPLL) {
		/*
		 * If responding to CPU_DEAD we must be running on another
		 * CPU.  Therefore, we can't access the downed CPU's CP15
		 * clock MUX registers from here and can't change clock sources.
		 * Just turn off the PLL- since the CPU is down already, halting
		 * its clock should be safe.
		 */
		if (reason != SETRATE_HOTPLUG || sc == &scalable[L2]) {
			set_sec_clk_src(sc, tgt_s->sec_src_sel);
			set_pri_clk_src(sc, tgt_s->pri_src_sel);
		}
		hfpll_disable(sc);
	} else if (strt_s->src != HFPLL && tgt_s->src == HFPLL) {
		hfpll_set_rate(sc, tgt_s);
		hfpll_enable(sc);
		/*
		 * If responding to CPU_UP_PREPARE, we can't change CP15
		 * registers for the CPU that's coming up since we're not
		 * running on that CPU.  That's okay though, since the MUX
		 * source was not changed on the way down, either.
		 */
		if (reason != SETRATE_HOTPLUG || sc == &scalable[L2])
			set_pri_clk_src(sc, tgt_s->pri_src_sel);
	} else {
		if (reason != SETRATE_HOTPLUG || sc == &scalable[L2])
			set_sec_clk_src(sc, tgt_s->sec_src_sel);
	}

	sc->current_speed = tgt_s;
}

/* Apply any per-cpu voltage increases. */
static int increase_vdd(int cpu, unsigned int vdd_core, unsigned int vdd_mem,
			unsigned int vdd_dig, enum setrate_reason reason)
{
	struct scalable *sc = &scalable[cpu];
	int rc = 0;

	/*
	 * Increase vdd_mem active-set before vdd_dig.
	 * vdd_mem should be >= vdd_dig.
	 */
	if (vdd_mem > sc->vreg[VREG_MEM].cur_vdd) {
		rc = rpm_vreg_set_voltage(sc->vreg[VREG_MEM].rpm_vreg_id,
				sc->vreg[VREG_MEM].rpm_vreg_voter, vdd_mem,
				sc->vreg[VREG_MEM].max_vdd, 0);
		if (rc) {
			pr_err("%s: vdd_mem (cpu%d) increase failed (%d)\n",
				__func__, cpu, rc);
			return rc;
		}
		 sc->vreg[VREG_MEM].cur_vdd = vdd_mem;
	}

	/* Increase vdd_dig active-set vote. */
	if (vdd_dig > sc->vreg[VREG_DIG].cur_vdd) {
		rc = rpm_vreg_set_voltage(sc->vreg[VREG_DIG].rpm_vreg_id,
				sc->vreg[VREG_DIG].rpm_vreg_voter, vdd_dig,
				sc->vreg[VREG_DIG].max_vdd, 0);
		if (rc) {
			pr_err("%s: vdd_dig (cpu%d) increase failed (%d)\n",
				__func__, cpu, rc);
			return rc;
		}
		sc->vreg[VREG_DIG].cur_vdd = vdd_dig;
	}

	/*
	 * Update per-CPU core voltage. Don't do this for the hotplug path for
	 * which it should already be correct. Attempting to set it is bad
	 * because we don't know what CPU we are running on at this point, but
	 * the CPU regulator API requires we call it from the affected CPU.
	 */
	if (vdd_core > sc->vreg[VREG_CORE].cur_vdd
						&& reason != SETRATE_HOTPLUG) {
		rc = regulator_set_voltage(sc->vreg[VREG_CORE].reg, vdd_core,
					   sc->vreg[VREG_CORE].max_vdd);
		if (rc) {
			pr_err("%s: vdd_core (cpu%d) increase failed (%d)\n",
				__func__, cpu, rc);
			return rc;
		}
		sc->vreg[VREG_CORE].cur_vdd = vdd_core;
	}

	return rc;
}

/* Apply any per-cpu voltage decreases. */
static void decrease_vdd(int cpu, unsigned int vdd_core, unsigned int vdd_mem,
			 unsigned int vdd_dig, enum setrate_reason reason)
{
	struct scalable *sc = &scalable[cpu];
	int ret;

	/*
	 * Update per-CPU core voltage. This must be called on the CPU
	 * that's being affected. Don't do this in the hotplug remove path,
	 * where the rail is off and we're executing on the other CPU.
	 */
	if (max(vdd_core, final_vmin) < sc->vreg[VREG_CORE].cur_vdd
					&& reason != SETRATE_HOTPLUG) {
		ret = regulator_set_voltage(sc->vreg[VREG_CORE].reg, max(vdd_core, final_vmin),
					    sc->vreg[VREG_CORE].max_vdd);
		if (ret) {
			pr_err("%s: vdd_core (cpu%d) decrease failed (%d)\n",
			       __func__, cpu, ret);
			return;
		}
		sc->vreg[VREG_CORE].cur_vdd = vdd_core;
	}

	/* Decrease vdd_dig active-set vote. */
	if (vdd_dig < sc->vreg[VREG_DIG].cur_vdd) {
		ret = rpm_vreg_set_voltage(sc->vreg[VREG_DIG].rpm_vreg_id,
				sc->vreg[VREG_DIG].rpm_vreg_voter, vdd_dig,
				sc->vreg[VREG_DIG].max_vdd, 0);
		if (ret) {
			pr_err("%s: vdd_dig (cpu%d) decrease failed (%d)\n",
				__func__, cpu, ret);
			return;
		}
		sc->vreg[VREG_DIG].cur_vdd = vdd_dig;
	}

	/*
	 * Decrease vdd_mem active-set after vdd_dig.
	 * vdd_mem should be >= vdd_dig.
	 */
	if (vdd_mem < sc->vreg[VREG_MEM].cur_vdd) {
		ret = rpm_vreg_set_voltage(sc->vreg[VREG_MEM].rpm_vreg_id,
				sc->vreg[VREG_MEM].rpm_vreg_voter, vdd_mem,
				sc->vreg[VREG_MEM].max_vdd, 0);
		if (ret) {
			pr_err("%s: vdd_mem (cpu%d) decrease failed (%d)\n",
				__func__, cpu, ret);
			return;
		}
		 sc->vreg[VREG_MEM].cur_vdd = vdd_mem;
	}
}

static unsigned int calculate_vdd_mem(struct acpu_level *tgt)
{
	return tgt->l2_level->vdd_mem;
}

static unsigned int calculate_vdd_dig(struct acpu_level *tgt)
{
	unsigned int pll_vdd_dig;

	if (tgt->l2_level->speed.src != HFPLL)
		pll_vdd_dig = 0;
	else if (tgt->l2_level->speed.pll_l_val > HFPLL_LOW_VDD_PLL_L_MAX)
		pll_vdd_dig = HFPLL_NOMINAL_VDD;
	else
		pll_vdd_dig = HFPLL_LOW_VDD;

	return max(tgt->l2_level->vdd_dig, pll_vdd_dig);
}

#define BOOST_UV 25000

static unsigned boost_uv;
static bool enable_boost;
module_param_named(boost, enable_boost, bool, S_IRUGO | S_IWUSR);

static unsigned int calculate_vdd_core(struct acpu_level *tgt)
{
	return tgt->vdd_core + (enable_boost ? boost_uv : 0);
}

/* Set the CPU's clock rate and adjust the L2 rate, if appropriate. */
static int acpuclk_8960_set_rate(int cpu, unsigned long rate,
				 enum setrate_reason reason)
{
	struct core_speed *strt_acpu_s, *tgt_acpu_s;
	struct l2_level *tgt_l2_l;
	struct acpu_level *tgt;
	unsigned int vdd_mem, vdd_dig, vdd_core;
	unsigned long flags;
	int rc = 0;

	if (cpu > num_possible_cpus()) {
		rc = -EINVAL;
		goto out;
	}

	if (reason == SETRATE_CPUFREQ || reason == SETRATE_HOTPLUG)
		mutex_lock(&driver_lock);

	strt_acpu_s = scalable[cpu].current_speed;

	/* Return early if rate didn't change. */
	if (rate == strt_acpu_s->khz && scalable[cpu].first_set_call == false)
		goto out;

	/* Find target frequency. */
	for (tgt = acpu_freq_tbl; tgt->speed.khz != 0; tgt++) {
		if (tgt->speed.khz == rate) {
			tgt_acpu_s = &tgt->speed;
			break;
		}
	}
	if (tgt->speed.khz == 0) {
		rc = -EINVAL;
		goto out;
	}

	/* Calculate voltage requirements for the current CPU. */
	vdd_mem  = calculate_vdd_mem(tgt);
	vdd_dig  = calculate_vdd_dig(tgt);
	vdd_core = calculate_vdd_core(tgt);

	/* Increase VDD levels if needed. */
	if (reason == SETRATE_CPUFREQ || reason == SETRATE_HOTPLUG) {
		rc = increase_vdd(cpu, vdd_core, vdd_mem, vdd_dig, reason);
		if (rc)
			goto out;
	}

	pr_debug("Switching from ACPU%d rate %u KHz -> %u KHz\n",
		cpu, strt_acpu_s->khz, tgt_acpu_s->khz);

#ifdef CONFIG_SEC_DEBUG_DCVS_LOG
	sec_debug_dcvs_log(cpu, strt_acpu_s->khz, tgt_acpu_s->khz);
#endif

	/* Set the CPU speed. */
	set_speed(&scalable[cpu], tgt_acpu_s, reason);

	/*
	 * Update the L2 vote and apply the rate change. A spinlock is
	 * necessary to ensure L2 rate is calulated and set atomically,
	 * even if acpuclk_8960_set_rate() is called from an atomic context
	 * and the driver_lock mutex is not acquired.
	 */
	spin_lock_irqsave(&l2_lock, flags);
	tgt_l2_l = compute_l2_level(&scalable[cpu], tgt->l2_level);
	set_speed(&scalable[L2], &tgt_l2_l->speed, reason);
	spin_unlock_irqrestore(&l2_lock, flags);

	/* Nothing else to do for power collapse or SWFI. */
	if (reason == SETRATE_PC || reason == SETRATE_SWFI)
		goto out;

	/* Update bus bandwith request. */
	set_bus_bw(tgt_l2_l->bw_level);

	/* Drop VDD levels if we can. */
	decrease_vdd(cpu, vdd_core, vdd_mem, vdd_dig, reason);

	scalable[cpu].first_set_call = false;
	pr_debug("ACPU%d speed change complete\n", cpu);

out:
	if (reason == SETRATE_CPUFREQ || reason == SETRATE_HOTPLUG)
		mutex_unlock(&driver_lock);
	return rc;
}

/* Initialize a HFPLL at a given rate and enable it. */
static void __init hfpll_init(struct scalable *sc, struct core_speed *tgt_s)
{
	pr_debug("Initializing HFPLL%d\n", sc - scalable);

	/* Disable the PLL for re-programming. */
	hfpll_disable(sc);

	/* Configure PLL parameters for integer mode. */
	writel_relaxed(0x7845C665, sc->hfpll_base + HFPLL_CONFIG_CTL);
	writel_relaxed(0, sc->hfpll_base + HFPLL_M_VAL);
	writel_relaxed(1, sc->hfpll_base + HFPLL_N_VAL);

	/* Program droop controller. */
	writel_relaxed(0x0108C000, sc->hfpll_base + HFPLL_DROOP_CTL);

	/* Set an initial rate and enable the PLL. */
	hfpll_set_rate(sc, tgt_s);
	hfpll_enable(sc);
}

/* Voltage regulator initialization. */
static void __init regulator_init(int set_vdd)
{
	int cpu, ret;
	struct scalable *sc;

	for_each_possible_cpu(cpu) {
		sc = &scalable[cpu];
		sc->vreg[VREG_CORE].reg = regulator_get(NULL,
					  sc->vreg[VREG_CORE].name);
		if (IS_ERR(sc->vreg[VREG_CORE].reg)) {
			pr_err("regulator_get(%s) failed (%ld)\n",
			       sc->vreg[VREG_CORE].name,
			       PTR_ERR(sc->vreg[VREG_CORE].reg));
			BUG();
		}

		ret = regulator_set_voltage(sc->vreg[VREG_CORE].reg,
					    set_vdd,
					    sc->vreg[VREG_CORE].max_vdd);
		if (ret)
			pr_err("regulator_set_voltage(%s) failed"
			       " (%d)\n", sc->vreg[VREG_CORE].name, ret);

		ret = regulator_enable(sc->vreg[VREG_CORE].reg);
		if (ret)
			pr_err("regulator_enable(%s) failed (%d)\n",
			       sc->vreg[VREG_CORE].name, ret);
	}
}

/* Set initial rate for a given core. */
static void __init init_clock_sources(struct scalable *sc,
				      struct core_speed *tgt_s)
{
	uint32_t regval;

	/* Select PLL8 as AUX source input to the secondary MUX. */
	writel_relaxed(0x3, sc->aux_clk_sel);

	/* Switch away from the HFPLL while it's re-initialized. */
	set_sec_clk_src(sc, SEC_SRC_SEL_AUX);
	set_pri_clk_src(sc, PRI_SRC_SEL_SEC_SRC);
	hfpll_init(sc, tgt_s);

	/* Set PRI_SRC_SEL_HFPLL_DIV2 divider to div-2. */
	regval = get_l2_indirect_reg(sc->l2cpmr_iaddr);
	regval &= ~(0x3 << 6);
	set_l2_indirect_reg(sc->l2cpmr_iaddr, regval);

	/* Switch to the target clock source. */
	set_sec_clk_src(sc, tgt_s->sec_src_sel);
	set_pri_clk_src(sc, tgt_s->pri_src_sel);
	sc->current_speed = tgt_s;

	/*
	 * Set this flag so that the first call to acpuclk_8960_set_rate() can
	 * drop voltages and set initial bus bandwidth requests.
	 */
	sc->first_set_call = true;
}

static void __init per_cpu_init(void *data)
{
	struct acpu_level *max_acpu_level = data;
	int cpu = smp_processor_id();

	init_clock_sources(&scalable[cpu], &max_acpu_level->speed);
	scalable[cpu].l2_vote = max_acpu_level->l2_level;
}

/* Register with bus driver. */
static void __init bus_init(unsigned int init_bw)
{
	int ret;

	bus_perf_client = msm_bus_scale_register_client(&bus_client_pdata);
	if (!bus_perf_client) {
		pr_err("unable to register bus client\n");
		BUG();
	}

	ret = msm_bus_scale_client_update_request(bus_perf_client, init_bw);
	if (ret)
		pr_err("initial bandwidth request failed (%d)\n", ret);
}

#ifdef CONFIG_CPU_FREQ_MSM
static struct cpufreq_frequency_table freq_table[NR_CPUS][(FREQ_TABLE_SIZE+1)];

static void cpufreq_table_init(int boot)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		int i, freq_cnt = 0;
		unsigned int max_freq = 0;
		struct cpufreq_policy *pol;

		/* Construct the freq_table tables from acpu_freq_tbl. */
		for (i = 0; acpu_freq_tbl[i].speed.khz != 0
				&& freq_cnt < ARRAY_SIZE(*freq_table); i++) {
			if (acpu_freq_tbl[i].use_for_scaling) {
				freq_table[cpu][freq_cnt].index = freq_cnt;
				freq_table[cpu][freq_cnt].frequency
					= acpu_freq_tbl[i].speed.khz;
				freq_cnt++;
				if (acpu_freq_tbl[i].speed.khz > max_freq)
					max_freq = acpu_freq_tbl[i].speed.khz;
			}
		}
		/* freq_table not big enough to store all usable freqs. */
		BUG_ON(acpu_freq_tbl[i].speed.khz != 0);

		freq_table[cpu][freq_cnt].index = freq_cnt;
		freq_table[cpu][freq_cnt].frequency = CPUFREQ_TABLE_END;

		pr_info("CPU%d: %d scaling frequencies supported.\n",
			cpu, freq_cnt);

		/* Register table with CPUFreq. */
		cpufreq_frequency_table_get_attr(freq_table[cpu], cpu);

		if (!boot)
			continue;

		/* Update maximum frequency, notify cpufreq core */
		pol = cpufreq_cpu_get(cpu);
                if (pol != NULL) {
			pol->cpuinfo.max_freq = max_freq;
			cpufreq_update_policy(cpu);
                }
	}
}
#else
static void __init cpufreq_table_init(int boot) {}
#endif

#define HOT_UNPLUG_KHZ STBY_KHZ
static int __cpuinit acpuclock_cpu_callback(struct notifier_block *nfb,
					    unsigned long action, void *hcpu)
{
	static int prev_khz[NR_CPUS];
	static int prev_pri_src[NR_CPUS];
	static int prev_sec_src[NR_CPUS];
	int cpu = (int)hcpu;

	switch (action) {
	case CPU_DYING:
	case CPU_DYING_FROZEN:
		/*
		 * The primary and secondary muxes must be set to QSB before L2
		 * power collapse and restored after.
		 */
		prev_sec_src[cpu] = get_sec_clk_src(&scalable[cpu]);
		prev_pri_src[cpu] = get_pri_clk_src(&scalable[cpu]);
		set_sec_clk_src(&scalable[cpu], SEC_SRC_SEL_QSB);
		set_pri_clk_src(&scalable[cpu], PRI_SRC_SEL_SEC_SRC);
		break;
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		prev_khz[cpu] = acpuclk_8960_get_rate(cpu);
		/* Fall through. */
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
		acpuclk_8960_set_rate(cpu, HOT_UNPLUG_KHZ, SETRATE_HOTPLUG);
		break;
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		if (WARN_ON(!prev_khz[cpu]))
			return NOTIFY_BAD;
		acpuclk_8960_set_rate(cpu, prev_khz[cpu], SETRATE_HOTPLUG);
		break;
	case CPU_STARTING:
	case CPU_STARTING_FROZEN:
		set_sec_clk_src(&scalable[cpu], prev_sec_src[cpu]);
		set_pri_clk_src(&scalable[cpu], prev_pri_src[cpu]);
		break;
	default:
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata acpuclock_cpu_notifier = {
	.notifier_call = acpuclock_cpu_callback,
};

static const int krait_needs_vmin(void)
{
	switch (read_cpuid_id()) {
	case 0x511F04D0:
	case 0x511F04D1:
	case 0x510F06F0:
		return 1;
	default:
		return 0;
	};
}

#ifdef ENABLE_VMIN
static void kraitv2_apply_vmin(struct acpu_level *tbl)
{
	for (; tbl->speed.khz != 0; tbl++)
		if (tbl->vdd_core < 1150000)
			tbl->vdd_core = 1150000;
}
#endif

#ifdef CONFIG_SEC_L1_DCACHE_PANIC_CHK
uint32_t global_sec_pvs_value;
static int __init sec_pvs_setup(char *str)
{
	uint32_t sec_pvs_value = memparse(str, &str);

	global_sec_pvs_value = sec_pvs_value;
	pr_info("%s: global_sec_pvs_value=%x\n",
			__func__, global_sec_pvs_value);

	return 1;
}

__setup("sec_pvs=", sec_pvs_setup);

static void boost_vdd_core(struct acpu_level *tbl)
{
	for (; tbl->speed.khz != 0; tbl++)
		tbl->vdd_core += 25000;
}
#endif

static struct acpu_level * __init select_freq_plan(void)
{
	struct acpu_level *l, *max_acpu_level = NULL;

	/* Select frequency tables. */
	if (cpu_is_msm8960()) {
		uint32_t pte_efuse, pvs, fmax, pvs_leakage;
		struct acpu_level *v1, *v2;

		pte_efuse = readl_relaxed(QFPROM_PTE_ROW1_LSB);
		pvs = (pte_efuse >> 10) & 0x7;
		if (pvs == 0x7)
			pvs = (pte_efuse >> 13) & 0x7;

		/*  This code is temporary */
		global_pvs = pvs;

		pte_efuse = readl_relaxed(QFPROM_PTE_ROW0_MSB);
		fmax = (pte_efuse >> 20) & 0x3;
		pvs_leakage = (pte_efuse >> 16) & 0x3;

		pr_alert("ACPU PVS:[%d],FMAX[%d]\n", pvs, fmax);
		switch (pvs) {
			case 0x0:
			case 0x7:
				pr_alert("ACPU PVS: Slow(L%d)\n",
					pvs_leakage);
				v1 = acpu_freq_tbl_8960_kraitv1_slow;
				v2 = acpu_freq_tbl_8960_kraitv2_slow;
				break;
			case 0x1:
				pr_alert("ACPU PVS: Nominal(L%d)\n",
					pvs_leakage);
				v1 = acpu_freq_tbl_8960_kraitv1_nom_fast;
				v2 = acpu_freq_tbl_8960_kraitv2_nom;
				break;
			case 0x3:
				switch (fmax) {
					case 0x1:
						pr_alert("ACPU PVS: Fast1(L%d)\n",
							pvs_leakage);
						v1 = acpu_freq_tbl_8960_kraitv1_slow;
						v2 = acpu_freq_tbl_8960_kraitv2_fast;
						break;
					case 0x2:
						pr_alert("ACPU PVS: Fast2(L%d)\n",
							pvs_leakage);
						v1 = acpu_freq_tbl_8960_kraitv1_slow;
						v2 = acpu_freq_tbl_8960_kraitv2_fast;
						break;
					case 0x3:
						pr_alert("ACPU PVS: Fast3(L%d)\n",
							pvs_leakage);
						v1 = acpu_freq_tbl_8960_kraitv1_slow;
							v2 = acpu_freq_tbl_8960_kraitv2_f3;
						break;
					default:
						pr_info("ACPU PVS: Fast\n");
						v1 = acpu_freq_tbl_8960_kraitv1_nom_fast;
						v2 = acpu_freq_tbl_8960_kraitv2_fast;
						break;
				}
				break;
			default:
				pr_warn("ACPU PVS: Unknown. Defaulting to slow.\n");
				v1 = acpu_freq_tbl_8960_kraitv1_slow;
				v2 = acpu_freq_tbl_8960_kraitv2_slow;
				break;
		}
#ifdef CONFIG_SEC_L1_DCACHE_PANIC_CHK
#if defined(CONFIG_MSM_DCVS_FOR_MSM8260A)
		if (((pvs == 0x3) && (global_sec_pvs_value == 0xfafa))
				|| ((pvs == 0x1) && (fmax != 0x1)
					&& (global_sec_pvs_value == 0xfafa))) {
#else
		if (((pvs == 0x3) && (global_sec_pvs_value == 0xfafa))
				|| ((pvs == 0x1)
					&& (global_sec_pvs_value == 0xfafa))) {
#endif
			pr_alert("ACPU PVS: pvs[%d]:fmax[%d]-r\n", pvs, fmax);
			boost_vdd_core(v2);
		}
#endif
		scalable = scalable_8960;
#ifdef EXTRA_TABLES
		if (cpu_is_krait_v1()) {
			acpu_freq_tbl = v1;
			l2_freq_tbl = l2_freq_tbl_8960_kraitv1;
			l2_freq_tbl_size = ARRAY_SIZE(l2_freq_tbl_8960_kraitv1);
		} else {
			acpu_freq_tbl = v2;
			l2_freq_tbl = l2_freq_tbl_8960_kraitv2;
			l2_freq_tbl_size = ARRAY_SIZE(l2_freq_tbl_8960_kraitv2);
		}
	} else if (cpu_is_apq8064()) {
		scalable = scalable_8064;
		acpu_freq_tbl = acpu_freq_tbl_8064;
		l2_freq_tbl = l2_freq_tbl_8064;
		l2_freq_tbl_size = ARRAY_SIZE(l2_freq_tbl_8064);
	} else if (cpu_is_msm8627()) {
		scalable = scalable_8627;
		acpu_freq_tbl = acpu_freq_tbl_8627;
		l2_freq_tbl = l2_freq_tbl_8627;
		l2_freq_tbl_size = ARRAY_SIZE(l2_freq_tbl_8627);
	} else if (cpu_is_msm8930()) {
		scalable = scalable_8930;
		acpu_freq_tbl = acpu_freq_tbl_8930;
		l2_freq_tbl = l2_freq_tbl_8930;
		l2_freq_tbl_size = ARRAY_SIZE(l2_freq_tbl_8930);
	} else {
		BUG();
	}
#else
		acpu_freq_tbl = v2;
		l2_freq_tbl = l2_freq_tbl_8960_kraitv2;
		l2_freq_tbl_size = ARRAY_SIZE(l2_freq_tbl_8960_kraitv2);
	}
#endif /* EXTRA_TABLES */
	if (krait_needs_vmin())
#ifdef ENABLE_VMIN
		kraitv2_apply_vmin(acpu_freq_tbl);
#else
		final_vmin = 1150000;
#endif

	/* Find the max supported scaling frequency. */
	for (l = acpu_freq_tbl; l->speed.khz != 0; l++)
		if (l->use_for_scaling)
			max_acpu_level = l;
	BUG_ON(!max_acpu_level);
	pr_info("Max ACPU freq: %u KHz\n", max_acpu_level->speed.khz);

	return max_acpu_level;
}

/* UV Stuff */
static int acpuclk_update_vdd_table(int num, unsigned int table[]) {
	int i;
	struct acpu_level *tgt = acpu_freq_tbl;
	mutex_lock(&driver_lock);
	if (table[0] < table[num-1]) {
		for (i = 0; i < num; i++, tgt++) {
			if (tgt->speed.khz == STBY_KHZ)
				tgt++;
			if (!tgt->vdd_core)
				break;
			tgt->vdd_core = table[i];
		}
	} else {
		for (i = num; i > 0; i--, tgt++) {
			if (!tgt->vdd_core)
				break;
			if (tgt->speed.khz == STBY_KHZ)
				tgt++;
			tgt->vdd_core = table[i];
		}
	}
	mutex_unlock(&driver_lock);
	return 0;
}
static int acpuclk_update_one_vdd(unsigned int freq, unsigned int uv) {
	int ret = -EINVAL;
	struct acpu_level *tgt = acpu_freq_tbl;
	for (; tgt->l2_level; tgt++) {
		if (tgt->speed.khz == STBY_KHZ)
			continue;
		if (tgt->speed.khz == freq) {
			tgt->vdd_core = uv;
			ret = 1;
			break;
		}
	}
	return ret;
}
static int acpuclk_update_all_vdd(int adj) {
	struct acpu_level *tgt = acpu_freq_tbl;
	for (; tgt->l2_level; tgt++) {
		if (tgt->speed.khz == STBY_KHZ)
			continue;
		tgt->vdd_core += adj;
	}
	return 1;
}
#define sanity_check(v) \
	if (v < 10000) \
		v = (v * 1000) + ((v % 5 == 2) ? 500 : 0); \
	if (v > 1400000 || v < 700000) \
		return -EINVAL;
/* My kingdom for a regular expression! */
ssize_t acpuclk_store_vdd_table(const char *buf, size_t count) {
	unsigned int freq, volt;
	int adjust, ret, idx, len, thislen;
	char mhz_label[5], mv_label[3];
	unsigned int table[FREQ_TABLE_SIZE];

	/* "[+-]mv" adjustments, also understands uv
	 * "echo -75" makes for simple initscripts
	 */
	ret = sscanf(buf, "- %i", &adjust);
	if (ret == 1) {
		if (adjust < 1000)
			adjust *= 1000;
		adjust = -adjust;
	} else {
		ret = sscanf(buf, "+ %i", &adjust);
		if (ret == 1 && adjust < 1000)
			adjust *= 1000;
	}
	if (ret == 1) {
		if (acpuclk_update_all_vdd(adjust) == 1)
			return count;
		else
			return -EINVAL;
	}

	thislen = 0;
	/* Kernel Tuner uses bare values */
	ret = sscanf(buf, "%u %u%n", &freq, &volt, &thislen);
	if (thislen < count - 1) {
		/* "num(mhz)?: uv([um]v)?" adjustments
		 * This allows tables to be saved & restored with cat
		 */
		ret = sscanf(buf, "%u %4s %u%n %2s%n", &freq, &mhz_label[0],
			&volt, &thislen, &mv_label[0], &thislen);
		if (thislen == count - 1) {
			for (idx = 0; idx < 4 && mhz_label[idx] != ':'; idx++);
			if (mhz_label[idx] != ':') thislen = 0;
		}
	}
	if (thislen == count - 1) {
		while (freq < 10000) freq *= 1000;
		sanity_check(volt);
		if (acpuclk_update_one_vdd(freq, volt) == 1)
			return count;
		else
			return -EINVAL;
	}

	/* table adjustments */
	for (idx = 0, len = 0; idx < FREQ_TABLE_SIZE && len < count - 1; idx++) {
		ret = sscanf(buf + len, " %u%n", &table[idx], &thislen);
		if (!ret) break;
		len += thislen;
		sanity_check(table[idx]);
	}
	if (idx == FREQ_TABLE_SIZE && len == count - 1) {
		if (acpuclk_update_vdd_table(FREQ_TABLE_SIZE, table))
			return count;
		else
			return -EINVAL;
	}

	printk(KERN_DEBUG "acpuclk: don't know what this is:\n");
	printk(KERN_DEBUG "acpuclk: %s\n", buf);
	return -EINVAL;
}
ssize_t acpuclk_show_vdd_table(char *buf, char *fmt, int fdiv, int vdiv) {
	int len;
	struct acpu_level *tgt = acpu_freq_tbl;

	for (len = 0; tgt->l2_level; tgt++) {
		if (tgt->speed.khz != STBY_KHZ)
			len += sprintf(buf + len, fmt,
				tgt->speed.khz / fdiv, tgt->vdd_core / vdiv);
	}
	return len;
}

/* Global UV interface */
static ssize_t show_vdd_levels(struct kobject *kobj,
		struct attribute *attr, char *buf) {
	return acpuclk_show_vdd_table(buf, "%8u: %8u\n", 1, 1);
}
static ssize_t store_vdd_levels(struct kobject *kobj, struct attribute *attr,
		const char *buf, size_t count) {
	return acpuclk_store_vdd_table(buf, count);
}
static struct global_attr vdd_levels_attr = __ATTR(vdd_levels, 0644,
		show_vdd_levels, store_vdd_levels);
static struct attribute *vdd_attributes[] = {
	&vdd_levels_attr.attr,
	NULL
};
static struct attribute_group vdd_attr_group = {
	.attrs = vdd_attributes,
	.name = "vdd_table",
};

/* Enable OC frequencies.  Also bump max voltage & bus speed. */
void acpuclk_enable_oc_freqs(unsigned int freq) {
	struct acpu_level *tgt = acpu_freq_tbl;

	scalable_8960[CPU0].vreg[VREG_CORE].max_vdd = 1400000;
	scalable_8960[CPU1].vreg[VREG_CORE].max_vdd = 1400000;

	for (; tgt->l2_level; tgt++) {
		if (tgt->speed.khz > BOOT_FREQ_LIMIT)
			tgt->use_for_scaling = tgt->speed.khz <= freq ? 1 : 0;
	}
	tgt--;
	tgt->l2_level->bw_level = MAX_BUS_LVL;

	cpufreq_table_init(0);
}

void acpuclk_set_override_vmin(int enable) {
	if (enable) {
		final_vmin = 700000;
	} else {
		final_vmin = krait_needs_vmin() ?
			1150000 : 700000;
	}
}
int acpuclk_get_override_vmin(void) {
	return final_vmin < 1150000;
}

static ssize_t store_vmin(struct kobject *kobj, struct attribute *attr,
		 const char *buf, size_t count) {
	unsigned int temp;
	if (sscanf(buf, "%u", &temp) == 1) {
		if (temp >= 700 && temp <= 1400) {
			final_vmin = temp * 1000;
			return count;
		}
	}
	return -EINVAL;
}
static ssize_t show_vmin(struct kobject *kobj,
		 struct attribute *attr, char *buf) {
	return sprintf(buf, "%u\n", final_vmin / 1000);
}
static struct global_attr vmin_attr = __ATTR(vmin, 0644,
		 show_vmin, store_vmin);
static struct attribute *dkp_attributes[] = {
	 &vmin_attr.attr,
	 NULL
};
static struct attribute_group dkp_attr_group = {
	 .attrs = dkp_attributes,
	 .name = "dkp",
};

static struct acpuclk_data acpuclk_8960_data = {
	.set_rate = acpuclk_8960_set_rate,
	.get_rate = acpuclk_8960_get_rate,
	.power_collapse_khz = STBY_KHZ,
	.wait_for_irq_khz = STBY_KHZ,
};

struct cpufreq_frequency_table *acpuclk_get_full_freq_table(unsigned int cpu) {
	struct cpufreq_frequency_table *tbl;
	int i, freq_cnt = 0;

	tbl = kmalloc((FREQ_TABLE_SIZE+5) *
		sizeof(struct cpufreq_frequency_table), GFP_KERNEL);
	if (!tbl) return 0;

	for (i = 0; acpu_freq_tbl[i].speed.khz != 0; i++) {
		if (acpu_freq_tbl[i].speed.khz != STBY_KHZ) {
			tbl[freq_cnt].index = freq_cnt;
			tbl[freq_cnt].frequency
				= acpu_freq_tbl[i].speed.khz;
			freq_cnt++;
		}
	}
	tbl[freq_cnt].index = freq_cnt;
	tbl[freq_cnt].frequency = CPUFREQ_TABLE_END;

	return tbl;
}

static int __init acpuclk_8960_init(struct acpuclk_soc_data *soc_data)
{
	struct acpu_level *max_acpu_level = select_freq_plan();

	regulator_init(max_acpu_level->vdd_core);
	bus_init(max_acpu_level->l2_level->bw_level);

	init_clock_sources(&scalable[L2], &max_acpu_level->l2_level->speed);
	on_each_cpu(per_cpu_init, max_acpu_level, true);

	cpufreq_table_init(1);

	acpuclk_register(&acpuclk_8960_data);
	register_hotcpu_notifier(&acpuclock_cpu_notifier);

	if (sysfs_create_group(cpufreq_global_kobject, &dkp_attr_group))
		pr_err("Unable to create dkp group!\n");
	if (sysfs_create_group(cpufreq_global_kobject, &vdd_attr_group))
		pr_err("Unable to create vdd_table group!\n");

	return 0;
}

struct acpuclk_soc_data acpuclk_8960_soc_data __initdata = {
	.init = acpuclk_8960_init,
};

struct acpuclk_soc_data acpuclk_8930_soc_data __initdata = {
	.init = acpuclk_8960_init,
};
