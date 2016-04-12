# Copyright (c) 2014, Linaro Limited
# Copyright (c) 2014, Freescale Semiconductor, Inc.
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause

# NADK_CFLAGS should match flags used to build NADK libraries

#overwrite some top level compiler options - required by NADK
NADK_CFLAGS = -Wno-cast-qual -Wno-pointer-arith
NADK_CFLAGS += -D_GNU_SOURCE
#NADK_CFLAGS += -DODP_USE_PHYS_IOVA
#NADK_CFLAGS += -DODP_ON_VM

PLAT_CFLAGS = $(NADK_CFLAGS)
PLAT_CFLAGS += -I$(top_srcdir)/platform/linux-dpaa2/flib/linux/
PLAT_CFLAGS += -I$(top_srcdir)/platform/linux-dpaa2/flib/qbman/include/drivers/
PLAT_CFLAGS += -I$(top_srcdir)/platform/linux-dpaa2/flib/qbman/include
PLAT_CFLAGS += -I$(top_srcdir)/platform/linux-dpaa2/flib/mc/
PLAT_CFLAGS += -I$(top_srcdir)/platform/linux-dpaa2/flib/rta/sec/rta/include/


AM_CFLAGS += $(PLAT_CFLAGS)

#these FLAGS are needed by yocto build
