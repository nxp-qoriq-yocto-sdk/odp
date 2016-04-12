
include $(top_srcdir)/platform/Makefile.inc
include Makefile.inc

AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/nadk/aiop
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/kni
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/nadk/notify
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/nadk/sec
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/nadk/conc
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/nadk/core
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/nadk/cmdif
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/nadk/eth
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/nadk/rts
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-dpaa2/include/nadk/common

AM_CFLAGS += -D_LITTLE_ENDIAN
AM_CFLAGS +=  -I$(srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/helper/include

#NADK_LIBS = -static
LIBS += $(NADK_LIBS)
AM_LDFLAGS += -L$(top_srcdir)/lib

SUBDIRS = flib .

include_HEADERS = \
		  $(top_srcdir)/include/odp.h

odpincludedir= $(includedir)/odp
odpinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/align.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/atomic.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/barrier.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/buffer.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/byteorder.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/classification.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/compiler.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/config.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/cpu.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/cpumask.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/crypto.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/debug.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/errno.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/event.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/hints.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/init.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/packet_flags.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/packet.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/packet_io.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/pool.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/queue.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/random.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/rwlock.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/schedule.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/schedule_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/shared_memory.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/spinlock.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/std_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/sync.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/system_info.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/thread.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/thrmask.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/ticketlock.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/time.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/timer.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/version.h

nadkincludecommondir= $(includedir)/nadk/common
nadkincludecommon_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/common/nadk_cfg.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/common/nadk_common.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/common/nadk_lock.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/common/nadk_queue.h

nadkincludecoredir= $(includedir)/nadk/core
nadkincludecore_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/core/nadk.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/core/nadk_dev.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/core/eal_filesystem.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/core/eal_hugepages.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/core/eal_internal_cfg.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/core/nadk_dev_intr_priv.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/core/nadk_dev_priv.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/core/nadk_hwq.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/core/nadk_hwq_priv.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/core/nadk_internal.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/core/nadk_io_portal_priv.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/core/nadk_vfio.h

nadkincludenotifydir= $(includedir)/nadk/notify
nadkincludenotify_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/notify/nadk_dev_notif.h

nadkincludertsdir= $(includedir)/nadk/rts
nadkincluderts_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_timer.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_time.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_string_fns.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_random.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_mpool.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_memzone.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_memory.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_memcpy.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_mbuf.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_malloc.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_log.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_hexdump.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_debug.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/malloc_elem.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/malloc_heap.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_malloc_heap.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_mbuf_priv.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_mbuf_priv_ldpaa.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_mbuf_support.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_memconfig.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_mpool_priv.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/rts/nadk_tailq.h

nadkincludecmdifdir= $(includedir)/nadk/cmdif
nadkincludecmdif_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/cmdif/shbp.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/cmdif/cmdif.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/cmdif/fsl_shbp.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/cmdif/cmdif_srv_flib.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/cmdif/cmdif_client_flib.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/cmdif/fsl_cmdif_flib_fd.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/cmdif/fsl_cmdif_flib_s.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/cmdif/fsl_cmdif_server.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/cmdif/fsl_cmdif_client.h

nadkincludeaiopdir= $(includedir)/nadk/aiop
nadkincludeaiop_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/aiop/nadk_aiop.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/aiop/nadk_aiop_priv.h


nadkincludeethdir= $(includedir)/nadk/eth
nadkincludeeth_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/eth/nadk_vq.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/eth/nadk_ethdev_priv_ldpaa.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/eth/nadk_eth_ldpaa_annot.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/eth/nadk_eth_ldpaa_qbman.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/eth/nadk_eth_priv.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/eth/nadk_ether.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/eth/nadk_ethdev.h

nadkincludesecdir= $(includedir)/nadk/sec
nadkincludesec_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/nadk/sec/nadk_sec_priv.h

odpplatincludedir= $(includedir)/odp/plat
odpplatinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/atomic_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/barrier_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/buffer_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/byteorder_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/classification_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/cpumask_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/crypto_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/crypto_ipsec_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/crypto_pdcp_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/event_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/init_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/packet_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/packet_annot.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/packet_io_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/pool_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/queue_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/rwlock_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/schedule_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/shared_memory_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/spinlock_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/strong_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/thrmask_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/ticketlock_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/timer_types.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/version_types.h

odpplatcmdifincludedir= $(includedir)/odp/plat/cmdif
odpplatcmdifinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/cmdif/fsl_cmdif_client.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/cmdif/fsl_cmdif_server.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/cmdif/odpfsl_cidev.h

odpplatkniincludedir= $(includedir)/odp/plat/kni
odpplatkniinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/kni/odpfsl_kni_api.h \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/kni/odpfsl_kni_mbuf.h

odpplatmallocincludedir= $(includedir)/odp/plat/malloc
odpplatmallocinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-dpaa2/include/odp/plat/malloc/odpfsl_data_malloc.h

odpapiincludedir= $(includedir)/odp/api
odpapiinclude_HEADERS = \
		  $(top_srcdir)/include/odp/api/align.h \
		  $(top_srcdir)/include/odp/api/atomic.h \
		  $(top_srcdir)/include/odp/api/barrier.h \
		  $(top_srcdir)/include/odp/api/buffer.h \
		  $(top_srcdir)/include/odp/api/byteorder.h \
		  $(top_srcdir)/include/odp/api/classification.h \
		  $(top_srcdir)/include/odp/api/compiler.h \
		  $(top_srcdir)/include/odp/api/config.h \
		  $(top_srcdir)/include/odp/api/cpu.h \
		  $(top_srcdir)/include/odp/api/cpumask.h \
		  $(top_srcdir)/include/odp/api/crypto.h \
		  $(top_srcdir)/include/odp/api/crypto_ipsec.h \
		  $(top_srcdir)/include/odp/api/crypto_pdcp.h \
		  $(top_srcdir)/include/odp/api/debug.h \
		  $(top_srcdir)/include/odp/api/errno.h \
		  $(top_srcdir)/include/odp/api/event.h \
		  $(top_srcdir)/include/odp/api/hints.h \
		  $(top_srcdir)/include/odp/api/init.h \
		  $(top_srcdir)/include/odp/api/packet.h \
		  $(top_srcdir)/include/odp/api/packet_flags.h \
		  $(top_srcdir)/include/odp/api/packet_io.h \
		  $(top_srcdir)/include/odp/api/packet_io_stats.h \
		  $(top_srcdir)/include/odp/api/pool.h \
		  $(top_srcdir)/include/odp/api/queue.h \
		  $(top_srcdir)/include/odp/api/random.h \
		  $(top_srcdir)/include/odp/api/rwlock.h \
		  $(top_srcdir)/include/odp/api/schedule.h \
		  $(top_srcdir)/include/odp/api/schedule_types.h \
		  $(top_srcdir)/include/odp/api/shared_memory.h \
		  $(top_srcdir)/include/odp/api/spinlock.h \
		  $(top_srcdir)/include/odp/api/std_types.h \
		  $(top_srcdir)/include/odp/api/sync.h \
		  $(top_srcdir)/include/odp/api/system_info.h \
		  $(top_srcdir)/include/odp/api/thread.h \
		  $(top_srcdir)/include/odp/api/thrmask.h \
		  $(top_srcdir)/include/odp/api/ticketlock.h \
		  $(top_srcdir)/include/odp/api/time.h \
		  $(top_srcdir)/include/odp/api/timer.h \
		  $(top_srcdir)/include/odp/api/version.h

noinst_HEADERS = \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_align_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_atomic_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_buffer_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_pool_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_classification_datamodel.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_classification_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_crypto_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_debug_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_packet_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_packet_io_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_packet_io_queue.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_packet_nadk.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_queue_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_schedule_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_spin_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/include/odp_timer_internal.h \
		  ${top_srcdir}/platform/linux-dpaa2/Makefile.inc


__LIB__libodp_la_LIBADD = $(top_srcdir)/platform/linux-dpaa2/flib/libflib.la

__LIB__libodp_la_SOURCES = \
			   ../linux-generic/odp_barrier.c \
			   odp_buffer.c \
			   odp_classification.c \
			   ../linux-generic/odp_cpu.c \
			   ../linux-generic/odp_cpumask.c \
			   odp_cpumask_task.c \
			   ../linux-generic/odp_errno.c \
			   odp_event.c \
			   odp_init.c \
			   odp_crypto.c \
			   ../linux-generic/odp_impl.c \
			   odp_packet.c \
			   odp_packet_io.c \
			   odp_packet_nadk.c \
			   odp_pool.c \
			   odp_queue.c \
			   ../linux-generic/odp_rwlock.c \
			   odp_schedule.c \
			   odp_shared_memory.c \
			   ../linux-generic/odp_spinlock.c \
			   odp_system_info.c \
			   odp_thread.c \
			   ../linux-generic/odp_thrmask.c \
			   ../linux-generic/odp_ticketlock.c \
			   ../linux-generic/odp_time.c \
			   odp_timer.c \
			   ../linux-generic/odp_version.c \
			   ../linux-generic/odp_weak.c \
			   malloc/odpfsl_data_malloc.c \
			   nadk/libcore/eal_hugepage_info.c \
			   nadk/libcore/nadk_dev.c \
			   nadk/libcore/nadk_ldpaa.c \
			   nadk/libcore/nadk_ldpaa_vfio.c \
			   nadk/libcore/trace.c \
			   nadk/libcore/nadk_core.c \
			   nadk/libio_portal/nadk_io_portal.c \
			   nadk/libsec/nadk_sec_ldpaa.c \
			   nadk/librts_mem/eal_memory.c \
			   nadk/librts_mem/eal_common_memory.c \
			   nadk/librts_mem/eal_common_memzone.c \
			   nadk/librts_time/nadk_time.c \
			   nadk/librts_time/nadk_timer.c \
			   nadk/librts_malloc/malloc_elem.c \
			   nadk/librts_malloc/malloc_heap.c \
			   nadk/librts_malloc/nadk_malloc.c \
			   nadk/libevent/nadk_dev_notif_priv.c \
			   nadk/libevent/nadk_dev_notif.c \
			   nadk/libevent/nadk_dev_intr_priv.c \
			   nadk/libeth/nadk_ethdev_ldpaa.c \
			   nadk/libeth/nadk_ethdev_priv_ldpaa.c \
			   nadk/libeth/nadk_eth_ldpaa.c \
			   nadk/libaiop/nadk_aiop.c \
			   nadk/libconc/nadk_conc_ldpaa.c \
			   nadk/librts_mbuf/nadk_mbuf_priv_ldpaa.c \
			   nadk/librts_mbuf/nadk_mbuf_ldpaa.c \
			   nadk/librts_mbuf/nadk_mbuf.c \
			   nadk/librts_common/eal_debug.c \
			   nadk/librts_common/eal_common_log.c \
			   nadk/librts_common/eal_common_hexdump.c \
			   nadk/librts_common/eal_log.c \
			   nadk/libcore/nadk_hwq.c \
			   nadk/librts_mpool/nadk_mpool.c \
			   arch/@ARCH@/odp_cpu_cycles.c \
			   kni/nadk_kni.c \
			   kni/odpfsl_kni_api.c \
			   nadk/libcmdif/cmdif_client_flib.c \
			   nadk/libcmdif/cmdif_client_gpp.c \
			   nadk/libcmdif/cmdif_srv_flib.c \
			   nadk/libcmdif/cmdif_srv_gpp.c \
			   nadk/libcmdif/shbp.c \
			   cmdif/odpfsl_cidev.c
