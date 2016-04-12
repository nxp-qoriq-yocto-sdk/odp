ACLOCAL_AMFLAGS=-I m4
AUTOMAKE_OPTIONS = foreign

SUBDIRS = @platform_with_platform@ \
	  helper \
	  test \
	  @platform_with_platform_test@ \
	  helper/test \
	  doc \
	  example \
	  scripts

include $(top_srcdir)/aminclude.am

EXTRA_DIST = bootstrap $(DX_CONFIG) config/README
#nobase_dist_pkgdata_DATA = $(top_srcdir)/kern/nadk_kni.ko
