AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
	$(COVERAGE_CFLAGS) $(LIBCRYPTO_CFLAGS)

noinst_LIBRARIES = libvlr.a

libvlr_a_SOURCES =	vlr.c
