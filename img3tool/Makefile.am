AM_CFLAGS = -I$(top_srcdir)/include $(GLOBAL_CFLAGS) $(openssl_CFLAGS) $(libgeneral_CFLAGS) $(libplist_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(openssl_LIBS) $(libgeneral_LIBS) $(libplist_LIBS)

lib_LTLIBRARIES = libimg3tool.la
bin_PROGRAMS = img3tool

libimg3tool_la_CFLAGS = $(AM_CFLAGS)
libimg3tool_la_CXXFLAGS = $(AM_CXXFLAGS)
libimg3tool_la_LDFLAGS = $(AM_LDFLAGS)
libimg3tool_la_SOURCES =	lzssdec.c \
							img3tool.cpp

img3tool_CFLAGS = $(AM_CFLAGS)
img3tool_CXXFLAGS = $(AM_CXXFLAGS)
img3tool_LDFLAGS = $(AM_LDFLAGS)
img3tool_LDADD = libimg3tool.la
img3tool_SOURCES = 	main.cpp
