AM_CFLAGS = $(libchronic_CFLAGS) -I../include
AM_LDFLAGS = $(libchronic_LIBS)

lib_LTLIBRARIES = libmacho-1.0.la
libmacho_1_0_la_CFLAGS = $(AM_CFLAGS)
libmacho_1_0_la_LDFLAGS = $(AM_LDFLAGS)
libmacho_1_0_la_SOURCES = \
						macho.c \
						command.c \
						segment.c \
						section.c \
						symtab.c \
						symbol.c