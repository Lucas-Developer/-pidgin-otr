AM_CFLAGS=	@LIBGCRYPT_CFLAGS@ @LIBOTR_CFLAGS@ @EXTRA_CFLAGS@
AM_CFLAGS += \
	-DUSING_GTK \
	-DPURPLE_PLUGINS \
	-DPIDGIN_OTR_VERSION=\"@VERSION@\" \
	-DLOCALEDIR=\"$(datadir)/locale\"

SUBDIRS=	po

plugindir=		${libdir}/pidgin

plugin_LTLIBRARIES=	pidgin-otr.la

pidgin_otr_la_SOURCES = \
	dialogs.c \
	gtk-dialog.c \
	gtk-ui.c \
	otr-plugin.c \
	tooltipmenu.c \
	ui.c

pidgin_otr_la_LDFLAGS=	-module -avoid-version
pidgin_otr_la_LDFLAGS+=	@LIBGCRYPT_LIBS@ @LIBOTR_LIBS@

EXTRA_DIST = \
	INSTALL.mingw \
	Makefile.mingw \
	Makefile.static \
	dialogs.h \
	gtk-dialog.h \
	otr-icons.h \
	otr-plugin.h \
	gtk-ui.h \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in \
	packaging/fedora/pidgin-otr.spec \
	packaging/windows/pidgin-otr.nsi \
	tooltipmenu.h \
	ui.h \
	po/Makefile.mingw \
	po/README

DISTCLEANFILES = \
	intltool-extract \
	intltool-merge \
	intltool-update
