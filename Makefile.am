AM_CFLAGS=	@LIBGCRYPT_CFLAGS@ @LIBOTR_CFLAGS@ @EXTRA_CFLAGS@
AM_CFLAGS+=	-DUSING_GTK -DPURPLE_PLUGINS \
		-DPIDGIN_OTR_VERSION=\"@VERSION@\" \
		-DLOCALEDIR=\"$(datadir)/locale\"

SUBDIRS=	po

plugindir=		${libdir}/pidgin

plugin_LTLIBRARIES=	pidgin-otr.la

pidgin_otr_la_SOURCES=	otr-plugin.c ui.c dialogs.c gtk-ui.c gtk-dialog.c \
                        tooltipmenu.c
pidgin_otr_la_LDFLAGS=	-module -avoid-version
pidgin_otr_la_LDFLAGS+=	@LIBGCRYPT_LIBS@ @LIBOTR_LIBS@

EXTRA_DIST=		dialogs.h gtk-dialog.h gtk-ui.h otr-plugin.h ui.h \
			otr-icons.h tooltipmenu.h \
			Makefile.mingw packaging/windows/pidgin-otr.nsi \
			packaging/fedora/pidgin-otr.spec po/Makefile.mingw \
			po/README intltool-extract.in intltool-merge.in \
			intltool-update.in Makefile.static INSTALL.mingw \
			source_date_epoch

DISTCLEANFILES=		intltool-extract intltool-merge intltool-update

# Don't include a filename or timestamp in the dist .tar.gz file, so that
# we can create a reproducible tarball (coupled with setting am__tar in
# configure.ac)
override GZIP_ENV='--best --no-name'

source_date_epoch: FORCE
	git log --format=%ct -1 > source_date_epoch
FORCE:
