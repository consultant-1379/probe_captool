SUBDIRS = src

EXTRA_DIST = \
	conf \
	Doxyfile.in \
	captool.sh \
	profile.sh profile-google.sh process-google-profiles.sh \
	valgrind.sh valgrind.sup \
	README.hacking

if HAS_SVNREV
EXTRA_DIST += SVNREV
endif

distdir = $(PACKAGE)-$(VERSION)$(if $(SVNREV),-r$(SVNREV),)

dist-hook:
	rm -rf `find $(distdir) -name .svn -type d`

AM_MAKEFLAGS = --silent

# stuff for doxygen, boost checking
#ACLOCAL_AMFLAGS = -I /usr/share/autoconf-archive
include $(top_srcdir)/aminclude.am

MOSTLYCLEANFILES = $(DX_CLEANFILES)
