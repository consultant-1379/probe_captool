AC_INIT([captool], [trunk])

AM_INIT_AUTOMAKE([foreign])
AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT([`pwd`])

save_cxxflags=$CXXFLAGS
AC_PROG_CXX()
if test x$save_cxxflags = x; then CXXFLAGS=; fi # I'm doing this to avoid default addition of "-g -O2" when profiling

AC_LANG([C++])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

DX_PDF_FEATURE([OFF])
DX_PS_FEATURE([OFF])
DX_INIT_DOXYGEN([$PACKAGE_NAME], [Doxyfile])

dnl Save SVN revision number
dnl   (based on http://www.freesoftwaremagazine.com/books/agaal/catalog_of_reusable_solutions)
AC_MSG_CHECKING([SVN revision number of the source])
SVNREV=`svnversion $srcdir`; \
which svnversion > /dev/null; \
if test $? -ne 0 || test "x$SVNREV" = "xexported"; then
	SVNREV=`cat $srcdir/SVNREV 2> /dev/null`
else
	echo -n $SVNREV > $srcdir/SVNREV
fi
AM_CONDITIONAL([HAS_SVNREV], [test x$SVNREV != x])
if test x$SVNREV != x; then
	AC_MSG_RESULT([$SVNREV])
else
	AC_MSG_RESULT([none])
fi
AC_SUBST([SVNREV])


dnl Static binaries build
AC_MSG_CHECKING([whether to build static programs])
AC_ARG_ENABLE(
	[static],
	[AS_HELP_STRING([--enable-static], [Build statically linked programs @<:@default no@:>@])],
	[case "${enableval}" in
		yes) static=true ;;
		no)  static=false ;;
		*) AC_MSG_ERROR([bad value ${enableval} for --enable-static]) ;;
	esac],
	[static=false])
AC_MSG_RESULT($static)


dnl Debug symbols option
AC_MSG_CHECKING([whether to build with debug information])
AC_ARG_ENABLE(
	[debug],
	[AS_HELP_STRING([--enable-debug], [Turn on debugging symbols @<:@default no@:>@])],
	[case "${enableval}" in
		yes) debug=true ;;
		no)  debug=false ;;
		*) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
	esac;
	AC_DEFINE([DEBUG])],
	[debug=false])
AC_MSG_RESULT($debug)


dnl Profiling executable build
AC_MSG_CHECKING([whether to build profiling binary])
AC_ARG_ENABLE(
	[profile],
	[AS_HELP_STRING([--enable-profile@<:@=perftools@:>@], [Build profiling binary (standard or `google-perftools') @<:@default no; implies `--enable-static'@:>@])],
	[case "${enableval}" in
		perftools) profile=true; profile_perftools=true ; static=true ;;
		yes) profile=true ; static=true ;;
		no)  profile=false ;;
		*) AC_MSG_ERROR([bad value ${enableval} for --enable-profile]) ;;
	esac],
	[profile=false])
AC_MSG_RESULT($profile)

AM_CONDITIONAL([STATIC], [test x$static = xtrue])
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])
AM_CONDITIONAL([PROFILE], [test x$profile = xtrue])
AM_CONDITIONAL([PROFILE_PERFTOOLS], [test x$profile_perftools = xtrue])


dnl Extra headers and libraries
AC_SEARCH_LIBS([dlopen], [dl])
AC_SEARCH_LIBS([pcap_close], [pcap])
AX_BOOST_BASE
AX_BOOST_ASIO

if test x$profile_perftools = xtrue; then
  AC_CHECK_HEADER([google/heap-profiler.h], [], [AC_MSG_ERROR([Missing headers from google-perftools])])
  AC_CHECK_HEADER([google/profiler.h], [], [AC_MSG_ERROR([Missing headers from google-perftools])])
  AC_SEARCH_LIBS([ProfilerStart], [profiler])
  AC_SEARCH_LIBS([HeapProfilerStart], [tcmalloc])
fi

PKG_CHECK_MODULES([extralibs], [libxml++-2.6 libconfig++ libpcre])
extralibs_LIBS="$extralibs_LIBS -pthread"
AC_SUBST([extralibs_CFLAGS])
AC_SUBST([extralibs_LIBS])

dnl uber hack: pkg-config m4cros do not return static libs
dnl  - also libpcre is not returned for glib in libxml++...
extra_static_libs="`$PKG_CONFIG --static --libs libxml++-2.6 libconfig++ libpcre` -ldl -lpcap"
AC_SUBST([extra_static_libs])

AC_CONFIG_FILES([Makefile src/Makefile Doxyfile])
AC_OUTPUT
