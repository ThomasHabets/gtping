# -*- Autoconf -*-
# gtping/configure.ac
#
# aclocal && autoheader && automake -a -c && autoconf -i
# or if working: autoreconf -i
#

AC_PREREQ(2.61)
AC_INIT([gtping], [0.15], [thomas@habets.se])
AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR([src/gtping.c])
AC_CONFIG_HEADER(config.h)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([m], [sqrt])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([recv], [socket])
AC_SEARCH_LIBS([send], [socket])
AC_SEARCH_LIBS([clock_gettime], [rt])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h netinet/in6.h stdlib.h \
string.h sys/socket.h sys/time.h unistd.h memory.h sys/uio.h \
ifaddrs.h \
])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_C_VOLATILE

EL_CLOCK_MONOTONIC

# Checks for library functions.
#AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([memcpy gettimeofday memset socket sqrt strerror strtoul])
AC_REPLACE_FUNCS(memset)

# Getaddrinfo
m4_include([config/herrno.m4])
m4_include([config/sockinttypes.m4])
AC_DECL_H_ERRNO
AC_TYPE_SOCKLEN_T
AC_TYPE_IN_PORT_T
AC_CHECK_FUNCS(getaddrinfo getnameinfo)
if test x"$ac_cv_func_getaddrinfo$ac_cv_func_getnameinfo" != xyesyes ; then
   AC_LIBOBJ(getaddrinfo)
fi


# struct msghdr has msg_control
# (4.4BSD, as opposed to 4.3BSD that has accrights)
AC_CACHE_CHECK([for msg_control field in struct msghdr],
                                  ac_cv_have_control_in_msghdr, [
                                  AC_TRY_RUN(
                                        [
#if defined (__SVR4) && defined (__sun)
# define _XOPEN_SOURCE
# define _XOPEN_SOURCE_EXTENDED 1
# define __EXTENSIONS__ 1
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
int main() {
#ifdef msg_control
exit(1);
#endif
struct msghdr m;
m.msg_control = 0;
m.msg_controllen = 0;
exit(0);
}
                ],
                        [ ac_cv_have_control_in_msghdr="yes" ],
                        [ ac_cv_have_control_in_msghdr="no" ]
                          )
])
AM_CONDITIONAL(HAVE_CONTROL_IN_MSGHDR,
               test x$ac_cv_have_control_in_msghdr = xyes)

# has MSG_ERRQUEUE.
# Only Linux has this as far as I know.
AC_CACHE_CHECK([for MSG_ERRQUEUE],
                                  ac_cv_have_msg_errqueue, [
                                  AC_TRY_RUN(
                                        [
#include <sys/types.h>
#include <sys/socket.h>
int main() {
int n;
n = MSG_ERRQUEUE;
exit(0);
}
                ],
                        [ ac_cv_have_msg_errqueue="yes" ],
                        [ ac_cv_have_msg_errqueue="no" ]
                          )
])
AM_CONDITIONAL(HAVE_MSG_ERRQUEUE, test x$ac_cv_have_msg_errqueue = xyes)

AM_CONDITIONAL(HAVE_IFADDRS_H, test x$ac_cv_header_ifaddrs_h = xyes)


# Output
AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile])
AC_OUTPUT

echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
