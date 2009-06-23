# -*- Autoconf -*-
# gtping/configure.ac
#
# aclocal && autoheader && automake -a -c && autoconf -i
# or if working: autoreconf -i
#

AC_PREREQ(2.61)
AC_INIT([gtping], [0.14], [thomas@habets.pp.se])
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR([gtping.c])
AC_CONFIG_HEADER(config.h)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([m], [sqrt])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([recv], [socket])
AC_SEARCH_LIBS([send], [socket])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h \
sys/socket.h sys/time.h unistd.h memory.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_C_VOLATILE

# Checks for library functions.
#AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([memcpy gettimeofday memset socket sqrt strerror strtoul])
AC_REPLACE_FUNCS(memset)

# Getaddrinfo
m4_include([m4/herrno.m4])
m4_include([m4/sockinttypes.m4])
AC_DECL_H_ERRNO
AC_TYPE_SOCKLEN_T
AC_TYPE_IN_PORT_T
AC_CHECK_FUNCS(getaddrinfo getnameinfo)
if test "$ac_cv_func_getaddrinfo$ac_cv_func_getnameinfo" != yesyes ; then
   AC_LIBOBJ(getaddrinfo)
fi


# struct msghdr has msg_control
# (4.4BSD, as opposed to 4.3BSD that has accrights)
AC_CACHE_CHECK([for msg_control field in struct msghdr],
                                  ac_cv_have_control_in_msghdr, [
                                  AC_TRY_RUN(
                                        [
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
#if test "x$" = "xyes" ; then
#   AC_DEFINE([HAVE_CONTROL_IN_MSGHDR], [], [msghdr.msg_control exists])
#fi


# Output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
