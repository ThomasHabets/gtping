#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(gtping, 0.12, thomas@habets.pp.se)
AM_INIT_AUTOMAKE([gtping], [0.12])
AC_CONFIG_SRCDIR([gtping.c])
#AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([m], [sqrt])
#AC_CHECK_LIB([socket], [socket], [], [echo lala ny rad exit 1])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_C_VOLATILE

# Checks for library functions.
AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([gettimeofday memset socket sqrt strerror strtoul])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
