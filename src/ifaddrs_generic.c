/** gtping/ifaddrs_generic.c
 *
 *  By Thomas Habets <thomas@habets.se> 2010
 *
 * Systems known to use this code: Solaris
 *
 * dummy getIfAddrs() for systems where we don't know how to list addresses.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/**
 *
 */
struct addrinfo*
getIfAddrs(const struct addrinfo *dest)
{
	return 0;
}
