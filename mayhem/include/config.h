/* mayhem/include/config.h — stands in for the autoconf-generated config.h of the
 * virtualsmartcard/ and pcsc-relay/ sub-projects, with the values ./configure
 * produces on Linux (configure.ac: VPCDSLOTS default 2, VPCDHOST NULL,
 * MSG_NOSIGNAL available, tcgetattr available). Only the fuzz harnesses and the
 * self-test compile against it. */
#ifndef VSC_MAYHEM_CONFIG_H
#define VSC_MAYHEM_CONFIG_H
#define HAVE_DECL_MSG_NOSIGNAL 1
#define HAVE_DECL_SO_NOSIGPIPE 0
#define HAVE_ARPA_INET_H 1
#define HAVE_STDINT_H 1
#define HAVE_TCGETATTR 1
#define VPCDSLOTS 2
#define VPCDHOST NULL
/* pcsc-relay's --enable-piccdev=PATH; here a runtime path so each process uses
 * its own scratch file under $TMPDIR. */
extern char vsc_piccdev[];
#define PICCDEV vsc_piccdev
#endif
