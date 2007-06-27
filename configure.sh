#! /bin/sh

# local options:  ac_help is the help message that describes them
# and LOCAL_AC_OPTIONS is the script that interprets them.  LOCAL_AC_OPTIONS
# is a script that's processed with eval, so you need to be very careful to
# make certain that what you quote is what you want to quote.

ac_help='
--with-av=SCRIPT	virus scanning script to run after receiving mail
--with-tcpwrappers	use tcp wrappers
--with-greylist		use the greylist code
--with-queuedir		directory to use for the mail queue (/var/spool/mqueue)
--use-peer-flag		enable -opeer (for debugging)'

# load in the configuration file
#
TARGET=postoffice
. ./configure.inc

AC_INIT $TARGET

AC_PROG_CC

AC_CHECK_HEADERS limits.h || AC_DEFINE "INT_MAX" "1<<((sizeof(int)*8)-1)"

AC_CHECK_FUNCS mmap || AC_FAIL "$TARGET requires mmap()"
AC_CHECK_HEADERS ndbm.h || AC_FAIL "$TARGET requires ndbm"
if QUIET AC_CHECK_FUNCS dbm_open || AC_LIBRARY dbm_open -ldb; then
    LOG "Found dbmopen()" ${AC_LIBS:+in ${AC_LIBS}}
else
    AC_FAIL "$TARGET requires ndbm"
fi

if [ "$WITH_TCPWRAPPERS" ]; then
    TLOGN	"Checking for libwrap "
cat << EOF > $$.c
#include <tcpd.h>
int allow_severity = 1;
int deny_severity = 1;
main()
{
    hosts_ctl();
}
EOF
    if $AC_CC -o $$.x $$.c ; then
	TLOG "(ok)"
	AC_DEFINE WITH_TCPWRAPPERS 1
    elif $AC_CC -o $$.x $$.c -lwrap; then
	TLOG "(-lwrap)"
	AC_DEFINE WITH_TCPWRAPPERS 1
	AC_LIBS="$AC_LIBS -lwrap"
    else
	TLOG "(no)"
	rm -f $$.c $$.x
	AC_FAIL "Cannot find tcp wrappers library -lwrap"
    fi
    rm -f $$.c $$.x
fi

if [ "$WITH_QUEUEDIR" ]; then
    AC_DEFINE QUEUEDIR \"${WITH_QUEUEDIR}/\"
else
    AC_DEFINE QUEUEDIR \"/var/spool/mqueue/\"
fi

test "$USE_PEER_FLAG" && AC_DEFINE USE_PEER_FLAG 1
test "$WITH_GREYLIST" && AC_DEFINE WITH_GREYLIST 1
test "$WITH_COAL"     && AC_DEFINE WITH_COAL 1
test "$WITH_AV"       && AC_DEFINE AV_PROGRAM \""$WITH_AV"\"

AC_DEFINE NOBODY_UID	"`id -u nobody`"
AC_DEFINE NOBODY_GID	"`id -u nobody`"

AC_OUTPUT Makefile

