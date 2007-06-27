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
--use-peer-flag		enable -opeer (for debugging)
--with-auth		enable smtp authentication (AUTH LOGIN)
--with-vhost[=PATH]	enable virtual hosting (/etc/virtual)
--with-vspool=PATH	virtual host mailspool (/var/spool/virtual)
--with-vuser=USER	user (or uid:gid) that should own vspool (mail)'

# load in the configuration file
#
TARGET=postoffice
. ./configure.inc

AC_INIT $TARGET

AC_PROG_CC

AC_CHECK_HEADERS limits.h || AC_DEFINE "INT_MAX" "1<<((sizeof(int)*8)-1)"

AC_CHECK_FUNCS mmap || AC_FAIL "$TARGET requires mmap()"

# for basename
if AC_CHECK_FUNCS basename; then
    AC_CHECK_HEADERS libgen.h
fi

if AC_CHECK_FUNCS statvfs; then
    if AC_CHECK_HEADERS sys/statvfs.h; then
	if AC_CHECK_STRUCT statvfs sys/statvfs.h; then
	    has_statfs=T
	fi
    fi
elif AC_CHECK_FUNCS statfs; then
    _h=
    if AC_CHECK_HEADERS sys/vfs.h; then
	_h=sys/vfs.h
    fi
    if AC_CHECK_HEADERS sys/param.h sys/mount.h; then
	_h="$_h sys/param.h sys/mount.h"
    fi
    if AC_CHECK_STRUCT statfs $_h; then
	has_statfs=T
    fi
fi

if [ "$has_statfs" ]; then
    AC_SUB STATFS  ''
else
    AC_SUB STATFS  '.\\"'
fi


if [ -z "$OS_LINUX" ]; then
    # can we use ifconfig -a inet to pick up local ip addresses?

    TLOGN "Can we get local IP addresses with /sbin/ifconfig "

    if /sbin/ifconfig -a inet 2>/dev/null > /tmp/if$$.out; then
	# the format we're looking for is inet x.x.x.x [other stuff]

	fail=
	res=`grep inet /tmp/if$$.out | awk '{print $2}'`
	for x in $res; do
	    res=`expr $x : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*'`
	    if [ "$res" -eq 0 ]; then
		fail=1
	    fi
	done

	if [ -n "$fail" -o -z "$res" ]; then
	    TLOG "(no)"
	else
	    TLOG "(yes)"
	    AC_DEFINE USE_IFCONFIG
	fi
    else
	TLOG "(no)"
    fi
    rm -f /tmp/if$$.out
fi


DB=
if [ -z "$USE_GDBM" ]; then
    if AC_CHECK_HEADERS ndbm.h; then
	if QUIET AC_CHECK_FUNCS dbm_open || AC_LIBRARY dbm_open -ldb; then
	    LOG "Found dbmopen()" ${AC_LIBS:+in ${AC_LIBS}}
	    AC_SUB NDBM ndbm
	    DB=ndbm
	fi
    fi
fi

if [ -z "$DB" ]; then
    if AC_CHECK_HEADERS gdbm.h; then
	if QUIET AC_CHECK_FUNCS gdbm_open || AC_LIBRARY gdbm_open -lgdbm; then
	    LOG "Found gdbm_open()" ${AC_LIBS:+in ${AC_LIBS}}
	    AC_SUB NDBM gdbm
	    DB=gdbm
	fi
    fi
fi

test -z "$DB" && AC_FAIL "$TARGET requires ndbm"

AC_LIBRARY res_query -lresolv || AC_FAIL "$TARGET requires res_query"

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


AC_CHECK_FLOCK || AC_DEFINE NO_FLOCK

AC_CHECK_HEADERS pwd.h grp.h ctype.h

# compile a little test program that can handle the many permutations
# of a user/group combo, since there doesn't seem to be a clean way of
# doing it using just system level stuff.
#             username  (uid,gid of this user)
#             user.group (uid of user, gid of group)
#             user.number (uid of user, specified gid)
#             number.group (specified uid, gid of group)
#             number.number (specified uid, gid)
#
cat << \EOF > $$.c
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <ctype.h>

main(int argc, char **argv)
{
    struct passwd *pwd;
    struct group *grp;

    char *p, *q;

    fprintf(stderr, "%s: UID/GID dumper for configure.sh\n", argv[0]);
    printf("av_UID=; av_GID=;\n");
    if (argc <= 1)
	exit(1);

    for (p = argv[1]; *p && (*p != ':') && (*p != '.'); ++p)
	;

    if (*p) {
	*p++ = 0;
	if ( pwd = getpwnam(argv[1]) )
	    printf("av_UID=%d;\n", pwd->pw_uid);
	else {
	    for (q=argv[1]; isdigit(*q); ++q)
		;
	    if (*q == 0)
		printf("av_UID=%s;\n", argv[1]);
	    else
		exit(1);
	}

	if ( grp = getgrnam(p) )
	    printf("av_GID=%d;\n", grp->gr_gid);
	else {
	    for (q=p; isdigit(*q); ++q)
		;
	    if (*q == 0)
		printf("av_GID=%s;\n", q);
	    else
		exit(1);
	}
    }
    else if (pwd = getpwnam(argv[1]) )
	printf("av_UID=%d;\nav_GID=%d;\n", pwd->pw_uid, pwd->pw_gid);
    else
	exit(1);
    exit(0);
}
EOF

$AC_CC -o uid $$.c
status=$?
rm -f $$.c
test $? -eq 0 || AC_FAIL "Could not compile UID/GID dumper"

if test "$WITH_VHOST"; then
    case "$WITH_VHOST" in
    /*) VPATH=$WITH_VHOST ;;
    *)	VPATH=/etc/virtual ;;
    esac

    test -d $VPATH || LOG "WARNING! vhost directory $VPATH does not exist"

    VSPOOL=${WITH_VSPOOL:-/var/spool/virtual}

    test -d $VSPOOL || LOG "WARNING! vhost directory $VSPOOL does not exist"

    VUSER=${WITH_VUSER:-mail}

    eval `./uid $VUSER`
    if [ "$av_UID" -a "$av_GID" ]; then
	AC_DEFINE VUSER_UID $av_UID
	AC_SUB    VUSER_UID $av_UID
	AC_DEFINE VUSER_GID $av_GID
	AC_SUB    VUSER_GID $av_GID
    else
	AC_FAIL "Virtual host spool owner $VUSER does not exist"
    fi

    AC_DEFINE VSPOOL  \"$VSPOOL\"
    AC_SUB    VSPOOL  $VSPOOL
    AC_DEFINE VPATH   \"$VPATH\"
    AC_SUB    VPATH   $VPATH
    AC_SUB    VHOST   ''
else
    AC_SUB VSPOOL ''
    AC_SUB VPATH  ''
    AC_SUB VHOST  '.\\"'
fi

if [ "$WITH_AUTH" ]; then
    AC_SUB	AUTHMK ''
    AC_DEFINE	SMTP_AUTH 1
else
    AC_SUB	AUTHMK '#'
fi

AC_DEFINE MAX_USERLEN	16

eval `./uid nobody`
if [ "$av_UID" -a "$av_GID" ]; then
    AC_DEFINE NOBODY_UID	$av_UID
    AC_DEFINE NOBODY_GID	$av_GID
else
    AC_FAIL "The 'nobody' account does not exist"
fi

rm -f uid


for x in confdir libexec execdir sbindir mandir; do
    R=`echo ac_$x | tr 'a-z' 'A-Z'`
    eval D=\$$R
    test -d $D || LOG "WARNING! ${x} directory $D does not exist"
done

AC_OUTPUT Makefile postoffice.8 newaliases.1 vhosts.7 domains.cf.5 dbm.1 greylist.7 smtpauth.5 postoffice.cf.5

