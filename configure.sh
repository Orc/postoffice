#! /bin/sh

# local options:  ac_help is the help message that describes them
# and LOCAL_AC_OPTIONS is the script that interprets them.  LOCAL_AC_OPTIONS
# is a script that's processed with eval, so you need to be very careful to
# make certain that what you quote is what you want to quote.

ac_help='
--use-peer-flag		enable -opeer (for debugging)
--use-mailwrappers	use mailwrappers if available
--with-tcpwrappers	use tcp wrappers
--with-greylist		use the greylist code
--with-queuedir		directory to use for the mail queue (/var/spool/mqueue)
--with-auth		enable smtp authentication (for AUTH LOGIN)
--with-milter		Use sendmail-style milters for message authentication
--with-av=SCRIPT	virus scanning script to run after receiving mail
--with-vhost[=PATH]	enable virtual hosting (/etc/virtual)
--with-vspool=PATH	virtual host mailspool (/var/spool/virtual)
--with-vuser=USER	user (or uid:gid) that should own vspool (mail)'

# load in the configuration file
#
TARGET=postoffice
USE_MAILWRAPPERS=T
. ./configure.inc

AC_INIT $TARGET

AC_PROG_CC

AC_SCALAR_TYPES
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

AC_CHECK_FUNCS setproctitle

if [ "$has_statfs" ]; then
    AC_SUB STATFS  ''
else
    AC_SUB STATFS  '.\\"'
fi


AC_PROG_AWK || exit 1

if [ -z "$OS_LINUX" ]; then
    # can we use ifconfig -a inet to pick up local ip addresses?

    TLOGN "Can we get local IP addresses with /sbin/ifconfig "

    if /sbin/ifconfig -a inet 2>/dev/null > /tmp/if$$.out; then
	# the format we're looking for is inet x.x.x.x [other stuff]

	fail=
	res=`grep inet /tmp/if$$.out | $AC_AWK_PROG '{print $2}'`
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
	if AC_QUIET AC_CHECK_FUNCS dbm_open || AC_LIBRARY dbm_open -ldb; then
	    LOG "Found dbmopen()" ${AC_LIBS:+in ${AC_LIBS}}
	    AC_SUB NDBM ndbm
	    DB=ndbm
	fi
    fi
fi

if [ -z "$DB" ]; then
    if AC_CHECK_HEADERS gdbm.h; then
	if AC_QUIET AC_CHECK_FUNCS gdbm_open || AC_LIBRARY gdbm_open -lgdbm;then
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
    hosts_ctl("smtp", "", "", "");
}
EOF
    if $AC_CC -o $$.x $$.c ; then
	TLOG "(ok)"
	AC_DEFINE WITH_TCPWRAPPERS 1
	AC_SUB    LIBWRAP ""
    elif $AC_CC -o $$.x $$.c -lwrap; then
	TLOG "(-lwrap)"
	AC_DEFINE WITH_TCPWRAPPERS 1
	AC_SUB    LIBWRAP "-lwrap"
    else
	TLOG "(no)"
	rm -f $$.c $$.x
	AC_FAIL "Cannot find tcp wrappers library -lwrap"
	AC_SUB    LIBWRAP ""
    fi
    rm -f $$.c $$.x
else
    AC_SUB    LIBWRAP ""
fi

case "$WITH_QUEUEDIR" in
"") AC_DEFINE QUEUEDIR \"/var/spool/mqueue/\" ;;
/*) AC_DEFINE QUEUEDIR \"${WITH_QUEUEDIR}/\"
    ;;
*)  AC_FAIL "The mail queue directory [$WITH_QUEUEDIR] must be a full pathname."
    ;;
esac

test "$USE_PEER_FLAG" && AC_DEFINE USE_PEER_FLAG 1
test "$WITH_GREYLIST" && AC_DEFINE WITH_GREYLIST 1
test "$WITH_COAL"     && AC_DEFINE WITH_COAL 1
if [ "$WITH_MILTER" ]; then
    AC_DEFINE WITH_MILTER 
    AC_SUB MILTERLIB mf.o
    AC_SUB MILTERMAN ''
else
    AC_SUB MILTERLIB ''
    AC_SUB MILTERMAN '.\\"'

    case "$WITH_AV" in
    \|*) AC_DEFINE AV_PROGRAM \""$WITH_AV"\" ;;
    ?*) AC_DEFINE AV_PROGRAM \"\|"$WITH_AV"\" ;;
    esac
fi

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


    VSPOOL=${WITH_VSPOOL:-/var/spool/virtual}
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
    TLOGN "checking for the crypt function "
    if AC_QUIET AC_CHECK_FUNCS crypt; then
	TLOG "(found)"
	AC_SUB LIBCRYPT ""
    else
	LIBS="$__libs -lcrypt"
	if AC_QUIET AC_CHECK_FUNCS crypt; then
	    TLOG "(in -lcrypt)"
	    AC_SUB LIBCRYPT "-lcrypt"
	else
	    TLOG "(not found)"
	    AC_FAIL "Cannot build AUTH support without a crypt() function"
	    unset WITH_AUTH
	    AC_SUB LIBCRYPT ""
	fi
    fi
    case "$WITH_AUTH" in
    [Pp][Aa][Ss][Ss][Ww][Dd])  AC_DEFINE AUTH_PASSWD 1 ;;
    esac
else
    AC_SUB LIBCRYPT ""
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

# check to see if ``make install'' needs to install all the binaries
# or just the ones that are compatable with mailwrapper.
# iff mailwrappers exists, and sendmail, send-mail, newaliases, and
# mailq are all identical to it (either via symlinks, hardlinks, or
# just as copies of it), install in a way that's compatable with them.

if [ "$USE_MAILWRAPPERS" ]; then
    TLOGN "Checking mailwrappers"

    if [ -x /usr/sbin/mailwrapper ]; then
	for x in /usr/sbin/sendmail /usr/bin/newaliases /usr/bin/mailq;do
	    if cmp -s $x /usr/sbin/mailwrapper; then
		TLOGN "."
	    else
		TLOG " (`basename $x` != mailwrapper)"
		unset USE_MAILWRAPPERS
		break
	fi
	done
	test "$USE_MAILWRAPPERS" && TLOG " (ok)"
    else
	TLOG " (no mailwrapper program)"
	unset USE_MAILWRAPPERS
    fi
fi

if [ "$USE_MAILWRAPPERS" ]; then
    # FreeBSD puts mailer.conf into /etc/mail, NetBSD and OpenBSD put
    # mailer.conf into /etc
    if [ "$OS_FREEBSD" -o "$OS_DRAGONFLY" ]; then
	AC_SUB MAILERCONF /etc/mail/mailer.conf
    elif [ "$OS_LINUX" ]; then
	# Gentoo Linux uses, or can use, mailwrappers, but the location
	# of the mailer.conf file varies.
	if [ -r /etc/mail/mailer.conf ]; then
	    AC_SUB MAILERCONF /etc/mail/mailer.conf
	else
	    AC_SUB MAILERCONF /etc/mailer.conf
	fi
    else
	AC_SUB MAILERCONF /etc/mailer.conf
    fi
    AC_SUB WHICH mailfilter
    AC_SUB MAILWRAPPER /usr/sbin/mailwrapper
else
    MF_PATH_INCLUDE FALSE false
    AC_SUB WHICH programs
fi


AC_OUTPUT Makefile postoffice.8 newaliases.1 vhosts.7 domains.cf.5 dbm.1 \
                   greylist.7 smtpauth.5 postoffice.cf.5 aliases.5 \
		   authexpire.8


# final warning checks, put here to put directory errors out where they
# won't be mixed up with the rest of the output

if [ "$use_mailwrapper" ]; then
    checkdirs="confdir libexec mandir"
else
    checkdirs="confdir libexec execdir sbindir mandir"
fi


for x in $checkdirs; do
    R=`echo ac_$x | tr 'a-z' 'A-Z'`
    eval D=\$$R
    test -d $D || LOG "WARNING! ${x} directory $D does not exist"
done

if [ "$WITH_VHOST" ]; then
    test -d $VPATH || LOG "WARNING! vhost directory $VPATH does not exist!"
    test -d $VSPOOL || LOG "WARNING! vhost directory $VSPOOL does not exist!"
fi

if [ "$WITH_QUEUEDIR" ]; then
    test -d $WITH_QUEUEDIR || LOG "WARNING! mail queue directory $WITH_QUEUEDIR does not exist!"
fi
