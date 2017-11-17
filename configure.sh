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
--with-pam		Use PAM for authentication (for AUTH LOGIN)
--with-gcc-patch	patch the code to stop gcc -Wall from complaining
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
AC_CC_QUIET
unset _MK_LIBRARIAN


AC_C_VOLATILE
AC_C_CONST
AC_SCALAR_TYPES
AC_CHECK_HEADERS limits.h || AC_DEFINE "INT_MAX" "1<<((sizeof(int)*8)-1)"

AC_CHECK_ALLOCA || AC_FAIL "$TARGET requires alloca()"

AC_CHECK_FUNCS scandir || AC_FAIL "$TARGET requires scandir()"
AC_CHECK_FUNCS mmap || AC_FAIL "$TARGET requires mmap()"
AC_CHECK_FUNCS memstr
if AC_CHECK_FUNCS strlcpy ; then
    AC_SUB 'STRLCPY' ''
else
    AC_SUB 'STRLCPY' 'strlcpy.o'
    AC_TEXT 'extern char *strlcpy(char*,char*,int);'
fi
    

if ! AC_CHECK_TYPE socklen_t sys/types.h sys/socket.h; then
    AC_DEFINE socklen_t int
fi

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

AC_CHECK_FUNCS getloadavg
AC_CHECK_FUNCS setproctitle
AC_CHECK_FUNCS setlinebuf
AC_CHECK_FUNCS fcntl

if AC_CHECK_FUNCS random; then
    AC_DEFINE Deal	'random()'
    AC_DEFINE Shuffle	'srandom(time(0))'
elif AC_CHECK_FUNCS rand; then
    AC_DEFINE Deal	'rand()'
    AC_Define Shuffle	'srand(time(0))'
else
    AC_DEFINE Deal     0
    AC_DEFINE Shuffle  0
fi

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
if [ -z "$WITH_GDBM" ]; then
    if AC_CHECK_HEADERS ndbm.h; then
	if AC_LIBRARY dbm_open -ldb; then
	    AC_SUB NDBM ndbm
	    DB=ndbm
	fi
    fi
fi

if [ -z "$DB" ]; then
    if AC_CHECK_HEADERS gdbm.h; then
	if AC_LIBRARY gdbm_open -lgdbm;then
	    AC_SUB NDBM gdbm
	    DB=gdbm
	fi
    fi
fi

test -z "$DB" && AC_FAIL "$TARGET requires ndbm or gdbm"

AC_DEFINE `echo USE_$DB|tr 'a-z' 'A-Z'` 1

# check for DB vs DBM type
#

TLOGN "Looking for $DB handle type "

DB_HANDLE=
for blobtype in 'DB*' 'DBM*' GDBM_FILE; do

    cat > /tmp/ac$$.c << EOF
#include <$DB.h>

typedef $blobtype DBhandle;
EOF

    if $AC_CC -c -o /tmp/ac$$.o /tmp/ac$$.c; then
	DB_HANDLE=$blobtype
	AC_DEFINE "DB_HANDLE" $blobtype
	TLOG "($blobtype)"
	break
    fi
done
rm -f /tmp/ac$$.c /tmp/ac$$.o

test -z "$DB_HANDLE" && AC_FAIL "(can't figure out $DB handle type)"

AC_CHECK_RESOLVER || AC_FAIL "$TARGET requires resolver(3)"

AC_EXEC_MODES

LIBWRAP=''
if [ "$WITH_TCPWRAPPERS" ]; then
    AC_DEFINE 'WITH_TCPWRAPPERS' '1'
    __ac_libs=$AC_LIBS
    AC_LIBRARY hosts_ctl -lwrap || AC_FAIL "Cannot use tcp wrappers without the libwrap library"

    if [ "$__ac_libs" != "$AC_LIBS" ]; then
	LIBWRAP='-lwrap'
	AC_LIBS=$__ac_libs
    fi
fi
AC_SUB LIBWRAP "${LIBWRAP}"

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
    AC_SUB MILTERMAN ''
else
    AC_SUB MILTERMAN '.\\"'

    case "$WITH_AV" in
    \|*) AC_DEFINE AV_PROGRAM \""$WITH_AV"\" ;;
    ?*) AC_DEFINE AV_PROGRAM \"\|"$WITH_AV"\" ;;
    esac
fi

AC_CHECK_FLOCK || AC_DEFINE NO_FLOCK

AC_CHECK_HEADERS pwd.h grp.h ctype.h

AC_CHECK_HEADERS time.h

# check how big a time_t is, make a printf/scanf format for it
# (netBSD 6+, Minix 3 are 64 bit, most others still 32 bit, but
# there's no printf/scanf format for this thing)
cat > ngc$$.c << EOF
#include <stdio.h>
#include <time.h>

main()
{
    time_t clock;

    if ( sizeof(clock) == sizeof(int) )
	puts("%d");
    else if ( sizeof(clock) == sizeof(long) )
	puts("%ld");
    else if ( sizeof(clock) == sizeof(long long) )
	puts("%lld");
    
    return 0;
}
EOF

if $AC_CC -o ngc$$ ngc$$.c; then
    TIME_T_FMT=`./ngc$$`
fi
rm -f ngc$$ ngc$$.c
LOG "time_t printf/scanf format is ${TIME_T_FMT:-%ld}"
AC_DEFINE TIME_T_FMT \"${TIME_T_FMT:-%ld}\"


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
	return 1;

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
		return 1;
	}

	if ( grp = getgrnam(p) )
	    printf("av_GID=%d;\n", grp->gr_gid);
	else {
	    for (q=p; isdigit(*q); ++q)
		;
	    if (*q == 0)
		printf("av_GID=%s;\n", q);
	    else
		return 1;
	}
    }
    else if (pwd = getpwnam(argv[1]) ) {
	printf("av_UID=%d;\nav_GID=%d;\n", pwd->pw_uid, pwd->pw_gid);
	return 0;
    }
    return 1;
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
    
    AC_CHECK_HEADERS crypt.h && AC_DEFINE HAS_CRYPT_H 1
	
    __ac_libs=$AC_LIBS
    if AC_LIBRARY crypt -lcrypt; then
	if [ "$__ac_libs" != "$AC_LIBS" ]; then
	    AC_LIBS=$__ac_libs
	    AC_SUB LIBCRYPT '-lcrypt'
	else
	    AC_SUB LIBCRYPT ''
	fi
    else
	unset WITH_AUTH
	AC_SUB LIBCRYPT ""
	AC_FAIL "Cannot build --with-auth without a crypt() function"
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

unset LIBPAM
if [ "$WITH_PAM" -a "$WITH_AUTH" ]; then
    if AC_CHECK_HEADERS security/pam_appl.h; then
	__ac_libs="$AC_LIBS"
	if AC_LIBRARY pam_start -lpam; then
	    AC_CHECK_FUNCS pam_strerror
	    if [ "$__ac_libs" != "$AC_LIBS" ]; then
		LIBPAM="-lpam"
		AC_LIBS=$__ac_libs
	    fi
	else
	    AC_FAIL "need a PAM library --with-pam"
	    unset WITH_PAM
	fi
    else
	unset WITH_PAM
    fi
fi

AC_SUB	LIBPAM "$LIBPAM"

if [ "$WITH_PAM" ]; then
    AC_SUB	PAMOK ''
    AC_DEFINE	WITH_PAM 1
else
    AC_SUB	PAMOK '#'
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
    if [ -x /usr/sbin/mailwrapper ]; then
	for x in /usr/sbin/sendmail /usr/bin/newaliases /usr/bin/mailq;do
	    if ! cmp -s $x /usr/sbin/mailwrapper; then
		TLOG "Not using mailwrappers (`basename $x` != mailwrapper)"
		unset USE_MAILWRAPPERS
		break
	fi
	done
	test "$USE_MAILWRAPPERS" && TLOG "Using mailwrappers"
    else
	TLOG "No mailwrappers on this system"
	unset USE_MAILWRAPPERS
    fi
fi

[ "$OS_FREEBSD" -o "$OS_DRAGONFLY" ] || AC_CHECK_HEADERS malloc.h

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


AC_DEFINE CONFDIR '"'$AC_CONFDIR'"'

AC_OUTPUT Makefile postoffice.8 newaliases.1 vhosts.7 domains.cf.5 dbm.1 \
                   greylist.7 smtpauth.5 postoffice.cf.5 aliases.5 \
		   authexpire.8 usermap.7 os/systemd/postoffice.service


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
