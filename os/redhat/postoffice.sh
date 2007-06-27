#!/bin/sh
#
#	/etc/rc.d/init.d/postoffice
#
# Starts postoffice
#
# chkconfig: 345 90 10
# description: The POSTOFFICE smtp server.
# processname: postoffice

# Source function library.
. /etc/init.d/functions

service="postoffice"
exe="/usr/lib/postoffice"
lockfile="/var/lock/subsys/postoffice"


test -x $exe || exit 0

RC=0

start() {
        test -f $lockfile && return 0
	echo -n $"Starting $service: "
	daemon $exe -bd -q45m; RC=$?
	echo
	[ $RC -eq 0 ] && touch $lockfile
	return $RC
}

stop() {
	echo -n $"Stopping $service: "
	killproc $exe; RC=$?
	echo
	[ $RC -eq 0 ] && rm -f $lockfile
	return $RC
}


case "$1" in
start)  start ;;
stop)   stop ;;
reload|restart)
	stop
	start ;;
condrestart)
	if test -f $lockfile; then
	    stop
	    start
	fi ;;
status) status $exe ;;
*)      echo $"Usage: $0 {start|stop|restart|condrestart|status}"
	exit 1 ;;
esac

exit $RC
