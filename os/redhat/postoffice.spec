#   package options
%define with_auth	yes
%define with_greylist	yes
%define with_tcpd	yes
%define with_virtual	yes

%define codeversion	1.2.4

Summary: A not so widely used Mail Transport Agent (MTA)
Name: postoffice
Version: %{codeversion}
Release: 1
License: BSD
Group: System Environment/Daemons
Source0: ftp://www.pell.chi.il.us/~orc/Code/postoffice/postoffice-%{codeversion}.tar.gz
Buildroot: %{_tmppath}/%{name}-root
BuildRequires: gdbm-devel
%if "%{with_tcpd}" == "yes"
BuildRequires: tcp_wrappers
%endif
PreReq: /usr/sbin/alternatives
Provides: %{_sbindir}/sendmail %{_bindir}/mailq %{_bindir}/newaliases
Provides: %{_mandir}/man1/mailq.1
Provides: %{_mandir}/man1/newaliases.1 %{_mandir}/man5/aliases.5
Provides: smtpdaemon


%description
The Postoffice program is a used Mail Transport Agent (MTA).  MTAs send
mail from one machine to another. Postoffice is not a client program,
which you use to read your email. Postoffice is a behind-the-scenes
program which actually moves your email over networks to where you want
it to go.

%prep
%setup -q

%build

OPTS=

%if "%{with_auth}" == "yes"
OPTS="$OPTS --with-auth"
%endif
%if "%{with_greylist}" == "yes"
OPTS="$OPTS --with-greylist"
%endif
%if "%{with_tcpd}" == "yes"
OPTS="$OPTS --with-tcpwrappers"
%endif
%if "%{with_virtual}" == "yes"
OPTS="$OPTS --with-vhost --with-vuser=news.uucp"
%endif


./configure.sh $OPTS --prefix=/usr \
                     --mandir=%{_mandir} \
                     --sbindir=%{_sbindir} \
                     --execdir=%{_bindir} --use-gdbm $OPTS

make

%install

rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT

make TARGET=$RPM_BUILD_ROOT/ install


(   cd $RPM_BUILD_ROOT;
    find . -type f -print | while read F;do
	Fn=`basename $F`
	Dn=`dirname $F`

	case "$Fn" in
	mailq.1|runq.1|sendmail.8|newaliases.1|smtpd.1|aliases.5|mailaddr.7)
		# rename to po.X to avoid collisions
		mv $F $Dn/po.$Fn
		;;
	esac
    done  )


install -d -m 755 -o 0 -g 0 $RPM_BUILD_ROOT/var/spool/mqueue
install -d -m 755 -o 0 -g 0 $RPM_BUILD_ROOT/etc/rc.d/init.d
install    -m 755 -o 0 -g 0 os/redhat/postoffice.sh \
                            $RPM_BUILD_ROOT/etc/rc.d/init.d/postoffice

%clean
rm -rf $RPM_BUILD_ROOT

%pre

%post
/usr/sbin/alternatives \
    --install %{_sbindir}/sendmail mta %{_sbindir}/postoffice 90 \
    --slave %{_bindir}/mailq mta-mailq %{_sbindir}/postoffice \
    --slave %{_bindir}/newaliases mta-newaliases %{_sbindir}/postoffice \
    --slave %{_bindir}/runq mta-runq %{_sbindir}/postoffice \
    --slave %{_bindir}/smtpd mta-smtpd %{_sbindir}/postoffice \
    --slave /usr/lib/sendmail mta-sendmail %{_sbindir}/postoffice \
    --slave %{_mandir}/man1/mailq.1.gz  mta-mailqman                    \
					%{_mandir}/man1/po.mailq.1.gz  \
    --slave %{_mandir}/man1/runq.1.gz  mta-runqman                     \
					%{_mandir}/man1/po.runq.1.gz  \
    --slave %{_mandir}/man8/sendmail.8.gz  mta-sendmailman                \
					%{_mandir}/man8/po.sendmail.8.gz  \
    --slave %{_mandir}/man1/newaliases.1.gz  mta-newaliasesman              \
					%{_mandir}/man1/po.newaliases.1.gz  \
    --slave %{_mandir}/man1/smtpd.1.gz mta-smtpdman                   \
					%{_mandir}/man1/po.smtpd.1.gz \
    --slave %{_mandir}/man5/aliases.5.gz mta-aliasesman                  \
					%{_mandir}/man5/po.aliases.5.gz  \
    --slave %{_mandir}/man7/mailaddr.7.gz mta-mailaddrman                \
					%{_mandir}/man7/po.mailaddr.7.gz \
    --initscript postoffice

%{_bindir}/newaliases       >/dev/null 2>&2
/etc/rc.d/init.d/postoffice start >/dev/null 2>&2
/sbin/chkconfig --add postoffice

%preun
if [ $1 = 0 ]; then
	/etc/rc.d/init.d/postoffice stop >/dev/null 2>&1
	/sbin/chkconfig --del postoffice
	/usr/sbin/alternatives --remove mta %{_sbindir}/postoffice
fi
exit 0

%files
%{_mandir}
%{_bindir}
%{_sbindir}
/usr/lib
/usr/libexec
/etc/rc.d/init.d
/var/spool/mqueue

%changelog
* Fri Feb 24 2006 David Parsons <orc@pell.chi.il.us> 1.2.3-1
- Initial version with rpm building support
