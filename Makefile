CC=cc -baout

LIBWRAP=-lwrap
INCWRAP=

PGMS = postoffice dbm expire
MAN8PAGES=postoffice.8 authexpire.8 sendmail.8
MAN7PAGES=mailaddr.7 greylist.7
MAN5PAGES=aliases.5 smtpauth.5
MAN1PAGES=newaliases.1 mailq.1 runq.1

MANPAGES=$(MAN8PAGES) $(MAN7PAGES) $(MAN5PAGES) $(MAN1PAGES)

prefix=/usr
libdir=$(prefix)/lib
libexec=$(prefix)/libexec
bindir=$(prefix)/bin
sbindir=$(prefix)/sbin
mandir=$(prefix)/man

LIBS=-ldb

OBJS=server.o letter.o smtp.o addr.o getif.o getloadavg.o \
     mx.o userok.o address.o spool.o recipient.o listq.o \
     mail.o local.o virusscan.o greylist.o runq.o mapfd.o \
     config.o remote.o mbox.o bounce.o postoffice.o \
     newaliases.o arpatok.o

all: $(PGMS)

postoffice: $(OBJS)
	$(CC) $(CFLAGS) -o postoffice $(OBJS) $(LIBS) $(LIBWRAP)

expire:	expire.c
	$(CC) $(CFLAGS) -o expire expire.c $(LIBS)

dbm:	dbm.c
	$(CC) $(CFLAGS) -o dbm dbm.c $(LIBS)

install: $(PGMS) $(MANPAGES)
	install -m 4711 -c postoffice $(libdir)
	install -m 444 -c $(MAN8PAGES) $(mandir)/man8
	install -m 444 -c $(MAN7PAGES) $(mandir)/man7
	install -m 444 -c $(MAN5PAGES) $(mandir)/man5
	install -m 444 -c $(MAN1PAGES) $(mandir)/man1
	install -m 711 -c dbm $(bindir)/ndbm
	install -m 711 -c expire $(libexec)/authexpire
	for x in runq mailq newaliases sendmail; do \
	    rm -f $(bindir)/$$x; \
	    ln -s $(libdir)/postoffice $(bindir)/$$x; \
	done
	rm -f $(libdir)/sendmail
	ln -s $(libdir)/postoffice $(libdir)/sendmail
	rm -f $(sbindir)/sendmail
	ln -s $(libdir)/postoffice $(sbindir)/sendmail


clean:
	rm -f *.o $(PGMS)

addr.o: addr.c
address.o: address.c letter.h env.h mx.h
arpatok.o: arpatok.c
bounce.o: bounce.c config.h letter.h env.h mbox.h bounce.h
config.o: config.c config.h env.h
dbm.o: dbm.c
expire.o: expire.c
getif.o: getif.c
getloadavg.o: getloadavg.c
greylist.o: greylist.c config.h letter.h env.h
letter.o: letter.c config.h letter.h env.h mx.h spool.h
listq.o: listq.c spool.h letter.h env.h
local.o: local.c letter.h env.h
mail.o: mail.c config.h letter.h env.h
mapfd.o: mapfd.c
mbox.o: mbox.c mbox.h env.h mx.h
mx.o: mx.c mx.h
newaliases.o: newaliases.c config.h aliases.h env.h
ns.o: ns.c
postoffice.o: postoffice.c config.h letter.h env.h smtp.h
recipient.o: recipient.c letter.h env.h
remote.o: remote.c config.h letter.h env.h mbox.h bounce.h
runq.o: runq.c config.h spool.h letter.h env.h bounce.h
server.o: server.c config.h letter.h env.h smtp.h mx.h
smtp.o: smtp.c config.h letter.h env.h smtp.h
spool.o: spool.c spool.h letter.h env.h mx.h
userok.o: userok.c config.h letter.h env.h aliases.h
virusscan.o: virusscan.c config.h letter.h env.h
