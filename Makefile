include Makefile.settings
LDFLAGS += -Bsymbolic -x -shared
CFLAGS += `$(KRB5CONFIG) --cflags krb5 kadm-client`
CFLAGS += -fPIC

# Uncomment these lines to build the module with local db support.
#KLOCAL = -DKADMIN_LOCAL
#LIBS   = -lkadm5srv

# Uncomment these lines to build the module with remote kadmin support.
KLOCAL =
LIBS  += `$(KRB5CONFIG) --libs krb5 kadm-client`
LIBS  += -lc

all: pam_krb5_migrate.so

pam_krb5_migrate.so: pam_krb5_migrate.o
	$(LD) -Bsymbolic -x -shared -o pam_krb5_migrate.so \
	  pam_krb5_migrate.o $(LIBS)

pam_krb5_migrate.o: pam_krb5_migrate.c
	$(CC) -o $@ -c $< $(KLOCAL) $(CFLAGS) $(DEFS)

check:: 

install: all
	install -d $(DESTDIR)/lib/security
	install -d $(DESTDIR)$(mandir)/man7
	install -m755 -o root pam_krb5_migrate.so $(DESTDIR)/lib/security/
	install -m0644 -o root pam_krb5_migrate.7 $(DESTDIR)$(mandir)/man7

ctags:
	ctags -R .

clean:
	rm -f *.o *.so test

distclean:: clean
	rm -rf autom4te.cache config.log config.status Makefile.settings
