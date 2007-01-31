-include Makefile.settings
LDFLAGS += -Bsymbolic -x -shared

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
	$(CC) -o $@ -c $< $(KLOCAL) $(CFLAGS)

check:: 

install: all
	install -m755 -o root pam_krb5_migrate.so /lib/security/

tags:
	ctags -R .

clean:
	rm -f *.o *.so test

distclean:: clean
	rm -rf autom4te.cache config.log config.status Makefile.settings
