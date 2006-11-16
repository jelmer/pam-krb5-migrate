CC = gcc
CFLAGS += -Wall `krb5-config --cflags krb5 kadm-client`
LDFLAGS += -Bsymbolic -x -shared

# Uncomment these lines to build the module with local db support.
#KLOCAL = -DKADMIN_LOCAL
#LIBS   = -lkadm5srv

# Uncomment these lines to build the module with remote kadmin support.
KLOCAL =
LIBS  += `krb5-config --libs krb5 kadm-client`
LIBS  += -lpam -ldl -lc

all: pam_krb5_migrate.so

pam_krb5_migrate.so: pam_krb5_migrate.o
	$(LD) -Bsymbolic -x -shared -o pam_krb5_migrate.so \
	  pam_krb5_migrate.o -L/usr/kerberos/lib $(LIBS)

pam_krb5_migrate.o: pam_krb5_migrate.c
	$(CC) -o $@ -c $< $(KLOCAL) $(CFLAGS)

install: all
	install -m755 -o root pam_krb5_migrate.so /lib/security/

clean:
	-rm *.o *.so

distclean: clean
