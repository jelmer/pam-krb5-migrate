CC = gcc
CFLAGS += -I/usr/kerberos/include
LDFLAGS += -Bsymbolic -x -shared

# Uncomment these lines to build the module with local db support.
#KLOCAL = -DKADMIN_LOCAL
#LIBS   = -lkadm5srv

# Uncomment these lines to build the module with remote kadmin support.
KLOCAL =
LIBS   = -lkadm5clnt

LIBS  += -lgssrpc -lgssapi_krb5 -lkdb5 -lkrb5 -lk5crypto
LIBS  += -ldyn -lcom_err -lpam -ldl -lc

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
