pam_krb5_migrate is a stackable authentication module that takes a username
and password from an earlier module in the stack, and attempts to
transparently add them to a Kerberos realm using the Kerberos 5 kadmin
service.
The module can be used to ease the administrative burdens of migrating a
large installed userbase from pre-existing authentication methods to a
Kerberos-based setup.

The most current version of this module can always be found at
https://www.samba.org/~jelmer/pam_krb5_migrate

For sample usage in a module stack, see the enclosed login.pam file.

The following options are recognized by the module:

debug                 turn debug logging on
keytab=<file>         use alternate keytab for authentication
                         (default is /etc/security/pam_krb5.keytab)
min_uid=<uid>         don't add principals for uid's lower than <uid>.
                         (default is 100)
principal=<name>      use the key for <name> instead of the default
                         pam_migrate/<hostname> key
realm=<REALM>         update the database for a realm other than the
                         default realm.

pam_krb5_migrate was written by Steve Langasek <vorlon@netexpress.net>.

Please send questions and comments (and especially bugfixes) to the current
maintainer, Jelmer Vernooĳ <jelmer@samba.org>.

