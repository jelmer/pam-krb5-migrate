AC_INIT(pam-krb5-migrate, 0.5, [jelmer@samba.org])
AC_PROG_CC
AC_PATH_PROG(KRB5CONFIG, krb5-config, no)
AC_CHECK_LIB(pam, pam_get_item, [], [AC_MSG_ERROR([pam not found])])
AC_CHECK_LIB(dl, dlopen, [], [AC_MSG_ERROR([libdl not found])])
AC_CONFIG_FILES([Makefile.settings])
AC_OUTPUT
