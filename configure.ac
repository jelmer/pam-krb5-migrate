AC_INIT(pam-krb5-migrate, 0.0.7, [jelmer@samba.org])
AC_PROG_CC
AC_PATH_PROG(KRB5CONFIG, krb5-config, no)
AC_CHECK_LIB(pam, pam_get_item, [], [AC_MSG_ERROR([pam not found])])
save_LIBS="$LIBS"
LIBS="$LIBS `$ac_cv_path_KRB5CONFIG --libs kadm-client`"
AC_CHECK_FUNCS(kadm5_get_policy)
PKG_CHECK_MODULES(COM_ERR, com_err)
LIBS="$save_LIBS"
AC_CONFIG_FILES([Makefile.settings])
AC_OUTPUT
