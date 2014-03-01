AC_INIT(pam-krb5-migrate, 0.0.11, [jelmer@samba.org])
AC_PROG_CC
AC_ARG_VAR(KRB5CONFIG, [Path to krb5-config script])
AC_PATH_PROGS(KRB5CONFIG, $ac_cv_env_KRB5CONFIG_value krb5-config krb5-config.heimdal)
AC_CHECK_LIB(pam, pam_get_item, [], [AC_MSG_ERROR([pam not found])])
save_LIBS="$LIBS"
save_CFLAGS="$CFLAGS"
LIBS="$LIBS `$ac_cv_path_KRB5CONFIG --libs kadm-client`"
CFLAGS="$CFLAGS `$ac_cv_path_KRB5CONFIG --cflags kadm-client`"
AC_CHECK_FUNCS(kadm5_get_policy)
PKG_CHECK_MODULES(COM_ERR, com_err)
AC_CHECK_HEADERS(kadm5/kadm_err.h)
AC_COMPILE_CHECK([number of arguments to kadm5_free_policy_ent],
[
#include <stdio.h>
#include <krb5.h>
#include <kadm5/admin.h>
],
[ kadm5_free_policy_ent(NULL); ],
[
AC_MSG_RESULT(1)
AC_DEFINE(KADM5_FREE_POLICY_ENT_1_ARG)],
[ AC_MSG_RESULT(2) ]
)

AC_COMPILE_CHECK([number of arguments to kadm5_init_with_skey],
[
#include <stdio.h>
#include <krb5.h>
#include <kadm5/admin.h>
],
[
kadm5_init_with_skey(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
],
[
AC_MSG_RESULT(7)
AC_DEFINE(KADM5_INIT_WITH_SKEY_7_ARGS)],
[
 AC_MSG_RESULT(9)
])

LIBS="$save_LIBS"
AC_CONFIG_FILES([Makefile.settings])
AC_OUTPUT
