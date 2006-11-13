/*
   Kerberos 5 migration module
   Version 0.0.1.
   PAM authentication module to transparently add passwords to a Kerberos 5
   database.

   Copyright (C) Steve Langasek 2000

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/*
 * TODO:
 * nullok, nonull options.  One may not want to add a principal
 * to a kerberos db with a null password.
 */

/* indicate the following groups are defined */
#define PAM_SM_AUTH

#include "pam_krb5_migrate.h"

#define DEFAULT_KEYTAB	"/etc/security/pam_krb5.keytab"


/* Cleanup function for pam data. */
static void _cleanup(pam_handle_t * pamh, void *x, int error_status)
{
    if(x)
        free(x);
    x = NULL;
}


/* syslogging function for errors and other information */
static void _log_err(int err, pam_handle_t *pamh, const char *format, ...)
{
    char *service = NULL;
    char logname[1024];
    va_list args;

    pam_get_item(pamh, PAM_SERVICE, (const void **) &service);
    if (service) {
        snprintf(logname, sizeof(logname) - 1, "%s(pam_krb5_migrate)",
service);
    } else {
        snprintf(logname, sizeof(logname) - 1, "pam_krb5_migrate");
    }

    va_start(args, format);
    openlog(logname, LOG_CONS | LOG_PID, LOG_AUTH);
    vsyslog(err, format, args);
    va_end(args);
    closelog();
}


/*
 * Safe duplication of character strings, leaving
 * no evidence for later stack analysis.
 */
static char * _xstrdup(pam_handle_t *pamh, const char *x)
{
    register char *new = NULL;

    if (x != NULL) {
        register int i;

        for (i = 0; x[i]; ++i); /* length of string */
        if ((new = malloc(++i)) == NULL) {
            i = 0;
            _log_err(LOG_CRIT, pamh, "out of memory in _xstrdup");
        } else {
            while (i-- > 0) {
                new[i] = x[i];
            }
        }
        x = NULL;
    }
    return new;                 /* return the duplicate or NULL on error */
}


/* this is a front-end for module-application conversations */

static int converse(pam_handle_t * pamh, int debug, int nargs,
                     struct pam_message **message,
                     struct pam_response **response)
{
    int retval;
    struct pam_conv *conv;
    retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
    if (retval == PAM_SUCCESS) {
        retval = conv->conv(nargs, (const struct pam_message **) message
                            , response, conv->appdata_ptr);
        if (retval != PAM_SUCCESS && debug) {
            _log_err(LOG_DEBUG, pamh, "conversation failure [%s]",
                     pam_strerror(pamh, retval));
        }
    } else {
        _log_err(LOG_ERR, pamh,
                 "couldn't obtain coversation function [%s]",
                 pam_strerror(pamh, retval));
    }
    return retval;				/* propagate error status */
}


static int make_remark(pam_handle_t * pamh, int debug,
                        int type, const char *text)
{
    struct pam_message *pmsg[1], msg[1];
    struct pam_response *resp;
    pmsg[0] = &msg[0];
    msg[0].msg = text;
    msg[0].msg_style = type;
    resp = NULL;
    return converse(pamh, debug, 1, pmsg, &resp);
    return PAM_SUCCESS;
}


/*
 * pam_sm_authenticate() takes an authentication token and stores
 * it to a Kerberos database using the kadmin API.
 *
 */
int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                        int argc, const char **argv)
{
    int retval, *ret_data = NULL;

    int debug = 0, quiet = flags & PAM_SILENT;
    int local = 1, remote = 1;
    char *def_realm = NULL;
    char *cp;
    char *name = NULL, *pass = NULL;
    const char *lname = NULL;
    char *princstr = NULL, *keytab_name = NULL;
    kadm5_ret_t kret;
    krb5_context context;
    krb5_principal princ;
    kadm5_principal_ent_rec newprinc;
    kadm5_config_params params;
    kadm5_policy_ent_rec defpol;
    long mask = 0;
    void *handle = NULL;


    /* Get a few bytes so we can pass our return value to pam_sm_setcred(). */
    ret_data = malloc(sizeof(int));

    /* Initialize the params struct for kadmin. */
    memset((char *) &params, 0, sizeof(params));

    if (kret = krb5_init_context(&context)) {
        _log_err(LOG_ERR, pamh, "%s while initializing krb5 library",
                 error_message(kret));
	retval = PAM_SYSTEM_ERR;
        goto cleanup;
    }

    while (argc--) {
        if (!strncmp(*argv, "debug", 5)) {
            debug = 1;
#ifndef KADMIN_LOCAL
        } else if (!strncmp(*argv, "keytab=", 7)) {
            keytab_name = _xstrdup(pamh, *argv+7);
            if (keytab_name == NULL) {
                retval = PAM_BUF_ERR;
                goto cleanup;
            }
#else
        } else if (!strncmp(*argv, "keytab=", 7)) {
            _log_err(LOG_NOTICE, pamh,
                     "module compiled with local database support,"
                     "ignoring option %s",
                     *argv);
#endif
        } else if (!strncmp(*argv, "principal=", 10)) {
            princstr = _xstrdup(pamh, *argv+10);
            if (princstr == NULL) {
                retval = PAM_BUF_ERR;
                goto cleanup;
            }
        } else if (!strncmp(*argv, "realm=", 6)) {
            def_realm = _xstrdup(pamh, *argv+6);
            if (def_realm == NULL) {
                retval = PAM_BUF_ERR;
                goto cleanup;
            }
        } else {
            _log_err(LOG_ERR, pamh, "unrecognized option [%s]", *argv);
            retval = PAM_SYSTEM_ERR;
            goto cleanup;
        }
        ++argv;
    }

    /* Even if connected locally, we need a realm so we can properly build
       principal names. */
    if (def_realm == NULL && krb5_get_default_realm(context, &def_realm))
    {
        _log_err(LOG_ERR, pamh, "unable to get default realm");
        if(!quiet) {
            make_remark(pamh, debug, PAM_ERROR_MSG,
                        "unable to get default Kerberos realm");
        }
        retval = PAM_SYSTEM_ERR;
        goto cleanup;
    }

    params.mask |= KADM5_CONFIG_REALM;
    params.realm = def_realm;


    /*
     * If no principal name is specified, the principal name is
     * pam_migrate/hostname.
     */

    if (princstr == NULL) {
        /* We want a principal using the service name (pam_migrate) and
           the hostname. */
        if (kret = krb5_sname_to_principal(context, NULL,
                                           "pam_migrate", KRB5_NT_SRV_HST,
                                           &princ))
        {
            _log_err(LOG_ERR, pamh, "%s creating host service principal",
                     error_message(kret));
             retval = PAM_SYSTEM_ERR;
             goto cleanup;
        }

        /* Can we extract a string from the result? */
        if (kret = krb5_unparse_name(context, princ, &princstr)) {
            _log_err(LOG_ERR, pamh, "%s while canonicalizing principal name",
                     error_message(kret));
             krb5_free_principal(context, princ);
             retval = PAM_SYSTEM_ERR;
             goto cleanup;
        }

        /* Done with it either way */
        krb5_free_principal(context, princ);
    }

    /*
     * Initialize the kadm5 connection.  Either we're running in local
     * mode, in which case anything goes; or we need a keytab.
     */
#ifndef KADMIN_LOCAL
    /* Get default keytab if none was provided. */
    if (!keytab_name) {
        keytab_name = _xstrdup(pamh, "/etc/security/pam_krb5.keytab");
        if (keytab_name == NULL) {
            retval = PAM_BUF_ERR;
            goto cleanup;
        }
    }

    if (debug) {
        _log_err(LOG_DEBUG, pamh,
                 "Authenticating as principal %s with keytab %s.\n",
                 princstr, keytab_name);
    }
#endif

    kret = kadm5_init_with_skey(princstr, keytab_name,
                                    KADM5_ADMIN_SERVICE,
                                    &params,
                                    KADM5_STRUCT_VERSION,
                                    KADM5_API_VERSION_2,
                                    &handle);
    free(princstr);
    princstr = NULL;

    if (kret) {
        _log_err(LOG_ERR, pamh, 
                 "%s while initializing kadmin interface",
                 error_message(kret));
        retval = PAM_SYSTEM_ERR;
        goto cleanup;
    }


    /* Everything is in order.  Get our username and our realm,
       and add the principal. */

    /* get the username */
    retval = pam_get_user(pamh, &lname, "Username: ");
    if (retval != PAM_SUCCESS) {
        if (debug) {
            _log_err(LOG_DEBUG, pamh, "could not identify user");
        }
        goto cleanup;
    }
    if (debug) {
        _log_err(LOG_DEBUG, pamh, "username [%s] obtained", lname);
    }

    name = malloc(strlen(lname) + strlen(def_realm) + 2);
    if (name == NULL) {
        _log_err(LOG_CRIT, pamh, "no memory for principal name");
        retval = PAM_BUF_ERR;
        goto cleanup;
    }

    strncpy(name, lname, strlen(lname) + 1);

    /* Make sure we're dealing with a valid username. */
    if ((cp = strchr(name, '@'))) {
        *cp = '\0';
    }
    if ((cp = strchr(name, '/'))) {
        *cp = '\0';
    }

    /* Tack on the @REALM portion of the principal name. */
    strncat(name, "@", 2);
    strncat(name, def_realm, strlen(def_realm) + 1);

    /* Get the authtok; if we don't have one, silently fail. */
    retval = pam_get_item(pamh, PAM_AUTHTOK,
                          (const void **)&pass);

    if (retval != PAM_SUCCESS)
    {
	_log_err(LOG_ALERT, pamh,
	         "pam_get_item returned error to pam_sm_authenticate");
	retval = PAM_AUTHTOK_RECOVER_ERR;
        goto cleanup;
    } else if (pass == NULL) {
	retval = PAM_AUTHTOK_RECOVER_ERR;
        goto cleanup;
    }

    /* Zero all fields in request structure */
    memset(&newprinc, 0, sizeof(newprinc));
    newprinc.attributes = 0;

    kret = krb5_parse_name(context, name, &newprinc.principal);
    if (kret) {
        _log_err(LOG_ERR, pamh, "%s while setting up principal \"%s\"",
                 error_message(kret), name);
        krb5_free_principal(context, newprinc.principal);
        retval = PAM_SYSTEM_ERR;
        goto cleanup;
    }

    if (!kadm5_get_policy(handle, "default", &defpol)) {
        if (debug) {
            _log_err(LOG_DEBUG, pamh,
                     "no policy specified for %s; assigning \"default\"",
                     name);
        }
        newprinc.policy = "default";
        mask |= KADM5_POLICY;
        (void) kadm5_free_policy_ent(handle, &defpol);
    } else {
        if (debug) {
            _log_err(LOG_DEBUG, pamh,
                     "no policy specified for %s; defaulting to no policy",
                     name);
        }
    }
    mask &= ~KADM5_POLICY_CLR;

    mask |= KADM5_PRINCIPAL;
    kret = kadm5_create_principal(handle, &newprinc, mask, pass);

    /* TODO: some errors are more noteworthy than others. */
    if (kret && kret != KADM5_DUP) { // No need to log that the
                                     // principal is already there.
        if (!quiet)
	    make_remark(pamh, debug, PAM_ERROR_MSG, error_message(kret));
        _log_err(LOG_NOTICE, pamh, "%s creating principal \"%s\"",
                 error_message(kret), name);
        krb5_free_principal(context, newprinc.principal);
        retval = PAM_IGNORE;
        goto cleanup;
    } else if (kret && debug) {
        _log_err(LOG_DEBUG, pamh, "principal %s already exists, continuing",
                 name);
    }

    krb5_free_principal(context, newprinc.principal);
    if (debug && !kret) {
        _log_err(LOG_NOTICE, pamh, "Principal \"%s\" created", name);
    }

    /* return PAM_IGNORE, so that we don't
       affect the authentication stack. */
    retval = PAM_IGNORE;

cleanup:

    kadm5_flush(handle);
    kadm5_destroy(handle);
    krb5_free_context(context);
    if (princstr)
        free(princstr);
    if (def_realm)
        free(def_realm);
    if (keytab_name)
        free(keytab_name);
    if (name)
        free(name);
    if (ret_data) {
        *ret_data = retval;
        pam_set_data(pamh, "krb5_migrate_return",
                     (void *) ret_data, _cleanup);
    }
    return retval;
}

/*
 * pam_sm_setcred: stub function.  We have no credentials to set,
 * so we just return a value to match pam_sm_authenticate.
 */

int pam_sm_setcred(pam_handle_t *pamh, int flags,
                   int argc, const char **argv)
{
    int retval, *pretval = NULL;

    retval = PAM_SUCCESS;

    /* Retrieve the previous return value. */
    pam_get_data(pamh, "krb5_migrate_return", (const void **) &pretval);

    /* Copy the return value to local memory. */
    if(pretval) {
        retval = *pretval;
    }

    /* Trigger the cleanup function. */
    pam_set_data(pamh, "krb5_migrate_return", NULL, NULL);

    return retval;
}


/* static module data */
#ifdef PAM_STATIC
struct pam_module _pam_krb5_migrate_auth_modstruct = {
     "pam_krb5_migrate",
     pam_sm_authenticate,
     pam_sm_setcred,
     NULL,
     NULL,
     NULL,
     NULL
};
#endif
