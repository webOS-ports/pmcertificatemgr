// @@@LICENSE
//
//      Copyright (c) 2008-2013 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// LICENSE@@@

/*****************************************************************************/
/* cert_x509.c: interaction with X.509 package files                         */
/*****************************************************************************/
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "cert_mgr.h"
#include "cert_cfg.h"
#include "cert_utils.h"
#include "cert_x509.h"
#include "cert_debug.h"

#define IPV6_ADDR_ASC_SIZE 39

static int get_ossl_nid(X509Properties);
static X509_NAME* get_cname(const X509*, X509Properties);
static int get_subject_altname(const X509*, char*, size_t);

#ifdef __cplusplus
extern "C" {
#endif

CertReturnCode CertX509ReadStrProperty(const X509 *cert, X509Properties property, char *o_buf, int len)
{
    /* Make sure we have a certificate */
    if (cert == NULL)
    {
        return CERT_BAD_CERTIFICATE;
    }

    /* Don't dereference NULL pointers */
    if (o_buf == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    /* Make sure we can at least write NUL to the output buffer */
    if (len <= 0)
    {
        return CERT_INSUFFICIENT_BUFFER_SPACE;
    }

    /* NUL terminate the output buffer before doing anything with it */
    *o_buf = '\0';

    switch (property)
    {
    case CERTX509_SUBJECT_ALT_NAME:
        return get_subject_altname(cert, o_buf, (size_t)len);

    case CERTX509_START_DATE:
        return getTimeString(X509_get_notBefore(cert), o_buf, len);

    case CERTX509_EXPIRATION_DATE:
        return getTimeString(X509_get_notAfter(cert), o_buf, len);

    default:
        {
            //### dataIdx = X509_NAME_get_text_by_NID(cname, nid, o_buf, len);
            int lastpos = -1;
            X509_NAME *cname;
            CertReturnCode result;
            int nid = get_ossl_nid(property);

            /* Make sure we have a valid OpenSSL property */
            if (nid == NID_undef)
            {
                return CERT_UNKNOWN_PROPERTY;
            }

            cname = get_cname(cert, property);

            if (cname == NULL)
            {
                return CERT_GENERAL_FAILURE;
            }

            result = CERT_PROPERTY_NOT_FOUND;

            do /* while (result == CERT_OK) */
            {
                X509_NAME_ENTRY *entry;

                lastpos = X509_NAME_get_index_by_NID(cname, nid, lastpos);

                if (lastpos == -1)
                {
                    break;
                }

                entry = X509_NAME_get_entry(cname, lastpos);

                /* Append the entry value to the output buffer */
                result = cmutils_strdsvcat(o_buf, len, (const char *)X509_NAME_ENTRY_get_data(entry), ',');
            } while (result == CERT_OK)

            return result;
        }
    }
}

CertReturnCode checkCert(const X509 *cert, const char *ca_file, const char *ca_path)
{
    X509_LOOKUP *lookup;
    X509_STORE *cert_ctx = X509_STORE_new();

    if (cert_ctx == NULL)
    {
        goto error;
    }

    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());

    if (lookup == NULL)
    {
        goto error;
    }

    if (ca_file == NULL)
    {
        X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
    }
    else if (!X509_LOOKUP_load_file(lookup, ca_file, X509_FILETYPE_PEM))
    {
        DPRINTF("Error loading file %s\n", ca_file);
        goto error;
    }

    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());

    if (lookup == NULL)
    {
        goto error;
    }

    if (ca_path == NULL)
    {
        X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
    }
    else if (!X509_LOOKUP_add_dir(lookup, ca_path, X509_FILETYPE_PEM))
    {
        DPRINTF("Error loading directory %s\n", ca_path);
        goto error;
    }

    X509_STORE_free(cert_ctx);

    return CERT_OK;

error:
    if (cert_ctx != NULL)
    {
        X509_STORE_free(cert_ctx);
    }

    return CERT_GENERAL_FAILURE;
}

static int get_subject_altname(const X509 *cert, char *o_buf, size_t len)
{
    int val_idx;
    char ipaddr[IPV6_ADDR_ASC_SIZE + 1];
    CertReturnCode append_result;
    GENERAL_NAMES *gens = X509_get_ext_d2i((X509 *)cert, NID_subject_alt_name, NULL, NULL);

    if (gens == NULL)
    {
        return CERT_PROPERTY_NOT_FOUND;
    }

    for (val_idx = 0, append_result = CERT_OK;
         (append_result == CERT_OK) && (val_idx < sk_GENERAL_NAME_num(gens));
         ++val_idx)
    {
        const char *p;
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(gens, val_idx);

        DSYSLOG(LOG_INFO, "1sub_str");

        switch (gen->type)
        {
        case GEN_IPADD:
            if (cmutils_ip2str(gen->d.ip, ipaddr, sizeof(ipaddr)) != CERT_OK)
            {
                /* Invalid IP address -- ignore */
                continue;
            }

            p = ipaddr;
            break;

        case GEN_DNS:
        case GEN_URI:
            p = (const char *)gen->d.ia5->data;
            break;

        default:
            continue;
        }

        append_result = cmutils_strdsvcat(o_buf, len, p, ',');
        DSYSLOG(LOG_INFO, "2 sub_str: %s", o_buf);
    }

    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);

    return append_result;
}

static X509_NAME* get_cname(const X509 *cert, X509Properties property)
{
    /* OpenSSL requires a mutable pointer to `cert` even though it
     * never changes it. So in order to keep the API clean we accept
     * immutable pointer and silently cast it to mutable to make OpenSSL
     * happy */
    switch (property)
    {
    case CERTX509_ISSUER_ORGANIZATION_NAME:
    case CERTX509_ISSUER_ORGANIZATION_UNIT_NAME:
    case CERTX509_ISSUER_COMMON_NAME:
    case CERTX509_ISSUER_COUNTRY:
    case CERTX509_ISSUER_STATE:
    case CERTX509_ISSUER_LOCATION:
        return X509_get_issuer_name((X509 *)cert);

    case CERTX509_SUBJECT_ORGANIZATION_NAME:
    case CERTX509_SUBJECT_ORGANIZATION_UNIT_NAME:
    case CERTX509_SUBJECT_COMMON_NAME:
    case CERTX509_SUBJECT_ALT_NAME:
    case CERTX509_SUBJECT_COUNTRY:
    case CERTX509_SUBJECT_STATE:
    case CERTX509_SUBJECT_LOCATION:
        return X509_get_subject_name((X509 *)cert);

    default:
        return NULL;
    }
}

static int get_ossl_nid(X509Properties property)
{
    /* Convert the CERTX509_* property to OpenSSL NID */
    switch (property)
    {
    case CERTX509_ISSUER_ORGANIZATION_NAME:
    case CERTX509_SUBJECT_ORGANIZATION_NAME:
        return NID_organizationName;

    case CERTX509_ISSUER_ORGANIZATION_UNIT_NAME:
    case CERTX509_SUBJECT_ORGANIZATION_UNIT_NAME:
        return NID_organizationalUnitName;

    case CERTX509_ISSUER_COMMON_NAME:
    case CERTX509_SUBJECT_COMMON_NAME:
        return NID_commonName;

    case CERTX509_SUBJECT_ALT_NAME:
        return NID_subject_alt_name;

    case CERTX509_ISSUER_SURNAME:
    case CERTX509_SUBJECT_SURNAME:
        return NID_surname;

    case CERTX509_ISSUER_COUNTRY:
    case CERTX509_SUBJECT_COUNTRY:
        return NID_countryName;

    case CERTX509_ISSUER_STATE:
    case CERTX509_SUBJECT_STATE:
        return NID_stateOrProvinceName;

    case CERTX509_ISSUER_LOCATION:
    case CERTX509_SUBJECT_LOCATION:
        return NID_localityName;

    default:
        return NID_undef;
    }
}

#ifdef __cplusplus
}
#endif
