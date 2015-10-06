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

/* cert_db.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/txt_db.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>

#include "cert_mgr.h"
#include "cert_cfg.h"
#include "cert_utils.h"
#include "cert_db.h"
#include "cert_debug.h"

/* workaround for missing OPENSSL_PSTRING type in openssl-0.9.8k
 * TODO: remove when support for openssl-0.9.8k not needed (>openssl-1.0.0i used)
 */
#ifndef sk_OPENSSL_PSTRING_num
#  define sk_OPENSSL_PSTRING_num sk_num
#endif
#ifndef sk_OPENSSL_PSTRING_value
#  define sk_OPENSSL_PSTRING_value sk_value
#endif

typedef struct db_attr_st
{
    int unique_subject;
} DB_ATTR;

typedef struct ca_db_st
{
    TXT_DB *db;
    DB_ATTR attributes;
} CA_DB;

static CA_DB* CertLockDatabase(int user);
static int CertUnlockDatabase(void);
static CertStatus getCertStatusByString(const char *status);
static void* OPENSSL_malloc_wrap(size_t sz);
static CertReturnCode cmdb_TXT_DB_read(FILE *fp, int num);
static int cmdb_TXT_DB_write(FILE *fp, TXT_DB *db);
static CA_DB* load_index(const char *db_path, DB_ATTR *db_attr);
static CertReturnCode save_index(const char *db_path, CA_DB *db);
static void free_index(CA_DB *db);
static int parse_yesno(const char *str, int def);


static CA_DB *g_clocaldb = NULL;
static DB_ATTR g_db_attr;
static int g_db_lock_ctr = 1;
static int g_db_user_id = 0;
static char g_loaded_db[MAX_CERT_PATH];

#ifdef __cplusplus
extern "C" {
#endif

static CA_DB* CertLockDatabase(int user)
{
    /* FIXME: This is not thread-safe */
    if ((g_db_lock_ctr++) || (g_clocaldb == NULL))
    {
        --g_db_lock_ctr;
        return NULL;
    }

    /* XXX: Is this used for anything? */
    g_db_user_id = user;

    return g_clocaldb;
}

static int CertUnlockDatabase(void)
{
    /* FIXME: This is not thread-safe */
    return --g_db_lock_ctr;
}



/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertInitDatabase                                                */
/*       Initial reading of the database                                     */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode CertInitDatabase(const char *db_path)
{
    CA_DB *db;
    struct stat statbuf;
    CertReturnCode result = CERT_GENERAL_FAILURE;

    if (g_clocaldb != NULL)
    {
        return CERT_DATABASE_LOCKED;
    }

    if (strlen(db_path) >= MAX_CERT_PATH)
    {
        return CERT_PATH_LIMIT_EXCEEDED;
    }

    if (g_db_lock_ctr == 0)
    {
        return CERT_DATABASE_NOT_AVAILABLE;
    }

    if (stat(db_path, &statbuf) != 0)
    {
        return CERT_FILE_ACCESS_FAILURE;
    }

    if ((CertInitLockFiles() != CERT_OK) ||
        (CertLockFile(CERT_DATABASE_LOCK) != CERT_OK))
    {
        return CERT_LOCK_FILE_LOCKED;
    }

    db = load_index(db_path, &g_db_attr);

    if (db == NULL)
    {
        result = CERT_FILE_ACCESS_FAILURE;
        goto cleanup;
    }

    strcpy(g_loaded_db, db_path);
    g_clocaldb = db;
    result = CERT_OK;

    /* Unlock the database in the grossest manner */
    g_db_lock_ctr = 0;

cleanup:
    CertUnlockFile(CERT_DATABASE_LOCK);

    return result;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertReadDatabase                                                */
/*       Initial reading of the database                                     */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/*      CERT_OK                                                              */
/*      CERT_DATABASE_INITIALIZATION_ERROR: The database was never init'ed   */
/*      CERT_FILE_ACCESS_FAILURE: The database file could not be accessed    */
/*      CERT_LOCKED_FILE_LOCKED: The database lockfile is unavailable        */
/* NOTES:                                                                    */
/*      1) Check to see if load_index() doesn't create a memory leak         */
/*                                                                           */
/*****************************************************************************/

CertReturnCode CertReadDatabase(const char *db_path)
{
    int i = 100;
    CA_DB *db;
    struct stat statbuf;
    CertReturnCode result = CERT_GENERAL_FAILURE;

    if (db_path == NULL)
    {
        return CERT_INVALID_ARG;
    }

    if (g_clocaldb == NULL)
    {
        return CERT_DATABASE_INITIALIZATION_ERROR;
    }

    if (stat(db_path, &statbuf) == -1)
    {
        return CERT_FILE_ACCESS_FAILURE;
    }

    /* Try getting the lock a few times. Give up after 100ms */
    while ((CertLockDatabase(1) == NULL) && (i-- > 0))
    {
        usleep(1000);
    }

    if (i <= 0)
    {
        result = CERT_DATABASE_LOCKED;
    }
    /* Don't reload if we already have it in memory */
    else if (strcmp(g_loaded_db, db_path) == 0)
    {
        result = CERT_OK;
    }
    else if (CertLockFile(CERT_DATABASE_LOCK) != CERT_OK)
    {
        result = CERT_LOCK_FILE_LOCKED;
    }
    else
    {
        db = load_index(db_path, &g_db_attr);

        if (db == NULL)
        {
            result = CERT_FILE_ACCESS_FAILURE;
        }
        else
        {
            free_index(g_clocaldb);
            strcpy(g_loaded_db, db_path);
            g_clocaldb = db;
            result = CERT_OK;
        }

        CertUnlockFile(CERT_DATABASE_LOCK);
    }

    CertUnlockDatabase();
    PRINT_RETURN_CODE(result);

    return result;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertWriteDatabase                                               */
/* INPUT:                                                                    */
/*       dbName: The database file itself                                    */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_DATABASE_NOT_AVAILABLE: The database could not be opened       */
/*       CERT_LOCK_FILE_LOCKED: The database lock could not be aquired       */
/*       CERT_NULL_BUFFER: Trying to save a database without a name          */
/* NOTES:                                                                    */
/*       1) The rather arcane splitting off of the extension is needed       */
/*          because there is an attribute file saved along with the database */
/*                                                                           */
/*****************************************************************************/

CertReturnCode CertWriteDatabase(const char *db_name)
{
    int i = 100;
    CA_DB *db;
    CertReturnCode result;

    /* Try getting the lock a few times. Give up after 100ms */
    while ((CertLockDatabase(2) == NULL) && (i-- > 0))
    {
        usleep(1000);
    }

    if (i <= 0)
    {
        result = CERT_DATABASE_LOCKED;
    }
    if (CertLockFile(CERT_DATABASE_LOCK) != CERT_OK)
    {
        result = CERT_LOCK_FILE_LOCKED;
    }
    else
    {
        db = CertLockDatabase(2);

        if (db == NULL)
        {
            result = CERT_DATABASE_NOT_AVAILABLE;
            goto cleanup;
        }

        if (db_name == NULL)
        {
            db_name = g_loaded_db;
        }

        result = save_index(db_name, db);
        CertUnlockFile(CERT_DATABASE_LOCK);
    }

cleanup:
    CertUnlockDatabase();

    return result;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertGetDatabaseInfo                                             */
/*       Get information on the database itself                              */
/* INPUT:                                                                    */
/*       dbName: The property of interest                                    */
/* OUTPUT:                                                                   */
/*       value: The value of the property expressed as a 32 bit int          */
/* RETURN:                                                                   */
/*       CERT_PROPERTY_NOT_FOUND: the property exists, but isn't available   */
/*       CERT_UNKNOWN_PROPERTY: the property itself doesn't exist            */
/*       CERT_DATABASE_NOT_AVAILABLE: the database could not be locked       */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode CertGetDatabaseInfo(CertDbProperty property, int *o_val)
{
    CertReturnCode result = CERT_GENERAL_FAILURE;
    CA_DB *db;

    if (o_val == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    db = CertLockDatabase(3);

    if (db == NULL)
    {
        return CERT_LOCK_FILE_LOCKED;
    }

    switch (property)
    {
        case CERT_DATABASE_SIZE:
            *o_val = sk_OPENSSL_PSTRING_num(db->db->data);

            if (*o_val < 0)
            {
                result = CERT_PROPERTY_NOT_FOUND;
            }
            else
            {
                result = CERT_OK;
            }

            break;

        default:
            result = CERT_UNKNOWN_PROPERTY;
            break;
    }

    CertUnlockDatabase();

    return result;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertGetDatabaseStrValue                                         */
/*       Return information stored in the database in a string               */
/* INPUT:                                                                    */
/*       index: the key for the desired certificate                          */
/*       property: the name of the information requested                     */
/*       len:  the length of the buffer passed into the function             */
/* OUTPUT:                                                                   */
/*       propertyStr: the value of the property                              */
/* RETURN:                                                                   */
/*       CERT_DATABASE_LOCKED: The database is currently being used elsewhere*/
/*       CERT_DATABASE_OUT_OF_BOUNDS: Attempting to look outside of the      */
/*          database's range.                                                */
/*       CERT_BUFFER_LIMIT_EXCEEDED: the requested property doesn't fit the  */
/*          buffer passed in                                                 */
/*       CERT_UNKNOWN_PROPERTY: The property passed in is not supported      */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode CertGetDatabaseStrValue(int index, CertDbItemProperty property, char *o_buf, int len)
{
    CA_DB *db;
    CertReturnCode result = CERT_GENERAL_FAILURE;

    if (o_buf == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    db = CertLockDatabase(4);

    if (db == NULL)
    {
        return CERT_LOCK_FILE_LOCKED;
    }

    if (index >= sk_OPENSSL_PSTRING_num(db->db->data))
    {
        result = CERT_DATABASE_OUT_OF_BOUNDS;
    }
    else
    {
        const char **pp = (const char **)sk_OPENSSL_PSTRING_value(db->db->data, index);

        switch (property)
        {
        case CERT_DATABASE_ITEM_STATUS:
        case CERT_DATABASE_ITEM_EXPIRATION:
        case CERT_DATABASE_ITEM_START:
        case CERT_DATABASE_ITEM_SERIAL:
        case CERT_DATABASE_ITEM_FILE:
        case CERT_DATABASE_ITEM_NAME:
            if (snprintf(o_buf, len, "%s", pp[property]) >= len)
            {
                result = CERT_BUFFER_LIMIT_EXCEEDED;
            }
            else
            {
                result = CERT_OK;
            }

            break;

        default:
            result = CERT_UNKNOWN_PROPERTY;
            break;
        }
    }

    CertUnlockDatabase();

    return result;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION:CertCreateDatabaseItem                                           */
/*       Something wicked this way comes                                     */
/*       Put a new item into the database                                    */
/* INPUT:                                                                    */
/*       x509: The database revolves around certificates                     */
/*       name: The name of the database file                                 */
/*       serial: The serial number for the certificate                       */
/*       value:  The status value                                            */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) Lots of allocations here, so we rely on a common error area to   */
/*          free what's needed to be freed                                   */
/*       2) Check to make sure there's no memory leak here                   */
/*       3) Move the status strings to an enum                               */
/*       4) I think that the error recovery is a bit baroque.  Look into an  */
/*          alternative one.                                                 */
/*                                                                           */
/*****************************************************************************/

CertReturnCode CertCreateDatabaseItemDirect(const char *db_path, const X509 *x509, const char *file_name, int sn, CertStatus status)
{
    CA_DB *db;
    ASN1_UTCTIME *asn_time;
    const char *status_str;
    char serial_str[(sizeof(sn) * 2) + 1]; /* Amount of hex digits (digit == nibble) + NUL character */
    char *record[CERT_DATABASE_ITEM_MAX];
    char **existing_row = NULL, **new_row = NULL;
    CertReturnCode result;

    status_str = CertGetStatusString(status);

    if (status_str == NULL)
    {
        return CERT_INVALID_ARG;
    }

    result = CertReadDatabase(db_path);

    if (result != CERT_OK)
    {
        return result;
    }

    memset(record, 0, sizeof(record));

    db = CertLockDatabase(5);

    if (db == NULL)
    {
        return CERT_DATABASE_LOCKED;
    }

    sprintf(serial_str, "%04x", sn);
    record[CERT_DATABASE_ITEM_SERIAL] = serial_str;

    /* Look for to see if the corresponding sn number exists */
    existing_row = TXT_DB_get_by_index(db->db, CERT_DATABASE_ITEM_SERIAL, record);

    /* Here we're looking at something brand new, so we can add it  */
    if (existing_row != NULL)
    {
        result = CERT_DATABASE_ITEM_EXISTS;
        goto done;
    }

    DPRINTF("Adding Entry with serial number %d to DB for %s\n", sn, file_name);

    /* We now just add it to the database */

    /* Find the expiration date           */
    asn_time = X509_get_notAfter(x509);

    /* Fortunately for us ASN1_TIME is just a string without NUL terminator
     * so we only need to duplicate and NUL terminate it */
    record[CERT_DATABASE_ITEM_EXPIRATION] =
        (char *)cmutils_memdup(OPENSSL_malloc_wrap, asn_time->data, asn_time->length, 1);

    if (record[CERT_DATABASE_ITEM_EXPIRATION] == NULL)
    {
        result = CERT_MEMORY_ERROR;
        goto done;
    }

    asn_time = X509_get_notBefore(x509);
    record[CERT_DATABASE_ITEM_START] =
        (char *)cmutils_memdup(OPENSSL_malloc_wrap, asn_time->data, asn_time->length, 1);

    if (record[CERT_DATABASE_ITEM_START] == NULL)
    {
        result = CERT_MEMORY_ERROR;
        goto done;
    }

    /* Copy the file name */
    record[CERT_DATABASE_ITEM_FILE] =
        (char *)cmutils_memdup(OPENSSL_malloc_wrap, file_name, strlen(file_name), 1);

    if (record[CERT_DATABASE_ITEM_FILE] == NULL)
    {
        result = CERT_MEMORY_ERROR;
        goto done;
    }

    /* Copy the status */
    record[CERT_DATABASE_ITEM_STATUS] =
        (char *)cmutils_memdup(OPENSSL_malloc_wrap, status_str, strlen(status_str), 1);

    if (record[CERT_DATABASE_ITEM_STATUS] == NULL)
    {
        result = CERT_MEMORY_ERROR;
        goto done;
    }

    /* Copy the serial number */
    record[CERT_DATABASE_ITEM_SERIAL] =
        (char *)cmutils_memdup(OPENSSL_malloc_wrap, serial_str, strlen(serial_str), 1);

    if (record[CERT_DATABASE_ITEM_SERIAL] == NULL)
    {
        result = CERT_MEMORY_ERROR;
        goto done;
    }

    record[CERT_DATABASE_ITEM_NAME] = X509_NAME_oneline(X509_get_subject_name((X509 *)x509), NULL, 0);

    if (record[CERT_DATABASE_ITEM_NAME] == NULL)
    {
        result = CERT_MEMORY_ERROR;
        goto done;
    }

    new_row = (char **)OPENSSL_malloc(sizeof(char *) * (CERT_DATABASE_ITEM_MAX + 1));

    if (new_row == NULL)
    {
        result = CERT_MEMORY_ERROR;
        goto done;
    }

    /* Copy data pointers */
    memcpy(new_row, record, sizeof(record));
    new_row[CERT_DATABASE_ITEM_MAX] = NULL;

    if (!TXT_DB_insert(db->db, new_row))
    {
        DPRINTF("failed to update database\n");
        DPRINTF("TXT_DB error number %ld\n", db->db->error);
        result = CERT_GENERAL_FAILURE;
        goto done;
    }

    result = CERT_OK;

done:
    CertUnlockDatabase();

    if ((result != CERT_OK) || ((result = CertWriteDatabase(NULL)) != CERT_OK))
    {
        int i;

        /* FIXME: If Write fails here, what do we do with the inserted item? */
        if (new_row != NULL)
        {
            OPENSSL_free(new_row);
        }

        for (i = 0; i < CERT_DATABASE_ITEM_MAX; ++i)
        {
            if (record[i] != NULL)
            {
                OPENSSL_free(record[i]);
            }
        }
    }

    return result;
}


CertReturnCode CertCreateDatabaseItem(const X509 *x509, const char *file_name, int sn, CertStatus status)
{
    char db_path[MAX_CERT_PATH];
    CertReturnCode result;

    result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE, db_path, sizeof(db_path));

    if (result != CERT_OK)
    {
        return result;
    }

    return CertCreateDatabaseItemDirect(db_path, x509, file_name, sn, status);
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertUpdateDatabaseItem                                          */
/*       Change a certificate property in the database                       */
/* INPUT:                                                                    */
/*       dbName: The database name                                           */
/*       serialNb: The serial number of the certificate                      */
/*       property: the property that you wish to change.                     */
/*       value: The new value for the certificate property                   */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode CertUpdateDatabaseItemDirect(const char *db_path, int sn, CertDbItemProperty property, const char *value)
{
    CA_DB *db;
    char *record[CERT_DATABASE_ITEM_MAX];
    char serial_str[(sizeof(sn) * 2) + 1]; /* Amount of hex digits (digit == nibble) + NUL character */
    CertReturnCode result = CERT_GENERAL_FAILURE;

    if (value == NULL)
    {
        return CERT_INVALID_ARG;
    }

    result = CertReadDatabase(db_path);

    if (result != CERT_OK)
    {
        return result;
    }

    db = CertLockDatabase(6);

    if (db == NULL)
    {
        return CERT_DATABASE_LOCKED;
    }

    sprintf(serial_str, "%04x", sn);
    memset(record, 0, sizeof(record));
    record[CERT_DATABASE_ITEM_SERIAL] = serial_str;

    char **pp = TXT_DB_get_by_index(db->db, CERT_DATABASE_ITEM_SERIAL, record);

    if (pp == NULL)
    {
        result = CERT_DATABASE_ITEM_NOT_FOUND;
        goto cleanup;
    }

    switch (property)
    {
    case CERT_DATABASE_ITEM_STATUS:
        {
            CertStatus status = getCertStatusByString(value);

            if (status == CERT_STATUS_UNDEFINED)
            {
                result = CERT_INVALID_ARG;
            }
            else
            {
                strcpy(pp[CERT_DATABASE_ITEM_STATUS], value);
                result = CERT_OK;
            }
        }

        break;

    case CERT_DATABASE_ITEM_EXPIRATION:
    case CERT_DATABASE_ITEM_START:
    case CERT_DATABASE_ITEM_NAME:
        DPRINTF("%s:This property probably shouldn't be changed %d\n", __FUNCTION__, property);
        result = CERT_CANNOT_UPDATE_PROPERTY;
        break;

    case CERT_DATABASE_ITEM_SERIAL:
    case CERT_DATABASE_ITEM_FILE:
        DPRINTF("UNIMPLEMENTED property in %s\n", __FUNCTION__);
        result = CERT_PROPERTY_STRING_NOT_FOUND;
        break;

    default:
        result = CERT_UNKNOWN_PROPERTY;
        break;
    }

cleanup:
    CertUnlockDatabase();

    if (result == CERT_OK)
    {
        result = CertWriteDatabase(NULL);
    }

    return result;
}

CertReturnCode CertUpdateDatabaseItem(int sn, CertDbItemProperty property, const char *value)
{
    char db_path[MAX_CERT_PATH];
    CertReturnCode result;

    result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE, db_path, sizeof(db_path));

    if (result != CERT_OK)
    {
        return result;
    }

    return CertUpdateDatabaseItemDirect(db_path, sn, property, value);
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertDatabaseCountCertsDirect                                    */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/*      CERT_OK                                                              */
/*      CERT_DATABASE_INITIALIZATION_ERROR: The database was never init'ed   */
/*      CERT_FILE_ACCESS_FAILURE: The database file could not be accessed    */
/*      CERT_LOCKED_FILE_LOCKED: The database lockfile is unavailable        */
/*      CERT_DATABASE_LOCKED: The database is currently in use               */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode CertDatabaseCountCertsDirect(const char *db_path, CertStatus status, int *o_ncerts)
{
    if (o_ncerts == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    switch (status)
    {
    case CERT_STATUS_ALL:
        return CertGetDatabaseInfo(CERT_DATABASE_SIZE, o_ncerts);

    case CERT_STATUS_VALID_CA:
    case CERT_STATUS_TRUSTED_SERVER_CA:
    case CERT_STATUS_EXPIRED:
    case CERT_STATUS_VALID_PEER:
    case CERT_STATUS_TRUSTED_PEER:
    case CERT_STATUS_REVOKED:
    case CERT_STATUS_SUSPENDED:
    case CERT_STATUS_TRUSTED_CLIENT_CA:
    case CERT_STATUS_VALID_CERT:
    case CERT_STATUS_USER_CERTIFICATE:
    case CERT_STATUS_WARNING:
    case CERT_STATUS_UNKNOWN:
        {
            CA_DB *db;
            int i, size, ncerts;
            CertReturnCode result;

            result = CertReadDatabase(db_path);

            if (result != CERT_OK)
            {
                return result;
            }

            db = CertLockDatabase(7);

            if (db == NULL)
            {
                return CERT_DATABASE_LOCKED;
            }

            size = sk_OPENSSL_PSTRING_num(db->db->data);

            for (i = 0, ncerts = 0; i < size; ++i)
            {
                const char **pp = (const char **)sk_OPENSSL_PSTRING_value(db->db->data, i);

                if (getCertStatusByString(pp[CERT_DATABASE_ITEM_STATUS]) == status)
                {
                    ++ncerts;
                }
            }

            CertUnlockDatabase();
            *o_ncerts = ncerts;

            return CERT_OK;
        }

    case CERT_STATUS_UNDEFINED:
    default:
        return CERT_UNKNOWN_PROPERTY;
    }
}

CertReturnCode CertDatabaseCountCerts(CertStatus status, int *o_ncerts)
{
    char db_path[MAX_CERT_PATH];
    CertReturnCode result;

    result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE, db_path, sizeof(db_path));

    if (result != CERT_OK)
    {
        return result;
    }

    return CertDatabaseCountCertsDirect(db_path, status, o_ncerts);
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertListDatabaseCertsByStatusDirect                             */
/*      Return a list of certificates filtered by status                     */
/* INPUT:                                                                    */
/*      dbName: the file containing the desired database                     */
/*      certStatus: the filter for listing                                   */
/*      certNb: the number of certificates possible in the array             */
/* OUTPUT:                                                                   */
/*      certList: an array of certificate serial numbers that match          */
/* RETURN:                                                                   */
/*      CERT_OK if the database was successfully read and deciphered         */
/*      CERT_UNKNOWN_PROPERTY if the status filter is undefined              */
/*      CERT_INSUFFICIENT_BUFFER_SPACE if there are too many certificates    */
/*         that match the filter for the array                               */
/*      CERT_DATABASE_LOCKED if the lock file has been aquired by another    */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode CertListDatabaseCertsByStatusDirect(const char *db_path, CertStatus status, int *o_list, int *io_ncerts)
{
    CA_DB *db;
    int i, size, ncerts;
    CertReturnCode result;

    if ((o_list == NULL) || (io_ncerts == NULL) || (*io_ncerts < 0))
    {
        return CERT_NULL_BUFFER;
    }

    if ((status < 0) || (status >= CERT_STATUS_UNDEFINED))
    {
        return CERT_UNKNOWN_PROPERTY;
    }

    result = CertReadDatabase(db_path);

    if (result != CERT_OK)
    {
        return result;
    }

    db = CertLockDatabase(8);

    if (db == NULL)
    {
        return CERT_DATABASE_LOCKED;
    }

    size = sk_OPENSSL_PSTRING_num(db->db->data);

    for (i = 0, ncerts = 0; (ncerts < *io_ncerts) && (i < size); ++i)
    {
        const char **pp = (const char **)sk_OPENSSL_PSTRING_value(db->db->data, i);

        if ((status == CERT_STATUS_ALL) ||
            (getCertStatusByString(pp[CERT_DATABASE_ITEM_STATUS]) == status))
        {
            sscanf(pp[CERT_DATABASE_ITEM_SERIAL], "%x", &o_list[i]);
            ++ncerts;
        }
    }

    CertUnlockDatabase();

    if (ncerts >= *io_ncerts)
    {
        return CERT_INSUFFICIENT_BUFFER_SPACE;
    }

    *io_ncerts = ncerts;

    return CERT_OK;
}

CertReturnCode CertListDatabaseCertsByStatus(CertStatus status, int *o_list, int *io_ncerts)
{
    char db_path[MAX_CERT_PATH];
    CertReturnCode result;

    result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE, db_path, sizeof(db_path));

    if (result != CERT_OK)
    {
        return result;
    }

    return CertListDatabaseCertsByStatusDirect(db_path, status, o_list, io_ncerts);
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertGetNameFromSerialNumberDirect                               */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode CertGetNameFromSerialNumberDirect(const char *db_path, int sn, char *o_buf, int len)
{
    int i, size;
    CA_DB *db;
    char serial_str[(sizeof(sn) * 2) + 1]; /* Amount of hex digits (digit == nibble) + NUL character */
    CertReturnCode result = CERT_DATABASE_ITEM_NOT_FOUND;

    if (o_buf == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    if (len <= 0)
    {
        return CERT_INSUFFICIENT_BUFFER_SPACE;
    }

    result = CertReadDatabase(db_path);

    if (result != CERT_OK)
    {
        return result;
    }

    db = CertLockDatabase(9);

    if (db == NULL)
    {
        return CERT_DATABASE_LOCKED;
    }

    sprintf(serial_str, "%04x", sn);

    size = sk_OPENSSL_PSTRING_num(db->db->data);

    for (i = 0; i < size; ++i)
    {
        const char **pp = (const char **)sk_OPENSSL_PSTRING_value(db->db->data, i);

        if (strcmp(pp[CERT_DATABASE_ITEM_SERIAL], serial_str) == 0)
        {
            if (snprintf(o_buf, len, "%s", pp[CERT_DATABASE_ITEM_FILE]) >= len)
            {
                result = CERT_INSUFFICIENT_BUFFER_SPACE;
            }
            else
            {
                result = CERT_OK;
            }

            break;
        }
    }

    CertUnlockDatabase();

    return result;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertGetNameFromSerialNumber                                     */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode CertGetNameFromSerialNumber(int sn, char *o_buf, int len)
{
    char db_path[MAX_CERT_PATH];
    CertReturnCode result;

    result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE, db_path, sizeof(db_path));

    if (result != CERT_OK)
    {
        return result;
    }

    return CertGetNameFromSerialNumberDirect(db_path, sn, o_buf, len);
}

const char* CertGetStatusString(CertStatus status)
{
    static const char status_strs[][2] =
    {
#   define CM_VAL(status, val) { val, '\0' }
        CERTMGR_ITEM_STATUSES
#   undef CM_VAL
    };

    if ((status < 0) || (status >= CERT_STATUS_UNDEFINED))
    {
        return NULL;
    }

    return status_strs[status];
}

static CertStatus getCertStatusByString(const char *status)
{
    int i;

    static const char status_strs[][2] =
    {
#   define CM_VAL(status, val) { val, '\0' }
        CERTMGR_ITEM_STATUSES
#   undef CM_VAL
    };

    if (status != NULL)
    {
        for (i = 0; i < CERT_STATUS_UNDEFINED; ++i)
        {
            if (strcmp(status, status_strs[i]) == 0)
            {
                return (CertStatus)i;
            }
        }
    }

    return CERT_STATUS_UNDEFINED;
}

static CertReturnCode cmdb_TXT_DB_read(FILE *fp, int num)
{
    /* FIXME: Implement! */
    return CERT_GENERAL_FAILURE;
}

static int cmdb_TXT_DB_write(FILE *fp, TXT_DB *db)
{
    /* For reasons unknown to me, someone over at Palm decided it was better to
     * copy the entire TXT_DB_write function from OpenSSL than to just use it.
     * I decided that while we're at it it'd be better if we do it in a more
     * efficient way, so I rewrote it to not use dynamic memory allocation at
     * all (except what stdio already allocates, that is).
     * This code should also (in theory) be more readable. */
    long record_idx;
    long nrecords = sk_OPENSSL_PSTRING_num(db->data);
    long nfields = db->num_fields;

    for (record_idx = 0; record_idx < nrecords; ++record_idx)
    {
        long field_idx;
        const char **record = (const char **)sk_OPENSSL_PSTRING_value(db->data, record_idx);

        for (field_idx = 0; field_idx < nfields; ++field_idx)
        {
            const char *field = record[field_idx];

            /* Append TAB separator after each field */
            if (field_idx > 0)
            {
                fputc('\t', fp);
            }

            if ((field != NULL) && (*field != '\0'))
            {
                char tmpbuf[MAX_CERT_PATH];

                do /* while (*field != '\0') */
                {
                    size_t written_bytes = 0;

                    do /* while ((*field != '\0') && (written_bytes < sizeof(tmpbuf))) */
                    {
                        switch (*field)
                        {
                        /* We use TAB as field separator and LF as record separator,
                         * so we need to distinguish between literals and separators.
                         * We do that by prepending a backslash ('\\') before each
                         * literal TAB or LF character. Note that OpenSSL's implementation
                         * doesn't handle LF literals, so this version is at least
                         * better in that aspect */
                        case '\t':
                        case '\n':
                            tmpbuf[written_bytes++] = '\\';

                        default:
                            tmpbuf[written_bytes++] = *field;
                        }

                        ++field;
                    } while ((*field != '\0') && (written_bytes < sizeof(tmpbuf)));

                    if (fwrite(tmpbuf, written_bytes, 1, fp) <= 0)
                    {
                        return CERT_GENERAL_FAILURE;
                    }
                } while (*field != '\0');
            }

            /* Append a new line after each record */
            if (fputc('\n', fp) != '\n')
            {
                return CERT_GENERAL_FAILURE;
            }
        }
    }

    return CERT_OK;
}

static CA_DB* load_index(const char *db_path, DB_ATTR *db_attr)
{
    FILE *db_file;
    long errorline = -1;
    CA_DB *retdb = NULL;
    TXT_DB *tmpdb = NULL;
    CONF *dbattr_conf = NULL;
    CertReturnCode result;
    char attrfilename[MAX_CERT_PATH];

    if (db_path == NULL)
    {
        goto done;
    }

    if (snprintf(attrfilename, sizeof(attrfilename), "%s.attr", db_path) >= (int)sizeof(attrfilename))
    {
        goto done;
    }

    db_file = fopen(db_path, "r");

    if (db_file == NULL)
    {
        DPRINTF("load_index: %s\n", strerror(errno));
        goto done;
    }

    result = cmdb_TXT_DB_read(db_file, CERT_DATABASE_ITEM_MAX);
    fclose(db_file);

    if (result != CERT_OK)
    {
        goto done;
    }

    dbattr_conf = NCONF_new(NULL);

    if ((dbattr_conf != NULL) &&
        (NCONF_load(dbattr_conf, attrfilename, &errorline) <= 0))
    {
        if (errorline > 0)
        {
            goto cleanup;
        }

        NCONF_free(dbattr_conf);
        dbattr_conf = NULL;
    }

    retdb = (CA_DB *)OPENSSL_malloc(sizeof(CA_DB));

    if (retdb == NULL)
    {
        DPRINTF("Out of memory\n");
        result = CERT_MEMORY_ERROR;
        goto cleanup;
    }

    retdb->db = tmpdb;
    tmpdb = NULL;

    if (db_attr != NULL)
    {
        retdb->attributes = *db_attr;
    }
    else if (dbattr_conf != NULL)
    {
        retdb->attributes.unique_subject =
            parse_yesno(NCONF_get_string(dbattr_conf, NULL, "unique_subject"), 1);
    }
    else
    {
        retdb->attributes.unique_subject = 1;
    }


cleanup:
    if (dbattr_conf)
    {
        NCONF_free(dbattr_conf);
    }

    if (tmpdb)
    {
        TXT_DB_free(tmpdb);
    }

done:
    return retdb;
}

static CertReturnCode save_index(const char *db_path, CA_DB *db)
{
    int fd;
    FILE *db_file, *attr_file;
    char filename[MAX_CERT_PATH];
    char attrfilename[MAX_CERT_PATH];
    CertReturnCode result = CERT_GENERAL_FAILURE;

    if (snprintf(attrfilename, sizeof(attrfilename), "%s.attr", db_path) >= (int)sizeof(attrfilename))
    {
        return CERT_PATH_LIMIT_EXCEEDED;
    }

    /* We already checked that the largest string fits nicely, so we
     * can run with sprintf without worries about buffer overruns */
    sprintf(filename, "%s", db_path);

    /* Open with `open` first to truncate the file while also
     * creating it if it doesn't exists */
    fd = open(filename, O_TRUNC | O_WRONLY);

    if (fd < 0)
    {
        return CERT_OPEN_FILE_FAILED;
    }

    /* Reopen with `fopen` to get buffering and other goodies */
    db_file = fdopen(fd, "w");

    if (db_file == NULL)
    {
        DPRINTF("unable to open '%s'\n", filename);
        result = CERT_OPEN_FILE_FAILED;
        goto error;
    }

    result = cmdb_TXT_DB_write(db_file, db->db);
    fclose(db_file);

    if (result != CERT_OK)
    {
        return result;
    }

    /* Same as with the DB file -- we need truncation */
    fd = open(attrfilename, O_TRUNC | O_WRONLY);

    if (fd < 0)
    {
        return CERT_OPEN_FILE_FAILED;
    }

    attr_file = fopen(attrfilename, "w");

    if (attr_file == NULL)
    {
        DPRINTF("unable to open '%s'\n", attrfilename);
        result = CERT_OPEN_FILE_FAILED;
        goto error;
    }

    if (fprintf(attr_file,
                "unique_subject = %s\n",
                db->attributes.unique_subject ? "yes" : "no") > 0)
    {
        result = CERT_OK;
    }

    fclose(attr_file);

done:
    return result;

error:
    close(fd);
    goto done;
}

static void free_index(CA_DB *db)
{
    if (db)
    {
        if (db->db)
        {
            TXT_DB_free(db->db);
        }

        OPENSSL_free(db);
    }
}

static int parse_yesno(const char *str, int def)
{
    int ret = !!def;

    if (str)
    {
        switch (*str)
        {
        case 'f': /* false */
        case 'F': /* FALSE */
        case 'n': /* no */
        case 'N': /* NO */
        case '0': /* 0 */
            ret = 0;
            break;

        case 't': /* true */
        case 'T': /* TRUE */
        case 'y': /* yes */
        case 'Y': /* YES */
        case '1': /* 1 */
            ret = 1;
            break;

        default:
            break;
        }
    }

    return ret;
}

static void* OPENSSL_malloc_wrap(size_t sz)
{
    /**
     * A dirty and ugly hack allowing cmutils_memdup to
     * work with OPENSSL_malloc which is defined as a macro that
     * expands to a function call with two additional parameters.
     */
    return OPENSSL_malloc(sz);
}

#ifdef __cplusplus
}
#endif
