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

/**
 * @file cert_db.h
 *
 * @brief Certificate Manager database routines
 *
 * @ingroup CERTMgrLib
 *
 */

#ifndef __CERT_DB_H__
#define __CERT_DB_H__

#include <openssl/txt_db.h>
#include "cert_cfg.h"
#include "cert_mgr.h"

/*! Properties of the data base itself    */
typedef enum
{
    CERT_DATABASE_SIZE,  /*!< The number of items in the database */
    CERT_DATABASE_MAX    /*!< A fencepost value                   */
} CertDbProperty;

  /*! Properties of items in the database */
typedef enum
{
    CERT_DATABASE_ITEM_STATUS,     /*!< The status of the certificate   */
    CERT_DATABASE_ITEM_EXPIRATION, /*!< The certificate expiration date */
    CERT_DATABASE_ITEM_START,      /*!< The certificate start date      */
    CERT_DATABASE_ITEM_SERIAL,     /*!< The certificate serial number   */
    CERT_DATABASE_ITEM_FILE,       /*!< The certificate file name       */
    CERT_DATABASE_ITEM_NAME,       /*!< The certificate name            */
    CERT_DATABASE_ITEM_MAX
} CertDbItemProperty;


#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Initialize the database system
 *
 * @param[in] dbName the file containing the desired database
 *
 * @return CERT_OK if the database was successfully initialized.
 * @return CERT_DATABASE_LOCKED if the database has already been initialized.
 * @return CERT_FILE_ACCESS_FAILURE if the file could not be found or loaded.
 * @return CERT_DATABASE_NOT_AVAILABLE if the couldn't get the protective lock.
 * @return CERT_DATABASE_INITIALIZATION_ERROR the database wasn't initialized.
 * @return CERT_LOCK_FILE_LOCKED if the lock file has been aquired by another.
 *
 */
extern CertReturnCode CertInitDatabase(const char *db_path);

/*!
 * Read the database into memory
 *
 * @param[in] dbName the file containing the desired database
 *
 * @return CERT_OK if the database was successfully read and deciphered
 * @return CERT_DATABASE_INITIALIZATION_ERROR the database wasn't initialized
 * @return CERT_FILE_ACCESS_FAILURE if the file could not be found or loaded
 * @return CERT_LOCK_FILE_LOCKED if the lock file has been aquired by another
 *
 */
extern CertReturnCode CertReadDatabase(const char *db_path);

/*!
 * Write the database to file
 *
 * @param[in] dbName the file for the desired database
 *
 * @return CERT_OK if the database was successfully written
 * @return CERT_DATABASE_NOT_AVAILABLE if The database could not be opened
 * @return CERT_NULL_BUFFER if trying to save a database without a name
 * @return CERT_LOCK_FILE_LOCKED if the lock file has been aquired by another
 *
 */
extern CertReturnCode CertWriteDatabase(const char *db_name);

/*!
 * Get information on the database itself
 *
 * @param[in]  dbName the property of interest
 * @param[out] value the value of the property
 *
 * @return CERT_OK The value of the property has been passed back
 * @return CERT_PROPERTY_NOT_FOUND if the property exists, but isn't available
 * @return CERT_UNKNOWN_PROPERTY if the property itself doesn't exist
 * @return CERT_DATABASE_NOT_AVAILABLE if the database could not be locked
 *
 * @todo set property to enumeration type.
 *
 */
extern CertReturnCode CertGetDatabaseInfo(CertDbProperty property, int *o_val);


/*!
 * Information stored in the database in a string
 *
 * @param[in] index the key for the desired certificate
 * @param[in] property is the name of the information requested
 * @param[in] len is the length of the buffer passed into the function
 *
 * @param[out] propertyStr is the value of the property
 *
 * @return CERT_OK if the database successfully divulged the information
 * @return CERT_DATABASE_OUT_OF_BOUNDS if the index exceeded the database
 * @return CERT_BUFFER_LIMIT_EXCEEDED if the requested property doesn't fit
 * @return CERT_UNKNOWN_PROPERTY if the requested property doesn't exist
 * @return CERT_DATABASE_LOCKED if the database is locked by another
 *
 */
extern CertReturnCode CertGetDatabaseStrValue(int index, CertDbItemProperty property, char *o_buf, int len);


/*!
 * Put a new item into the database
 *
 * @param[in] x509 The database revolves around certificates
 * @param[in] serial The serial number for the certificate
 * @param[in] value  The status value.
 *
 * @return CERT_OK if the database was successfully read and deciphered
 * @return CERT_DATABASE_INITIALIZATION_ERROR the database wasn't initialized
 * @return CERT_FILE_ACCESS_FAILURE if the file could not be found or loaded
 * @return CERT_LOCK_FILE_LOCKED if the lock file has been aquired by another
 *
 */
extern CertReturnCode CertCreateDatabaseItemDirect(const char *db_path, const X509 *x509, const char *file_name, int sn, CertStatus status);

extern CertReturnCode CertCreateDatabaseItem(const X509 *x509, const char *file_name, int sn, CertStatus status);

extern CertReturnCode CertUpdateDatabaseItemDirect(const char *db_path, int sn, CertDbItemProperty property, const char *value);

extern CertReturnCode CertUpdateDatabaseItem(int sn, CertDbItemProperty property, const char *value);

/*!
 * Count the certificates registered in the given database
 *
 * @param[in] dbName the file containing the desired database.
 * @param[in] certStatus the filter for counting
 * @param[out] certNb the number of certificates that match the filter
 *
 * @return CERT_OK if the database was successfully read and deciphered
 * @return CERT_UNKNOWN_PROPERTY if the status filter is unknown.
 * @return CERT_DATABASE_NOT_AVAILABLE if the database couldn't be read.
 * @return CERT_DATABASE_LOCKED if the lock file has been aquired by another
 *
 */
extern CertReturnCode CertDatabaseCountCertsDirect(const char *db_path, CertStatus status, int *o_ncerts);

extern CertReturnCode CertDatabaseCountCerts(CertStatus status, int *o_ncerts);


/*!
 * Return a list of certificates filtered by status
 *
 * @param[in] dbName the file containing the desired database
 * @param[in] certStatus the filter for listing
 * @param[out] certList an array of certificate serial numbers that match
 * @param[in] certNb the number of certificates in the array
 *
 * @return CERT_OK if the database was successfully read and deciphered
 * @return CERT_UNKNOWN_PROPERTY if the status filter is undefined
 * @return CERT_INSUFFICIENT_BUFFER_SPACE if there are too many certificates
 *           that match the filter for the array
 * @return CERT_DATABASE_LOCKED if the lock file has been aquired by another
 *
 */
extern CertReturnCode CertListDatabaseCertsByStatusDirect(const char *db_path, CertStatus status, int *o_list, int *io_ncerts);

/*!
 * Return a list of certificates filtered by status from the default database
 *
 * @param[in] dbName the file containing the desired database
 * @param[in] certStatus the filter for listing
 * @param[out] certList an array of certificate serial numbers that match
 * @param[in] certNb the number of certificates in the array
 *
 * @return CERT_OK if the database was successfully read and deciphered
 * @return CERT_UNKNOWN_PROPERTY if the status filter is undefined
 * @return CERT_INSUFFICIENT_BUFFER_SPACE if there are too many certificates
 *           that match the filter for the array
 * @return CERT_DATABASE_LOCKED if the lock file has been aquired by another
 *
 */
extern CertReturnCode CertListDatabaseCertsByStatus(CertStatus status, int *o_list, int *io_ncerts);


/*!
 * Read the database into memory
 *
 * @param[in] dbName the file containing the desired database
 *
 * @return CERT_OK if the database was successfully read and deciphered
 * @return CERT_DATABASE_INITIALIZATION_ERROR the database wasn't initialized
 * @return CERT_FILE_ACCESS_FAILURE if the file could not be found or loaded
 * @return CERT_LOCK_FILE_LOCKED if the lock file has been aquired by another
 *
 */
extern CertReturnCode CertGetNameFromSerialNumberDirect(const char *db_path, int sn, char *o_buf, int len);

/*!
 * Read the database into memory
 *
 * @param[in] dbName the file containing the desired database
 *
 * @return CERT_OK if the database was successfully read and deciphered
 * @return CERT_DATABASE_INITIALIZATION_ERROR the database wasn't initialized
 * @return CERT_FILE_ACCESS_FAILURE if the file could not be found or loaded
 * @return CERT_LOCK_FILE_LOCKED if the lock file has been aquired by another
 *
 */
extern CertReturnCode CertGetNameFromSerialNumber(int sn, char *o_buf, int len);

extern const char* CertGetStatusString(CertStatus status);

#ifdef __cplusplus
}
#endif

#endif // __CERT_DB_H__
