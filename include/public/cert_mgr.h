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
 * @brief  This file contains an API for managing certificates
 *
 * @defgroup CERTMgrLib The certificate manager library
 * @ingroup CERTMgrLib
 *
 * @file cert_mgr.h
 * <hr>
 * @todo CERT_DEF_CONF_FILE should be placed in a standard location
 **/

#ifndef __CERT_MGR_H__
#define __CERT_MGR_H__

#include <sys/types.h>
#include <openssl/x509v3.h>

#define CERT_DEFAULT_DIRECTORY  "./.cert_store"
#define CERT_PROPERTY_DIR       0x00000001
#define CERT_VERSION_NUMBER     "0.1"
#define MAX_CERT_PATH           256

/*!
 * The maximum number of files with the same name
 * we make the arbitrary assumption that there can be
 * no more than 100 files with the same hash
 */
#define CERT_MAX_HASHED_FILES  100

typedef enum
{
    CERT_GENERAL_LOCK,
    CERT_DATABASE_LOCK,
    CERT_MAX_LOCK
} CertLocks;

/*!
 *
 * @brief Return Values
 * Return function values and error messages
 */
typedef enum
{
    CERT_OK,                       /*!< No Failure                          */
    CERT_GENERAL_FAILURE,          /*!< General Failure, should not occur   */
    CERT_UNSUPPORTED_CERT_TYPE,    /*!< Certificate type not supported      */
    CERT_ILLEGAL_KEY_PACKAGE_TYPE, /*!< Package type not supported.         */
    CERT_NULL_BUFFER,              /*!< Buffer unexpectedly NULL            */
    CERT_BUFFER_LIMIT_EXCEEDED,    /*!< Target string is too long           */
    CERT_OPEN_FILE_FAILED,         /*!< The file could not be opened        */
    CERT_FILE_ACCESS_FAILURE,      /*!< The file could not be accessed      */
    CERT_FILE_READ_FAILURE,        /*!< The file could not be read          */
    CERT_UNDEFINED_ROOT_DIR,       /*!< The configured root not defined     */
    CERT_DUPLICATE,                /*!< The certificate already exists      */
    CERT_MEMORY_ERROR,             /*!< Function dependant memory error     */
    CERT_ITER_EXCEED,              /*!< An iterator has gone beyond bounds  */
    CERT_INVALID_ARG,              /*!< Function dependant argument error   */
    CERT_PASSWD_WRONG,             /*!< bad password for decryption         */
    CERT_LINK_ERR,                 /*!< File (un)link was unsuccessfull     */
    CERT_INSUFFICIENT_BUFFER_SPACE,/*!< User passed in buffer space         */
    CERT_PATH_LIMIT_EXCEEDED,      /*!< The path exceeds system limits      */
    CERT_UNDEFINED_DESTINATION,    /*!< The directory doesn't exist         */
    CERT_TEMP_FILE_CREATION_FAILED,/*!< The temp file can't be created      */
    CERT_CONFIG_UNAVAILABLE,       /*!< The config tag doesn't exist        */
    CERT_UNKNOWN_PROPERTY,         /*!< The property isn't defined          */
    CERT_PROPERTY_NOT_FOUND,       /*!< The property couldn't be resolved      */
    CERT_PROPERTY_STRING_NOT_FOUND,/*!< No string associated with the property */
    CERT_ILLFORMED_CONFIG_FILE,    /*!< Something's broken in the file         */
    CERT_DATE_PENDING,             /*!< The certificate is not yet valid       */
    CERT_DATE_EXPIRED,             /*!< The certificate is no longer valid     */
    CERT_FILE_PARSE_ERROR,         /*!< The input file is illformed            */
    CERT_LOCK_FILE_CREATION_FAILURE,/*!< The lock file could not be created    */
    CERT_LOCK_FILE_LOCKED,         /*!< The lock file is already locked        */
    CERT_BAD_CERTIFICATE,          /*!< The certificate is bad (maybe NULL)    */
    CERT_SERIAL_NUMBER_FILE_UNAVAILABLE,/*!<Can't access the serial number file*/
    CERT_SERIAL_NUMBER_UNAVAILABLE,/*!< Can't resolve the current serial #     */
    CERT_DATABASE_INITIALIZATION_ERROR,/*!< The database couldn't be init'ed   */
    CERT_DATABASE_NOT_AVAILABLE,   /*!< The database is not available          */
    CERT_DATABASE_OUT_OF_BOUNDS,   /*!< A db search has been exhausted         */
    CERT_DATABASE_LOCKED,          /*!< The database is unavailable            */
    CERT_TOO_MANY_HASHED_FILES,    /*!< Too many cert files with the same name */
    CERT_CANNOT_UPDATE_PROPERTY,   /*!< should not change/update property */
    CERT_DIRECTORY_CREATION_FAILED,/*!< The directory could not be created     */
    CERT_DATABASE_ITEM_NOT_FOUND,
    CERT_DATABASE_ITEM_EXISTS,
    CERT_MAX_RETURN_CODE
} CertReturnCode;

/*! known certificate types */
typedef enum
{
    CERTTYPE_PEM,     /*!< Privacy Enhanced Mail wrapper        */
    CERTTYPE_P12,     /*!< PKCS #12 wrapper                     */
    CERTTYPE_DER,     /*!< Distinguished Encoding Rules wrapper */
    CERTTYPE_UNKNOWN
} CertPkgType;

/**
 * Defines the CertFileExt enumeration with file extensions
 */
#define CERTMGR_FILE_EXTS \
    CM_VAL(CERT_UNKNOWN_FILE, "UNKNOWN"), \
    /*!< extension for PEM  */ \
    CM_VAL(CERT_PEM_FILE, "pem"), \
    /*!< extension for pkcs12 */ \
    CM_VAL(CERT_P12_FILE, "p12"), \
    /*!< extension for pkcs12 */ \
    CM_VAL(CERT_PFX_FILE, "pfx"), \
    /*!< extension for der */ \
    CM_VAL(CERT_DER_FILE, "der"), \
    /*!< extension for pem */ \
    CM_VAL(CERT_CRT_FILE, "crt"), \
    /*!< extension for der */ \
    CM_VAL(CERT_CER_FILE, "cer"), \
    /*!< extension for crl */ \
    CM_VAL(CERT_CRL_FILE, "crl")

/*! extension types */
typedef enum
{
#define CM_VAL(ext, str) ext
    CERTMGR_FILE_EXTS,
#undef CM_VAL
    CERT_MAX_FILE_EXTENSIONS
} CertFileExt;

/*! Destination directories for various file types */
typedef enum
{
    CERT_DIR_PRIVATE_KEY,  /*!< Dir where private keys are placed            */
    CERT_DIR_PUBLIC_KEY,   /*!< Dir where public keys are placed             */
    CERT_DIR_CRL,          /*!< Dir where the cert revocation list is placed */
    CERT_DIR_CERTIFICATES, /*!< Dir where X.509 Certs are placed             */
    CERT_DIR_AUTHORIZED,   /*!< Dir where authorized certificates are linked */
    CERT_DIR_PACKAGES,     /*!< Dir where containers are placed              */
    CERT_MAX_DEST_DIRS
} CertDestDir;

/**
 * Defines the CertObject enumeration with file names and file extensions
 */
#define CERTMGR_OBJS \
    /*!< RSA Private Key */ \
    CM_VAL(CERT_OBJECT_RSA_PRIVATE_KEY, "rsa", "pem"), \
    /*!< RSA Public Key */ \
    CM_VAL(CERT_OBJECT_RSA_PUBLIC_KEY, "rsa", "pem"), \
    /*!< DSA Private Key */ \
    CM_VAL(CERT_OBJECT_DSA_PRIVATE_KEY, "dsa", "pem"), \
    /*!< DSA Public Key */ \
    CM_VAL(CERT_OBJECT_DSA_PUBLIC_KEY, "dsa", "pem"), \
    /*!< Diffie-Hellman parameters */ \
    CM_VAL(CERT_OBJECT_DH_PARAMETERS, "dh", "pem"), \
    /*!< Eliptic Curve */ \
    CM_VAL(CERT_OBJECT_EC_PRIVATE_KEY, "ec", "pem"), \
    /*!< X.509 Certificate */ \
    CM_VAL(CERT_OBJECT_CERTIFICATE, "", "pem"), \
    /*!< Certificate request */ \
    CM_VAL(CERT_OBJECT_REQUEST, "req", "pem"), \
    /*!< Certificate revocation list */ \
    CM_VAL(CERT_OBJECT_CRL, "crl", "pem"), \
    /*!< Certificate authorization list */ \
    CM_VAL(CERT_OBJECT_C_AUTHORIZATION, "ca", "pem")

/*! Objects that we can find in a container */
typedef enum
{
#   define CM_VAL(obj, fname, fext) obj
    CERTMGR_OBJS,
#   undef CM_VAL
    CERT_OBJECT_MAX_OBJECT
} CertObject;

#define CERTMGR_ITEM_STATUSES \
    /*!< Used for collecting everything */ \
    CM_VAL(CERT_STATUS_ALL, 'x'), \
    /*!< The certificate authority is valid */ \
    CM_VAL(CERT_STATUS_VALID_CA, 'c'), \
    /*!< Trusted to issue server certs. implies CERT_STATUS_VALID_CA */ \
    CM_VAL(CERT_STATUS_TRUSTED_SERVER_CA, 'C'), \
    /*!< The certificate is expired */ \
    CM_VAL(CERT_STATUS_EXPIRED, 'E'), \
    /*!< The certificate is a valid peer */ \
    CM_VAL(CERT_STATUS_VALID_PEER, 'p'), \
    /*!< implies CERT_STATUS_VALID_PEER */ \
    CM_VAL(CERT_STATUS_TRUSTED_PEER, 'P'), \
    /*!< The certificate has been revoked */ \
    CM_VAL(CERT_STATUS_REVOKED, 'R'), \
    /*!< The certificate has been suspended */ \
    CM_VAL(CERT_STATUS_SUSPENDED, 'S'), \
    /*!< Trusted to issue client certs. implies CERT_STATUS_VALID_CA */ \
    CM_VAL(CERT_STATUS_TRUSTED_CLIENT_CA, 'T'), \
    /*!< The certificate is valid */ \
    CM_VAL(CERT_STATUS_VALID_CERT, 'V'), \
    CM_VAL(CERT_STATUS_USER_CERTIFICATE, 'u'), \
    CM_VAL(CERT_STATUS_WARNING, 'w'), \
    CM_VAL(CERT_STATUS_UNKNOWN, 'X')

/*!
 * Status for certificates.  These can be used by the counting functions
 */
typedef enum
{
#define CM_VAL(status, val) status
    CERTMGR_ITEM_STATUSES,
#undef CM_VAL
    CERT_STATUS_UNDEFINED
} CertStatus;

/*
 * Separate set of errors mirroring OpenSSL errors, or just use
 *  OpenSSL errors?
 */
typedef enum
{
    CERT_CM_ALL_OK         = 0,
    CERT_CM_UNREADABLE     = 1,
    CERT_CM_SOMETHING_ELSE = 2,
    CERT_CM_DATE_PENDING   = 4,
    CERT_CM_DATE_EXPIRED   = 8,
    CERT_CM_ALL_BROKEN     = CERT_CM_UNREADABLE |
                             CERT_CM_SOMETHING_ELSE |
                             CERT_CM_DATE_PENDING | CERT_CM_DATE_EXPIRED
} CertMgrError;

/*! Information kept in the certificate itself */
typedef enum
{
    CERT_INFO_ISSUED_TO,
    CERT_INFO_ISSUED_BY,
    CERT_INFO_START_DATE,
    CERT_INFO_EXPIRATION_DATE,
    CERT_INFO_MAX_PROPERTY
} CertMgrField;


/**
 * A callback prototype used to get certificate passphrase used by the
 * following certificate file handling functions:
 *  - `CertInstallKeyPackageDirect`
 *  - `CertInstallKeyPackage`
 *  - `CertAddClientCert`
 *  - `CertInstallPackageDirect`
 *  - `CertReadKeyPackageDirect`
 *
 * When this callback is called, it should write the passphrase into
 * `o_buf` (no need to the terminating NUL) using whatever data stored
 * by the caller in `ctx` as long as there is enough `len` to hold it
 * and return the amount of bytes written. An return value of 0 or
 * less indicates an error.
 */
typedef int (*CertPassCallback)(char *o_buf, int len, void *ctx);

#ifdef __cplusplus
extern "C" {
#endif


/*!
 * @brief Setup the directory structure necessary for CertMgr to be initialized
 *
 * This function builds the necessary directory and initialized the necessary
 * file that the certmgr need to run properly.
 *
 *
 * @return CERT_OK: The database was successfully read and deciphered
 * @return CERT_CONFIG_UNAVAILABLE: The named configuration file is not
 */
extern CertReturnCode SetupCertMgrEnviroment(void);

/*!
 * @brief Initialize the instance of the certificate Manager
 *
 * This function initializes a particular instance
 *    of the Certificate Manager based on the configuration file passed in.
 *    The configuration file is structured in the manner of an SSL
 *    configuration.  Setting the paramter to NULL has the effects of
 *    using default settings.  The default settings checked are the enviroment
 *    variable OPENSSL_CONF and the system default CERT_DEF_CONF_FILE, in
 *    that order.
 *
 * @param[in] configFile the configuration file
 *
 * @return CERT_OK: The database was successfully read and deciphered
 * @return CERT_PATH_LIMIT_EXCEEDED: The path string is too long
 * @return CERT_OPEN_FILE_FAILED: The config file couldn't be opened
 * @return CERT_ILLFORMED_CONFIG_FILE: There was some problem in the config
 * @return CERT_CONFIG_UNAVAILABLE: The named configuration file is not
 *           available
 * @return CERT_UNDEFINED_DESTINATION if the certificate root dir not available
 *
 */
extern CertReturnCode CertInitCertMgr(const char *config_file);


/*!
 * @brief Reset the configuration of the certificate Manager
 *
 * This function re-initializes a particular instance
 *    of the Certificate Manager based on the configuration file passed in.
 *    Any changes made to the configuration file since initialization
 *    will be realized at this time.
 *
 * @param[in] configFile the configuration file
 *
 * @return CERT_OK: The database was successfully read and deciphered
 * @return CERT_INSUFFICIENT_BUFFER_SPACE: The origianal configuration file
 *             string is ill-defined.
 * @return CERT_OPEN_FILE_FAILED: The config file couldn't be opened
 * @return CERT_ILLFORMED_CONFIG_FILE: There was some problem in the config
 * @return CERT_CONFIG_UNAVAILABLE: The named configuration is not
 *           available in the configuration file
 * @return CERT_UNDEFINED_DESTINATION if the certificate root dir not available
 *
 */
extern CertReturnCode CertResetConfig(const char *config_file);

/**
 * @brief Read a Key Package into memory
 *
 *       Read a Key Package into memory and gives access to the component
 *       parts to the designated.  Decrypt if necessary.  The password,
 *       passwd  is in clear text.
 *
 *
 * @param[in] pPkgPath The name of the package file.
 * @param[in] pDestPath The path to the package file
 * @param[in] pcbk The callback function for encrypting the package
 * @param[in] pwd_ctxt The passkey in clear text for decrypting the package
 * @param[out] serialNb An identifying number for the certificate
 *
 * @return CERT_OK
 * @return CERT_SERIAL_NUMBER_FILE_UNAVAILABLE: The Certificate Manager is not
 *              properly initialized
 * @return CERT_SERIAL_NUMBER_UNAVAILABLE: The system was unable to provied a
 *             valid serial number
 * @return CERT_FILE_ACCESS_FAILURE: The system was unable to write the x.509
 *           certificate.
 * @return CERT_DATABASE_LOCKED: The system was unable to access the database
 * @return CERT_DATABASE_NOT_AVAILABLE: The system was unable to access the
 *           the database
 * @return CERT_LOCKFILE_LOCKED: The database is currently used
 * @return CERT_FILE_PARSE_ERROR: The input file is ill-formed
 * @return CERT_FILE_READ_ERROR: The input file cannot be read
 * @return CERT_OPEN_FILE_FAILED: The input file cannot be opened
 * @return CERT_ILLEGAL_KEY_PACKAGE_TYPE: The package is not a supported type
 * @return CERT_OPEN_FILE_FAILED: the requested package could not be opened.
 *           perhaps a password problem
 *
 */
extern CertReturnCode CertReadKeyPackageDirect(const char *pkg_path, const char *dst_path, CertPassCallback pcbk, void *pwd_ctxt, int *sn);

/* Given a path to a client cert file, which may be encrypted with a
 * password (e.g. provided by IT), decrypts, re-encrypts using the
 * global password manager, and writes result into a file in the
 * directory used for client certs.  pcbk will be called if the
 * certificat is encrypted; otherwise, it's ignored.  Broadcasts the
 * change to any registered listeners (on what property?).
 *
 * Files are stored on disk 3DES encrypted.  The password needed to
 * decrypt them is also stored encrypted on disk, encrypted with the
 * user's current actual password.  The decrypted password is what's
 * provided.
 */
extern CertReturnCode CertInstallKeyPackageDirect(const char *pkg_path, const char *dst_path, CertPassCallback pcbk, void *pwd_ctxt, int *sn);

/**
 * @brief  Resolve a Key Package into its component parts to the default
 *         directory.
 *
 *       1) Packages are assumed to be encoded by their extension
 *       2) The following types are supported
 *          PKCS#12
 *              .pfx
 *              .p12
 *          DER
 *              .der Distinguished Encoding Rules
 *              .cer Canonical Encoding Rules
 *          PEM
 *              .pem Privacy Enhanced Mail
 *              .crt used in at least Debian (Ubuntu) defined pem files
 *       3) The constituent parts of the package are not re-encrypted, but,
 *          rather, rely on the native Linux permission controls with the
 *          following defaults:
 *          certs/   rwxr-x-r-x
 *          private/ rwx------
 *          This presupposes that the destination path has permissions set
 *          correctly
 *       4) The location of the package itself is placed in
 *          directory denoted by CERTCFG_PACKAGE_DIR.
 *
 *
 * @param[in] pPkgPath The name of the package file.
 * @param[in] pDestPath The path to the package file
 * @param[in] pcbk The callback function for encrypting the package
 * @param[in] pwd_ctxt The passkey in clear text for decrypting the package
 * @param[out] serialNb An identifying number for the certificate
 *
 * @return CERT_OK
 * @return CERT_SERIAL_NUMBER_FILE_UNAVAILABLE: The Certificate Manager is not
 *              properly initialized
 * @return CERT_SERIAL_NUMBER_UNAVAILABLE: The system was unable to provied a
 *             valid serial number
 * @return CERT_FILE_ACCESS_FAILURE: The system was unable to write the x.509
 *           certificate.
 * @return CERT_DATABASE_LOCKED: The system was unable to access the database
 * @return CERT_DATABASE_NOT_AVAILABLE: The system was unable to access the
 *           the database
 * @return CERT_LOCKFILE_LOCKED: The database is currently used
 * @return CERT_FILE_PARSE_ERROR: The input file is ill-formed
 * @return CERT_FILE_READ_ERROR: The input file cannot be read
 * @return CERT_OPEN_FILE_FAILED: The input file cannot be opened
 * @return CERT_ILLEGAL_KEY_PACKAGE_TYPE: The package is not a supported type
 * @return CERT_OPEN_FILE_FAILED: the requested package could not be opened.
 *           perhaps a password problem
 *
 */
extern CertReturnCode CertInstallKeyPackage(const char *pkg_path, CertPassCallback pcbk, void *pwd_ctxt, int *sn);

/* Given the path to a client cert, delete it.  Broadcast the change
 * to any registered listeners (on what property?).
 */
extern CertReturnCode CertRemoveCertificateDirect(int sn, const char *cert_path);

/**
 *
 * @brief Remove a certificate from the default directory
 *
 * @param[in] serialNb The certificate ID.
 * @param[in] pCertPath The location of the certificate.
 *
 * @return CERT_OK
 * CERT_UNDEFINED_DESTINATION: The path isn't defined
 * CERT_PATH_LIMIT_EXCEEDED: The combination of path and certificate name
 *     exceeds the pre-defined limits
 * CERT_LINK_ERROR: The certificate removal failed.
 */
extern CertReturnCode CertRemoveCertificate(int sn);

/**
 * @brief Retrieve the number of certificates based on status
 *
 * Count the number of certificates that match the status.
 *
 * @param pDatabase The certificate database
 * @param status The filter
 * @param pNCerts The number of certificates that matched the status
 *
 * @return CERT_OK
 * @return CERT_DATABASE_INITIALIZATION_ERROR: The database was never init'ed
 * @return CERT_FILE_ACCESS_FAILURE: The database file could not be accessed
 * @return CERT_LOCKED_FILE_LOCKED: The database lockfile is unavailable
 * @return CERT_DATABASE_LOCKED: The database is currently in use
 */
extern CertReturnCode CertGetCertificateCountDirect(const char *db_path, CertStatus status, int *o_ncerts);

/* Return the number of Authorized Certs currently installed.
 */
/**
 * @brief Retrieve the number of certificates based on status from the
 *        default database
 *
 * Count the number of certificates that match the status.
 *
 * @param pDatabase The certificate database
 * @param status The filter
 * @param pNCerts The number of certificates that matched the status
 *
 * @return CERT_OK
 * @return CERT_DATABASE_INITIALIZATION_ERROR: The database was never init'ed
 * @return CERT_FILE_ACCESS_FAILURE: The database file could not be accessed
 * @return CERT_LOCKED_FILE_LOCKED: The database lockfile is unavailable
 * @return CERT_DATABASE_LOCKED: The database is currently in use
 */
extern CertReturnCode CertGetCertificateCount(CertStatus status, int *o_ncerts);

/* Given a filename, stores the file in the authorized certs directory
 * under a name compatible with openssl's load_verify_locations.  (See
 * p. 129 of o'reilly's OpenSSL book.)  Filename will be unique thanks
 * to the above requirement. Will return an error if the file doesn't
 * contain data in a format we can handle, but not if it's
 * unauthorized, expired, etc.
 */
/**
 * @brief Add a certificate to the list of valid certificates
 *
 * @param serialNb The certificate ID
 *
 * @return CERT_OK:
 * @return CERT_UNSUPPORTED_CERT_TYPE: the certificate package is not a
 *     supported package type
 * @return CERT_OPEN_FILE_FAILURE: the certificate file could not be opened
 * @return CERT_FILE_READ_FAILURE: the PEM was not read successfully
 * @return CERT_TOO_MANY_HASH_FILES: We've exceeded the number of files whose
 *      base name is the same.
 */
extern CertReturnCode CertAddAuthorizedCert(const int sn);

/**
 * @brief Add a certificate to the list of trusted certificates
 *
 * @param sn The certificate ID
 *
 * @return CERT_OK:
 * @return CERT_UNSUPPORTED_CERT_TYPE: the certificate package is not a
 *     supported package type
 * @return CERT_OPEN_FILE_FAILURE: the certificate file could not be opened
 * @return CERT_FILE_READ_FAILURE: the PEM was not read successfully
 * @return CERT_TOO_MANY_HASH_FILES: We've exceeded the number of files whose
 *      base name is the same.
 */
extern CertReturnCode CertAddTrustedCert(const int sn);


/**
 *
 * @brief Check to see if the certificate is valid.
 *
 * @param serialNb The certificate ID to validate
 *
 * @return CERT_OPEN_FILE_FAILURE: the file associated with the serialNB could
 *            not be opened
 * @return CERT_BUFFER_LIMIT_EXCEEDED: The path is too long for the default
 *            buffer size.
 * @return CERT_INSUFFICIENT_BUFFER_SPACE: There were problems resolving the
 *            root path.
 * @return CERT_UNSUPPORTED_CERT_TYPE: The certificate type is not supported
 * @return CERT_DATE_EXPIRED: The certificate may be inedible
 * @return CERT_DATE_PENDING: The certificate is premature
 * @return CERT_DATABASE_LOCKED: The database could not be updated
 */
extern CertReturnCode CertValidateCertificate(const int sn);

extern CertReturnCode CertPemToX509(const char *pem_path, X509 **o_cert);

extern CertReturnCode CertGetX509(const char *pkg_path, void *pass, X509 **o_cert);

#ifdef __cplusplus
}
#endif


#endif //#define __CERT_MGR_H__
