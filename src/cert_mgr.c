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
 * @file
 *
 * General interface to the Certificate Manager.
 *
 */
/*--************************************************************************-*/
/* cert_mgr.c: General interface to the certificate manager                  */
/*             Maybe change to cert_ui                                       */
/*--************************************************************************-*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <linux/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/conf.h>
#include <openssl/ec.h>

#include "cert_cfg.h"
#include "cert_utils.h"
#include "cert_db.h"
#include "cert_x509.h"
#include "cert_debug.h"
#include "cert_mgr_prv.h"

#ifdef __cplusplus
extern "C" {
#endif

CertReturnCode SetupCertMgrEnviroment(void)
{
    CertReturnCode result;
    char cert_path[MAX_CERT_PATH];
    char db_name[MAX_CERT_PATH];

    result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE, db_name, sizeof(db_name));

    if (result != CERT_OK)
    {
        return result;
    }

    DPRRINTF("%s: path %s\n", __FUNCTION__, db_name);
    result = CertCfgGetObjectStrValue(CERTCFG_CERT_DIR, cert_path, sizeof(cert_path));

    if ((result != CERT_OK) || (cert_path[0] == '\0'))
    {
        DPRRINTF("CertInitCertMgr unable to read cert path");
        strcpy(cert_path, "/var/ssl/certs");
    }

    if (cmutils_mkdirp(cert_path) != 0)
    {
        DPRRINTF("ERROR making dir '%s'\n", cert_path);
        return CERT_DIRECTORY_CREATION_FAILED;
    }

    if (cmutils_touchp(db_name, NULL) != 0)
    {
        DPRINTF("ERROR touching '%s'\n", db_name);
        return CERT_OPEN_FILE_FAILED;
    }

    result = CertCfgGetObjectStrValue(CERTCFG_CERT_SERIAL_NAME, cert_path, sizeof(cert_path));

    if ((result != CERT_OK) || (cert_path[0] == '\0'))
    {
        DPRRINTF("CertInitCertMgr unable to read serial path");
        strcpy(cert_path, "/var/ssl/serial");
    }

    if (cmutils_touchp(cert_path, "01\n"))
    {
        DPRRINTF("ERROR writing '%s'\n", cert_path);
        return CERT_OPEN_FILE_FAILED;
    }

    result = CertCfgGetObjectStrValue(CERTCFG_PRIVATE_KEY_DIR, cert_path, sizeof(cert_path));

    if ((result != CERT_OK) || (cert_path[0] == '\0'))
    {
        DPRRINTF("CertInitCertMgr unable to read private key path");
        strcpy(cert_path, "/var/ssl/private");
    }

    if (cmutils_mkdirp(cert_path) != 0)
    {
        DPRRINTF("ERROR creating dir '%s'\n", cert_path);
        return CERT_DIRECTORY_CREATION_FAILED;
    }

    return CERT_OK;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertInitCertMgr                                                 */
/* INPUT:                                                                    */
/*       configFile the configuration file                                   */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_OK:                                                            */
/*       CERT_PATH_LIMIT_EXCEEDED: The path string is too long               */
/*       CERT_OPEN_FILE_FAILED: The config file couldn't be opened           */
/*       CERT_ILLFORMED_CONFIG_FILE: There was some problem in the config    */
/*       CERT_CONFIG_UNAVAILABLE: The named configuration not available      */
/*       CERT_UNDEFINED_DESTINATION: The certificate root dir not available  */
/* NOTES:                                                                    */
/*       1) If configFile == NULL then the set of possible defaults is       */
/*          checked in the following order:                                  */
/*           1. The environment variable OPENSSL_CONF                        */
/*           2. The system default, CERT_DEF_CONF_FILE, in cert_mgr.h        */
/*       2) Put this into a library initialization routine                   */
/*                                                                           */
/*--***********************************************************************--*/

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
 * @param[in] config_file the configuration file
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

CertReturnCode CertInitCertMgr(const char *config_file)
{
    static int is_initialized = 0;

    if (!is_initialized)
    {
        CertReturnCode result;
        char db_name[MAX_CERT_PATH];

        result = CertCfgOpenConfigFile(config_file, getenv("OPENSSL_CONFIG_NAME"));

        if (result == CERT_UNDEFINED_ROOT_DIR)
        {
            result = SetupCertMgrEnviroment();
        }

        if (result != CERT_OK)
        {
            return result;
        }

        if (CertInitLockFiles() != CERT_OK)
        {
            DPRRINTF("CertInitCertMgr: CertInitLockFiles");
            return CERT_LOCK_FILE_CREATION_FAILURE;
        }

        if ((CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE, db_name, sizeof(db_name)) != CERT_OK) ||
            (CertInitDatabase(db_name) != CERT_OK))
        {
            return CERT_DATABASE_NOT_AVAILABLE;
        }

        OpenSSL_add_all_algorithms();

        if (seedSSLPrng() != CERT_OK)
        {
            return CERT_GENERAL_FAILURE;
        }

        is_initialized = 1;
    }

    return CERT_OK;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertResetConfig                                                 */
/*       Reset the configuration of the certificate Manager                  */
/* INPUT:                                                                    */
/*       configFile: The configuration file                                  */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_OK: The database was successfully read and deciphered          */
/*       CERT_INSUFFICIENT_BUFFER_SPACE: The origianal configuration file    */
/*           string is ill-defined.                                          */
/*       CERT_OPEN_FILE_FAILED: The config file couldn't be opened           */
/*       CERT_ILLFORMED_CONFIG_FILE: There was some problem in the config    */
/*       CERT_CONFIG_UNAVAILABLE: The named configuration is not             */
/*           available in the configuration file                             */
/*       CERT_UNDEFINED_DESTINATION if the certificate root dir not available*/
/*                                                                           */
/* NOTES:                                                                    */
/*       1) Pick up any changes made to the configuration file               */
/*                                                                           */
/*--***********************************************************************--*/

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
CertReturnCode CertResetConfig(const char *config_file)
{
    char config_name[MAX_CERT_PATH];

    if (CertCfgGetObjectStrValue(CERTCFG_CONFIG_NAME, config_name, sizeof(config_name)) == CERT_OK)
    {
        return CertCfgOpenConfigFile(config_file, config_name)
    }

    /* Load it from the environment */
    return CertCfgOpenConfigFile(config_file, getenv("OPENSSL_CONFIG_NAME"));
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertReadKeyPackageDirect                                        */
/*       Read a Key Package into memory and gives access to the component    */
/*       parts to the designated.  Decrypt if necessary.  The password,      */
/*       passwd  is in clear text.                                           */
/* INPUT:                                                                    */
/*       pkg_path: The name of the package file                              */
/*       dst_path: The path to the package file                              */
/*       pcbk: The callback function for encrypting the package              */
/*       pwd_ctxt: The passkey in clear text for decrypting the package      */
/* OUTPUT:                                                                   */
/*       sn: An identifying number for the certificate                       */
/* RETURN:                                                                   */
/*       CERT_OK:                                                            */
/*       CERT_SERIAL_NUMBER_FILE_UNAVAILABLE: The Certificate Manager is not */
/*           properly initialized                                            */
/*       CERT_SERIAL_NUMBER_UNAVAILABLE: The system was unable to provied a  */
/*           valid serial number                                             */
/*       CERT_FILE_ACCESS_FAILURE: The system was unable to write the x.509  */
/*           certificate.                                                    */
/*       CERT_DATABASE_LOCKED: The system was unable to access the database  */
/*       CERT_DATABASE_NOT_AVAILABLE: The system was unable to access the    */
/*           the database                                                    */
/*       CERT_LOCKFILE_LOCKED: The database is currently used                */
/*       CERT_FILE_PARSE_ERROR: The input file is ill-formed                 */
/*       CERT_FILE_READ_ERROR: The input file cannot be read                 */
/*       CERT_OPEN_FILE_FAILED: The input file cannot be opened              */
/*       CERT_ILLEGAL_KEY_PACKAGE_TYPE: The package is not a supported type  */
/*       CERT_OPEN_FILE_FAILED: the requested package could not be opened.   */
/*           perhaps a password problem                                      */
/* NOTES:                                                                    */
/*       1) Packages are assumed to be encoded by their extension            */
/*       2) The following types are supported                                */
/*          PKCS#12                                                          */
/*              .pfx                                                         */
/*              .p12                                                         */
/*          DER                                                              */
/*              .der Distinguished Encoding Rules                            */
/*              .cer Canonical Encoding Rules                                */
/*          PEM                                                              */
/*              .pem Privacy Enhanced Mail                                   */
/*              .crt used in at least Debian (Ubuntu) defined pem files      */
/*       4) The location of the package itself is placed in                  */
/*          directory denoted by CERTCFG_PACKAGE_DIR.                        */
/*       5) This is not currently exported to applications                   */
/*                                                                           */
/*--***********************************************************************--*/

/**
 * @brief Read a Key Package into memory
 *
 *       Read a Key Package into memory and gives access to the component
 *       parts to the designated.  Decrypt if necessary.  The password,
 *       passwd  is in clear text.
 *
 *
 * @param[in] pkg_path The name of the package file.
 * @param[in] dst_path The path to the package file
 * @param[in] pcbk The callback function for encrypting the package
 * @param[in] pwd_ctxt The passkey in clear text for decrypting the package
 * @param[out] sn An identifying number for the certificate
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
CertReturnCode CertReadKeyPackageDirect(const char *pkg_path, const char *dst_path, CertPassCallback pcbk, void *pwd_ctxt, int *sn)
{
    switch (getFileType(pkg_path))
    {
    case CERT_PFX_FILE:
    case CERT_P12_FILE:
        DPRRINTF("%s crt p12 file \n", __FUNCTION__);
        return p12ToFile(pkg_path, dst_path, pcbk, pwd_ctxt, sn);

    case CERT_DER_FILE:
    case CERT_CER_FILE:
    case CERT_CRT_FILE:
    case CERT_PEM_FILE:
    case CERT_CRL_FILE:
        if (pemToFile(pkg_path, dst_path, pcbk, pwd_ctxt, sn) == CERT_OK)
        {
            PRINTF("%s crt pem file \n", __FUNCTION__);
            return CERT_OK;
        }

        if (derToFile(pkg_path, dst_path, sn) == CERT_OK)
        {
            DPRINTF("%s crt der file \n", __FUNCTION__);
            return CERT_OK;
        }

        return CERT_GENERAL_FAILURE;

    default:
        return CERT_ILLEGAL_KEY_PACKAGE_TYPE;
    }
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertInstallKeyPackageDirect                                     */
/*       Resolve a Key Package into its component parts to the designated    */
/*       destination directory.  Decrypt if necessary.  The password, passwd */
/*       is in clear text.                                                   */
/* INPUT:                                                                    */
/*       pkg_path: The location of the package file                          */
/*       dst_path: The root directory for the resolved, decrypted data       */
/*       pcbk: The callback function for decrypting the package              */
/*       pwd_ctxt: The passkey in clear text for decrypting the package      */
/* OUTPUT:                                                                   */
/*       sn: The certificate ID number                                       */
/* RETURN:                                                                   */
/*       CERT_OK:                                                            */
/*       CERT_ILLEGAL_PACKAGE_TYPE: The package is not a supported type      */
/*       CERT_OPEN_FILE_FAILED: the requested package could not be opened.   */
/*           perhaps a password problem                                      */
/*       CERT_UNDEFINED_DESTINATION: the destination directory could not be  */
/*           resolved.                                                       */
/* NOTES:                                                                    */
/*       1) Packages are assumed to be encoded by their extension            */
/*       2) The following types are supported                                */
/*          PKCS#12                                                          */
/*              .pfx                                                         */
/*              .p12                                                         */
/*          DER                                                              */
/*              .der Distinguished Encoding Rules                            */
/*              .cer Canonical Encoding Rules                                */
/*          PEM                                                              */
/*              .pem Privacy Enhanced Mail                                   */
/*              .crt used in at least Debian (Ubuntu) defined pem files      */
/*       3) The constituent parts of the package are not re-encrypted, but,  */
/*          rather, rely on the native Linux permission controls with the    */
/*          following defaults:                                              */
/*          certs/   rwxr-x-r-x                                              */
/*          private/ rwx------                                               */
/*          This presupposes that the destination path has permissions set   */
/*          correctly                                                        */
/*       4) The location of the package itself is placed in                  */
/*          directory denoted by CERTCFG_PACKAGE_DIR.                        */
/*                                                                           */
/*--***********************************************************************--*/

/**
 * @brief  Resolve a Key Package into its component parts to the designated
 *       destination directory.
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
 * @param[in] pkg_path The name of the package file.
 * @param[in] dst_path The path to the package file
 * @param[in] pcbk The callback function for encrypting the package
 * @param[in] pwd_ctxt The passkey in clear text for decrypting the package
 * @param[out] sn An identifying number for the certificate
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

CertReturnCode CertInstallKeyPackageDirect(const char *pkg_path, const char *dst_path, CertPassCallback pcbk, void *pwd_ctxt, int *sn)
{
    switch (getFileType(pkg_path))
    {
    case CERT_PFX_FILE:
    case CERT_P12_FILE:
        DPRRINTF("%s p12 pfx file\n", __FUNCTION__);
        return p12ToFile(pkg_path, dst_path, pcbk, pwd_ctxt, sn);

    case CERT_DER_FILE:
    case CERT_CER_FILE:
    case CERT_CRT_FILE:
    case CERT_PEM_FILE:
    case CERT_CRL_FILE:
        if (pemToFile(pkg_path, dst_path, pcbk, pwd_ctxt, sn) == CERT_OK)
        {
            DPRRINTF("%s crt pem file \n", __FUNCTION__);
            return CERT_OK;
        }

        if (derToFile(pkg_path, dst_path, sn) == CERT_OK)
        {
            DPRRINTF("%s crt der file \n", __FUNCTION__);
            return CERT_OK;
        }

        return CERT_GENERAL_FAILURE;

    default:
        return CERT_ILLEGAL_KEY_PACKAGE_TYPE;
    }
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertInstallKeyPackage                                           */
/*       Resolve a Key Package into its component parts to the default       */
/*       destination directories.  Decrypt if necessary.  The password,      */
/*       passwd, is in clear text.                                           */
/* INPUT:                                                                    */
/*       pPkgPath: The location of the package file                          */
/*       pcbk: The callback function for decrypting the package              */
/*       pwd_ctxt: The passkey in clear text for decrypting the package      */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_OK:                                                            */
/*       CERT_ILLEGAL_PACKAGE_TYPE: The package is not a supported type      */
/*       CERT_OPEN_FILE_FAILED: the requested package could not be opened.   */
/*           perhaps a password problem                                      */
/*       CERT_UNDEFINED_DESTINATION: the destination directory could not be  */
/*           resolved.                                                       */
/* NOTES:                                                                    */
/*       1) Packages are encoded by their extension                          */
/*       2) The following types are supported                                */
/*          PKCS#12                                                          */
/*              .pfx                                                         */
/*              .p12                                                         */
/*          DER                                                              */
/*              .der Distinguished Encoding Rules                            */
/*              .cer Canonical Encoding Rules                                */
/*          PEM                                                              */
/*              .pem Privacy Enhanced Mail                                   */
/*              .crt used in at least Debian definition of pem               */
/*       3) The constituent parts of the package are not re-encrypted, but,  */
/*          rather, rely on the native Linux permission controls.            */
/*          This presupposes that the destination path has permissions set   */
/*          correctly                                                        */
/*       4) The destination directory is resolved at initialization time from*/
/*          the rules defined in the configuration file                      */
/*                                                                           */
/*--***********************************************************************--*/

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
 * @param[out] sn An identifying number for the certificate
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

CertReturnCode CertInstallKeyPackage(const char *pkg_path, CertPassCallback pcbk, void *pwd_ctxt, int *sn)
{
    char dst_path[MAX_CERT_PATH];
    CertReturnCode result;

    result = CertCfgGetObjectStrValue(CERTCFG_ROOT_DIR, dst_path, sizeof(dst_path));

    if (result != CERT_OK)
    {
        return result;
    }

    if (dst_path[0] == '\0')
    {
        return CERT_UNDEFINED_DESTINATION;
    }

    return CertInstallKeyPackageDirect(pkg_path, pDestPath, pcbk, pwd_ctxt, sn);
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertRemoveCertificateDirect                                     */
/*       Remove a certificate from the designated directory                  */
/* INPUT:                                                                    */
/*       sn: The certificate ID.                                       */
/*       cert_path The location of the certificate.                          */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/*       CERT_OK                                                             */
/*       CERT_UNDEFINED_DESTINATION: The path isn't defined                  */
/*       CERT_PATH_LIMIT_EXCEEDED: The combination of path and certificate   */
/*           name exceeds the pre-defined limits                             */
/*       CERT_LINK_ERROR: The certificate removal failed.                    */
/* NOTES:                                                                    */
/*       1) removeCert will do the error checking on both pCertName and  */
/*          *CertPath                                                        */
/*                                                                           */
/*--***********************************************************************--*/

/**
 *
 * @brief Remove a certificate from the designated directory
 *
 * @param[in] sn The certificate ID.
 * @param[in] cert_path The location of the certificate.
 *
 * @return CERT_OK
 * CERT_UNDEFINED_DESTINATION: The path isn't defined
 * CERT_PATH_LIMIT_EXCEEDED: The combination of path and certificate name
 *     exceeds the pre-defined limits
 * CERT_LINK_ERROR: The certificate removal failed.
 */
CertReturnCode CertRemoveCertificateDirect(int sn, const char *cert_path)
{
    int err_code;
    return removeCert(sn, cert_path, "", "pem", &err_code);
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertRemoveCertificate                                           */
/*       Remove a certificate from the default directory                     */
/* INPUT:                                                                    */
/*       sn: the certificate to be removed                             */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/*       CERT_OK                                                             */
/*       CERT_UNDEFINED_DESTINATION: The path isn't defined                  */
/*       CERT_PATH_LIMIT_EXCEEDED: The combination of path and certificate   */
/*           name exceeds the pre-defined limits                             */
/*       CERT_LINK_ERROR: The certificate removal failed.                    */
/* NOTES:                                                                    */
/*       1) All files installed with the certificate will be removed         */
/*                                                                           */
/*--***********************************************************************--*/

/**
 *
 * @brief Remove a certificate from the default directory
 *
 * @param[in] sn The certificate ID.
 *
 * @return CERT_OK
 * CERT_UNDEFINED_DESTINATION: The path isn't defined
 * CERT_PATH_LIMIT_EXCEEDED: The combination of path and certificate name
 *     exceeds the pre-defined limits
 * CERT_LINK_ERROR: The certificate removal failed.
 */
CertReturnCode CertRemoveCertificate(int sn)
{
    static const struct
    {
        CertCfgProperty dir;
        const char *fprefix;
        const char *fext;
    } cert_dirs[] =
    {
        { CERTCFG_CERT_DIR, "", "pem" },
        { CERTCFG_CERT_DIR, "ca", "pem" },
        { CERTCFG_PRIVATE_KEY_DIR, "rsa", "pem" },
        { CERTCFG_PRIVATE_KEY_DIR, "dsa", "pem" },
        { CERTCFG_AUTH_CERT_DIR, "", "pem" },
        { CERTCFG_PUBLIC_KEY_DIR, "rsa", "pem" },
        { CERTCFG_PUBLIC_KEY_DIR, "dsa", "pem" },
        { CERTCFG_CRL_DIR, "crl", "pem.gz" }
    };
    int err_code, iter_dir;
    CertReturnCode result;
    char cert_path[MAX_CERT_PATH];

    /* Get one after another */
    for (iter_dir = 0; iter_dir < sizeof(cert_dirs) / sizeof(cert_dirs[0]); ++iter_dir)
    {
        if ((CertCfgGetObjectStrValue(cert_dirs[iter_dir].dir, cert_path, sizeof(cert_path)) == CERT_OK) &&
            (cert_path[0] != '\0'))
        {
            result = removeCert(sn, cert_path, cert_dirs[iter_dir].fprefix, cert_dirs[iter_dir].fext, &err_code);

            if (result != CERT_OK)
            {
                break;
            }
        }
    }

    /* whether or not things went well */
    removeBrokenLinkFiles();

    if (result != CERT_OK)
    {
        return result;
    }

    return CertUpdateDatabaseItem(sn, CERT_DATABASE_ITEM_STATUS, CertGetStatusString(CERT_STATUS_ALL));
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertGetCertificateCountDirect                                   */
/*       Retrieve the number of certificates based on status                 */
/* INPUT:                                                                    */
/*       db_path: The certificate database                                   */
/*       status: The filter                                                  */
/* OUTPUT:                                                                   */
/*       o_ncerts: The number of certificates that matched the status         */
/* RETURN:                                                                   */
/*       CERT_OPEN_FILE_FAILED: The certificate directory couldn't be opened */
/* NOTES:                                                                    */
/*       1) There are no checks for database consistency                     */
/*                                                                           */
/*--***********************************************************************--*/
/**
 * @brief Retrieve the number of certificates based on status
 *
 * Count the number of certificates that match the status.
 *
 * @param db_path The certificate database
 * @param status The filter
 * @param o_ncerts The number of certificates that matched the status
 *
 * @return CERT_OK
 * @return CERT_DATABASE_INITIALIZATION_ERROR: The database was never init'ed
 * @return CERT_FILE_ACCESS_FAILURE: The database file could not be accessed
 * @return CERT_LOCKED_FILE_LOCKED: The database lockfile is unavailable
 * @return CERT_DATABASE_LOCKED: The database is currently in use
 */
CertReturnCode CertGetCertificateCountDirect(const char *db_path, CertStatus status, int *o_ncerts)
{
    return CertDatabaseCountCertsDirect(db_path, status, o_ncerts);
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertGetCertificateCount                                         */
/*       Resolve the current certificate directory and count its contents    */
/* INPUT:                                                                    */
/*       status: The filter                                                  */
/* OUTPUT:                                                                   */
/*       o_ncerts: The number of certificates that matched the status         */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) There are no checks for database consistency                     */
/*                                                                           */
/*--***********************************************************************--*/

/**
 * @brief Retrieve the number of certificates based on status from the
 *        default database
 *
 * Count the number of certificates that match the status.
 *
 * @param status The filter
 * @param o_ncerts The number of certificates that matched the status
 *
 * @return CERT_OK
 * @return CERT_DATABASE_INITIALIZATION_ERROR: The database was never init'ed
 * @return CERT_FILE_ACCESS_FAILURE: The database file could not be accessed
 * @return CERT_LOCKED_FILE_LOCKED: The database lockfile is unavailable
 * @return CERT_DATABASE_LOCKED: The database is currently in use
 */
CertReturnCode CertGetCertificateCount(CertStatus status, int *o_ncerts)
{
    char db_path[MAX_CERT_PATH];

    if (CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE, db_path, sizeof(db_path)) == CERT_OK)
    {
        return CertGetCertificateCountDirect(db_path, status, o_ncerts);
    }

    return CERT_GENERAL_FAILURE;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: certAddAuthorizedCertificate                                    */
/*       Set a certificate to authorized                                     */
/* INPUT:                                                                    */
/*       sn: the serial number of the certificate file to be authorized*/
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_OK:                                                            */
/*       CERT_UNSUPPORTED_CERT_TYPE: the certificate package is not a        */
/*          supported package type                                           */
/*       CERT_OPEN_FILE_FAILURE: the certificate file could not be opened    */
/*       CERT_FILE_READ_FAILURE: the PEM was not read successfully           */
/*       CERT_TOO_MANY_HASH_FILES: We've exceeded the number of files whose  */
/*           base name is the same.                                          */
/* NOTES:                                                                    */
/*       1) The expectation is that the file is named after the first 4 bytes*/
/*          of the hash to be an Authoritative certificate.  Validation has  */
/*          not yet been achieved.                                           */
/*       2) Authorized certificates will be held in a database similar to    */
/*          index.txt for issued certificates                                */
/*       3) The output is placed in the defaults defined by the configuration*/
/*          file along with a copy of the certificate.  the actual files are */
/*          links rather than copies.  The convention followed on Ubuntu is  */
/*          the original container is in an arbitrary location with the      */
/*          suffix .crt.   The destination files are .pem for the straight   */
/*          copy and .# for the copy with the hash as the name.              */
/*       4) This treats the package as if it were in the correct format.  It */
/*          does not break it down into its constituent parts.               */
/*       5) No checks are made to the certificate.  It is assumed that the   */
/*          checks will be made at the time of the certificate's use.  This  */
/*          is as it should be.                                              */
/*                                                                           */
/*--***********************************************************************--*/

/**
 * @brief Add a certificate to the list of valid certificates
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
CertReturnCode CertAddAuthorizedCert(const int sn)
{
    X509 *cert = NULL;
    CertReturnCode result;
    unsigned long hash;
    char cert_path[MAX_CERT_PATH];
    char filename[MAX_CERT_PATH];

#if 0
    result = CertGetNameFromSerialNumber(sn, cert_path, sizeof(cert_path));
#else
    result = makeCertPathFromSerial(sn, cert_path, sizeof(cert_path));
#endif

    if (result != CERT_OK)
    {
        return result;
    }

    result = CertPemToX509(cert_path, &cert);

    if (result != CERT_OK)
    {
        return result;
    }

    hash = X509_subject_name_hash(cert);

    result = getCertLinkPath(filename, sizeof(filename), hash, cert_path, CERTCFG_AUTH_CERT_DIR);

    if (result != CERT_OK)
    {
        goto end;
    }

    if (symlink(cert_path, filename) == -1)
    {
        DPRINTF("ERROR %d creating symlink '%s' -> '%s'\n", errno, filename, cert_path);
        result = CERT_LINK_ERR;
        goto end;
    }

    DPRRINTF("%s - %s - %s\n", __FUNCTION__, cert_path, filename);

    // ericm: also make a link in trusted cache dir that points to this cert
    result = getCertLinkPath(filename, sizeof(filename), hash, cert_path, CERTCFG_TRUSTED_CA_DIR);

    if (result != CERT_OK)
    {
        goto unlink_auth;
    }

    if (symlink(cert_path, filename) == -1)
    {
        DPRRINTF("ERROR %d creating symlink '%s' -> '%s'\n", errno, filename, cert_path);
        result = CERT_LINK_ERR;
        goto unlink_auth;
    }

    result = CertUpdateDatabaseItem(sn, CERT_DATABASE_ITEM_STATUS, CertGetStatusString(CERT_STATUS_VALID_CA));

    if (result != CERT_OK)
    {
        goto unlink_trusted;
    }

    DPRINTF("%s - %s - %s\n", __FUNCTION__, cert_path, filename);
    /* don't update db, it was done above */

end:
    X509_free(cert);

    return result;

error:
unlink_trusted:
    unlink(filename);

unlink_auth:
    if (getCertLinkPath(filename, sizeof(filename), hash, cert_path, CERTCFG_AUTH_CERT_DIR) == CERT_DUPLICATE)
    {
        unlink(filename);
    }

    goto end;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: certAddTrustedCertificate                                    */
/*       Set a certificate to trusted                                     */
/* INPUT:                                                                    */
/*       sn: the serial number of the certificate file to be authorized*/
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_OK:                                                            */
/*       CERT_UNSUPPORTED_CERT_TYPE: the certificate package is not a        */
/*          supported package type                                           */
/*       CERT_OPEN_FILE_FAILURE: the certificate file could not be opened    */
/*       CERT_FILE_READ_FAILURE: the PEM was not read successfully           */
/*       CERT_TOO_MANY_HASH_FILES: We've exceeded the number of files whose  */
/*           base name is the same.                                          */
/* NOTES:                                                                    */
/*                                                                           */
/*--***********************************************************************--*/

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

CertReturnCode CertAddTrustedCert(const int sn)
{
    return CertUpdateDatabaseItem(sn, CERT_DATABASE_ITEM_STATUS, CertGetStatusString(CERT_STATUS_TRUSTED_PEER));
}


/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertValidateCertificate                                         */
/*       Check to see if the certificate is valid.                           */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/*       CERT_OPEN_FILE_FAILURE: the file associated with the sn could */
/*            not be opened                                                  */
/*       CERT_BUFFER_LIMIT_EXCEEDED: The path is too long for the default    */
/*            buffer size.                                                   */
/*       CERT_INSUFFICIENT_BUFFER_SPACE: There were problems resolving the   */
/*            root path                                                      */
/*       CERT_UNSUPPORTED_CERT_TYPE: The certificate type is not supported   */
/*       CERT_DATE_EXPIRED: The certificate may be inedible                  */
/*       CERT_DATE_PENDING: The certificate is premature                     */
/*       CERT_DATABASE_LOCKED: The database could not be updated             */
/* NOTES:                                                                    */
/*       1) CERT_DATABASE_LOCKED will obscure whether or not the certificate */
/*          is valid                                                         */
/*                                                                           */
/*--***********************************************************************--*/
/**
 *
 * @brief Check to see if the certificate is valid.
 *
 * @param sn The certificate ID to validate
 *
 * @return CERT_OPEN_FILE_FAILURE: the file associated with the sn could
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
CertReturnCode CertValidateCertificate(const int sn)
{
    int ctype;
    CertMgrError err_code;
    CertReturnCode result;
    char path[MAX_CERT_PATH];

    result = makeCertPathFromSerial(sn, path, sizeof(path));

    if (result != CERT_OK)
    {
        return result;
    }

    if (!cmutils_exists(path))
    {
        return CERT_OPEN_FILE_FAILED;
    }

    /* File formats are mutually exclusive in interpretation */
    for (ctype = CERTTYPE_PEM; ctype < CERTTYPE_UNKNOWN; ++ctype)
    {
        result = validateCertPath(path, sn, ctype, &err_code);

        /* This test fails if the file is the wrong CERTTYPE
         * So go on the the next one */
        if (result != CERT_FILE_READ_FAILURE)
        {
            break;
        }
    }

    return result;
}

/*--***********************************************************************--*/
/*--**** FILE TO MEMORY                                            ********--*/
/*--***********************************************************************--*/

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertPemToX509                                                       */
/*       Read a PEM encoded certificate into memory                          */
/* INPUT:                                                                    */
/*       pem_path: the path to the PEM encoded file                           */
/* OUTPUT:                                                                   */
/*       o_cert: the X.509 certificate for use                                */
/* RETURN:                                                                   */
/*       CERT_OK: the certificate had been read successfully                 */
/*       CERT_OPEN_FILE_FAILURE: the bio file could not be opened            */
/*       CERT_FILE_READ_FAILURE: the PEM was not read successfully           */
/* NOTES:                                                                    */
/*                                                                           */
/*--***********************************************************************--*/

CertReturnCode CertPemToX509(const char *pem_path, X509 **o_cert)
{
    BIO *bio;
    X509 *cert;
    char pass[] = "    ";

    /* Don't dereference NULL pointers */
    if ((pem_path == NULL) || (o_cert == NULL))
    {
        return CERT_INVALID_ARG;
    }

    bio = BIO_new_file(pem_path, "r");

    if (bio == NULL)
    {
        PRINT_RETURN_CODE(CERT_OPEN_FILE_FAILED);
        return CERT_OPEN_FILE_FAILED;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, pass);

    BIO_free(bio);

    if (cert == NULL)
    {
        PRINT_RETURN_CODE(CERT_FILE_READ_FAILURE);
        logSSLErrors();
        return CERT_FILE_READ_FAILURE;
    }

    *o_cert = cert;

    return CERT_OK;
}

CertReturnCode CertGetX509(const char *pkg_path, void *pass, X509 **o_cert)
{
    if (pkg_path == NULL)
    {
        return CERT_INVALID_ARG;
    }

    if (o_cert == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    switch (getFileType(pkg_path))
    {
    case CERT_PFX_FILE:
    case CERT_P12_FILE:
        {
            EVP_PKEY *key;
            STACK_OF(X509) *ca;
            CertReturnCode result;

            DPRINTF("%s p12 pfx file\n", __FUNCTION__);
            result = p12ToX509(pkg_path, pass, o_cert, &key, &ca);

            if (pkey != NULL)
            {
                EVP_PKEY_free(key);
            }

            if (ca != NULL)
            {
                sk_X509_free(ca);
            }

            return result;
        }

    case CERT_DER_FILE:
    case CERT_CER_FILE:
    case CERT_CRT_FILE:
    case CERT_PEM_FILE:
        if (CertPemToX509(pkg_path, o_cert) == CERT_OK)
        {
            DPRINTF("%s crt pem file \n", __FUNCTION__);
            return CERT_OK;
        }

        if (derToX509(pkg_path, o_cert) == CERT_OK)
        {
            DPRINTF("%s crt der file \n", __FUNCTION__);
            return CERT_OK;
        }

        return CERT_GENERAL_FAILURE;

    default:
        PRINT_ERROR4("Path", pkg_path, "FileType", (int)getFileType(pkg_path));
        return CERT_ILLEGAL_KEY_PACKAGE_TYPE;
    }
}


/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: derToX509                                                       */
/*       Read a DER encoded X.509 information into memory                    */
/* INPUT:                                                                    */
/*       der_path: the path to the DER encoded file                           */
/* OUTPUT:                                                                   */
/*       o_cert: the X.509 certificate for use                                */
/* RETURN:                                                                   */
/*       CERT_OK: the certificate had been read successfully                 */
/*       CERT_FILE_ACCESS_FAILURE: the bio file opening failed               */
/*       CERT_FILE_READ_FAILURE: the PEM was not read successfully           */
/* NOTES:                                                                    */
/*                                                                           */
/*--***********************************************************************--*/

static CertReturnCode derToX509(const char *der_path, X509 **o_cert)
{
    X509 *cert;
    FILE *file = fopen(der_path, "r");

    if (file == NULL)
    {
        PRINT_RETURN_CODE(CERT_FILE_ACCESS_FAILURE);
        return CERT_FILE_ACCESS_FAILURE;
    }

    cert = d2i_X509_fp(file, NULL);

    if (cert == NULL)
    {
        cert = X509_new();
        rewind(file);

        if (PEM_read_X509(file, &cert, NULL, NULL) == NULL)
        {
            X509_free(cert);
            cert = NULL;
        }
    }

    fclose(file);

    if (cert == NULL)
    {
        PRINT_RETURN_CODE(CERT_FILE_READ_FAILURE);
        logSSLErrors();
        return CERT_FILE_READ_FAILURE;
    }

    *o_cert = cert;

    return CERT_OK;
}

static CertReturnCode p12ToX509(const char *p12_path, void *pass, X509 **o_cert, EVP_PKEY **o_key, STACK_OF(X509) **o_ca)
{
    FILE *fp;
    X509 *cert;
    PKCS12 *p12;
    EVP_PKEY *pkey;
    STACK_OF(X509) *ca;

    /* Don't derefrence NULL pointers */
    if (p12_path == NULL)
    {
        return CERT_INVALID_ARG;
    }

    /* Don't derefrence NULL pointers */
    if ((o_cert == NULL) || (o_key == NULL) || (o_ca == NULL))
    {
        return CERT_NULL_BUFFER;
    }

    fp = fopen(p12_path, "r");

    if (fp == NULL)
    {
        PRINT_RETURN_CODE(CERT_FILE_READ_FAILURE);
        return CERT_FILE_READ_FAILURE;
    }

    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);

    if (p12 == NULL)
    {
        PRINT_RETURN_CODE(CERT_FILE_READ_FAILURE);
        return CERT_FILE_READ_FAILURE;
    }

    /* Try to verify without passphrase */
    if ((!PKCS12_verify_mac(p12, "", 0)) &&
        (!PKCS12_verify_mac(p12, NULL, 0)))
    {
        DPRINTF("%s password required \n", __FUNCTION__);

        if (!PKCS12_verify_mac(p12, pass, strlen(pass)))
        {
            DPRINTF("%s password incorrect %s\n", __FUNCTION__, (const char *)pass);
            return CERT_PASSWD_WRONG;
        }
    }

    if ((!PKCS12_parse(p12, pass, &pkey, &cert, &ca)) ||
        (cert == NULL))
    {
        PRINT_RETURN_CODE(CERT_FILE_READ_FAILURE);
        logSSLErrors();
        return CERT_FILE_READ_FAILURE;
    }

    *o_cert = cert;
    *o_key = pkey;
    *o_ca = ca;

    return CERT_OK;
}

/*--***********************************************************************--*/
/*--**** FILE TO FILE                                              ********--*/
/*--***********************************************************************--*/
/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: p12ToFile                                                       */
/*       Decrypt the PKCS#12 package and populate the given directory with   */
/*       the results                                                         */
/* INPUT:                                                                    */
/*       pkg_path: The location of the package file                          */
/*       pcbk: a callback function for optional re-encrypting                */
/*       dst_path: The root location for the resolved, decrypted data       */
/*       pass: The passkey in clear text for decrypting the package          */
/* OUTPUT:                                                                   */
/*       serial: an identifying number for the associated files              */
/* RETURN:                                                                   */
/*       CERT_OK: No absolute errors were found                              */
/*       CERT_FILE_PARSE_ERROR: the PKCS#12 file was not parsed properly     */
/*       CERT_FILE_READ_FAILURE: the PKCS#12 file could not be read          */
/*       CERT_OPEN_FILE_FAILED: the PKCS#12 file could not be opened         */
/* NOTES:                                                                    */
/*      1) From the documentation on openssl PKCS12_parse throws away most   */
/*         attributes keeping only:                                          */
/*             friendlyName                                                  */
/*             localKeyID                                                    */
/*      2) Similarly, attributes cannot be stored in the private key EVP_PKEY*/
/*      3) default locations are as follows:                                 */
/*             certificates:  dst_path/new_certs/    rwxr-x---              */
/*             private key:   dst_path/private/      rwx------              */
/*             public key:    dst_path/public/       rwxr-xr-x              */
/*      4) The passkey must be a NULL terminated string                      */
/*                                                                           */
/*--***********************************************************************--*/

static CertReturnCode p12ToFile(const char *pkg_path, const char *dst_path, CertPassCallback pcbk, void *pass, int *o_sn)
{
    char *base_name;
    X509 *cert;
    EVP_PKEY *pkey;
    STACK_OF(X509) *ca;
    CertReturnCode result;
    int sn = 0, is_duplicated = 0;

    if (pkg_path == NULL)
    {
        return CERT_INVALID_ARG;
    }

    if (o_sn == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    base_name = fileBaseName(pkg_path);

    if (base_name == NULL)
    {
        return CERT_GENERAL_FAILURE;
    }

    DPRINTF("%s %s \n", __FUNCTION__, pkg_path);

    result = getNextSerialNumber(&sn);

    if (result != CERT_OK)
    {
        return result;
    }

    result = p12ToX509(pkg_path, pass, &cert, &pkey, &ca);

    if (result != CERT_OK)
    {
        goto done;
    }

    *o_sn = sn;

    /* We've gotten everything,
     * now let's write it out the the dest */

    result = installX509Cert(cert, base_name, sn) == CERT_OK);

    if (result != CERT_OK)
    {
        if (result == CERT_DUPLICATE)
        {
            is_duplicated = 1;
            result = CERT_OK;
        }

        goto done;
    }

    if (pkey != NULL)
    {
        CertObject key_type;

        /* find out what type of key it is */
        key_type = getPrivKeyType(pkey);

        if (key_type >= CERT_OBJECT_MAX_OBJECT)
        {
            DPRINTF("unknown keyType %d\n", key_type);
            /* not sure what else to do here */
            /* XXX: Should we break and error out or can we continue to CA? */
        }
        else
        {
            switch (key_type)
            {
            case CERT_OBJECT_RSA_PRIVATE_KEY:
                result = installDSAPrivKey((RSA *)pkey->pkey.rsa, base_name, sn);
                break;

            case CERT_OBJECT_EC_PRIVATE_KEY:
                result = installECPrivKey((EC_KEY *)pkey->pkey.ec, base_name, sn);
                break;

            default:
                DPRINTF("%s keyType %d\n", __FUNCTION__, key_type);
                break;
            }
        }
    }

    if (ca != NULL)
    {
        result = installCACerts(ca, base_name, sn);
    }

done:
    if ((result == CERT_OK) && (!is_duplicated))
    {
        result = CertCreateDatabaseItem(cert, base_name, sn, CERT_STATUS_UNKNOWN);
        DPRINTF("%s item created in db \n", __FUNCTION__);
    }

    X509_free(cert);

    if (pkey != NULL)
    {
        EVP_PKEY_free(pkey);
    }

    if (ca != NULL)
    {
        sk_X509_free(ca);
    }

    free(base_name);

    return result;
}

static CertReturnCode derToFile(const char *cert_path, const char *dst_path, int *o_sn)
{
    int sn;
    FILE *der_file;
    char *base_name;
    CertReturnCode result;

    if (cert_path == NULL)
    {
        return CERT_INVALID_ARG;
    }

    if (o_sn == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    result = getNextSerialNumber(&sn);

    if (result != CERT_OK)
    {
        return result;
    }

    der_file = fopen(cert_path, "r");

    if (der_file == NULL)
    {
        DPRINTF("%s file access failure \n", __FUNCTION__);
        return CERT_FILE_ACCESS_FAILURE;
    }

    char *base_name = fileBaseName(cert_path);

    if (base_name == NULL)
    {
        result = CERT_GENERAL_FAILURE;
    }
    else
    {
        X509 *cert;
        DSA *dsa_priv, *dsa_pub;
        RSA *rsa_priv, *rsa_pub;
        EC_KEY *ec_priv_key;
        X509_CRL *crl;

        cert = d2i_X509_fp(der_file, NULL);

        if (cert == NULL)
        {
            DPRINTF("%s no cert \n", __FUNCTION__);
            result = CERT_BAD_CERTIFICATE;
            goto cleanup;
        }

        result = installX509Cert(cert, base_name, &sn);
        X509_free(cert);

        /* If a duplicate certificate is found, just skip installation */
        /* FIXME: This will bite us if the installation of keys failed
         * and we retry installation becuase it'd simply skip over */
        if (result != CERT_OK)
        {
            if (result == CERT_DUPLICATE)
            {
                *o_sn = sn;
                result = CERT_OK;
            }

            goto cleanup;
        }

        DPRINTF("%s item created in db \n", __FUNCTION__);

        rewind(der_file);
        dsa_priv = d2i_DSAPrivateKey_fp(der_file, NULL);

        if (dsa_priv != NULL)
        {
            DPRINTF("%s DSA private key read \n", __FUNCTION__);

            result = installDSAPrivKey(dsa_priv, base_name, sn);
            DSA_free(dsa_priv);

            if (result != CERT_OK)
            {
                goto cleanup;
            }
        }

        rewind(der_file);
        dsa_pub = d2i_DSA_PUBKEY_fp(der_file, NULL);

        if (dsa_pub != NULL)
        {
            DPRINTF("%s DSA pubkey read\n", __FUNCTION__);

            result = installDSAPubKey(dsa_pub, base_name, sn);
            DSA_free(dsa_pub);

            if (result != CERT_OK)
            {
                goto cleanup;
            }
        }

        rewind(der_file);
        rsa_priv = d2i_RSAPrivateKey_fp(der_file, NULL);

        if (rsa_priv != NULL)
        {
            DPRINTF("%s RSA private key read \n", __FUNCTION__);
            result = installRSAPrivKey(rsa_priv, base_name, sn);
            RSA_free(rsa_priv);

            if (result != CERT_OK)
            {
                goto cleanup;
            }
        }

        rewind(der_file);
        rsa_pub = d2i_RSA_PUBKEY_fp(der_file, NULL);

        if (rsa_pub != NULL)
        {
            DPRINTF("%s RSA public key read \n", __FUNCTION__);
            result = installRSAPubKey(rsa_pub, base_name, sn);
            RSA_free(rsa_pub);

            if (result != CERT_OK)
            {
                goto cleanup;
            }
        }

        rewind(der_file);
        ec_priv_key = d2i_ECPrivateKey_fp(der_file, NULL);

        if (ec_priv_key != NULL)
        {
            DPRINTF("%s ECDSA private key read \n", __FUNCTION__);
            result = installECPrivKey(ec_priv_key, base_name, sn);
            EC_KEY_free(ec_priv_key);

            if (result != CERT_OK)
            {
                goto cleanup;
            }
        }

        /* Don't need to write EC pub key, just cert */

        rewind(der_file);
        crl = d2i_X509_CRL_fp(der_file, NULL);

        if (crl != NULL)
        {
            DPRINTF("%s crl read 0x%lX\n", __FUNCTION__, X509_NAME_hash(X509_CRL_get_issuer(crl)));
            result = installX509CRL(crl, base_name, sn);
            X509_CRL_free(crl);
        }

        /* Set the output SN if everything went OK */
        *o_sn = sn;

cleanup:
        free(base_name);
    }

    fclose(der_file);

    return result;
}

static CertReturnCode pemToFile(const char *cert_path, const char *dst_path, CertPassCallback pcbk, void *pwd_ctxt, int *o_sn)
{
    int sn;
    FILE *pem_file;
    char *base_name;
    CertReturnCode result;

    result = getNextSerialNumber(&sn);

    if (result != CERT_OK)
    {
        return result;
    }

    pem_file = fopen(pCertPath, "r");

    if (pem_file == NULL)
    {
        DPRINTF("%s file access failure \n", __FUNCTION__);
        return CERT_FILE_ACCESS_FAILURE;
    }

    base_name = fileBaseName(pCertPath);

    if (base_name == NULL)
    {
        result = CERT_GENERAL_FAILURE;
    }
    else
    {
        X509 *cert;
        DSA *dsa_priv, *dsa_pub;
        RSA *rsa_priv, *rsa_pub;
        EC_KEY *ec_priv_key;
        X509_CRL *crl;
        struct cm_pem_cb_data pcs =
        {
            .cb = cb,
            .ctx = pwd_ctxt,
            .pwd_len = -1,
            .cached_pwd = NULL
        };

        cert = PEM_read_X509(pem_file, NULL, pem_callback, &pcs);

        if (cert == NULL)
        {
            DPRINTF("%s no cert \n", __FUNCTION__);
            result = CERT_BAD_CERTIFICATE;
            goto cleanup;
        }

        result = installX509Cert(cert, base_name, &sn);
        X509_free(cert);

        /* If a duplicate certificate is found, just skip installation */
        /* FIXME: This will bite us if the installation of keys failed
         * and we retry installation becuase it'd simply skip over */
        if (result != CERT_OK)
        {
            if (result == CERT_DUPLICATE)
            {
                *o_sn = sn;
                result = CERT_OK;
            }

            goto cleanup;
        }

        rewind(pem_file);
        dsa_priv = PEM_read_DSAPrivateKey(pem_file, NULL, pem_callback, &pcs);

        if (dsa_priv != NULL)
        {
            DPRINTF("%s DSA private key read \n", __FUNCTION__);

            result = installDSAPrivKey(dsa_priv, base_name, sn);
            DSA_free(dsa_priv);

            if (result != CERT_OK)
            {
                goto cleanup;
            }
        }

        rewind(pem_file);
        dsa_pub = PEM_read_DSA_PUBKEY(pem_file, NULL, pem_callback, &pcs);

        if (dsa_pub != NULL)
        {
            DPRINTF("%s DSA pubkey read\n", __FUNCTION__);

            result = installDSAPubKey(dsa_pub, base_name, sn);
            DSA_free(dsa_pub);

            if (result != CERT_OK)
            {
                goto cleanup;
            }
        }

        rewind(pem_file);
        rsa_priv = PEM_read_RSAPrivateKey(pem_file, NULL, pem_callback, &pcs);

        if (rsa_priv != NULL)
        {
            DPRINTF("%s RSA private key read \n", __FUNCTION__);
            result = installRSAPrivKey(rsa_priv, base_name, sn);
            RSA_free(rsa_priv);

            if (result != CERT_OK)
            {
                goto cleanup;
            }
        }

        rewind(pem_file);
        rsa_pub = PEM_read_RSA_PUBKEY(pem_file, NULL, pem_callback, &pcs);

        if (rsa_pub != NULL)
        {
            DPRINTF("%s RSA public key read \n", __FUNCTION__);
            result = installRSAPubKey(rsa_pub, base_name, sn);
            RSA_free(rsa_pub);

            if (result != CERT_OK)
            {
                goto cleanup;
            }
        }

        rewind(pem_file);
        ec_priv_key = PEM_read_ECPrivateKey(pem_file, NULL, pem_callback, &pcs);

        if (ec_priv_key != NULL)
        {
            DPRINTF("%s ECDSA private key read \n", __FUNCTION__);
            result = installECPrivKey(ec_priv_key, base_name, sn);
            EC_KEY_free(ec_priv_key);

            if (result != CERT_OK)
            {
                goto cleanup;
            }
        }

        /* Don't need to write EC pub key, just cert */

        rewind(pem_file);
        crl = PEM_read_X509_CRL(pem_file, NULL, NULL, NULL);

        if (crl != NULL)
        {
            DPRINTF("%s crl read 0x%lX\n", __FUNCTION__, X509_NAME_hash(X509_CRL_get_issuer(crl)));
            result = installX509CRL(crl, base_name, sn);
            X509_CRL_free(crl);
        }

        /* Set the output SN if everything went OK */
        *o_sn = sn;

cleanup:
        /* It sure looks weird that we need to cleanup the callback's
         * allocation, but this code smell was probably deemed necessary
         * by whoever wrote the "optimization" over at Palm */
        if (pcs.cached_pwd != NULL)
        {
            free(pcs.cached_pwd);
        }

        free(base_name);
    }

    fclose(pem_file);

    return result;
}

static int pem_callback(char *o_buf, int len, int rwflag, void *cb_arg)
{
    struct cm_pem_cb_data *pcs = (struct cm_pem_cb_data *)cb_arg;

    /* This appears to be an optimization of some sort in order to
     * avoid calling the callback every time a password is required
     * (thus avoiding heavy operations that the callback might need
     *  to do -- such as accessing a DB to get the password, etc.) */

    if ((cached_pwd != NULL) && (len >= pcs->pwd_len))
    {
        DPRINTF(stdout, "%s have cache %s \n", __FUNCTION__, pcs->pwdCache);
        memcpy(o_buf, pcs->cached_pwd, pcs->pwd_len);
    }
    else if (pcs->cb != NULL)
    {
        DPRINTF("%s password %s %d \n", __FUNCTION__, (char*)pcs->ctxt, result);
        pcs->pwd_len = (*pcs->cb)(o_buf, len, pcs->ctxt);

        if (pcs->pwd_len > 0)
        {
            pcs->cached_pwd = (char *)malloc(pcs->pwd_len);

            if (pcs->cached_pwd != NULL)
            {
                memcpy(pcs->cached_pwd, o_buf, pcs->pwd_len);
            }
        }
    }

    return pcs->pwd_len;
}

static CertReturnCode getNextSerialNumber(int *o_sn)
{
    int sn = 0;
    char serial_file[MAX_CERT_PATH];
    CertReturnCode_t result;

    if (o_sn == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    /* lock the database              */
    if (CertLockFile(CERT_FILELOCK_DATABASE) != CERT_OK)
    {
        return CERT_GENERAL_FAILURE;
    }

    /* Get the current serial number  */
    result = CertCfgGetObjectStrValue(CERTCFG_CERT_SERIAL_NAME, serial_file, sizeof(serial_file));

    if (result == CERT_OK)
    {
        sn = CertGetSerialNumberInc(serial_file, 1);

        if (sn != 0)
        {
            *o_sn = sn;
        }
        else
        {
            result = CERT_SERIAL_NUMBER_UNAVAILABLE;
        }
    }

    CertUnlockFile(CERT_FILELOCK_DATABASE);

    return result;
}

static CertReturnCode checkIfCertsDiffer(const char *path1, const char *path2)
{
    X509 *cert1, *cert2;
    FILE *file1, *file2;
    CertReturnCode result = CERT_GENERAL_FAILURE;

    if ((path1 == NULL) || (path2 == NULL))
    {
        return CERT_INVALID_ARG;
    }

    file1 = fopen(path1, "r");

    if (file1 == NULL)
    {
        goto done;
    }

    file2 = fopen(path2, "r");

    if (file2 == NULL)
    {
        goto close_file1;
    }

    cert1 = PEM_read_X509(file1, NULL, NULL, NULL);

    if (cert1 == NULL)
    {
        goto cleanup_files;
    }

    cert2 = PEM_read_X509(file2, NULL, NULL, NULL);

    if (cert2 == NULL)
    {
        goto cleanup_cert1;
    }

    DPRINTF("%s look for dup %s %s\n", __FUNCTION__, path1, path2);

    if (X509_cmp(cert1, cert2) != 0)
    {
        result = CERT_OK;
    }
    else
    {
        result = CERT_DUPLICATE;
        DPRINTF("%s duplicate found \n", __FUNCTION__);
    }

cleanup_certs:
    X509_free(cert2);

cleanup_cert1:
    X509_free(cert1);

cleanup_files:
    fclose(file2);

close_file1:
    fclose(file1);

done:
    return result;
}

static CertReturnCode removeBrokenLinkFiles(void)
{
    char cert_path[MAX_CERT_PATH];

    if ((CertCfgGetObjectStrValue(CERTCFG_CERT_DIR, cert_path, sizeof(cert_path)) != CERT_OK) ||
        (cert_path[0] == '\0'))
    {
        DPRRINTF("CertInitCertMgr unable to read cert path");
        strcpy(cert_path, "/var/ssl/certs");
    }

    if (cmutils_rmdeadlinks(cert_path, 1) != 0)
    {
        return CERT_GENERAL_FAILURE;
    }
    // XXX also remove links from cache dir

    return CERT_OK;
}

/*
* ericm: remove a single link to a cert
*/
static CertReturnCode removeCertLink(unsigned long hash, const char *fullpath, CertCfgProperty basedir)
{
    CertReturnCode result;
    char dir[MAX_CERT_PATH];
    char filename[MAX_CERT_PATH];
    int pos, ext_ctr = 0, left_space;

    result = CertCfgGetObjectStrValue(basedir, dir, sizeof(dir));

    if (result != CERT_OK)
    {
        return result;
    }

    /* We can't work with empty value */
    if (dir[0] == '\0')
    {
        return CERT_GENERAL_FAILURE;
    }

    pos = snprintf(filename, sizeof(filename), "%s/%08lx.", dir, hash);

    if (pos >= filename)
    {
        CERT_BUFFER_LIMIT_EXCEEDED;
    }

    left_space = sizeof(filename) - pos;

    /* Look for the link to the cert */
    /* stop after the first one we find as there should be only one */
    do /* while (ext_ctr < CERT_MAX_HASHED_FILES) */
    {
        struct stat statbuf;

        if (snprintf(filename + pos, left_space, "%d", ext_ctr) >= left_space)
        {
            return CERT_BUFFER_LIMIT_EXCEEDED;
        }

        if ((lstat(filename,&statbuf) == 0) && (S_ISLNK(statbuf.st_mode)))
        {
            char linkpath[MAX_CERT_PATH];

            /* check that the link points to our cert */
            int len = readlink(filename, linkpath, sizeof(linkpath));

            if (len < 0)
            {
                return CERT_GENERAL_FAILURE;
            }

            /* XXX: This is unsafe. We might remove another link that only
             * happen to succeed in path comparison because its path begins
             * with the same characters, though I'm not sure if we should
             * just fail the removal in that case */

            /* No need to NUL terminate. We only compare the first
             * MAX_CERT_PATH bytes at most */
            if ((strncmp(fullpath, linkpath, MAX_CERT_PATH) == 0) &&
                (unlink(filename) == 0))
            {
                return CERT_OK;
            }
        }
    } while (ext_ctr < CERT_MAX_HASHED_FILES);

    return CERT_GENERAL_FAILURE;
}

/*
 * ericm: remove the links to a cert
 */
static CertReturnCode removeAllCertLinks(const char *fullpath)
{
    X509 *cert;
    CertReturnCode result;

    result = CertPemToX509(fullpath, &cert);

    if ((result == CERT_OK) && (cert != NULL))
    {
        CertReturnCode snd_result;
        unsigned long hash = X509_subject_name_hash(cert);

        /* delete links in both dirs */
        result = removeCertLink(hash, fullpath, CERTCFG_AUTH_CERT_DIR);

        /* try to delete the other link even if the first failed */
        snd_result = removeCertLink(hash, fullpath, CERTCFG_TRUSTED_CA_DIR);

        /* Pick the result of the second link removal if it failed */
        if (snd_result != CERT_OK)
        {
            result = snd_result;
        }

        X509_free(cert);
    }

    return result;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: removeCert                                                  */
/*       Remove a certificate and its hash links from a certificate store    */
/* INPUT:                                                                    */
/*       cert: the name of the certificate                                   */
/*       dirDefType: the default type of certificate which can be            */
/*                   CERT_SYSTEM_DEFAULT_DIR: the system-wide set of defaults*/
/*                   CERT_USER_DEFAULT_DIR: User level set of defaults       */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_OK: the certificate was successfully removed                   */
/*       CERT_PATH_LIMIT_EXCEEDED: not enough buffer allocated for the       */
/*                directory path                                             */
/*       CERT_LINK_ERR: Linking itself was not successfull (check errno)     */
/* NOTES:                                                                    */
/*                                                                           */
/*--***********************************************************************--*/

static CertReturnCode removeCert(int sn, const char *path, const char *prefix, const char *ext, int *o_err)
{
    int counter;
    char full_path[MAX_CERT_PATH];

    DSYSLOG(LOG_INFO, "func: %s, prefix: %s", __FUNCTION__,prefix);

    if (path == NULL)
    {
        return CERT_UNDEFINED_DESTINATION;
    }

    if ((prefix == NULL) || (ext == NULL))
    {
        CERT_INVALID_ARG;
    }

    if (o_err == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    /* for pfx certs(eg: E.pfx) delete files of the form caE_0.pem, caE_1.pem */
    if (prefix[0] == '\0')
    {
        prefix = "ca";
    }

    if (snprintf(full_path, sizeof(full_path),
                 "%s/%s%X.%s", path, prefix, sn, ext) >= sizeof(full_path))
    {
        return CERT_PATH_LIMIT_EXCEEDED;
    }

    for (counter = 0; counter < CERT_MAX_HASHED_FILES; ++counter)
    {
        if (!cmutils_exists(full_path))
        {
            DPRINTF("file not found - %s - %s\n", __FUNCTION__, full_path);
            break;
        }

        /* don't pass along return code from removeAllCertLinks
        ** since not all "certs" we remove here will have links
        */
        removeAllCertLinks(full_path);

        if (unlink(full_path) != 0)
        {
            DPRINTF("unlink failed - %s - %s\n", __FUNCTION__, full_path);
            *err = errno;
            PRINT_ERROR2(strerror(errno), errno);

            return CERT_LINK_ERR;
        }

        if (snprintf(full_path, sizeof(full_path),
                     "%s/%s%s_%d.%s", path, prefix, certStr, counter, ext) >= sizeof(full_path))
        {
            return CERT_BUFFER_LIMIT_EXCEEDED;
        }
    }

    /* Return error if we broke out because no file has been found */
    if (counter <= 0)
    {
        return CERT_LINK_ERR;
    }

    /* No error */
    o_err = 0;

    return CERT_OK;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: getCertLinkPath                                              */
/*       Make a file name from the first 4 bytes of the file's hash          */
/* INPUT:                                                                    */
/*       buf: */
/*       bufSize: the size of the buffer                                     */
/*       hash: Really just an arbitrary number that happens to be the hash of*/
/*             the file of interest                                          */
/*       infile: The file of interest                                        */
/*       basedir: The base location                                          */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/*       CERT_TOO_MANY_HASH_FILES: We've exceeded the number of files whose  */
/*           base name is the same.                                          */
/* NOTES:                                                                    */
/*       1) The file includes the default directory path for authorized certs*/
/*       2) The same hash means that the file has the same subject name.     */
/*          This happens with different certificates with the same subject or*/
/*          a duplicate certificate.                                         */
/*                                                                           */
/*--***********************************************************************--*/

static CertReturnCode getCertLinkPath(char *o_buf, int len, unsigned long hash, const char *infile, CertCfgProperty basedir)
{
    int pos, ext_ctr = 0, space_left;
    CertReturnCode result;
    char filename[MAX_CERT_PATH];
    char dir[MAX_CERT_PATH];

    if (o_buf == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    if (len <= 0)
    {
        return CERT_INSUFFICIENT_BUFFER_SPACE;
    }

    result = CertCfgGetObjectStrValue(basedir, dir, sizeof(dir));

    /* CERTCFG_AUTH_CERT_DIR, */
    if (result != CERT_OK)
    {
        return result;
    }

    if (dir[0] == '\0')
    {
        return CERT_UNDEFINED_DESTINATION;
    }

    pos = snprintf(filename, sizeof(filename), "%s/%08lx.", dir, hash);

    if (pos >= sizeof(filename))
    {
        return CERT_INSUFFICIENT_BUFFER_SPACE;
    }

    space_left = sizeof(filename) - pos;

    /* Let's check to see if we've already installed this certificate */
    for (ext_ctr = 0; ext_ctr < CERT_MAX_HASHED_FILES; ++ext_ctr)
    {
        if (snprintf(filename + pos, space_left, "%d", ext_ctr) >= space_left)
        {
            return CERT_INSUFFICIENT_BUFFER_SPACE;
        }

        if (!cmutils_exists(filename))
        {
            if (snprintf(o_buf, len, "%s", filename) >= len)
            {
                return CERT_INSUFFICIENT_BUFFER_SPACE;
            }

            return CERT_OK;
        }

        /* the same name, is it the same inside ? */
        if (checkIfCertsDiffer(filename, infile) == CERT_DUPLICATE)
        {
            return CERT_DUPLICATE;
        }
    }

    return CERT_TOO_MANY_HASHED_FILES;

    return result;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: getFileType                                                  */
/* INPUT:                                                                    */
/*       file: the file name                                                 */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       The file type based on its extension                                */
/* NOTES:                                                                    */
/*       1) The list of supported file extensions is kept in cert_mgr.h      */
/*                                                                           */
/*--***********************************************************************--*/

static CertFileExt getFileType(const char *file)
{
    static const char *ext_a[CERT_MAX_FILE_EXTENSIONS] =
    {
#       define CM_VAL(ext, str) str
        CERTMGR_FILE_EXTS
#       undef CM_VAL
    };
    int type;
    char *extn;


    if (file == NULL)
    {
        goto error;
    }

    extn = strrchr(file, '.');

    if (extn == NULL)
    {
        goto error;
    }

    /* Skip the dot */
    ++extn;

    /* start from 1 because 0 is "UNKNOWN"  */
    for (type = CERT_UNKNOWN_FILE + 1; type < CERT_MAX_FILE_EXTENSIONS; ++type)
    {
        if (strcasecmp(ext_a[type], extn) == 0)
        {
            return type;
        }
    }

error:
    return CERT_UNKNOWN_FILE;
}

static CertReturnCode installCACerts(STACK_OF(X509) *ca, const char *base_name, int sn)
{
    X509 *x509;
    int item_idx;
    CertReturnCode result;

    if (ca == NULL)
    {
        return CERT_BAD_CERTIFICATE;
    }

    if (sn == 0)
    {
        return CERT_INVALID_ARG;
    }

    /* this is the list of CA certs for verification */
    /* the file is the hased name of the certificate subject */
    for (item_idx = 1, result = CERT_OK; ((x509 = sk_X509_pop(ca)) != NULL) && (result == CERT_OK); ++item_idx)
    {
        char *ca_path = getPathBySerialCtr(base_name, CERT_DIR_CERTIFICATES, CERT_OBJECT_C_AUTHORIZATION, sn, item_idx);

        if (ca_path != NULL)
        {
            FILE *ca_cert_file = open(ca_path, "w");

            if (ca_cert_file == NULL)
            {
                DPRINTF("cert_mgr: %s\n", strerror(errno));
                result = CERT_FILE_ACCESS_FAILURE;
            }
            else
            {
                if (!PEM_write_X509(ca_cert_file, x509))
                {
                    result = CERT_GENERAL_FAILURE;
                }

                fclose(ca_cert_file);

                DPRINTF("%s ca install %s\n", __FUNCTION__, ca_path);
                DPRINTF("%s ca hash 0x%lx\n", __FUNCTION__, X509_subject_name_hash(x509));

                if (result == CERT_OK)
                {
                    char filename[MAX_CERT_PATH];

                    result = getCertLinkPath(filename, sizeof(filename),
                                             X509_subject_name_hash(x509),
                                             ca_path, CERTCFG_TRUSTED_CA_DIR);

                    if ((result == CERT_OK) && (symlink(ca_path, filename) == -1))
                    {
                        DPRINTF("ERROR %d creating symlink '%s' -> '%s'\n", errno, ca_path, filename);
                        result = CERT_LINK_ERR;
                    }
                }
            }

            free(ca_path);
        }

        X509_free(x509);
    }

    return result;
}

static CertReturnCode installX509Cert(const X509 *cert, const char *base_name, int *io_sn)
{
    int dup_sn;
    char *cert_path;
    CertReturnCode result = CERT_GENERAL_FAILURE;

    if (cert == NULL)
    {
        return CERT_BAD_CERTIFICATE;
    }

    if ((io_sn == NULL) || (*io_sn == 0))
    {
        return CERT_INVALID_ARG;
    }

    dup_sn = getCertSerialFromLocalStore(cert);

    if (dup_sn != 0)
    {
        /* Already installed. Skip */
        *io_sn = dup_sn;
        DPRINTF("%s duplicate cert found %d\n", __FUNCTION__, dup_sn);

        return CERT_DUPLICATE;
    }

    cert_path = getPathBySerialCtr(base_name, CERT_DIR_CERTIFICATES, CERT_OBJECT_CERTIFICATE, *io_sn, count);

    if (cert_path != NULL)
    {
        FILE *cert_file = fopen(cert_path, "w");

        if (cert_file == NULL)
        {
            result = CERT_OPEN_FILE_FAILED;
        }
        else
        {
            if (!PEM_write_X509(out_cert_file, cert))
            {
                result = CERT_GENERAL_FAILURE;
            }

            fclose(cert_file);

            if (result == CERT_OK)
            {
                result = CertCreateDatabaseItem(cert, base_name, *io_sn, CERT_STATUS_UNKNOWN);
            }
        }

        free(cert_path);
    }

    return result;
}

static CertReturnCode installDSAPrivKey(const DSA *dsa_priv, const char *base_name, int sn)
{
    char *dsa_dest_priv_path;
    CertReturnCode result = CERT_GENERAL_FAILURE;

    if ((dsa_priv == NULL) || (sn == 0))
    {
        return CERT_INVALID_ARG;
    }

    dsa_dest_priv_path = getPathBySerial(base_name, CERT_DIR_PRIVATE_KEY, CERT_OBJECT_DSA_PRIVATE_KEY, sn);

    if (dsa_dest_priv_path != NULL)
    {
        FILE *dsa_priv_file = fopen(dsa_dest_priv_path, "w");

        if (dsa_priv_file == NULL)
        {
            DPRINTF("%s unable to write DSA private key\n", __FUNCTION__);
            result = CERT_OPEN_FILE_FAILURE;
        }
        else
        {
            if (PEM_write_DSAPrivateKey(dsa_priv_file, dsa_priv, NULL, NULL, 0, 0, NULL))
            {
                result = CERT_OK;
            }

            fclose(dsa_priv_file);
        }

        free(dsa_dest_priv_path);
    }

    return result;
}

static CertReturnCode installDSAPubKey(const DSA *dsa_pub, const char *base_name, int sn)
{
    char *dsa_dest_pub_path;
    CertReturnCode result = CERT_GENERAL_FAILURE;

    if ((dsa_pub == NULL) || (sn == 0))
    {
        return CERT_INVALID_ARG;
    }

    dsa_dest_pub_path = getPathBySerial(base_name, CERT_DIR_PUBLIC_KEY, CERT_OBJECT_DSA_PUBLIC_KEY, sn);

    if (dsa_dest_pub_path != NULL)
    {
        FILE *dsa_pub_file = fopen(dsa_dest_pub_path, "w");

        if (dsa_pub_file == NULL)
        {
            DPRINTF("%s unable to write DSA pub key\n", __FUNCTION__);
            result = CERT_OPEN_FILE_FAILURE;
        }
        else
        {
            if (PEM_write_DSA_PUBKEY(dsa_pub_file, dsa_pub))
            {
                result = CERT_OK;
            }

            fclose(dsa_pub_file);
        }

        free(dsa_dest_pub_path);
    }

    return result;
}

static CertReturnCode installRSAPrivKey(const RSA *rsa_priv, const char *base_name, int sn)
{
    char *rsa_dest_priv_path;
    CertReturnCode result = CERT_GENERAL_FAILURE;

    if ((rsa_priv == NULL) || (sn == 0))
    {
        return CERT_INVALID_ARG;
    }

    rsa_dest_priv_path = getPathBySerial(base_name, CERT_DIR_PRIVATE_KEY, CERT_OBJECT_RSA_PRIVATE_KEY, sn);

    if (rsa_dest_priv_path != NULL)
    {
        FILE *rsa_priv_file = fopen(rsa_dest_priv_path, "w");

        if (rsa_priv_file == NULL)
        {
            DPRINTF("%s unable to write RSA private key\n", __FUNCTION__);
            result = CERT_OPEN_FILE_FAILURE;
        }
        else
        {
            if (PEM_write_RSAPrivateKey(rsa_priv_file, rsa_priv, NULL, NULL, 0, 0, NULL))
            {
                result = CERT_OK;
            }

            fclose(rsa_priv_file);
        }

        free(rsa_dest_priv_path);
    }

    return result;
}

static CertReturnCode installRSAPubKey(const RSA *rsa_pub, const char *base_name, int sn)
{
    char *rsa_dest_pub_path;
    CertReturnCode result = CERT_GENERAL_FAILURE;

    if ((rsa_pub == NULL) || (sn == 0))
    {
        return CERT_INVALID_ARG;
    }

    rsa_dest_pub_path = getPathBySerial(base_name, CERT_DIR_PUBLIC_KEY, CERT_OBJECT_RSA_PUBLIC_KEY, sn);

    if (rsa_dest_pub_path != NULL)
    {
        FILE *rsa_pub_file = fopen(rsa_dest_pub_path, "w");

        if (rsa_pub_file == NULL)
        {
            DPRINTF("%s unable to write RSA pub key\n", __FUNCTION__);
            result = CERT_OPEN_FILE_FAILURE;
        }
        else
        {
            if (PEM_write_RSAPublicKey(rsa_pub_file, rsa_pub))
            {
                result = CERT_OK;
            }

            fclose(rsa_pub_file);
        }

        free(rsa_dest_pub_path);
    }

    return result;
}

static CertReturnCode installECPrivKey(const EC_KEY *ec_priv_key, const char *base_name, int sn)
{
    /* ECDSA */
    /* NOTE: we append the private key to the cert because
    ** WAPI expects that.  The real (secure) way to do this
    ** is to store the key in keymanager
    */
    char *ec_dest_priv_path;
    CertReturnCode result = CERT_GENERAL_FAILURE;

    if ((ec_priv_key == NULL) || (sn == 0))
    {
        return CERT_INVALID_ARG;
    }

    ec_dest_priv_path = getPathBySerial(base_name, CERT_DIR_CERTIFICATES, CERT_OBJECT_CERTIFICATE, sn);

    if (ec_dest_priv_path != NULL)
    {
        FILE *ec_priv_file = fopen(ec_dest_priv_path, "a");

        if (ec_priv_file == NULL)
        {
            DPRINTF("%s unable to write ECDSA private key\n", __FUNCTION__);
            result = CERT_OPEN_FILE_FAILURE;
        }
        else
        {
            if (PEM_write_ECPrivateKey(ec_priv_file, ec_priv_key, NULL, NULL, 0, 0, NULL))
            {
                result = CERT_OK;
            }

            fclose(ec_priv_file);
        }

        free(ec_dest_priv_path);
    }

    return result;
}

static CertReturnCode installX509CRL(const X509_CRL *crl, const char *base_name, int sn)
{
    char *crl_dest_path;
    CertReturnCode result = CERT_GENERAL_FAILURE;

    if ((crl == NULL) || (sn == 0))
    {
        return CERT_INVALID_ARG;
    }

    crl_dest_path = getPathBySerialCtr(base_name, CERT_DIR_CRL, CERT_OBJECT_CRL, sn);

    if (crl_dest_path != NULL)
    {
        FILE *crl_file = fopen(crl_dest_path, "w");

        if (crl_file == NULL)
        {
            DPRINTF("%s unable to write CRL\n", __FUNCTION__);
            result = CERT_OPEN_FILE_FAILURE;
        }
        else
        {
            if (PEM_write_X509_CRL(crl_file, crl))
            {
                result = CERT_OK;
            }

            fclose(crl_file);

            if (result == CERT_OK)
            {
                size_t crl_path_len = strlen(crl_dest_path);
                /* CRL path + ".gz" + NUL character */
                char *gzipped_path = (char *)malloc(crl_path_len + 4);

                if (gzipped_path == NULL)
                {
                    result = CERT_MEMORY_ERROR;
                }
                else
                {
                    sprintf(gzipped_path, "%s.gz", crl_dest_path);

                    if (cmutils_gzip(crl_dest_path, gzipped_path) != 0)
                    {
                        result = CERT_GENERAL_FAILURE;
                    }

                    free(gzipped_path);
                }
            }
        }

        free(crl_dest_path);
    }

    return result;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: makeCertPathFromSerial                                             */
/* INPUT:                                                                    */
/*       sn: the ID of the certificate                                       */
/*       len:  the length of the input buffer                                */
/* OUTPUT:                                                                   */
/*       o_path: The path for the certificate based on the configuration     */
/* RETURN:                                                                   */
/*       CERT_OK                                                             */
/*       CERT_BUFFER_LIMIT_EXCEEDED: the input buffer is insufficient for the*/
/*           full path                                                       */
/* NOTES:                                                                    */
/*       1) The list of supported file extensions is kept in cert_mgr.h      */
/*                                                                           */
/*--***********************************************************************--*/

static CertReturnCode makeCertPathFromSerial(int sn, char *o_path, int len)
{
    char dir[MAX_CERT_PATH];
    CertReturnCode result;

    if (o_path == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    if (len <= 0)
    {
        CERT_INSUFFICIENT_BUFFER_SPACE;
    }

    result = CertCfgGetObjectStrValue(CERTCFG_CERT_DIR, dir, sizeof(dir));

    if ((result == CERT_OK) &&
        (snprintf(o_path, len, "%s/%X.pem", dir, sn) >= len))
    {
        result = CERT_BUFFER_LIMIT_EXCEEDED;
    }

    return result;
}

static CertReturnCode validateCertPath(const char *path, int sn, CertPkgType cert_type, CertMgrError *o_err)
{
    X509 *cert;
    CertReturnCode result;

    if (path == NULL)
    {
        return CERT_INVALID_ARG;
    }

    if (o_err == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    *o_err = CERT_CM_ALL_OK;

    switch (cert_type)
    {
    case CERTTYPE_PEM:
        result = CertPemToX509(path, &cert);
        break;

    case CERTTYPE_DER:
        result = derToX509(path, &cert);
        break;

    default:
        return CERT_UNSUPPORTED_CERT_TYPE;
    }

    if (result == CERT_OK)
    {
        /* If we get here then we know that the type has been found
         * we use result to signal that the type has been found, so
         * use a local result to carry forward errors within the
         * certificate */
        int status = 0;

        /* FIXME: This code does the wrong thing and tries to cover it up by
         * casting a string to an int. We should implement a CertGetDatabaseItemInfo
         * function in cert_db if we want this code to do something useful */
        if ((CertGetDatabaseInfo(CERT_DATABASE_ITEM_STATUS, &status) == CERT_OK) &&
            (status != CERT_STATUS_TRUSTED_PEER))
        {
            /* We trust the certificate per user's blessing, do not invalidate.*/
            /* TODO: return that the cert is valid. */
            CertReturnCode cert_result = checkCertDates(cert);

            if (cert_result != CERT_OK)
            {
                switch (cert_result)
                {
                case CERT_DATE_EXPIRED:
                    *o_err |= CERT_CM_DATE_EXPIRED;
                    result = CertUpdateDatabaseItem(sn,
                                                    CERT_DATABASE_ITEM_STATUS,
                                                    CertGetStatusString(CERT_STATUS_EXPIRED));
                    break;

                case CERT_DATE_PENDING:
                    *o_err |= CERT_CM_DATE_PENDING;
                    result = CertUpdateDatabaseItem(sn,
                                                    CERT_DATABASE_ITEM_STATUS,
                                                    CertGetStatusString(CERT_STATUS_SUSPENDED));
                    break;

                default:
                    break;
                }
            }
        }

        if (result == CERT_OK)
        {
            char ca_path[MAX_CERT_PATH];
            const char *ca_path_ptr = NULL;

            if ((CertCfgGetObjectStrValue(CERTCFG_AUTH_CERT_DIR, ca_path, sizeof(ca_path)) == CERT_OK) &&
                (ca_path[0] != '\0'))
            {
                ca_path_ptr = ca_path;
            }

            result = checkCert(cert, NULL, ca_path_ptr);
        }

        X509_free(cert);
    }

    return result;
}


/*--**************************************************************************
 * helper functions
 **************************************************************************--*/

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: seedSSLPrng                                                       */
/*       Seed the pseudo-random number generator                             */
/* INPUT:                                                                    */
/*       file: the file name                                                 */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*                                                                           */
/* NOTES:                                                                    */
/*                                                                           */
/*--***********************************************************************--*/

static int getCertSerialFromLocalStore(const X509 *cert)
{
    if (cert != NULL)
    {
        int items;

        //  SSL_library_init();
        //  SSL_load_error_strings();
        if (CertGetDatabaseInfo(CERT_DATABASE_SIZE, &items) == CERT_OK)
        {
            int item_idx;

            for (item_idx = 0; item_idx < items; ++item_idx)
            {
                char serial_str[128];

                if ((CertGetDatabaseStrValue(item_idx, CERT_DATABASE_ITEM_SERIAL, serial_str, sizeof(serial_str)) == CERT_OK) &&
                    (serial_str[0] != '\0'))
                {
                    char *end_ptr;
                    char cert_path[MAX_CERT_PATH];
                    int serial = strtol(serial_str, &end_ptr, 16);

                    if (*end_ptr == '\0')
                    {
                        if (makeCertPathFromSerial(serial, cert_path, sizeof(cert_path)) == CERT_OK)
                        {
                            X509 *candidate_cert;

                            if ((CertPemToX509(cert_path, &candidate_cert) == CERT_OK) &&
                                (candidate_cert != NULL) &&
                                (X509_cmp(candidate_cert, cert) == 0))
                            {
                                return serial;
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}

static CertReturnCode seedSSLPrng(void)
{
    /* Warning: /dev/random blocks if not enough entropy is available
       (which is almost always the case).  If this is happening, try
       /dev/urandom, or save seeds across boots. */
    if (RAND_load_file("/dev/urandom", 1024) == 1024)
    {
        return CERT_OK;
    }

    return CERT_GENERAL_FAILURE;
}

#ifdef __cplusplus
}
#endif
