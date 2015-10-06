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
 * @file cert_cfg.h
 *
 * @brief Certificate Manager configuration file routines
 *
 * @ingroup CERTMgrLib
 *
 */

#ifndef __CERT_CFG_H__
#define __CERT_CFG_H__

#include "cert_mgr.h"

/**
 * Defines the CertCfgProperty properties and their configuration strings
 */
#define CERTCFG_PROPS \
    /*!< File with the ssl configuration */ \
    CM_VAL(CERTCFG_CONFIG_FILE, CERT_DEF_CONF_FILE), \
    /*!< Configuration with the config file */ \
    CM_VAL(CERTCFG_CONFIG_NAME, "default_ca"), \
    /*!< directory root for the cert info */ \
    CM_VAL(CERTCFG_ROOT_DIR, "dir"), \
    /*!< Where certificates are kept */ \
    CM_VAL(CERTCFG_CERT_DIR, "certs"), \
    /*!< A personal ceritificate [optional] */ \
    CM_VAL(CERTCFG_CERTIFICATE, "certificate"), \
    /*!< The location for private keys [def == private] */ \
    CM_VAL(CERTCFG_PRIVATE_KEY_DIR, "private_dir"), \
    /*!< A personal private key [optional] */ \
    CM_VAL(CERTCFG_PRIVATE_KEY, "private_key"), \
     /*!< lists the certificates [def == index.txt] */ \
    CM_VAL(CERTCFG_CERT_DATABASE, "database"), \
     /*!< serial number file */ \
    CM_VAL(CERTCFG_CERT_SERIAL_NAME, "serial"), \
    /*!< location for certificates that have been authourized */ \
    CM_VAL(CERTCFG_AUTH_CERT_DIR, "authorized"), \
     /*!< directory for public keys */ \
    CM_VAL(CERTCFG_PUBLIC_KEY_DIR, "public_dir"), \
    /*!< directory for Certificate Revocation Lists */ \
    CM_VAL(CERTCFG_CRL_DIR, "crl_dir"), \
    /*!< location for uninstalled packages (pem, der, pk12) */ \
    CM_VAL(CERTCFG_PACKAGE_DIR, "package_dir"), \
    /*!< serial number for certificate creation */ \
    CM_VAL(CERTCFG_CERT_SERIAL, "authorized"), \
    /*!< trusted CA directory */ \
    CM_VAL(CERTCFG_TRUSTED_CA_DIR, "trusted_ca_dir")

/*!
 * The various labels of interest within the configuration file.
 * cert_cfg.c has the definitive values for them in propertyNameList[]
 */
typedef enum
{
#   define CM_VAL(prop, str) prop
    CERTCFG_PROPS,
#   undef CM_VAL
    CERTCFG_MAX_PROPERTY
} CertCfgProperty;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Open a configuration file
 *
 * The named configuration file is opened and the named configuration
 * is used to set the system up.
 * If the value of cfg_file == NULL, the following are checked in order:
 *   OPENSSL_CONF environmental variable or CERT_DEF_CONF_FILE
 *   defined in cert_mgr.h.
 * We expect the repository directory to be labeled "dir" in the
 *          config file
 *
 * @param[in] cfg_file The name of the configuration file
 * @param[in] cfg_name The name of the configuration
 *
 * @return CERT_OK:
 * @return CERT_PATH_LIMIT_EXCEEDED: The path string is too long
 * @return CERT_OPEN_FILE_FAILED: The config file couldn't be opened
 * @return CERT_ILLFORMED_CONFIG_FILE: There was some problem in the config
 * @return CERT_CONFIG_UNAVAILABLE: The named configuration not available
 * @return CERT_UNDEFINED_DESTINATION: The certificate root dir not available
 */
extern CertReturnCode CertCfgOpenConfigFile(const char *cfg_file, const char *cfg_name);

/**
 * @brief Get the value of a property in the configuration.
 *
 * Properties, if they can be expressed as an integer, can be checked here.
 * Currently CERTCFG_CERT_SERIAL is the only property available.
 *
 * @param[in] property The property in question.
 * @param[out] o_val the value associated with the property.
 *             <serial number\> when the property is CERTCFG_CERT_SERIAL.
 *
 * @return CERT_OK
 * @return CERT_SERIAL_NUMBER_UNAVAILABLE: The serial number is not available.
 * @return CERT_UNKNOWN_PROPERTY: The property is not supported.
 */
extern CertReturnCode CertCfgSetObjectValue(CertCfgProperty property, int value);
extern CertReturnCode CertCfgGetObjectValue(CertCfgProperty property, int *o_val);

/**
 * @brief Set the value of a property in the configuration.
 *
 * @param[in] property The property
 * @param[in] value the value to associate with the property.
 *
 * @return CERT_OK
 * @return CERT_PATH_LIMIT_EXCEEDED The size of the user supplied buffer is
 *             too big for a value.
 * @return CERT_UNKNOWN_PROPERTY The property is not supported.
 * @return CERT_MEMORY_ERROR There was a problem allocating memory for
 *              the association.
 */
extern CertReturnCode CertCfgSetObjectStrValue(CertCfgProperty property, const char *value);

/**
 * @brief Get the value of a property in the configuration.
 *
 * Most properties can be checked here. The caller supplies the buffer
 * and sends the length.
 *
 * @param[in] property The property
 * @param[out] o_buf the value associated with the property.
 * @param[in] len The length of the user supplied buffer
 *
 * @return CERT_OK
 * @return CERT_PATH_LIMIT_EXCEEDED The size of the user supplied buffer is
 *             too small
 * @return CERT_UNKNOWN_PROPERTY The property is not supported.
 */
extern CertReturnCode CertCfgGetObjectStrValue(CertCfgProperty property, char *o_buf, int len);

#ifdef __cplusplus
}
#endif

#endif  /*  __CERT_CFG_H__ */
