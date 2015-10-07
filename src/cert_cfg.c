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
/* cert_cfg.c: functions for dealing directly with configuration files       */
/*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/conf.h>

#include "cert_mgr.h"
#include "cert_cfg.h"
#include "cert_utils.h"

/* #define D_DEBUG_ENABLED */
#include "cert_debug.h"


/* Currently just hold this stuff in globals.  This is not something we
 * want to continue into the future.
 * Wouldn't an actual object be nice! */
typedef struct
{
    CONF *conf;
    char *desc_str[CERTCFG_MAX_PROPERTY];
} CertConfigObject;

static CertReturnCode certcfg_populate_config(CONF *conf, const char *cfg_file, const char *cfg_name);
static CertReturnCode certcfg_set_val(CertConfigObject *obj, CertCfgProperty property, const char *value);


static CertConfigObject g_config = { NULL, { NULL } };

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertCfgOpenConfigFile                                           */
/*       Open the configuration file                                         */
/* INPUT:                                                                    */
/*       cfg_file: a fully qualified path to the ssl configuration file      */
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
/*       1) Not thread safe                                                  */
/*       2) If the value of cfg_file == NULL, the following are checked in   */
/*          order:                                                           */
/*            OPENSSL_CONF environmental variable                            */
/*            CERT_DEF_CONF_FILE defined in cert_mgr.h                       */
/*       3) We expect the repository directory to be labeled "dir" in the    */
/*          config file                                                      */
/*       4) NCONF_load seems to indescriminatly open arbitrary files         */
/*                                                                           */
/*****************************************************************************/

CertReturnCode CertCfgOpenConfigFile(const char *cfg_file, const char *cfg_name)
{
    long err;
    CONF *conf;
    const char *dir_name;
    CertReturnCode result;

    /* First check the environment */
    if ((cfg_file == NULL) &&
        ((cfg_file = getenv("OPENSSL_CONF")) == NULL))
    {
        /* Use the default */
        cfg_file = CERT_DEF_CONF_FILE;
    }

    /* Make sure it's reasonable */
    if (strlen(cfg_file) >= MAX_CERT_PATH)
    {
        return CERT_PATH_LIMIT_EXCEEDED;
    }

    conf = NCONF_new(NCONF_default());

    if (conf == NULL)
    {
        return CERT_GENERAL_FAILURE;
    }

    if (!NCONF_load(conf, cfg_file, &err))
    {
        if (err == 0)
        {
            PRINT_RETURN_CODE(CERT_OPEN_FILE_FAILED);
            result = CERT_OPEN_FILE_FAILED;
        }
        else
        {
            PRINT_RETURN_CODE(CERT_ILLFORMED_CONFIG_FILE);
            result = CERT_ILLFORMED_CONFIG_FILE;
        }

        goto error;
    }

    /* Figure out the configuration inside the designate file that we want
     * to use */
    if ((cfg_name == NULL) &&
        ((cfg_name = NCONF_get_string(conf, "ca", "default_ca")) == NULL))
    {
        result = CERT_CONFIG_UNAVAILABLE;
        goto error;
    }

    dir_name = NCONF_get_string(conf, cfg_name, "dir");

    /* Let's find out if there is anything reasonable */
    if (dir_name == NULL)
    {
        PRINT_RETURN_CODE(CERT_ILLFORMED_CONFIG_FILE);
        result = CERT_ILLFORMED_CONFIG_FILE;
        goto error;
    }
    else
    {
        struct stat stat_buf;

        if (stat(dir_name, &stat_buf) != 0)
        {
            fprintf(stdout, "Can't find %s\n", dir_name);
            result = CERT_UNDEFINED_ROOT_DIR;
            goto error;
        }
    }

    /* Now resolve the rest of the defaults from the config file
     * We are asuming that the file is well formed or this might have problems.
     * if we can't resolve the directory then fail.
     * if we can't resolve the subdirectories, don't fail put them under dir. */
    result = certcfg_populate_config(conf, cfg_file, cfg_name);

    if (result != CERT_OK)
    {
error:
        NCONF_free(conf);
    }

    return result;
}

CertReturnCode CertCfgSetObjectValue(CertCfgProperty property, int value)
{
    /* XXX: Not implemented. The only property that can have an int value
     * is the serial number, though I'm not sure how to handle this change.
     * We should probably recreate all the certificate links, which isn't
     * part of CertCfg responsibility. We're probably just better off throwing
     * this function away */
    return CERT_GENERAL_FAILURE;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertCfgGetObjectValue                                           */
/*       Get the value of a property in the configuration.                   */
/* INPUT:                                                                    */
/*       property: denotes a property that is stored as an integer    */
/* OUTPUT:                                                                   */
/*       value: The value the value associated with the property.            */
/* RETURN:                                                                   */
/*       CERT_OK                                                             */
/*       CERT_SERIAL_NUMBER_UNAVAILABLE: The serial number is not available. */
/*       CERT_UNKNOWN_PROPERTY: The property is not supported.               */
/* NOTES:                                                                    */
/*       1) Not thread safe                                                  */
/*                                                                           */
/*****************************************************************************/
CertReturnCode CertCfgGetObjectValue(CertCfgProperty property, int *o_val)
{
    if (o_val == NULL)
    {
        return CERT_INVALID_ARG;
    }

    if (property == CERTCFG_CERT_SERIAL)
    {
        char file_path[MAX_CERT_PATH];
        CertReturnCode result;

        result = CertCfgGetObjectStrValue(CERTCFG_CERT_SERIAL_NAME, file_path, sizeof(file_path));

        if (result == CERT_OK)
        {
            int sn = CertGetSerialNumber(file_path);

            if (!sn)
            {
                return CERT_SERIAL_NUMBER_UNAVAILABLE;
            }

            *o_val = sn;
        }

        return result;
    }

    return CERT_UNKNOWN_PROPERTY;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertCfgSetObjectStrValue                                       */
/*       Figure out the proper configuration file                            */
/* INPUT:                                                                    */
/*       property: denotes a property that is stored as a string*/
/* OUTPUT:                                                                   */
/*        value: the value associated with the property.                     */
/* RETURN:                                                                   */
/**/
/* NOTES:                                                                    */
/*       1) Not thread safe                                                  */
/*                                                                           */
/*****************************************************************************/
CertReturnCode CertCfgSetObjectStrValue(CertCfgProperty property, const char *value)
{
    /* Check for correctness */
    if ((property < 0) || (property >= CERTCFG_MAX_PROPERTY))
    {
        return CERT_UNKNOWN_PROPERTY;
    }

    /* Check for reasonable size */
    if ((value != NULL) && (strlen(value) >= MAX_CERT_PATH))
    {
        return CERT_PATH_LIMIT_EXCEEDED;
    }

    return certcfg_set_val(&g_config, property, value);
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertCfgGetObjectStrValue                                        */
/*       Figure out the proper configuration file                            */
/* INPUT:                                                                    */
/*       property: denotes a property that is stored as a string   */
/*       buf: A user supplied buffer                                         */
/*       bufLen; the length of the supplied buffer                           */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_OK:                                                            */
/*       CERT_INSUFFICIENT_BUFFER_SPACE: The user memory is not sufficiently */
/*           large to hold the data                                          */
/*       CERT_UNKNOWN_PROPERTY: The requested prperty is not supported       */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/
CertReturnCode CertCfgGetObjectStrValue(CertCfgProperty property, char *o_buf, int len)
{
    if ((property < 0) || (property >= CERTCFG_MAX_PROPERTY))
    {
        PRINT_ERROR2("Unknown string property", property);
        PRINT_RETURN_CODE(CERT_UNKNOWN_PROPERTY);

        return CERT_UNKNOWN_PROPERTY;
    }

    if (o_buf == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    if (len <= 0)
    {
        return CERT_INSUFFICIENT_BUFFER_SPACE;
    }

    if (g_config.desc_str[property] == NULL)
    {
        *o_buf = '\0';
    }
    else
    {
        if (strlen(g_config.desc_str[property]) >= (size_t)len)
        {
            return CERT_INSUFFICIENT_BUFFER_SPACE;
        }

        strcpy(o_buf, g_config.desc_str[property]);
    }

    PRINT_CFG_STR_PROPS(property, o_buf);

    return CERT_OK;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: populateConfig                                                  */
/*       Convenience function for populating the configuration structure from*/
/*       its configuration file                                              */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/
static CertReturnCode certcfg_populate_config(CONF *conf, const char *cfg_file, const char *cfg_name)
{
    static const char *propert_names[] =
    {
#       define CM_VAL(prop, str) str
        CERTCFG_PROPS
#       undef CM_VAL
    };
    CertConfigObject new_config = { NULL, { NULL } };
    CertCfgProperty property = CERTCFG_ROOT_DIR;

    /* Try to set the cfg_file and cfg_name in the new configuration */
    if ((certcfg_set_val(&new_config, CERTCFG_CONFIG_FILE, cfg_file) != CERT_OK) ||
        (certcfg_set_val(&new_config, CERTCFG_CONFIG_NAME, cfg_name) != CERT_OK))
    {
        goto error;
    }

    /* Set the rest of the properties */
    for ( ; property < CERTCFG_MAX_PROPERTY; ++property)
    {
        const char *str_val = NCONF_get_string(conf, cfg_name, propert_names[property]);

        if (certcfg_set_val(&new_config, property, str_val) != CERT_OK)
        {
            goto error;
        }

        /* No need to free as NCONF_get_string doesn't return a copy */
    }

    /* Free old configuration if exists */
    if (g_config.conf != NULL)
    {
        while (property-- > 0)
        {
            certcfg_set_val(&g_config, property, NULL);
        }

        NCONF_free(g_config.conf);
    }

    g_config = new_config;

    return CERT_OK;

error:
    /* Dispose of the values already set */
    while (property-- > 0)
    {
        certcfg_set_val(&new_config, property, NULL);
    }

    return CERT_MEMORY_ERROR;
}

static CertReturnCode certcfg_set_val(CertConfigObject *obj, CertCfgProperty property, const char *value)
{
    char *val_cpy = NULL;

    if (value != NULL)
    {
        val_cpy = strdup(value);

        /* Abort if failed to allocate the needed memory */
        if (val_cpy == NULL)
        {
            return CERT_MEMORY_ERROR;
        }
    }

    /* Free existing value */
    if (obj->desc_str[property] != NULL)
    {
        free(obj->desc_str[property]);
    }

    obj->desc_str[property] = val_cpy;
    PRINT_CFG_STR_PROPS(property, val_cpy);

    return CERT_OK;
}

#ifdef __cplusplus
}
#endif
