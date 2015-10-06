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

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <zlib.h>

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>

#include "cert_mgr.h"
#include "cert_cfg.h"
#include "cert_debug.h"
#include "cert_utils.h"

static const char* cmutils_basename(const char *path);
static void cmutils_chopbasename(char *io_path);

static int cert_lockfile_fd = -1;

#ifdef __cplusplus
extern "C" {
#endif

CertReturnCode cmutils_ip2str(const ASN1_OCTET_STRING *ip, char *o_buf, size_t buf_len)
{
    int written_chars;
    const unsigned char *p;

    if (ip == NULL)
    {
        return CERT_INVALID_ARG;
    }

    if (o_buf == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    p = ip->data;

    switch (ip->length)
    {
    case 4: /* IPv4 */
        written_chars =
            snprintf(o_buf, buf_len,
                     "%d.%d.%d.%d",
                     p[0], p[1], p[2], p[3]);
        break;

    case 16: /* IPv6 */
        written_chars =
            snprintf(o_buf, buf_len,
                     "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                     (p[0] << 8) | p[1],
                     (p[2] << 8) | p[3],
                     (p[4] << 8) | p[5],
                     (p[6] << 8) | p[7],
                     (p[8] << 8) | p[9],
                     (p[10] << 8) | p[11],
                     (p[12] << 8) | p[13],
                     (p[14] << 8) | p[15]);
        break;

    default: /* Not an IP address */
        return CERT_INVALID_ARG;
    }

    /* Make sure the output buffer is NUL terminated */
    if (written_chars >= buf_len)
    {
        return CERT_INSUFFICIENT_BUFFER_SPACE;
    }

    DSYSLOG(LOG_INFO, "IP is: %s", o_buf);

    return CERT_OK;
}

CertReturnCode cmutils_strdsvcat(char *o_dst, size_t dst_size, const char *src, char delim)
{
    size_t append_delim = 0;
    size_t dst_len, req_len;

    /* Don't dereference NULL destination */
    if (o_dst == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    /* Don't dereference NULL source */
    if (src == NULL)
    {
        return CERT_INVALID_ARG;
    }

    dst_len = strlen(o_dst);

    /* Make sure we got a valid destination buffer */
    if (dst_len >= dst_size)
    {
        return CERT_INVALID_ARG;
    }

    req_len = strlen(src);

    /* Append comma if the output string isn't empty */
    if ((dst_len > 0) && (o_dst[dst_len - 1] != delim))
    {
        append_delim = 1;
    }

    /* Make sure we can append src with NUL */
    if ((req_len + append_delim) >= dst_size - dst_len)
    {
        return CERT_INSUFFICIENT_BUFFER_SPACE;
    }

    /* Append delimiter if needed */
    if (append_delim)
    {
        o_dst[dst_len] = delim;
    }

    /* Copy NUL terminated src */
    strcpy(o_dst + dst_len + append_delim, src);

    return CERT_OK;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: gettimeString                                                   */
/*       */
/* INPUT:                                                                    */
/*       */
/* OUTPUT:                                                                   */
/*       */
/*       */
/*       */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode getTimeString(const ASN1_TIME *time_data, char *o_buf, int buflen)
{
    BIO *bio;
    CertReturnCode result;

    if (time_data == NULL)
    {
        return CERT_INVALID_ARG;
    }

    if (o_buf == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    bio = BIO_new(BIO_s_mem());

    if (bio == NULL)
    {
        return CERT_MEMORY_ERROR;
    }

    if (!ASN1_TIME_print(bio, time_data))
    {
        result = CERT_GENERAL_FAILURE;
    }
    else
    {
        BUF_MEM *bufmem;
        BIO_get_mem_ptr(bio, &bufmem);

        if (bufmem->length >= buflen)
        {
            result = CERT_INSUFFICIENT_BUFFER_SPACE;
        }
        else
        {
            memcpy(o_buf, bufmem->data, bufmem->length);
            o_buf[bufmem->length] = '\0';
            result = CERT_OK;
        }
    }

    BIO_free(bio);

    return result;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: checkCertDates                                                  */
/*       Check whether or not the certificate in its valid period of time    */
/* INPUT:                                                                    */
/*       cert: the X.509 certificate in question in memory                   */
/* OUTPUT:                                                                   */
/*       CERT_OK: The certificate is within the valid range of dates         */
/*       CERT_DATE_PENDING: It's too early for the certificate's use         */
/*       CERT_DATE_EXPIRED: It's too late for the certificate's use          */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode checkCertDates(const X509 *cert)
{
    time_t now = time(NULL);
    ASN1_STRING *date;

    date = X509_get_notBefore(cert);

    if (X509_cmp_time(date, &now) > 0)
    {
        return CERT_DATE_PENDING;
    }

    date = X509_get_notAfter(cert);

    if (X509_cmp_time(date, &now) < 0)
    {
        return CERT_DATE_EXPIRED;
    }

    return CERT_OK;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION*: CertGetSerialNumber                                            */
/*       Read the current serial number from the file                        */
/* INPUT:                                                                    */
/*       path: The serial number file                                        */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       The value in the serial number file                                 */
/* NOTES:                                                                    */
/*       1) The serial number file is resolved through the configuration file*/
/*          There may be several serial number files depending on what is    */
/*          kept track of.  The default for SSL is serial in the default dir.*/
/*          That file keeps track of the certificates issued from that       */
/*          location.                                                        */
/*       2) The algorithm is quite simple and should be forgiving when open- */
/*          ing the wrong file.  0 is considered an error                    */
/*       3) The serial number file must be protected around this call        */
/*                                                                           */
/*****************************************************************************/

int CertGetSerialNumber(const char *path)
{
    int sn = 0;
    int fd = open(path, O_RDONLY);

    if (fd >= 0)
    {
        char in_buf[MAX_CERT_PATH];
        int len = read(fd, in_buf, sizeof(in_buf) - 1);

        if (len >= 0)
        {
            in_buf[len] = '\0';

            if (sscanf(in_buf, "%x", &sn) != 1)
            {
                sn = 0;
            }
        }

        close(fd);
    }

    return sn;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION*: CertGetSerialNumberInc                                         */
/*       Read the current serial number from the file and change the number  */
/*       by the given amount.                                                */
/* INPUT:                                                                    */
/*       path: The serial number file                                        */
/*       increment: added to the serial number and stored into the file      */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) The serial number file is resolved through the configuration file*/
/*          There may be several serial number files depending on what is    */
/*          kept track of.  The default for SSL is serial in the default dir.*/
/*          That file keeps track of the certificates issued from that       */
/*          location.                                                        */
/*       2) The algorithm is quite simple and should be forgiving when open- */
/*          ing the wrong file.  0 is considered an error                    */
/*       3) The increment value may be negative to allow for resetting the   */
/*          serial number file in case of an error                           */
/*       4) The serial number file must be protected around this call        */
/*                                                                           */
/*****************************************************************************/

int CertGetSerialNumberInc(const char *path, int increment)
{
    int sn = 0;
    int fd = open(path, O_RDWR);

    if (fd >= 0)
    {
        char in_buf[MAX_CERT_PATH];
        int len = read(fd, in_buf, sizeof(in_buf) - 1);

        if (len < 0)
        {
            DPRINTF("Error %d reading certificate serial number\n", errno);
        }
        else if ((sscanf(in_buf, "%x", &sn) == 1) && (sn))
        {
            DPRINTF("Serial is currently %d\n", sn);

            if (snprintf(in_buf, sizeof(in_buf), "%X ", sn + increment) >= sizeof(in_buf))
            {
                DPRINTF("Temporary buffer too small to hold the new SN\n");
            }
            else if (lseek(fd, 0, SEEK_SET) != 0)
            {
                DPRINTF("Error %d seeking to beginning of %s\n", errno, path);
            }
            else if (ftruncate(fd, 0) != 0)
            {
                DPRINTF("Error %d truncating %s\n", errno, path);
            }
            else if (write(fd, in_buf, 4) != 4)
            {
                DPRINTF("Error %d writing to %s\n", errno, path);
            }
        }

        close(fd);
    }

    return sn;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertInitLockFiles                                              */
/*       Initialize the lock file for serializing data access.  It's crude,  */
/*       but should be sufficient                                            */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) Initialization must be done after the configuration file is read */
/*       2) I could have harmonized the certificate error codes with those   */
/*          passed by lock, but it's too much work.                          */
/*       3) TODO: Make the lock file a variable so we can change it          */
/*       4) TODO: The lock file name and its descriptor should be part of the*/
/*          configuration object                                             */
/*                                                                           */
/*****************************************************************************/

CertReturnCode CertInitLockFiles(void)
{
    int path_len;
    char new_root_path[MAX_CERT_PATH];
    static char lockfile_path[MAX_CERT_PATH];

    if ((CertCfgGetObjectStrValue(CERTCFG_ROOT_DIR, new_root_path, sizeof(new_root_path)) != CERT_OK) ||
        (new_root_path[0] == '\0'))
    {
        strcpy(new_root_path, ".");
    }

    path_len = strlen(new_root_path);

    /* we may need finer grain than one, but for now */
    if (snprintf(new_root_path + path_len,
                 sizeof(new_root_path) - path_len,
                 "/.lock") >= sizeof(new_root_path) - path_len)
    {
        return CERT_INSUFFICIENT_BUFFER_SPACE;
    }

    if (cert_lockfile_fd >= 0)
    {
        int i = 100, fd;

        /* Already initialized */
        if (strcmp(new_root_path, lockfile_path) == 0)
        {
            return CERT_OK;
        }

        /* Otherwise -- root path has changed. Need to close the old lock file and create new.
         * Try to get an exclusive lock to make sure nothing changes in between */
        while ((CertLockFile(CERT_FILELOCK_DATABASE) != CERT_OK) && (i-- > 0))
        {
            usleep(1000);
        }

        if (i <= 0)
        {
            /* Already initialized and failed to drop old lock. Don't leak FDs */
            return CERT_LOCK_FILE_CREATION_FAILURE;
        }

        fd = cert_lockfile_fd;
        cert_lockfile_fd = -1;
        close(fd);
    }

    cert_lockfile_fd = open(new_root_path, O_CREAT | O_WRONLY | O_TRUNC, 0700);

    if (cert_lockfile_fd < 0)
    {
        PRINT_ERROR2("Can't open lockfile", errno);
        PRINT_ERROR2(new_root_path, 0);
        PRINT_RETURN_CODE(result);
        return CERT_UNDEFINED_DESTINATION;
    }

    strcpy(lockfile_path, new_root_path);

    /* This won't work if the process closed stdin */
    return CERT_OK;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertLockFile                                                   */
/*       Lock access to the database                                         */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) This is an internal function, but should it be needed at some    */
/*          future point we can add a finer tuned locking mechanism.         */
/*                                                                           */
/*****************************************************************************/

int CertLockFile(CertFileLock lock_type)
{
    int lockstate = lockf(cert_lockfile_fd, F_TLOCK, 0);
    (void)lock_type;

    if (lockstate < 0)
    {
        DPRINTF("CertLockFile: %s\n", strerror(errno));
        return errno;
    }

    return CERT_OK;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertUnlockFile                                                  */
/*       Unlock access to the files                                          */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) This is an internal function, but should it be needed at some    */
/*          future point we can add a finer tuned locking mechanism.         */
/*                                                                           */
/*****************************************************************************/

int CertUnlockFile(CertFileLock lock_type)
{
    int lockstate = lockf(cert_lockfile_fd, F_ULOCK, 0);
    (void)lock_type;

    if (lockstate < 0)
    {
        DPRINTF("CertUnlockFile: %s\n", strerror(errno));
        return errno;
    }

    return CERT_OK;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: getPathBySerial                                                  */
/*       Create a proper path and file name for the object type              */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) objectFileName must be kept coordinated with CertObject_t as     */
/*          defined in cert_mgr.h                                            */
/*       2) objectFileExt must be kept coordinated with CertObject_t as      */
/*          defined in cert_mgr.h                                            */
/*       3) The extension for the hashed CA file is hardcoded                */
/*                                                                           */
/*****************************************************************************/
char* getPathBySerial(const char *base_name, CertDestDir dst_dir_type, CertObject obj_type, int sn)
{
	return getPathBySerialCtr(base_name, dst_dir_type, obj_type, sn, 0);
}

char* getPathBySerialCtr(const char *base_name, CertDestDir dst_dir_type, CertObject obj_type, int sn, int count)
{
    static const char *obj_fnames[] =
    {
#       define CM_VAL(obj, fname, fext) fname
        CERTMGR_OBJS
#       undef CM_VAL
    };
    static const char *obj_fexts[] =
    {
#       define CM_VAL(obj, fname, fext) fext
        CERTMGR_OBJS
#       undef CM_VAL
    };
    CertCfgProperty cfg_prop;
    char cfg_dir[MAX_CERT_PATH];
    char full_path[MAX_CERT_PATH];

    /* XXX: Why do we require the user to supply base_name if we don't ever use it? */
    (void)base_name;

    if ((obj_type < 0) ||
        (obj_type >= CERT_OBJECT_MAX_OBJECT) ||
        (count < 0))
    {
        return NULL;
    }

    switch (dst_dir_type)
    {
    case CERT_DIR_PRIVATE_KEY:
        cfg_prop = CERTCFG_PRIVATE_KEY_DIR;
        break;

    case CERT_DIR_PUBLIC_KEY:
        cfg_prop = CERTCFG_PUBLIC_KEY_DIR;
        break;

    case CERT_DIR_CRL:
        cfg_prop = CERTCFG_CRL_DIR;
        break;

    case CERT_DIR_CERTIFICATES:
        cfg_prop = CERTCFG_CERT_DIR;
        break;

    case CERT_DIR_PACKAGES:
        cfg_prop = CERTCFG_PACKAGE_DIR;
        break;

    default:
        return NULL;
    }

    if (CertCfgGetObjectStrValue(cfg_prop, cfg_dir, sizeof(cfg_dir)) != CERT_OK)
    {
        return NULL;
    }

    if (count == 0)
    {
        if (snprintf(full_path, sizeof(full_path), "%s/%s%X.%s",
                     cfg_dir,
                     obj_fnames[obj_type],
                     sn,
                     obj_fexts[obj_type]) >= sizeof(full_path))
        {
            return NULL;
        }
    }
    else if (snprintf(full_path, sizeof(full_path), "%s/%s%X_%d.%s",
                      cfg_dir,
                      obj_fnames[obj_type],
                      sn,
                      count - 1,
                      obj_fexts[obj_type]) >= sizeof(full_path))
    {
        return NULL;
    }

    return strdup(full_path);

    /* Let's check to see if we've already installed this certificate */
//			if(CERT_OBJECT_C_AUTHORIZATION == obj_type) {
//				int counter = 0;
//				for (counter = 0; counter < CERT_MAX_HASHED_FILES; ++counter) {
//					if (exists(full_path)) {
//						memset(full_path, 0, sizeof(full_path));
//						sprintf(full_path, "%s/%s%X_%d.%s", cfg_dir, obj_fnames[obj_type],
//											sn, counter, obj_fexts[obj_type]);
//					} else {
//						break;
//					}
//				}
//			}
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: fileBaseName                                                    */
/*       Given a path name return the final file without an extension        */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) We chop off the extension first to allow for "." and "..".       */
/*          basename() should take care of the rest                          */
/*                                                                           */
/*****************************************************************************/

char *fileBaseName(const char *path)
{
    const char *base_ptr, *ext_ptr;

    if (path == NULL)
    {
        return NULL;
    }

    base_ptr = cmutils_basename(path);
    ext_ptr = strrchr(base_ptr, '.');

    /* Strip extention if exists
     * (handle ".", "..", ".hidden" and "w." gracefully) */
    if ((ext_ptr != NULL) && (ext_ptr > base_ptr) && (ext_ptr[1] != '\0'))
    {
        return (char *)cmutils_memdup(malloc, base_ptr, ext_ptr - base_ptr, 1);
    }

    return strdup(base_ptr);
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: getPrivKeyType                                                  */
/*       Check the key type and translate it into a type that the certificate*/
/*       manager understands                                                 */
/* INPUT:                                                                    */
/*       pkey: a pointer to an EVP private key structure                     */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_RSA_PRIVATE_KEY:                                               */
/* NOTES:                                                                    */
/*       1) I can't believe that SSL didn't have an interegator for this,    */
/*          everything seems so OO.  But according to                        */
/*          _Network_Security_with_OpenSSL_, 1st ed. pg 282 para 4, derefer- */
/*          rencing the structure itself must be done.                       */
/*                                                                           */
/*****************************************************************************/

CertObject getPrivKeyType(const EVP_PKEY *pkey)
{
    switch (EVP_PKEY_type(pkey->type))
    {
    case EVP_PKEY_RSA:
        return CERT_OBJECT_RSA_PRIVATE_KEY;

    case EVP_PKEY_DSA:
        return CERT_OBJECT_DSA_PRIVATE_KEY;

    case EVP_PKEY_EC:
        return CERT_OBJECT_EC_PRIVATE_KEY;

    default:
        return CERT_OBJECT_MAX_OBJECT;
    }
}

CertReturnCode makePath(const char *file, CertCfgProperty file_type, char *o_path, int len)
{
    int target;
    CertReturnCode result;
    char root_path[MAX_CERT_PATH];
    char targ_path[MAX_CERT_PATH];

    /* Validate the supplied file path */
    if (file == NULL)
    {
        return CERT_INVALID_ARG;
    }

    /* Don't dereference NULL pointers */
    if (o_path == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    /* Make sure we can at least NUL terminate it */
    if (len <= 0)
    {
        return CERT_INSUFFICIENT_BUFFER_SPACE;
    }

    /* Make sure we support getting the path to the file */
    switch (file_type)
    {
    case CERTCFG_CONFIG_FILE:
    case CERTCFG_CERT_DATABASE:
    case CERTCFG_CERT_SERIAL_NAME:
        target = -1;
        break;

    case CERTCFG_CERTIFICATE:
        target = CERTCFG_CERT_DIR;
        break;

    case CERTCFG_PRIVATE_KEY:
        target = CERTCFG_PRIVATE_KEY_DIR;
        break;

    case CERTCFG_CRL_DIR:
        target = CERTCFG_CRL_DIR;
        break;

    case CERTCFG_CONFIG_NAME:
    case CERTCFG_ROOT_DIR:
    case CERTCFG_CERT_DIR:
    case CERTCFG_PRIVATE_KEY_DIR:
    case CERTCFG_CERT_SERIAL:
    case CERTCFG_PUBLIC_KEY_DIR:
    case CERTCFG_PACKAGE_DIR:
    case CERTCFG_AUTH_CERT_DIR:
        return CERT_PROPERTY_NOT_FOUND;

    default:
        return CERT_UNKNOWN_PROPERTY;
    }

    result = CertCfgGetObjectStrValue(CERTCFG_ROOT_DIR, root_path, sizeof(root_path));

    if (result != CERT_OK)
    {
        return result;
    }

    if (target != -1)
    {
        result = CertCfgGetObjectStrValue(target, targ_path, sizeof(targ_path));

        if (result != CERT_OK)
        {
            return result;
        }

        if (snprintf(o_path, len, "%s/%s/%s", root_path, targ_path, file) >= len)
        {
            return CERT_INSUFFICIENT_BUFFER_SPACE;
        }
    }
    else if (snprintf(o_path, len, "%s/%s", root_path, file) >= len)
    {
        return CERT_INSUFFICIENT_BUFFER_SPACE;
    }

    return CERT_OK;
}

CertReturnCode certSerialNumberToFileName(const int sn, char *o_buf, int len)
{
    CertReturnCode result;
    char cert_dir[MAX_CERT_PATH];

    if (o_buf == NULL)
    {
        return CERT_NULL_BUFFER;
    }

    if (len <= 0)
    {
        return CERT_INSUFFICIENT_BUFFER_SPACE;
    }

    result = CertCfgGetObjectStrValue(CERTCFG_AUTH_CERT_DIR, cert_dir, sizeof(cert_dir));

    if (result != CERT_OK)
    {
        DPRINTF("Error %d getting certificate value\n", errno);
        return result;
    }

    if (snprintf(o_buf, len, "%s/%X.pem", cert_dir, sn) >= len)
    {
        return CERT_INSUFFICIENT_BUFFER_SPACE;
    }

    return CERT_OK;
}

int cmutils_mkdirp(const char *path)
{
    /* FIXME: Need to normalize the path to avoid situations where
     * we create directories which aren't actually parents at all
     * (e.g. "/var/usr/local/bin/blah/../../../../../home/user") */
    int rc;
    char *path_cpy;
    struct stat statbuf;
    size_t orig_len, cur_len;

    if (path == NULL)
    {
        return -1;
    }

    /* Do not make a directory if it exists */
    if (stat(path, &statbuf) == 0)
    {
        return 0;
    }

    /* We'll be manipulating the path, so copy it */
    path_cpy = strdup(path);

    if (path_cpy == NULL)
    {
        return -1;
    }

    orig_len = strlen(path_cpy);

    /* Trim trailing slashes */
    while ((orig_len > 0) && (path_cpy[orig_len - 1] == '/'))
    {
        path_cpy[--orig_len] = '\0';
    }

    cmutils_chopbasename(path_cpy);

    while (stat(path_cpy, &statbuf) == -1)
    {
        /* If the path is cut to the beginning it
         * only means that the entire tree doesn't
         * exists -- which can only happen if the
         * original `path` was relative.
         * There's nothing we can do in that case */
        if ((*path_cpy == '\0') || (errno != ENOENT))
        {
            rc = -1;
            goto end;
        }

        /* Parent is missing too.
         * Go up until we find an existing directory */
        cmutils_chopbasename(path_cpy);
    }

    cur_len = strlen(path_cpy);

    /* Iterate parents, restoring the original
     * path in the process */
    while (cur_len < orig_len)
    {
        /* An evil user might supply something like
         * "foo/./././bar/../bar/./". Handle it gracefully */
        if (stat(path_cpy, &statbuf) == -1)
        {
            rc = mkdir(path_cpy, 0777);

            if (rc < 0)
            {
                goto end;
            }
        }

        /* Replace the NUL character with '/' */
        path_cpy[cur_len] = '/';
        cur_len += strlen(&path_cpy[cur_len]);
    }

    /* Actually make the dir if the last segments wern't evil
     * and it doesn't exists yet */
    if (stat(path_cpy, &statbuf) == -1)
    {
        rc = mkdir(path_cpy, 0777);
    }

end:
    free(path_cpy);
    return rc;
}

int cmutils_touchp(const char *path, const char *data)
{
    int fd, rc;
    struct stat statbuf;

    if (path == NULL)
    {
        return -1;
    }

    /* Make sure the parent dir exists */
    if ((stat(path, &statbuf) != 0) && (errno == ENOENT))
    {
        char *parent = strdup(path);

        if (parent == NULL)
        {
            return -1;
        }

        cmutils_chopbasename(parent);
        rc = cmutils_mkdirp(parent);
        free(parent);

        if (rc != 0)
        {
            goto done;
        }
    }

    fd = open(path, O_CREAT | O_WRONLY, 0777);

    if (fd < 0 )
    {
        return -1;
    }

    if ((data != NULL) &&
        (data[0] != '\0') &&
        (write(fd, data, strlen(data)) < 0))
    {
        rc = -1;
    }
    else
    {
        rc = 0;
    }

    close(fd);

done:
    return rc;
}

int cmutils_rmdeadlinks(const char *path, int recursive)
{
    DIR *dir;
    int oper_result;
    struct dirent *dp;
    char *subpath = NULL;
    size_t path_len, subpath_buf_len = 0;

    if (path == NULL)
    {
        return -1;
    }

    dir = opendir(path);

    if (dir == NULL)
    {
        return -1;
    }

    path_len = strlen(path);

    /* Iterate directory entries */
    while ((dp = readdir(dir)) != NULL)
    {
        size_t subpath_len = strlen(dp->d_name);

        /* Skip "." and ".." (we could just do with strcmp,
         * but it's more efficient this way) */
        if ((subpath_len > 2) ||
            (dp->d_name[0] != '.') ||
            ((dp->d_name[1] != '\0') && (dp->d_name[1] != '.')))
        {
            struct stat statbuf;
            size_t req_subpath_len = path_len + subpath_len + 2; /* Account for '\0' and '/' */

            /* There's no way to preallocate enough memlory to hold the path
             * so unfortunately we have to resort to multiple mini allocations,
             * but we optimize it a bit by only allocating new memory when the
             * allocated buffer can't hold the new path */
            if (subpath_buf_len < req_subpath_len)
            {
                char *new_path = (char *)realloc(subpath, req_subpath_len);

                if (new_path == NULL)
                {
                    oper_result = -1;
                    goto cleanup;
                }

                subpath = new_path;
                subpath_buf_len = req_subpath_len;
            }

            /* No need for `snprintf` because we know exactly how many
             * bytes are going to be used */
            sprintf(subpath, "%s/%s", path, dp->d_name);

            /* Get file information (DO NOT follow symlinks) */
            if (lstat(subpath, &statbuf) != 0)
            {
                oper_result = -1;
            }
            /* If we're required to remove symlinks recursively and
             * it's a directory -- recurse */
            else if ((recursive) && (S_ISDIR(statbuf.st_mode)))
            {
                oper_result = cmutils_rmdeadlinks(subpath, 1);
            }
            /* Unlink the file if it's a broken symlink */
            else if ((S_ISLNK(statbuf.st_mode)) &&
                     (stat(subpath, &statbuf) != 0) &&
                     (errno == ENOENT) &&
                     (unlink(subpath) != 0))
            {
                oper_result = -1;
            }

            if (oper_result == -1)
            {
                goto cleanup;
            }
        }
    }

    oper_result = 0;

cleanup:
    if (subpath != NULL)
    {
        free(subpath);
    }

    closedir(dir);

    return oper_result;
}

int cmutils_exists(const char *path)
{
    struct stat buf;
    return stat(path, &buf) == 0;
}

int cmutils_gzip(const char *src_file, const char *out_file)
{
    int result = -1;
    size_t len;
    FILE *plain_file;
    gzFile comp_file;
    /* Is 1024 good? We don't want to eat too much stack space */
    unsigned char tmpbuf[1024];

    plain_file = fopen(src_file, "rb");

    if (plain_file == NULL)
    {
        goto done;
    }

    /* gzip's default compression level is 6. Use that */
    comp_file = gzopen(out_file, "wb6");

    if (comp_file == NULL)
    {
        goto cleanup_infile;
    }

    /* Read data and compress it */
    while ((len = fread(tmpbuf, 1, sizeof(tmpbuf), plain_file)) > 0)
    {
        if (!gzwrite(comp_file, tmpbuf, (unsigned)len))
        {
            goto cleanup_all;
        }
    }

    /* This might change if gzclose fails */
    if (feof(plain_file))
    {
        result = 0;
    }

cleanup_all:
    if (gzclose(comp_file) != Z_OK)
    {
        result = -1;
    }

cleanup_infile:
    fclose(plain_file);

done:
    return result;
}

void* cmutils_memdup(void *(*allocator)(size_t sz), const void *mem, int len, int added_mem)
{
    void *cpy;
    ;

    if ((mem == NULL) || (len <= 0) || ((added_mem + len) <= 0))
    {
        return NULL;
    }

    if (allocator == NULL)
    {
        allocator = malloc;
    }

    cpy = (*allocator)((size_t)(len + added_mem));

    if (cpy != NULL)
    {
        memcpy(cpy, mem, len);

        if (added_mem > 0)
        {
            memset((char *)cpy + added_mem, 0, added_mem);
        }
    }

    return cpy;
}

static const char* cmutils_basename(const char *path)
{
    /* This version of basename is not compatible with the POSIX version */
    size_t len;
    static const char *cd = ".";

    if (path == NULL)
    {
        return cd;
    }

    len = strlen(path);

    while ((len > 0) && (path[len - 1] != '/'))
    {
        --len;
    }

    return &path[len];
}

static void cmutils_chopbasename(char *io_path)
{
    if (io_path != NULL)
    {
        size_t len = strlen(io_path);

        while ((len > 0) && (io_path[len - 1] != '/'))
        {
            --len;
        }

        io_path[len] = '\0';
    }
}

#ifdef __cplusplus
}
#endif
