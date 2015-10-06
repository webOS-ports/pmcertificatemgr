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

/****************/
/* cert_utils.h */
/****************/

#ifndef __CERT_UTILS_H__
#define __CERT_UTILS_H__

#include <openssl/pkcs12.h>
#include "cert_mgr.h"
#include "cert_cfg.h"

typedef enum
{
    CERT_FILELOCK_SERIAL,
    CERT_FILELOCK_DATABASE,
} CertFileLock;

#ifdef __cplusplus
extern "C" {
#endif

extern CertReturnCode cmutils_ip2str(const ASN1_OCTET_STRING *ip, char *o_buf, size_t buf_len);

extern CertReturnCode cmutils_strdsvcat(char *o_dst, size_t dst_size, const char *src, char delim);

extern CertReturnCode getTimeString(const ASN1_TIME *time_data, char *o_buf, int buflen);

extern CertReturnCode checkCertDates(const X509 *cert);

extern int CertGetSerialNumber(const char *path);

extern int CertGetSerialNumberInc(const char *path, int increment);

extern CertReturnCode CertInitLockFiles(void);

extern int CertLockFile(CertFileLock lock_type);

extern int CertUnlockFile(CertFileLock lock_type);

extern char* getPathBySerial(const char *base_name, CertDestDir dst_dir_type, CertObject obj_type, int sn);

extern char* getPathBySerialCtr(const char *base_name, CertDestDir dst_dir_type, CertObject obj_type, int sn, int count);

extern char *fileBaseName(const char *path);

extern CertObject getPrivKeyType(const EVP_PKEY *pkey);

extern CertReturnCode makePath(const char *file, CertCfgProperty file_type, char *o_path, int len);

extern CertReturnCode certSerialNumberToFileName(const int sn, char *o_buf, int len);

extern int cmutils_mkdirp(const char *path);

extern int cmutils_touchp(const char *path, const char *data);

extern int cmutils_rmdeadlinks(const char *path, int recursive);

extern int cmutils_exists(const char *path);

extern int cmutils_gzip(const char *src_file, const char *out_file);

extern void* cmutils_memdup(void *(*allocator)(size_t sz), const void *mem, int len, int added_mem);

#ifdef __cplusplus
}
#endif

#endif  // !__CERT_UTILS_H__
