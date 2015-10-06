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
/* cert_debug.h: functions for debugging                                     */
/*****************************************************************************/

#ifndef __CERT_DEBUG_H__
#define __CERT_DEBUG_H__

#ifdef D_DEBUG_ENABLED
#   include <stdio.h>
#   include <syslog.h>
#   include "cert_mgr.h"
#   include "cert_cfg.h"
#   include "cert_x509.h"

#   define MAX_CFG_STR_PROPS 16

    extern char *strProps[];
    extern char *strPropNames[];
    extern char *strErrorNames[];

#   define PRINT_RETURN_CODE(a) \
    if (a) { \
        fprintf(stderr, "Error in %s line %d (%d): %s\n", \
               __FUNCTION__, __LINE__, a, (a < CERT_MAX_RETURN_CODE) ? strErrorNames[a] : "UNKNOWN ERROR"); \
    }

#   define PRINT_SIMPLE_RETURN_CODE(a) \
    printf(stderr, "%s: (%d)\n", (a < CERT_MAX_RETURN_CODE) ? strErrorNames[a] : "UNKNOWN", a)

#   define PRINT_CFG_STR_PROPS(A, B) \
    printf(stderr, "DEBUG: func = %s, property = %s, prop value = %s\n", __FUNCTION__, strProps[A], B)

#   define PRINT_ERROR2(A, B) \
    printf(stderr, "ERROR: func = %s, err = %s, value = %d\n", __FUNCTION__, A, B);

#   define PRINT_ERROR4(A, B, C, D) \
    printf(stderr, "ERROR: func = %s, err = %s, value = %s, %s = %d\n", __FUNCTION__, A, B, C, D);

#   define DPRINTF(fmt, ...)    fprintf(stderr, fmt, ##__VA_ARGS__)

#   define DSYSLOG(c, fmt, ...) syslog(c, fmt, ##__VA_ARGS__)

    /**
     * Dump functions for debugging
     */
#   ifdef __cplusplus
    extern "C" {
#   endif

    /* CertMgr */
    extern void initSSLErrors(void);
    extern void logSSLErrors(void);

    /* PKCS */
    extern CertReturnCode CertPKCS12Dump(const char *pkg_path);

    /* X509 */
    extern void CertX509Dump(const X509 *cert);

#   ifdef __cplusplus
    }
#   endif
#else  //  !D_DEBUG_ENABLED
#   define PRINT_RETURN_CODE(a)
#   define PRINT_SIMPLE_RETURN_CODE(a)
#   define PRINT_CFG_STR_PROPS(A, B)
#   define PRINT_ERROR2(A, B)
#   define PRINT_ERROR4(A, B, C, D)
#   define DPRINTF(fmt, ...)
#   define DSYSLOG(c, fmt, ...)

    /* CertMgr */
#   define initSSLErrors()
#   define logSSLErrors()

    /* PKCS */
#   define CertPKCS12Dump(pkg_path) CERT_OK

    /* X509 */
#   define CertX509Dump(cert)
#endif //  D_DEBUG_ENABLED

#endif // __CERT_DEBUG_H__
