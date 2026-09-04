/* @@@LICENSE
 *
 *      Copyright (c) 2008-2013 LG Electronics, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * LICENSE@@@ */

/*****************************************************************************/
/* test_store.h: shared helpers for the test programs                        */
/*****************************************************************************/

#ifndef __PMCERTMGR_TEST_STORE_H__
#define __PMCERTMGR_TEST_STORE_H__

/* Every includer defines _XOPEN_SOURCE before its first system header;
 * nftw() is only declared when it does. */
#ifndef _XOPEN_SOURCE
#error "define _XOPEN_SOURCE 700 before including test_store.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ftw.h>

#include "cert_mgr.h"

static int gChecks, gFails;

#define CHECK(cond, fmt, ...)                                       \
    do {                                                            \
        gChecks++;                                                  \
        if (!(cond)) {                                              \
            gFails++;                                               \
            printf("  FAIL  " fmt "\n", ##__VA_ARGS__);             \
        }                                                           \
    } while (0)

#define REPORT()                                                    \
    do {                                                            \
        printf("\n%s  (%d checks, %d failures)\n",                  \
               gFails ? "== FAILURES ==" : "== ALL PASS ==",        \
               gChecks, gFails);                                    \
        fflush(stdout);                                             \
    } while (0)

static int tsCmpStr(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int tsUnlinkOne(const char *path, const struct stat *sb, int flag,
                      struct FTW *ftw)
{
    (void)sb;
    (void)flag;
    (void)ftw;

    return remove(path);
}

/* Delete a scratch directory so a test starts from nothing. Refuses anything
 * that is not an absolute-looking scratch path, to make an accident here as
 * unlikely as possible. */
static int tsResetDir(const char *root)
{
    if ((NULL == root) || ('\0' == root[0]) ||
        (0 == strcmp(root, "/")) || (0 == strcmp(root, ".")) ||
        (0 == strcmp(root, ".."))) {
        fprintf(stderr, "refusing to reset '%s'\n", root ? root : "(null)");
        return -1;
    }

    if (0 != nftw(root, tsUnlinkOne, 16, FTW_DEPTH | FTW_PHYS)) {
        if (ENOENT != errno) {
            perror(root);
            return -1;
        }
    }

    return 0;
}

/* Write the openssl.cnf describing a store rooted at "root", without
 * creating any of the directories it names. The library provisions those
 * itself on first use, which is what a device relies on.
 *
 * Any previous contents are removed, so the tests are re-runnable against
 * the same build tree -- ctest reuses it. */
static int tsWriteConfig(const char *root, char *cnfPath, size_t cnfPathLen)
{
    FILE *f;

    if (0 != tsResetDir(root)) {
        return -1;
    }

    if ((0 != mkdir(root, 0755)) && (EEXIST != errno)) {
        perror(root);
        return -1;
    }

    snprintf(cnfPath, cnfPathLen, "%s/openssl.cnf", root);

    if (NULL == (f = fopen(cnfPath, "w"))) {
        perror(cnfPath);
        return -1;
    }

    fprintf(f,
        "[ ca ]\n"
        "default_ca = default_ca\n"
        "\n"
        "[ default_ca ]\n"
        "dir             = %s/store\n"
        "certificate     = $dir/cacert.pem\n"
        "database        = $dir/index.txt\n"
        "new_certs_dir   = $dir/newcerts\n"
        "certs           = $dir/certs\n"
        "private_dir     = $dir/private\n"
        "public_dir      = $dir/public\n"
        "serial          = $dir/serial\n"
        "authorized      = $dir/certs\n"
        "crl_dir         = $dir/crl\n"
        "package_dir     = $dir/packages\n"
        "trusted_ca_dir  = $dir/trustedcerts\n",
        root);
    fclose(f);

    return 0;
}

/* Collect the .crt files in a directory, sorted, into a malloc'd array. */
static int tsListCerts(const char *dir, char ***outNames)
{
    char **names = NULL;
    size_t cap = 0;
    int n = 0;
    DIR *d;
    struct dirent *e;

    if (NULL == (d = opendir(dir))) {
        fprintf(stderr, "cannot open %s\n", dir);
        return -1;
    }

    while (NULL != (e = readdir(d))) {
        size_t l = strlen(e->d_name);

        if ((l > 4) && (0 == strcmp(e->d_name + l - 4, ".crt"))) {
            if ((size_t)n == cap) {
                char **grown;

                cap = cap ? (cap * 2) : 256;
                grown = realloc(names, cap * sizeof(*names));

                if (NULL == grown) {
                    closedir(d);
                    free(names);
                    return -1;
                }
                names = grown;
            }
            names[n++] = strdup(e->d_name);
        }
    }
    closedir(d);

    qsort(names, n, sizeof(*names), tsCmpStr);
    *outNames = names;

    return n;
}

static void tsFreeCerts(char **names, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        free(names[i]);
    }
    free(names);
}

static const char *tsReturnCode(int r)
{
    switch (r) {
    case CERT_OK:                    return "CERT_OK";
    case CERT_GENERAL_FAILURE:       return "CERT_GENERAL_FAILURE";
    case CERT_DATE_EXPIRED:          return "CERT_DATE_EXPIRED";
    case CERT_DATE_PENDING:          return "CERT_DATE_PENDING";
    case CERT_LINK_ERR:              return "CERT_LINK_ERR";
    case CERT_BAD_CERTIFICATE:       return "CERT_BAD_CERTIFICATE";
    case CERT_OPEN_FILE_FAILED:      return "CERT_OPEN_FILE_FAILED";
    case CERT_UNDEFINED_DESTINATION: return "CERT_UNDEFINED_DESTINATION";
    case CERT_UNDEFINED_ROOT_DIR:    return "CERT_UNDEFINED_ROOT_DIR";
    case CERT_DUPLICATE:             return "CERT_DUPLICATE";
    default: {
        static char buf[32];
        snprintf(buf, sizeof(buf), "code %d", r);
        return buf;
    }
    }
}

#endif /* __PMCERTMGR_TEST_STORE_H__ */
