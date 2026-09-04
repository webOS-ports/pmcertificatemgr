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
/* ca_bundle_test.c                                                          */
/*                                                                           */
/* Drives the library over a real CA bundle -- by default the Mozilla root    */
/* store shipped by ca-certificates, which is what the recipe RDEPENDS on.    */
/*                                                                           */
/* It builds a throwaway store under a temporary directory, installs every    */
/* certificate in the bundle, reads them back, authorizes, validates and      */
/* removes them, then checks the database agrees at each step.                */
/*                                                                           */
/* Worth running under sanitizers, which is where it earns its keep:          */
/*                                                                           */
/*   cmake -DBUILD_TESTS=ON \                                                 */
/*         -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g -O1" ..           */
/*   ./ca_bundle_test /tmp/certstore                                          */
/*                                                                           */
/* Bundle location can be overridden with $CA_BUNDLE_DIR.                     */
/*****************************************************************************/

/* nftw() and friends: must precede every system header */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <ftw.h>

#include "cert_mgr.h"
#include "cert_cfg.h"
#include "cert_db.h"
#include "cert_x509.h"
#include "cert_mgr_prv.h"

#define DEFAULT_BUNDLE "/usr/share/ca-certificates/mozilla"

static int gChecks, gFails;

#define CHECK(cond, fmt, ...)                                       \
    do {                                                            \
        gChecks++;                                                  \
        if (!(cond)) {                                              \
            gFails++;                                               \
            printf("  FAIL  " fmt "\n", ##__VA_ARGS__);             \
        }                                                           \
    } while (0)

/* Ask OpenSSL directly whether a DN carries the given NID, so the
 * expectations below hold for any corpus rather than a specific bundle. */
static int dnHasNid(X509_NAME *name, int nid)
{
    return (NULL != name) && (0 <= X509_NAME_get_index_by_NID(name, nid, -1));
}

static int cmpStr(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Lay down a self-contained store plus the openssl.cnf that describes it. */
static int unlinkOne(const char *path, const struct stat *sb, int flag,
                    struct FTW *ftw)
{
    (void)sb; (void)flag; (void)ftw;
    return remove(path);
}

static int makeStore(const char *root, char *cnfPath, size_t cnfPathLen)
{
    static const char *dirs[] = {
        "certs", "private", "public", "crl", "packages", "trustedcerts",
        "newcerts", NULL
    };
    char path[MAX_CERT_PATH];
    FILE *f;
    int i;

    /* start from nothing, so the test is re-runnable against a build tree
     * ctest has already used */
    if ((NULL == root) || ('\0' == root[0]) || (0 == strcmp(root, "/"))) {
        fprintf(stderr, "refusing to reset '%s'\n", root ? root : "(null)");
        return -1;
    }
    if ((0 != nftw(root, unlinkOne, 16, FTW_DEPTH | FTW_PHYS)) &&
        (ENOENT != errno)) {
        perror(root);
        return -1;
    }

    if ((0 != mkdir(root, 0755)) && (EEXIST != errno)) {
        perror("mkdir store root");
        return -1;
    }

    for (i = 0; dirs[i] != NULL; i++) {
        snprintf(path, sizeof(path), "%s/%s", root, dirs[i]);
        if ((0 != mkdir(path, 0755)) && (EEXIST != errno)) {
            perror(path);
            return -1;
        }
    }

    snprintf(path, sizeof(path), "%s/index.txt", root);
    if (NULL == (f = fopen(path, "w"))) {
        perror(path);
        return -1;
    }
    fclose(f);

    snprintf(path, sizeof(path), "%s/serial", root);
    if (NULL == (f = fopen(path, "w"))) {
        perror(path);
        return -1;
    }
    fprintf(f, "01\n");
    fclose(f);

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
        "dir             = %s\n"
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

int main(int argc, char **argv)
{
    char      **names = NULL;
    int32_t    *serials = NULL;
    size_t      namesCap = 0;
    const char *bundle;
    const char *root;
    char        cnfPath[MAX_CERT_PATH];
    char        buf[MAX_CERT_PATH];
    DIR        *d;
    struct dirent *e;
    CertReturnCode_t r;
    int32_t     count = 0;
    int         nNames = 0, nInstalled = 0, i;

    if (argc < 2) {
        fprintf(stderr,
                "usage: %s <store-dir> [bundle-dir]\n"
                "  store-dir  scratch directory to build a cert store in\n"
                "  bundle-dir directory of .crt files (default %s,\n"
                "             or $CA_BUNDLE_DIR)\n",
                argv[0], DEFAULT_BUNDLE);
        return 2;
    }

    root = argv[1];
    bundle = (argc > 2) ? argv[2] : getenv("CA_BUNDLE_DIR");
    if (NULL == bundle) {
        bundle = DEFAULT_BUNDLE;
    }

    if (0 != makeStore(root, cnfPath, sizeof(cnfPath))) {
        return 2;
    }
    printf("  store:  %s\n", root);
    printf("  bundle: %s\n", bundle);

    /* ---------------- init ---------------- */
    r = CertInitCertMgr(cnfPath);
    CHECK(CERT_OK == r, "CertInitCertMgr -> %d", r);
    if (CERT_OK != r) {
        return 1;
    }

    r = CertCfgGetObjectStrValue(CERTCFG_CERT_DIR, buf, sizeof(buf));
    CHECK(CERT_OK == r, "read back CERTCFG_CERT_DIR -> %d", r);

    /* An unset property must say so rather than leave the buffer untouched. */
    memset(buf, 0xAA, sizeof(buf));
    r = CertCfgGetObjectStrValue(CERTCFG_CERTIFICATE, buf, sizeof(buf));
    CHECK((CERT_OK != r) || ('\0' != buf[0]),
          "unset property must not report CERT_OK with an untouched buffer");

    /* ---------------- enumerate the bundle ---------------- */
    if (NULL == (d = opendir(bundle))) {
        fprintf(stderr, "cannot open bundle dir %s\n", bundle);
        return 2;
    }
    while (NULL != (e = readdir(d))) {
        size_t l = strlen(e->d_name);

        if ((l > 4) && (0 == strcmp(e->d_name + l - 4, ".crt"))) {
            if ((size_t)nNames == namesCap) {
                namesCap = namesCap ? (namesCap * 2) : 256;
                names = realloc(names, namesCap * sizeof(*names));
                serials = realloc(serials, namesCap * sizeof(*serials));
                if ((NULL == names) || (NULL == serials)) {
                    fprintf(stderr, "out of memory at %zu entries\n", namesCap);
                    closedir(d);
                    return 2;
                }
            }
            names[nNames++] = strdup(e->d_name);
        }
    }
    closedir(d);
    qsort(names, nNames, sizeof(names[0]), cmpStr);

    printf("  certs:  %d\n\n", nNames);
    CHECK(nNames > 0, "bundle contains certificates");
    if (0 == nNames) {
        return 1;
    }

    /* ---------------- install every certificate ---------------- */
    for (i = 0; i < nNames; i++) {
        char    path[MAX_CERT_PATH];
        int32_t serial = 0;

        snprintf(path, sizeof(path), "%s/%s", bundle, names[i]);
        r = CertInstallKeyPackage(path, NULL, NULL, &serial);

        if (CERT_OK == r) {
            serials[nInstalled++] = serial;
        } else {
            printf("  install failed (%d): %s\n", r, names[i]);
        }
    }
    printf("  installed: %d/%d\n", nInstalled, nNames);
    CHECK(nInstalled == nNames, "installed every certificate (%d/%d)",
          nInstalled, nNames);

    /* Serial numbers handed out must be distinct. */
    {
        int dups = 0, j;
        for (i = 0; i < nInstalled; i++) {
            for (j = i + 1; j < nInstalled; j++) {
                if (serials[i] == serials[j]) {
                    dups++;
                }
            }
        }
        CHECK(0 == dups, "no duplicate serial numbers (%d collisions)", dups);
    }

    /* ---------------- the database agrees ---------------- */
    r = CertGetCertificateCount(CERT_STATUS_ALL, &count);
    CHECK(CERT_OK == r, "CertGetCertificateCount -> %d", r);
    CHECK(count == nInstalled, "database holds %d, installed %d",
          count, nInstalled);

    /* A listing must respect the caller's array bound. */
    {
        int32_t small[4];
        int32_t n = (int32_t)(sizeof(small) / sizeof(small[0]));

        memset(small, 0, sizeof(small));
        r = CertListDatabaseCertsByStatus(CERT_STATUS_ALL, small, &n);
        CHECK(CERT_INSUFFICIENT_BUFFER_SPACE == r,
              "undersized list buffer reports INSUFFICIENT_BUFFER_SPACE (got %d)", r);
        CHECK(n <= (int32_t)(sizeof(small) / sizeof(small[0])),
              "reported count %d must not exceed the %zu-entry buffer",
              n, sizeof(small) / sizeof(small[0]));
    }

    /* ---------------- read the certificates back ----------------
     * Every value the library reports is checked against what OpenSSL says
     * about the same certificate, so this holds for any corpus. Plenty of
     * real roots carry no commonName or no organizationName in their issuer
     * DN; the library must say so rather than invent a value. */
    {
        int opened = 0, expiry = 0, agreeCn = 0, agreeOrg = 0;
        int haveCn = 0, haveOrg = 0;

        for (i = 0; i < nInstalled; i++) {
            char  path[MAX_CERT_PATH];
            char  val[512];
            X509 *x = NULL;
            X509_NAME *issuer;
            int   wantCn, wantOrg, gotCn, gotOrg;

            if (CERT_OK != makePathToCert(serials[i], path, sizeof(path))) {
                continue;
            }
            if ((CERT_OK != CertPemToX509(path, &x)) || (NULL == x)) {
                continue;
            }
            opened++;

            issuer = X509_get_issuer_name(x);
            wantCn  = dnHasNid(issuer, NID_commonName);
            wantOrg = dnHasNid(issuer, NID_organizationName);
            if (wantCn)  haveCn++;
            if (wantOrg) haveOrg++;

            memset(val, 0xAA, sizeof(val));
            gotCn = (CERT_OK == CertX509ReadStrProperty(x, CERTX509_ISSUER_COMMON_NAME,
                                                        val, sizeof(val))) && val[0];
            if (gotCn == wantCn) {
                agreeCn++;
            } else {
                printf("  issuer CN mismatch on serial %d: openssl says %d, library %d\n",
                       serials[i], wantCn, gotCn);
            }

            memset(val, 0xAA, sizeof(val));
            gotOrg = (CERT_OK == CertX509ReadStrProperty(x, CERTX509_ISSUER_ORGANIZATION_NAME,
                                                         val, sizeof(val))) && val[0];
            if (gotOrg == wantOrg) {
                agreeOrg++;
            }

            /* dates come from the Time variant, which is what certmgrd calls */
            memset(val, 0xAA, sizeof(val));
            if ((CERT_OK == CertX509ReadTimeProperty(x, CERTX509_EXPIRATION_DATE,
                                                     val, sizeof(val))) && val[0]) {
                expiry++;
            }

            X509_free(x);
        }

        printf("  reopened %d/%d; %d carry an issuer CN, %d an issuer O\n",
               opened, nInstalled, haveCn, haveOrg);
        CHECK(opened == nInstalled, "reopened every installed certificate (%d/%d)",
              opened, nInstalled);
        CHECK(expiry == nInstalled, "expiration date on every certificate (%d/%d)",
              expiry, nInstalled);
        CHECK(agreeCn == nInstalled,
              "issuer CN agrees with OpenSSL on every certificate (%d/%d)",
              agreeCn, nInstalled);
        CHECK(agreeOrg == nInstalled,
              "issuer O agrees with OpenSSL on every certificate (%d/%d)",
              agreeOrg, nInstalled);
    }

    /* An output buffer too small for the value must be refused, not overrun. */
    {
        char  path[MAX_CERT_PATH];
        char  tiny[4];
        X509 *x = NULL;

        if ((CERT_OK == makePathToCert(serials[0], path, sizeof(path))) &&
            (CERT_OK == CertPemToX509(path, &x)) && (NULL != x)) {
            memset(tiny, 0xAA, sizeof(tiny));
            r = CertX509ReadStrProperty(x, CERTX509_ISSUER_ORGANIZATION_NAME,
                                        tiny, sizeof(tiny));
            CHECK(CERT_OK != r,
                  "4-byte buffer refused for a long field (got %d)", r);
            X509_free(x);
        }
    }

    /* ---------------- authorize, validate, remove ----------------
     * checkCert() really does call X509_verify_cert() now, so validation is
     * assertable: an authorized certificate inside its validity window must
     * verify, and one outside it must not. Expectations come from OpenSSL's
     * view of the same certificate so this holds for any corpus. */
    {
        int authorized = 0, removed = 0;
        int agreeValid = 0, expectValid = 0, inWindow;

        for (i = 0; i < nInstalled; i++) {
            if (CERT_OK == CertAddAuthorizedCert(serials[i])) {
                authorized++;
            }
        }
        printf("  authorized %d/%d\n", authorized, nInstalled);
        CHECK(authorized == nInstalled, "authorized every certificate (%d/%d)",
              authorized, nInstalled);

        for (i = 0; i < nInstalled; i++) {
            char  path[MAX_CERT_PATH];
            X509 *x = NULL;
            int   valid;

            if (CERT_OK != makePathToCert(serials[i], path, sizeof(path))) {
                continue;
            }
            if ((CERT_OK != CertPemToX509(path, &x)) || (NULL == x)) {
                continue;
            }

            /* notBefore <= now <= notAfter, per OpenSSL */
            inWindow = (0 >= X509_cmp_current_time(X509_get_notBefore(x))) &&
                       (0 <  X509_cmp_current_time(X509_get_notAfter(x)));
            X509_free(x);

            if (inWindow) {
                expectValid++;
            }

            valid = (CERT_OK == CertValidateCertificate(serials[i]));

            if (valid == inWindow) {
                agreeValid++;
            } else {
                printf("  validation mismatch on serial %d: in window %d, valid %d\n",
                       serials[i], inWindow, valid);
            }
        }

        printf("  validated: %d of %d are inside their validity window\n",
               expectValid, nInstalled);
        CHECK(agreeValid == nInstalled,
              "validation agrees with the validity window on every certificate (%d/%d)",
              agreeValid, nInstalled);
        if (expectValid == nInstalled) {
            printf("  note: every certificate in this corpus is currently valid;\n"
                   "        use gen_test_certs.sh for expired/not-yet-valid cases\n");
        }

        /* A certificate that was installed but never authorized has no trust
         * anchor and must be rejected. Before X509_verify_cert() was wired up
         * this returned CERT_OK just like everything else. */
        {
            int32_t unauth = 0;
            char    path[MAX_CERT_PATH];

            snprintf(path, sizeof(path), "%s/%s", bundle, names[0]);
            CertRemoveCertificate(serials[0]);

            if (CERT_OK == CertInstallKeyPackage(path, NULL, NULL, &unauth)) {
                r = CertValidateCertificate(unauth);
                CHECK(CERT_OK != r,
                      "an unauthorized certificate is rejected (got %d)", r);
                CertRemoveCertificate(unauth);
            }
            serials[0] = serials[nInstalled - 1];
            nInstalled--;
        }

        for (i = 0; i < nInstalled; i++) {
            if (CERT_OK == CertRemoveCertificate(serials[i])) {
                removed++;
            }
        }
        printf("  removed %d/%d\n", removed, nInstalled);
        CHECK(removed == nInstalled, "removed every certificate (%d/%d)",
              removed, nInstalled);
    }

    for (i = 0; i < nNames; i++) {
        free(names[i]);
    }
    free(names);
    free(serials);

    printf("\n%s  (%d checks, %d failures)\n",
           gFails ? "== FAILURES ==" : "== ALL PASS ==", gChecks, gFails);

    return (0 != gFails);
}
