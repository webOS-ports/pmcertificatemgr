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
/* store_lifecycle_test.c                                                    */
/*                                                                           */
/* Covers the behaviours ca_bundle_test does not: first-boot provisioning,   */
/* duplicate detection, and whether removing a certificate really revokes    */
/* trust. These are the paths where bugs have actually hidden, because none  */
/* of them show up when each certificate is installed exactly once into a    */
/* store somebody prepared by hand.                                          */
/*                                                                           */
/*   store_lifecycle_test <scratch-dir> [bundle-dir]                         */
/*                                                                           */
/*****************************************************************************/

/* nftw() and friends: must precede every system header */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <unistd.h>

#include "cert_mgr.h"
#include "cert_cfg.h"
#include "cert_db.h"
#include "cert_x509.h"
#include "cert_mgr_prv.h"

#include "test_store.h"

#define DEFAULT_BUNDLE "/usr/share/ca-certificates/mozilla"

/* Count entries under /proc/self/fd, to catch descriptors leaking per call */
static int openFds(void)
{
    DIR *d = opendir("/proc/self/fd");
    struct dirent *e;
    int n = 0;

    if (NULL == d) {
        return -1;
    }
    while (NULL != (e = readdir(d))) {
        if ('.' != e->d_name[0]) {
            n++;
        }
    }
    closedir(d);

    return n - 1;   /* the readdir fd itself */
}

static int dirExists(const char *path)
{
    struct stat sb;
    return (0 == stat(path, &sb)) && S_ISDIR(sb.st_mode);
}

int main(int argc, char **argv)
{
    const char *scratch;
    const char *bundle;
    char        cnfPath[MAX_CERT_PATH];
    char        path[MAX_CERT_PATH];
    char        dir[MAX_CERT_PATH];
    char      **names = NULL;
    int32_t    *first = NULL, *second = NULL;
    int         nNames, i, r;
    int32_t     count = 0;

    if (argc < 2) {
        fprintf(stderr,
                "usage: %s <scratch-dir> [bundle-dir]\n"
                "  scratch-dir  empty directory to build a store under\n"
                "  bundle-dir   directory of .crt files (default %s,\n"
                "               or $CA_BUNDLE_DIR)\n",
                argv[0], DEFAULT_BUNDLE);
        return 2;
    }

    scratch = argv[1];
    bundle = (argc > 2) ? argv[2] : getenv("CA_BUNDLE_DIR");
    if (NULL == bundle) {
        bundle = DEFAULT_BUNDLE;
    }

    /* ------------------------------------------------------------------
     * First boot: only the configuration file exists. Everything the
     * configuration names has to be provisioned by the library itself,
     * which is exactly what a device relies on -- the recipe installs
     * openssl.cnf and nothing under the root it points at.
     * ------------------------------------------------------------------ */
    if (0 != tsWriteConfig(scratch, cnfPath, sizeof(cnfPath))) {
        return 2;
    }
    printf("  config: %s\n", cnfPath);
    printf("  bundle: %s\n", bundle);

    r = CertInitCertMgr(cnfPath);
    CHECK(CERT_OK == r, "CertInitCertMgr on a bare store -> %s", tsReturnCode(r));
    if (CERT_OK != r) {
        REPORT();
        return 1;
    }

    {
        static const struct {
            certcfg_Property_t prop;
            const char        *what;
        } needed[] = {
            { CERTCFG_CERT_DIR,       "certificate" },
            { CERTCFG_PRIVATE_KEY_DIR,"private key" },
            { CERTCFG_CRL_DIR,        "CRL" },
            { CERTCFG_AUTH_CERT_DIR,  "authorized" },
            { CERTCFG_TRUSTED_CA_DIR, "trusted CA" }
        };
        size_t n;

        for (n = 0; n < sizeof(needed) / sizeof(needed[0]); n++) {
            if (CERT_OK != CertCfgGetObjectStrValue(needed[n].prop, dir, sizeof(dir))) {
                continue;
            }
            CHECK(dirExists(dir), "%s directory was provisioned (%s)",
                  needed[n].what, dir);
        }

        /* The lock file belongs in the configured root, not the working
         * directory -- CertInitCertMgr() used to fall back to "." whenever
         * the configured root did not fit in its 64 byte buffer. */
        CHECK(0 != access(".lock", F_OK),
              "no lock file was dropped in the working directory");
    }

    /* ------------------------------------------------------------------
     * Install the bundle twice. The second pass must be recognised as
     * duplicates: same serial numbers back, no new database rows.
     * ------------------------------------------------------------------ */
    nNames = tsListCerts(bundle, &names);
    if (0 >= nNames) {
        fprintf(stderr, "no certificates in %s\n", bundle);
        REPORT();
        return 2;
    }
    printf("  certs:  %d\n\n", nNames);

    first  = calloc((size_t)nNames, sizeof(*first));
    second = calloc((size_t)nNames, sizeof(*second));

    if ((NULL == first) || (NULL == second)) {
        free(first);
        free(second);
        tsFreeCerts(names, nNames);
        return 2;
    }

    {
        int pass, installed[2] = { 0, 0 };
        int32_t after[2] = { 0, 0 };

        for (pass = 0; pass < 2; pass++) {
            int32_t *out = pass ? second : first;

            for (i = 0; i < nNames; i++) {
                int32_t serial = 0;

                snprintf(path, sizeof(path), "%s/%s", bundle, names[i]);

                if (CERT_OK == CertInstallKeyPackage(path, NULL, NULL, &serial)) {
                    out[i] = serial;
                    installed[pass]++;
                }
            }
            CertGetCertificateCount(CERT_STATUS_ALL, &count);
            after[pass] = count;
            printf("  pass %d: installed %d/%d, database holds %d\n",
                   pass + 1, installed[pass], nNames, count);
        }

        CHECK(installed[0] == nNames, "first pass installed everything (%d/%d)",
              installed[0], nNames);
        CHECK(installed[1] == nNames, "second pass accepted everything (%d/%d)",
              installed[1], nNames);
        CHECK(after[0] == nNames, "database holds one row per certificate (%d)",
              after[0]);
        CHECK(after[1] == after[0],
              "reinstalling added no rows (%d then %d)", after[0], after[1]);

        {
            int same = 0;

            for (i = 0; i < nNames; i++) {
                if (first[i] == second[i]) {
                    same++;
                }
            }
            CHECK(same == nNames,
                  "reinstalling returned the original serial every time (%d/%d)",
                  same, nNames);
        }
    }

    /* ------------------------------------------------------------------
     * Removing a certificate must revoke it. Reinstalling without
     * authorizing must leave it untrusted -- before checkCert() actually
     * verified, and while it still fell back to OpenSSL's system store,
     * this came back CERT_OK.
     * ------------------------------------------------------------------ */
    {
        int fdBefore, fdAfter;
        int32_t reinstalled = 0;

        for (i = 0; i < nNames; i++) {
            CertAddAuthorizedCert(first[i]);
        }

        r = CertValidateCertificate(first[0]);
        CHECK(CERT_OK == r, "an authorized certificate validates (%s)",
              tsReturnCode(r));

        r = CertRemoveCertificate(first[0]);
        CHECK(CERT_OK == r, "CertRemoveCertificate -> %s", tsReturnCode(r));

        snprintf(path, sizeof(path), "%s/%s", bundle, names[0]);
        r = CertInstallKeyPackage(path, NULL, NULL, &reinstalled);
        CHECK(CERT_OK == r, "the removed certificate reinstalls (%s)",
              tsReturnCode(r));
        CHECK(reinstalled != first[0],
              "a removed certificate is no longer a duplicate (serial %d then %d)",
              first[0], reinstalled);

        r = CertValidateCertificate(reinstalled);
        CHECK(CERT_OK != r,
              "installed but unauthorized must not validate (got %s)",
              tsReturnCode(r));

        r = CertAddAuthorizedCert(reinstalled);
        CHECK(CERT_OK == r, "authorizing it again -> %s", tsReturnCode(r));
        r = CertValidateCertificate(reinstalled);
        CHECK(CERT_OK == r, "and then it validates (%s)", tsReturnCode(r));

        /* Repeated read-only traffic must not accumulate descriptors. */
        fdBefore = openFds();
        for (i = 0; i < 20; i++) {
            int32_t n = 0;
            CertGetCertificateCount(CERT_STATUS_ALL, &n);
        }
        fdAfter = openFds();
        printf("  fds: %d -> %d after 20 queries\n", fdBefore, fdAfter);
        CHECK(fdAfter <= fdBefore + 2, "no descriptor growth (%d -> %d)",
              fdBefore, fdAfter);
    }

    free(first);
    free(second);
    tsFreeCerts(names, nNames);

    REPORT();

    return (0 != gFails);
}
