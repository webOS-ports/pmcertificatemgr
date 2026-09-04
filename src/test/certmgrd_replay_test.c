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
/* certmgrd_replay_test.c                                                    */
/*                                                                           */
/* Replays the library call sequences certmgrd makes -- install_cb, list_cb  */
/* and remove_cb from its certmgr_service.c -- without needing the luna-bus. */
/* The point is to exercise the pairing of the two components, which is      */
/* where the interesting bugs live: listAll parsed the database serial with  */
/* atoi() while every writer in this library formats it with "%X", so over a */
/* full CA bundle roughly a third of the entries vanished from the listing   */
/* and some of the rest described the wrong certificate.                     */
/*                                                                           */
/* Keep this in step with certmgrd/src/certmgr_service.c.                    */
/*                                                                           */
/*   certmgrd_replay_test <scratch-dir> [bundle-dir]                         */
/*                                                                           */
/*****************************************************************************/

/* nftw() and friends: must precede every system header */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "cert_mgr.h"
#include "cert_cfg.h"
#include "cert_db.h"
#include "cert_x509.h"
#include "cert_mgr_prv.h"

#include "test_store.h"

#define DEFAULT_BUNDLE "/usr/share/ca-certificates/mozilla"

/* certmgrd list_cb: walk the database and build a reply row per certificate.
 * Returns the number of rows it managed to produce, or -1. */
static int certmgrdListAll(int *outSkipped)
{
    int32_t count = 0, n;
    int rows = 0, skipped = 0;
    char serial[128];
    char status[8];
    char path[MAX_CERT_PATH];
    char property_start[64];
    char property_expiration[64];
    char property_issuer[64];
    char property_issuer_organization[64];
    char property_subject_organization[64];
    char property_subject[64];
    char property_subject_surname[64];
    char property_subject_organization_unit[64];
    char property_issuer_organization_unit[64];
    X509 *cert = NULL;

    if (0 != CertGetDatabaseInfo(CERT_DATABASE_SIZE, &count)) {
        return -1;
    }

    for (n = 0; n < count; n++) {
        long parsed;
        char *endp = NULL;
        int num;

        if (0 != CertGetDatabaseStrValue(n, CERT_DATABASE_ITEM_SERIAL,
                                         serial, sizeof(serial))) {
            continue;
        }

        /* base 16 -- the database stores what CertCreateDatabaseItem wrote
         * with "%X". certmgrd used atoi() here. */
        errno = 0;
        parsed = strtol(serial, &endp, 16);

        if ((0 != errno) || (endp == serial) || (parsed <= 0)) {
            skipped++;
            continue;
        }
        num = (int)parsed;

        if (0 != makePathToCert(num, path, MAX_CERT_PATH)) {
            skipped++;
            continue;
        }
        if (0 != CertPemToX509(path, &cert)) {
            skipped++;
            continue;
        }

        CertGetDatabaseStrValue(n, CERT_DATABASE_ITEM_STATUS, status, sizeof(status));
        CertX509ReadTimeProperty(cert, CERTX509_START_DATE, property_start, 64);
        CertX509ReadTimeProperty(cert, CERTX509_EXPIRATION_DATE, property_expiration, 64);
        CertX509ReadStrProperty(cert, CERTX509_ISSUER_COMMON_NAME, property_issuer, 64);
        CertX509ReadStrProperty(cert, CERTX509_SUBJECT_ORGANIZATION_NAME,
                                property_subject_organization, 64);
        CertX509ReadStrProperty(cert, CERTX509_ISSUER_ORGANIZATION_NAME,
                                property_issuer_organization, 64);
        CertX509ReadStrProperty(cert, CERTX509_SUBJECT_COMMON_NAME, property_subject, 64);
        CertX509ReadStrProperty(cert, CERTX509_SUBJECT_SURNAME, property_subject_surname, 64);
        CertX509ReadStrProperty(cert, CERTX509_SUBJECT_ORGANIZATION_UNIT_NAME,
                                property_subject_organization_unit, 64);
        CertX509ReadStrProperty(cert, CERTX509_ISSUER_ORGANIZATION_UNIT_NAME,
                                property_issuer_organization_unit, 64);

        X509_free(cert);
        cert = NULL;
        rows++;
    }

    if (NULL != outSkipped) {
        *outSkipped = skipped;
    }

    return rows;
}

int main(int argc, char **argv)
{
    const char *scratch, *bundle;
    char    cnfPath[MAX_CERT_PATH];
    char    path[MAX_CERT_PATH];
    char  **names = NULL;
    int32_t *serials = NULL;
    int     nNames, nInstalled = 0, i, rows, skipped = 0, r;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <scratch-dir> [bundle-dir]\n", argv[0]);
        return 2;
    }

    scratch = argv[1];
    bundle = (argc > 2) ? argv[2] : getenv("CA_BUNDLE_DIR");
    if (NULL == bundle) {
        bundle = DEFAULT_BUNDLE;
    }

    if (0 != tsWriteConfig(scratch, cnfPath, sizeof(cnfPath))) {
        return 2;
    }

    r = CertInitCertMgr(cnfPath);
    CHECK(CERT_OK == r, "CertInitCertMgr -> %s", tsReturnCode(r));
    if (CERT_OK != r) {
        REPORT();
        return 1;
    }

    nNames = tsListCerts(bundle, &names);
    if (0 >= nNames) {
        fprintf(stderr, "no certificates in %s\n", bundle);
        return 2;
    }
    serials = calloc((size_t)nNames, sizeof(*serials));
    if (NULL == serials) {
        tsFreeCerts(names, nNames);
        return 2;
    }
    printf("  corpus: %d certificates\n", nNames);

    /* certmgrd install_cb: CertInstallKeyPackage then CertAddAuthorizedCert */
    for (i = 0; i < nNames; i++) {
        int32_t serial = 0;

        snprintf(path, sizeof(path), "%s/%s", bundle, names[i]);

        if (CERT_OK == CertInstallKeyPackage(path, NULL, NULL, &serial)) {
            if (CERT_OK == CertAddAuthorizedCert(serial)) {
                serials[nInstalled++] = serial;
            }
        }
    }
    printf("  install + authorize: %d/%d\n", nInstalled, nNames);
    CHECK(nInstalled == nNames, "installed and authorized everything (%d/%d)",
          nInstalled, nNames);

    /* certmgrd list_cb */
    rows = certmgrdListAll(&skipped);
    printf("  listAll: %d rows, %d skipped\n", rows, skipped);
    CHECK(0 <= rows, "listAll completed");
    CHECK(rows == nInstalled,
          "listAll returned every installed certificate (%d/%d)", rows, nInstalled);
    CHECK(0 == skipped, "listAll skipped nothing (%d skipped)", skipped);

    /* Repeat: certmgrd serves this on every subscription, so a per-call leak
     * or descriptor leak here shows up quickly on a device. */
    for (i = 0; i < 5; i++) {
        (void)certmgrdListAll(NULL);
    }

    /* certmgrd remove_cb */
    {
        int removed = 0;

        for (i = 0; i < nInstalled; i++) {
            if (CERT_OK == CertRemoveCertificate(serials[i])) {
                removed++;
            }
        }
        printf("  remove: %d/%d\n", removed, nInstalled);
        CHECK(removed == nInstalled, "removed everything (%d/%d)",
              removed, nInstalled);

        rows = certmgrdListAll(&skipped);
        CHECK(0 == rows, "listAll is empty after removing everything (%d rows)",
              rows);
    }

    free(serials);
    tsFreeCerts(names, nNames);

    REPORT();

    return (0 != gFails);
}
