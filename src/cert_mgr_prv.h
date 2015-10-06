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

#ifndef __CERT_MGR_PRIV__
#define __CERT_MGR_PRIV__

#include "cert_mgr.h"

struct cm_pem_cb_data
{
    CertPassCallback cb;
    void *ctx;
    int pwd_len;
    char *cached_pwd;
};

#ifdef __cplusplus
extern "C" {
#endif


static CertReturnCode derToX509(const char *der_path, X509 **o_cert);

static CertReturnCode p12ToX509(const char *p12_path, void *pass, X509 **o_cert, EVP_PKEY **o_key, STACK_OF(X509) **o_ca);

static CertReturnCode p12ToFile(const char *pkg_path, const char *dst_path, CertPassCallback pcbk, void *pass, int *o_sn);

static CertReturnCode derToFile(const char *cert_path, const char *dst_path, int *o_sn);

static CertReturnCode pemToFile(const char *cert_path, const char *dst_path, CertPassCallback pcbk, void *pwd_ctxt, int *o_sn);

static int pem_callback(char *o_buf, int len, int rwflag, void *cb_arg);

static CertReturnCode getNextSerialNumber(int *o_sn);

static CertReturnCode checkIfCertsDiffer(const char *path1, const char *path2);

static CertReturnCode removeBrokenLinkFiles(void);

static CertReturnCode removeCertLink(unsigned long hash, const char *fullpath, CertCfgProperty basedir);

static CertReturnCode removeAllCertLinks(const char *fullpath);

static CertReturnCode removeCert(int sn, const char *path, const char *prefix, const char *ext, int *o_err);

static CertReturnCode getCertLinkPath(char *o_buf, int len, unsigned long hash, const char *infile, CertCfgProperty basedir);

static CertFileExt getFileType(const char *file);

static CertReturnCode installCACerts(STACK_OF(X509) *ca, const char *base_name, int sn);

static CertReturnCode installX509Cert(const X509 *cert, const char *base_name, int *io_sn);

static CertReturnCode installDSAPrivKey(const DSA *dsa_priv, const char *base_name, int sn);

static CertReturnCode installDSAPubKey(const DSA *dsa_pub, const char *base_name, int sn);

static CertReturnCode installRSAPrivKey(const RSA *rsa_priv, const char *base_name, int sn);

static CertReturnCode installRSAPubKey(const RSA *rsa_pub, const char *base_name, int sn);

static CertReturnCode installECPrivKey(const EC_KEY *ec_priv_key, const char *base_name, int sn);

static CertReturnCode installX509CRL(const X509_CRL *crl, const char *base_name, int sn);

static CertReturnCode makeCertPathFromSerial(int sn, char *o_path, int len);

static CertReturnCode validateCertPath(const char *path, int sn, CertPkgType cert_type, CertMgrError *o_err);

static int getCertSerialFromLocalStore(const X509 *cert);

static CertReturnCode seedSSLPrng(void);

#ifdef __cplusplus
}
#endif

#endif  /* __CERT_MGR_PRIV__ */
