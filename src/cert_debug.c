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
/* cert_debug.c                                                              */
/*****************************************************************************/

#ifdef D_DEBUG_ENABLED

#include <openssl/pkcs12.h>
#include <openssl/err.h>


const char *strProps[] =
{
    "CERTCFG_CONFIG_FILE",
    "CERTCFG_CONFIG_NAME",
    "CERTCFG_ROOT_DIR",
    "CERTCFG_CERT_DIR",
    "CERTCFG_CERTIFICATE",
    "CERTCFG_PRIVATE_KEY_DIR",
    "CERTCFG_PRIVATE_KEY",
    "CERTCFG_CERT_DATABASE",
    "CERTCFG_CERT_SERIAL",
    "CERTCFG_PUBLIC_KEY_DIR",
    "CERTCFG_CRL_DIR",
    "CERTCFG_PACKAGE_DIR",
    "CERTCFG_AUTH_CERT_DIR",
    "CERTCFG_MAX_PROPERTY"
};

const char *strPropNames[] =
{
    "Configuration file",
    "Configuration name",
    "Root directory",
    "Certificate directory",
    "Certificate",
    "Private Key directory",
    "Private Key",
    "Certificate Database",
    "Certificate Serial Number file",
    "Public Key directory",
    "Certificate Revocation List directory",
    "Raw package directory",
    "Authorized Certificate directory",
    "UNKNOWN PROPERTY"
};

const char *strErrorNames[] =
{
    "CERT_OK",
    "CERT_GENERAL_FAILURE",
    "CERT_UNSUPPORTED_CERT_TYPE",
    "CERT_ILLEGAL_KEY_PACKAGE_TYPE",
    "CERT_NULL_BUFFER",
    "CERT_BUFFER_LIMIT_EXCEEDED",
    "CERT_OPEN_FILE_FAILED",
    "CERT_FILE_ACCESS_FAILURE",
    "CERT_FILE_READ_FAILURE",
    "CERT_UNDEFINED_ROOT_DIR",
    "CERT_DUPLICATE",
    "CERT_MEMORY_ERROR",
    "CERT_ITER_EXCEED",
    "CERT_INVALID_ARG",
    "CERT_PASSWD_WRONG",
    "CERT_LINK_ERR",                  // File (un)link was unsuccessfull
    "CERT_INSUFFICIENT_BUFFER_SPACE", // User passed in buffer space
    "CERT_PATH_LIMIT_EXCEEDED",       // The path is too long
    "CERT_UNDEFINED_DESTINATION",    // The directory doesn't exist
    "CERT_TEMP_FILE_CREATION_FAILED",
    "CERT_CONFIG_UNAVAILABLE",        // config doesn't exist in the file
    "CERT_UNKNOWN_PROPERTY",          // the property doesn't exist
    "CERT_PROPERTY_NOT_FOUND",        // The property couldn't be resolved
    "CERT_PROPERTY_STRING_NOT_FOUND", // No string associated with the property
    "CERT_ILLFORMED_CONFIG_FILE",     // Something's broken in the file
    "CERT_DATE_PENDING",
    "CERT_DATE_EXPIRED",
    "CERT_FILE_PARSE_ERROR",
    "CERT_LOCK_FILE_CREATION_FAILURE",
    "CERT_BAD_CERTIFICATE",
    "CERT_SERIAL_NUMBER_FILE_UNAVAILABLE",
    "CERT_SERIAL_NUMBER_UNAVAILABLE",
    "CERT_DATABASE_INITIALIZATION_ERROR",
    "CERT_DATABASE_NOT_AVAILABLE",
    "CERT_DATABASE_OUT_OF_BOUNDS",
    "CERT_DATABASE_LOCKED",
    "CERT_TOO_MANY_HASHED_FILES",
    "UNKNOWN ERROR"
};

/* taken from openssl/crypto/objects/objects.h */
#define ENCRYPT_NAME_MAX 25
const char *encryptNames[ENCRYPT_NAME_MAX] =
{
    "undefined",
    "rsadsi",
    "pkcs",
    "md2",
    "md5",
    "rc4",
    "rsaEncryption",
    "m2dWithRSAEncryption",
    "md5WithRSAEncryption",
    "pbeWithMD2AndDES-CBC",
    "pbeWithMD5AndDES-CBC",
    "X500",
    "X509",
    "CommonName",
    "CountryName",
    "locality",
    "State",
    "Organization",
    "OrganizationUnitName",
    "RSA",
    "pkcs7",
    "pkcs7-data",
    "pkcs7-signedData",
    "pkcs7-envelopeData",
    "pkcs7-signedAndEnvelopedData",
};

void initSSLErrors(void)
{
    ERR_load_crypto_strings();
    ERR_load_PKCS12_strings();
}

void logSSLErrors(void)
{
    // we'll get this error if bad passwd: PEM_F_PEM_DO_HEADER ???
    for (;; )
    {
    unsigned long sslerr = ERR_get_error();
    if ( 0 == sslerr )
    {
        break;
    }
    else
    {
        /* Ok to call these multiple times: they're only loaded once
           internally. */
        ERR_load_CRYPTO_strings();
        ERR_load_SSL_strings();

        char buf[512];
        ERR_error_string_n( sslerr, buf, sizeof(buf) );

    }
    }
}

CertReturnCode CertPKCS12Dump(const char *pPkgPath)
{
  CertReturnCode result = CERT_GENERAL_FAILURE;
  FILE *fp = fopen(pPkgPath, "r");

  if (NULL != fp)
    {
      PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);

      fclose( fp );

      if (NULL != p12)
        {
#if 0
          const char *pass = passForP12(p12, pwdbuf, sizeof(pwdbuf),
                                        pcbk, pwd_ctxt);
#else
          const char *pass = "Help Im a Rock";
#endif
          if (NULL != pass)
            {
              EVP_PKEY *pkey;
              X509 *cert;
              STACK_OF(X509) *ca = NULL;

              if (0 != PKCS12_parse(p12, pass, &pkey, &cert, &ca))
                {
                  char destPath[MAX_CERT_PATH];

                  if (NULL != pkey)
                    {
                      result = CertCfgGetObjectStrValue(CERTCFG_PRIVATE_KEY_DIR,
                                               destPath, MAX_CERT_PATH);
                      printf("PKEY->type = %s (%d)\n",
                             encryptNames[pkey->type], pkey->type);
                      printf("PKEY->save_type = 0x%x\n", pkey->save_type);
                      EVP_PKEY_free(pkey );
                    }
                  if (NULL != cert)
                    {
                      result = CertCfgGetObjectStrValue(CERTCFG_CERT_DIR,
                                               destPath, MAX_CERT_PATH);
                      CertX509Dump(cert);
                      X509_free(cert);
                    }
                  if (NULL != ca)
                    {
                      result = CertCfgGetObjectStrValue(CERTCFG_PRIVATE_KEY_DIR,
                                               destPath, MAX_CERT_PATH);
                      sk_X509_free(ca);
                    }
                }
              else
                {
                  /* PKCS 12 parse error */
                }
            }
          else
            {
              /* Password failure */
            }
          PKCS12_free( p12 );
        }
    }
  return result;

}

void CertX509Dump(X509 *cert)
{
  char outputStr[64];
  int rVal;

  printf("Certificate:\n");
  if (CERT_OK ==
      (rVal = CertX509ReadStrProperty(cert,
                       CERTX509_ISSUER_COMMON_NAME,
                       outputStr, 64)))
    printf("\tIssuer Common name = %s\n", outputStr);
  else
    printf("Issuer Common Name not found (%d)\n", rVal);

  if (CERT_OK ==
      (rVal = CertX509ReadStrProperty(cert,
                       CERTX509_SUBJECT_COMMON_NAME,
                       outputStr, 64)))
    printf("\tSubject Common name = %s\n", outputStr);
  else
    printf("Subject Common Name not found (%d)\n", rVal);


 if (CERT_OK ==
      (rVal = CertX509ReadStrProperty(cert,
                                       CERTX509_SUBJECT_ALT_NAME, //ALT NAME
                                       outputStr, 64)))
    printf("\tSubject Alt name = %s\n", outputStr);
  else
    printf("Subject Alt name not found (%d)\n", rVal);


  if (CERT_OK ==
      (rVal = CertX509ReadStrProperty(cert,
                       CERTX509_ISSUER_ORGANIZATION_NAME,
                       outputStr, 64)))
    printf("\tIssuer Org name = %s\n", outputStr);
  else
    printf("Issuer Org Name not found (%d)\n", rVal);

  if (CERT_OK ==
      (rVal = CertX509ReadStrProperty(cert,
                       CERTX509_SUBJECT_ORGANIZATION_NAME,
                       outputStr, 64)))
    printf("\tSubject Org name = %s\n", outputStr);
  else
    printf("Subject Org Name not found (%d)\n", rVal);


  /* Check to see if we have a valid certificate by date */
  rVal = checkCertDates(cert);

  switch (rVal)
    {
    case CERT_OK:
      printf("Certificate is VALID\n");
      break;

    case CERT_DATE_PENDING:
      printf("Certificate is not yet valid\n");
      break;

    case CERT_DATE_EXPIRED:
      printf("Certificate is expired\n");
      break;

    }
  if (CERT_OK ==
      (rVal = CertX509ReadStrProperty(cert,
                    CERTX509_START_DATE,
                       outputStr, 64)))
    printf("\tStart data = %s\n", outputStr);
  else
    printf("Start date not found (%d)\n", rVal);

  if (CERT_OK ==
      (rVal = CertX509ReadStrProperty(cert,
                    CERTX509_EXPIRATION_DATE,
                       outputStr, 64)))
    printf("\tExpiration date = %s\n", outputStr);
  else
    printf("Expiration date not found (%d)\n", rVal);
}

#endif /* D_DEBUG_ENABLED */
