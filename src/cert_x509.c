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
/* cert_x509.c: interaction with X.509 package files                         */
/*****************************************************************************/
#include <stdio.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "cert_mgr.h"
#include "cert_cfg.h"

#include "cert_utils.h"

#include "cert_x509.h"

#include <syslog.h>
#include <glib.h>

#define CERT_X509_STORE_FLAGS  0

#ifdef D_DEBUG_ENABLED
void CertX509Dump(X509 *cert);
#endif

int make_property_ssl_equiv(int);
X509_NAME* get_cname(int, X509*);
int get_subjectaltname(X509*, char*, int);
int copy_csv_to_buffer(char*, char*, const int, int);
int ip_to_string(char*,int, GENERAL_NAME*);

int CertX509ReadStrProperty(X509 *cert, int property, char *pBuf, int len)
{
  int result = CERT_OK;
  int dataIdx = 0;
  int truncated = 0;
  X509_NAME *cName;
  //  ASN1_STRING *data;
  int lproperty;

  if (NULL == cert)
    {
      result = CERT_BAD_CERTIFICATE;
      return result;
    }

  if ((NULL == pBuf) || (0 >= len))
    {
      return CERT_INSUFFICIENT_BUFFER_SPACE;
    }

  /* copy_csv_to_buffer() appends with g_strlcat(), which starts by taking
   * strlen() of the destination. pBuf comes straight from the caller and was
   * never initialised here, so that read ran off the end of short buffers. */
  pBuf[0] = '\0';

  lproperty=  make_property_ssl_equiv(property);
  cName= get_cname(property,cert);

  if (NULL == cName)
    {
      return CERT_PROPERTY_NOT_FOUND;
    }

  if(lproperty==NID_subject_alt_name){  // if 1

	  dataIdx= get_subjectaltname(cert,pBuf, len);
}  //end 1
 else{
      //### dataIdx = X509_NAME_get_text_by_NID(cName, lproperty, pBuf, len);

		char *sub_str = pBuf;
		int space_taken = 0;
		int space_left = len;

		//int loc;
		X509_NAME_ENTRY *e;
		//loc = -1;
		int lastpos = -1;
		int atleast_one_entry = 0;
		for (;;)
		{
			lastpos = X509_NAME_get_index_by_NID(cName, lproperty, lastpos);                       //(nm, NID_commonName, lastpos);
			if (lastpos == -1){
				if(atleast_one_entry)
					dataIdx = 1;
				else
					dataIdx = -1;
				break;
			}
			atleast_one_entry = 1;
			e = X509_NAME_get_entry(cName, lastpos);
			/* Do something with e */
			ASN1_IA5STRING *data;
			data = X509_NAME_ENTRY_get_data(e);
			syslog(LOG_INFO,"all common name: %s", (char *) data->data);
			if (0 < space_left) {
				space_taken = copy_csv_to_buffer(sub_str, (char *)data->data, len, space_left);

				/* 0 means the value did not fit and was truncated */
				if (0 == space_taken)
					truncated = 1;
			} else {
				truncated = 1;
			}
			space_left= space_left - space_taken;
		}

 }
  if (0 >  dataIdx) {
    return CERT_PROPERTY_NOT_FOUND;
  }

  if (truncated) {
    return CERT_BUFFER_LIMIT_EXCEEDED;
  }

  {
	  // trim trailing ','
	  size_t pBufLen = strlen(pBuf);

	  /* pBufLen is 0 whenever the entry held an empty string; pBuf[-1] is
	   * not ours to touch */
	  if ((0 < pBufLen) && (pBuf[pBufLen-1] == ','))
		pBuf[pBufLen-1] = '\0';

	  return CERT_OK;
  }
}

int get_subjectaltname(X509* cert, char* buf, int buf_len){

/*
    Copy "," separated dNSName values
    of the subjectAltName extension, to pBuf
*/

  GENERAL_NAMES *gens;
  GENERAL_NAME  *gen;
  int i;
  char *sub_str= buf;
  int space_taken=0;
  int space_left= buf_len;

  gens = X509_get_ext_d2i(cert , NID_subject_alt_name, NULL, NULL);

  for(i = 0; i < sk_GENERAL_NAME_num(gens); i++){
      gen = sk_GENERAL_NAME_value(gens, i);
      syslog(LOG_INFO,"1sub_str");

      if((gen->type == GEN_DNS)||(gen->type == GEN_URI)){
          if(0 < space_left)
	  space_taken= copy_csv_to_buffer(sub_str, (char*)gen->d.ia5->data, buf_len, space_left);
	  space_left= space_left -space_taken;
      }

      if(gen->type == GEN_IPADD) {
          if(0 < space_left) {
#define IP_STRING_MAX 40
	      char oline[IP_STRING_MAX];
	      const int oline_len = IP_STRING_MAX;
	      oline[0]='\0';
	      ip_to_string(oline, oline_len, gen);
	      space_taken= copy_csv_to_buffer(sub_str,  oline, buf_len, space_left);
	      space_left= space_left - space_taken;
	  }
      }

      syslog(LOG_INFO,"2 sub_str: %s space_taken:%d space_left:%d",sub_str, space_taken, space_left);
  }

  sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
  return CERT_OK;

}


int ip_to_string(char* oline, int oline_len, GENERAL_NAME* gen)
{
  int i;
  unsigned char *p;
  char htmp[5];

  p = gen->d.ip->data;

  if(gen->d.ip->length == 4)
    BIO_snprintf(oline, oline_len,"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);  //sizeof oline replaced by 40

  else if(gen->d.ip->length == 16){
    oline[0] = 0;
    for (i = 0; i < 8; i++){
      BIO_snprintf(htmp, sizeof htmp,"%X", p[0] << 8 | p[1]);
      p += 2;
      g_strlcat(oline, htmp, oline_len);
      if (i != 7) g_strlcat(oline, ":", oline_len);
    }
  }

  else{
    BIO_snprintf(oline, strlen((char*)oline), "IP Address <invalid>");
  }

  syslog(LOG_INFO,"IP is: %s",oline);

  return 0;

}


int copy_csv_to_buffer(char* sub_str, char* oline, const int buf_len, int space_left)
{

  // copies the string into buffer
  // and returns the number of chararacters copied

  //ASN1_STRING_to_UTF8((unsigned char**)&pBuf,gen->d.ia5);

  int req_len, space_taken;

  req_len= strlen((char*)oline);

  g_strlcat(sub_str, (char*)oline, buf_len);
  if( (req_len+1) >  space_left ){
      return 0;
  }
  space_taken=req_len+1;

  if((1+space_taken) <= space_left) {
    g_strlcat(sub_str,",", buf_len);
    space_taken = space_taken +1; // '\0' is allready taken for in (req_len+1)
  }


  return space_taken;
}


X509_NAME* get_cname (int property,X509 *cert)
{
  X509_NAME *cName;

  switch (property){
    case CERTX509_ISSUER_ORGANIZATION_NAME:
    case CERTX509_ISSUER_ORGANIZATION_UNIT_NAME:
    case CERTX509_ISSUER_COMMON_NAME:
    case CERTX509_ISSUER_COUNTRY:
    case CERTX509_ISSUER_STATE:
    case CERTX509_ISSUER_LOCATION:
      cName = X509_get_issuer_name(cert);
      break;

    case CERTX509_SUBJECT_ORGANIZATION_NAME:
    case CERTX509_SUBJECT_ORGANIZATION_UNIT_NAME:
    case CERTX509_SUBJECT_COMMON_NAME:
    case CERTX509_SUBJECT_ALT_NAME:   //ALT NAME
    case CERTX509_SUBJECT_COUNTRY:
    case CERTX509_SUBJECT_STATE:
    case CERTX509_SUBJECT_LOCATION:
      cName = X509_get_subject_name(cert);
      break;

    default:
      cName = NULL;
    }

  return cName;
}


int make_property_ssl_equiv(int property)
{

  int lProperty;

  /* make the property comensurate with SSL  */
  switch(property)
    {
    case CERTX509_ISSUER_ORGANIZATION_NAME:
    case CERTX509_SUBJECT_ORGANIZATION_NAME:
      lProperty = NID_organizationName;
      break;
    case CERTX509_ISSUER_ORGANIZATION_UNIT_NAME:
    case CERTX509_SUBJECT_ORGANIZATION_UNIT_NAME:
      lProperty = NID_organizationalUnitName;
      break;
    case CERTX509_ISSUER_COMMON_NAME:
    case CERTX509_SUBJECT_COMMON_NAME:
      lProperty = NID_commonName;
      break;
    case CERTX509_SUBJECT_ALT_NAME:  // ALT NAME
      lProperty = NID_subject_alt_name;
      break;
    case CERTX509_ISSUER_SURNAME:
    case CERTX509_SUBJECT_SURNAME:
      lProperty = NID_surname;
      break;
    case CERTX509_ISSUER_COUNTRY:
    case CERTX509_SUBJECT_COUNTRY:
	  lProperty = NID_countryName;
	  break;
    case CERTX509_ISSUER_STATE:
    case CERTX509_SUBJECT_STATE:
	  lProperty = NID_stateOrProvinceName;
	  break;
    case CERTX509_ISSUER_LOCATION:
    case CERTX509_SUBJECT_LOCATION:
	  lProperty = NID_localityName;
	  break;


    default:
      lProperty = 0;
    }

return lProperty;

}



int CertX509ReadTimeProperty(X509 *cert, int property, char *pBuf, int len)
{
  int rValue;
  char buf[64];
  ASN1_TIME *cTime;

  switch (property)
    {
    case CERTX509_START_DATE:
      cTime = X509_get_notBefore(cert);
      if (CERT_OK ==
          (rValue = getTimeString(cTime, buf, sizeof(buf))))
        {
          g_strlcpy(pBuf, buf, len);
        }
      break;

    case CERTX509_EXPIRATION_DATE:
      cTime = X509_get_notAfter(cert);
      if (CERT_OK ==
          (rValue = getTimeString(cTime, buf, sizeof(buf))))
        {
          g_strlcpy(pBuf, buf, len);
        }
      break;

    default:
      rValue = CERT_UNKNOWN_PROPERTY;
    }
  return rValue;
}

void CertX509Dump(X509 *cert)
{
#ifndef D_DEBUG_ENABLED
  (void)cert;
#else
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
      (rVal = CertX509ReadTimeProperty(cert,
					CERTX509_START_DATE,
				       outputStr, 64)))
    printf("\tStart data = %s\n", outputStr);
  else
    printf("Start date not found (%d)\n", rVal);

  if (CERT_OK ==
      (rVal = CertX509ReadTimeProperty(cert,
					CERTX509_EXPIRATION_DATE,
				       outputStr, 64)))
    printf("\tExpiration date = %s\n", outputStr);
  else
    printf("Expiration date not found (%d)\n", rVal);

#endif
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: verifyErrorToReturnCode                                         */
/*       Map an X509_V_ERR_* verification failure onto a CertReturnCode_t     */
/*                                                                           */
/*****************************************************************************/

static int verifyErrorToReturnCode(int verifyError)
{
  switch (verifyError)
    {
    case X509_V_OK:
      return CERT_OK;

    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_CRL_HAS_EXPIRED:
      return CERT_DATE_EXPIRED;

    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_CRL_NOT_YET_VALID:
      return CERT_DATE_PENDING;

    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
    case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
    case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
      return CERT_FILE_PARSE_ERROR;

    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    case X509_V_ERR_CERT_UNTRUSTED:
      return CERT_LINK_ERR;

    case X509_V_ERR_CERT_REVOKED:
      return CERT_BAD_CERTIFICATE;

    case X509_V_ERR_OUT_OF_MEM:
      return CERT_MEMORY_ERROR;

    default:
      return CERT_BAD_CERTIFICATE;
    }
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: checkCert                                                       */
/*       Verify a certificate against the trusted store                      */
/* INPUT:                                                                    */
/*       cert: the certificate to verify                                     */
/*       CAfile: a PEM bundle of trust anchors, or NULL                      */
/*       CApath: a c_rehash-style directory of anchors, or NULL              */
/*               If both are NULL, OpenSSL's system-wide store is used. If   */
/*               either is given, only that source is trusted.               */
/* RETURN:                                                                   */
/*       CERT_OK if a trusted chain was built                                */
/*       CERT_DATE_EXPIRED, CERT_DATE_PENDING for validity window failures   */
/*       CERT_LINK_ERR if no trusted chain could be built                    */
/*       CERT_BAD_CERTIFICATE for any other verification failure             */
/* NOTES:                                                                    */
/*       1) This used to build the store, populate both lookups and then     */
/*          return 0 without ever calling X509_verify_cert() -- the call was */
/*          inside "#if 0" -- so every certificate that parsed was reported  */
/*          as trusted.                                                      */
/*       2) CertAddAuthorizedCert() and CertAddTrustedCert() maintain the    */
/*          <hash>.<n> symlinks that X509_LOOKUP_hash_dir() expects, so an   */
/*          authorized self-signed certificate anchors itself.               */
/*                                                                           */
/*****************************************************************************/

int checkCert(X509 *cert, char *CAfile, char *CApath)
{
  X509_STORE *cert_ctx = NULL;
  X509_STORE_CTX *csc = NULL;
  X509_LOOKUP *lookup = NULL;
  int rValue = CERT_GENERAL_FAILURE;
  int i;

  if (NULL == cert)
    return CERT_BAD_CERTIFICATE;

  cert_ctx = X509_STORE_new();

  if (cert_ctx == NULL)
    {
      rValue = CERT_GENERAL_FAILURE;
      goto end;
    }

  lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());

  if (lookup == NULL)
    {
      rValue = CERT_GENERAL_FAILURE;
      goto end;
    }

  if (CAfile)
    {
      i = X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM);
      if (!i)
        {
          fprintf(stderr, "Error loading file %s\n", CAfile);
          rValue = CERT_OPEN_FILE_FAILED;
          goto end;
        }
    }
  else if (!CApath)
    {
      /* Only when the caller named no trust source at all do we fall back to
       * OpenSSL's system-wide store. Loading it unconditionally -- which is
       * what the openssl "verify" applet this was lifted from does -- would
       * mean anything in /etc/ssl/certs verified regardless of whether it
       * had been authorized here, and ca-certificates is always installed. */
      X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
    }

  lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());

  if (lookup == NULL)
    {
      rValue = CERT_GENERAL_FAILURE;
      goto end;
    }

  if (CApath)
    {
      i = X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM);
      if (!i)
        {
          fprintf(stderr, "Error loading directory %s\n", CApath);
          rValue = CERT_OPEN_FILE_FAILED;
          goto end;
        }
    }
  else if (!CAfile)
    {
      X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
    }

  csc = X509_STORE_CTX_new();

  if (csc == NULL)
    {
      rValue = CERT_MEMORY_ERROR;
      goto end;
    }

  if (!X509_STORE_CTX_init(csc, cert_ctx, cert, NULL))
    {
      rValue = CERT_GENERAL_FAILURE;
      goto end;
    }

  if (1 == X509_verify_cert(csc))
    {
      rValue = CERT_OK;
    }
  else
    {
      int verifyError = X509_STORE_CTX_get_error(csc);

      rValue = verifyErrorToReturnCode(verifyError);
    }

 end:

  if (csc != NULL)
    X509_STORE_CTX_free(csc);

  if (cert_ctx != NULL)
    X509_STORE_free(cert_ctx);

  return rValue;
}
