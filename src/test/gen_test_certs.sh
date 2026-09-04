#!/bin/bash
#
# Generate a large, varied certificate corpus for ca_bundle_test.
#
#   gen_test_certs.sh <outdir> [count]
#
# The Mozilla root store from ca-certificates is only ~120 certificates and is
# fairly uniform. This produces as many as asked for, spread over RSA/EC keys
# and DN shapes that have caused trouble: non-ASCII fields, fields at the
# X.509 64-character limit, subjects with no commonName at all, multi-valued
# RDNs (which make CertX509ReadStrProperty join with commas), and validity
# windows in the past and the future.
#
# Combine with the real roots for a mixed corpus:
#
#   ./gen_test_certs.sh /tmp/corpus 800
#   cp /usr/share/ca-certificates/mozilla/*.crt /tmp/corpus/
#   ./ca_bundle_test /tmp/store /tmp/corpus
#
set -e
OUT=$1; N=${2:-1000}
rm -rf "$OUT"; mkdir -p "$OUT"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

openssl genrsa -out "$TMP/rsa2048.key" 2048 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/ec256.key" 2>/dev/null
openssl ecparam -name secp384r1  -genkey -noout -out "$TMP/ec384.key" 2>/dev/null

MAXFIELD=$(printf 'L%.0s' $(seq 1 64))          # 64 = X.509 ub-organization-name
UTF8="Ünïcödé Çertificate Authority ÅÄÖ"

for i in $(seq 1 "$N"); do
  case $((i % 7)) in
    0) K=$TMP/rsa2048.key; S="/C=NL/ST=Zuid-Holland/L=Delft/O=Test Org $i/OU=Unit $i/CN=rsa-$i.test" ;;
    1) K=$TMP/ec256.key;   S="/C=DE/O=EC Org $i/CN=ec256-$i.test" ;;
    2) K=$TMP/ec384.key;   S="/C=US/O=EC384 Org $i/OU=Deep Unit/CN=ec384-$i.test" ;;
    3) K=$TMP/rsa2048.key; S="/C=FR/O=$UTF8/CN=utf8-$i.test" ;;              # non-ASCII DN
    4) K=$TMP/ec256.key;   S="/C=GB/O=$MAXFIELD/CN=maxlen-$i.test" ;;        # 64-char field
    5) K=$TMP/rsa2048.key; S="/C=JP/OU=NoCommonName/O=NoCN Org $i" ;;        # no CN at all
    6) K=$TMP/ec256.key;   S="/C=SE/O=Multi $i/OU=Alpha/OU=Beta/OU=Gamma/CN=multi-$i.test" ;; # multi-valued RDN
  esac

  case $((i % 20)) in
    7)  openssl req -new -x509 -key "$K" -subj "$S" \
            -not_before 20100101000000Z -not_after 20110101000000Z \
            -out "$OUT/gen_$i.crt" 2>/dev/null ;;                            # expired
    13) openssl req -new -x509 -key "$K" -subj "$S" \
            -not_before 20900101000000Z -not_after 20910101000000Z \
            -out "$OUT/gen_$i.crt" 2>/dev/null ;;                            # not yet valid
    *)  openssl req -new -x509 -key "$K" -subj "$S" -days 3650 \
            -out "$OUT/gen_$i.crt" 2>/dev/null ;;
  esac
done
ls "$OUT"/*.crt | wc -l
