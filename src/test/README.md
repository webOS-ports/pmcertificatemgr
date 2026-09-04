# Tests

Off by default. Configure with `-DBUILD_TESTS=ON`:

```sh
cmake -DBUILD_TESTS=ON ..
make
ctest --output-on-failure
```

Each program provisions its own store from nothing but a generated
`openssl.cnf` — the same thing a device does on first boot, where the recipe
installs the config file and nothing under the root it names — and wipes that
store on startup, so they are re-runnable against the same build tree.

| test | covers |
|---|---|
| `ca_bundle_test` | install, read back, authorize, validate and remove every certificate in a bundle. Each value is compared against what OpenSSL says about the same certificate, so it holds for any corpus. |
| `store_lifecycle_test` | first-boot provisioning, duplicate detection on reinstall, whether removal actually revokes trust, and file descriptor growth. |
| `certmgrd_replay_test` | the call sequences certmgrd makes (`install_cb`, `list_cb`, `remove_cb`), so the pairing is exercised without needing the luna bus. Keep in step with `certmgrd/src/certmgr_service.c`. |

## Certificates to test with

By default they use the Mozilla root store from `ca-certificates`
(`/usr/share/ca-certificates/mozilla`), which the recipe already RDEPENDs on.
Point them somewhere else with a second argument or `$CA_BUNDLE_DIR`.

That bundle is only ~120 certificates and fairly uniform. `gen_test_certs.sh`
produces as many as you ask for, spread over RSA and EC keys and the DN shapes
that have caused trouble — non-ASCII fields, fields at the X.509 64-character
limit, subjects with no commonName, multi-valued RDNs, and validity windows in
the past and the future:

```sh
./src/test/gen_test_certs.sh /tmp/corpus 800
cp /usr/share/ca-certificates/mozilla/*.crt /tmp/corpus/
./src/test/ca_bundle_test /tmp/store /tmp/corpus
```

## Sanitizers

This is where these tests earn their keep — most of what they have caught was
a leak or an overrun rather than a wrong answer:

```sh
cmake -DBUILD_TESTS=ON \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" ..
make
ASAN_OPTIONS=detect_leaks=1 ./src/test/ca_bundle_test /tmp/store /tmp/corpus
```

Note the store grows: installing N certificates costs O(N) work per install
because duplicate detection scans what is already there, so a 900-certificate
corpus under sanitizers takes a few minutes.

## PmCertificateMgrTest

The original interactive debug shell. It needs the tracing helpers in
`cert_debug.c`, so it is only built with `-DD_DEBUG_ENABLED=ON`, and it is not
wired into ctest.
