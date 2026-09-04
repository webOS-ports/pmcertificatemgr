# @@@LICENSE
#
#      Copyright (c) 2008-2013 LG Electronics, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# LICENSE@@@

# PmCertificateMgrTest is an executable for stand-alone testing and
# debugging.  This program is unsupported.  It is provided here to
# assist in debugging the library.
#
# Both programs here are built only when the tree is configured with
# -DBUILD_TESTS=ON. They link against the PmCertificateMgr target in this
# build, so nothing needs to be installed first.
#
# PmCertificateMgrTest additionally wants the library built with
# src/cert_debug.c and D_DEBUG_ENABLED defined; configure with
# -DBUILD_TESTS=ON -DD_DEBUG_ENABLED=ON for that.
#
# PmCertificateMgrTest calls strErrorNames[] and friends from cert_debug.c,
# which is only compiled into the library when D_DEBUG_ENABLED is set.
if(D_DEBUG_ENABLED)
	add_executable(PmCertificateMgrTest PmCertificateMgr.c)
	target_link_libraries(PmCertificateMgrTest PmCertificateMgr ${OPENSSL_LDFLAGS} ${GLIB2_LDFLAGS})
else()
	message(STATUS "PmCertificateMgrTest needs -DD_DEBUG_ENABLED=ON; skipping")
endif()

# ca_bundle_test drives the library over a real CA bundle -- by default the
# Mozilla root store from ca-certificates, which is what the recipe RDEPENDS
# on. It builds its own throwaway store, so it needs no fixtures:
#
#   cmake -DBUILD_TESTS=ON -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g -O1" ..
#   make
#   ./src/test/ca_bundle_test /tmp/certstore
#
# Point it somewhere else with a second argument or $CA_BUNDLE_DIR.
add_executable(ca_bundle_test ca_bundle_test.c)
target_link_libraries(ca_bundle_test PmCertificateMgr ${OPENSSL_LDFLAGS} ${GLIB2_LDFLAGS})

add_test(NAME ca_bundle
         COMMAND ca_bundle_test ${CMAKE_CURRENT_BINARY_DIR}/ca_bundle_store)

