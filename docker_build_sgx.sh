#!/usr/bin/env bash

set -e

cd /app/

git clone https://github.com/oktal/pistache.git pistache
mkdir pistache-build && cd pistache-build && cmake ../pistache
make pistache -j 10
cp src/libpistache.a ../sgx-src/lib
cd ../

. /opt/intel/sgxsdk/environment
mkdir sgx-build && cd sgx-build && cmake ../sgx-src
make rest_sgx -j 10
cd ../

mkdir -p bin
mv sgx-src/bin/* bin/

rm -rf sgx-src sgx-build pistache pistache-build