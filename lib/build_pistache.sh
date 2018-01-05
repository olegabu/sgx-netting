#!/usr/bin/env bash

[ -e pistache ] || git clone https://github.com/oktal/pistache.git

mkdir -p pistache-build

pushd pistache-build
cmake ../pistache && make pistache -j 10
popd

cp pistache-build/src/libpistache.a .

rm -rf pistache pistache-build