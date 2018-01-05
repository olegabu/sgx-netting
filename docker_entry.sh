#!/bin/bash

source /opt/intel/sgxsdk/environment

LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. exec ./rest_sgx 80