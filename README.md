# Secure Netting Algorithm Running in a protected Intel SGX Enclave


This module implements *semi local compression algorithm* described 
in [Optimizing the Compression Cycle: Algorithms for Multilateral Netting in OTC Derivatives Markets](doc/SSRN-id2273802.pdf). 

The goal is to run a netting algo in an enclave so that each party can submit their inputs: 
payments (direction, recipient and amount) or derivative contracts (direction, recipient, notional) encrypted to hide them
from other parties, adversaries and the executor of the algo. The inputs are decrypted within the enclave, the
algo calculates, results are encrypted and returned to the parties.

1. enclave is created, a pair of keys is generated: the private key never leaves the enclave, public one is made 
available for every party to submit their inputs.
1. each party uses enclave's public key to encrypt their inputs: payments to other parties. The inputs are submitted
to the algo as a one dimensional array and become a row in a symmetrical matrix of payments. Along with the inputs the
party submits its public key with which the enclave will encrypt the results to send back.
1. once every party's rows have been submitted, the algo decrypts the matrix with the enclave's private key and 
calculates the results: a sparser symmetrical matrix whose rows still represent each party's payments whose number is
now reduced by the compression algo.
1. each party queries the algo for their part of the results: a row of payments. The algo encrypts the results with the 
party's public key it has saved with the inputs and returns encrypted results. The party decrypts the results using their private key.
 
 # Milestones
 
1. implement compression algo in C using description in the publication and 
[Java code](doc/SemiLocalCompressionAlgorithm.java) as reference. 
*Deliverables*: a compiled library with the implementation, an executable to run it, unit tests. Input to the library: a 
matrix of payments in clear text. Output: matrix of the results in clear text.
1. put the library into the enclave to run the algo
*Deliverables*: an executable that establishes an enclave and runs the algo from the library. Input and outputs are 
still clear text
1. create a service that receives encrypted input as rows to the matrix one by one, calculates once it's received all
   inputs and outputs encrypted results.
*Deliverables*: an executable that takes inputs as files of one dimensional arrays of numbers representing a row in the
 input matrix plus a public key; outputs are files with arrays of resulting numbers encrypted by the party's public key
1. http or grpc endpoint to receive inputs and respond to queries for results
1. add remote attestation query endpoint
1. put in a docker container 

# Requirements
For this project, you mainly need the SGX SDK.
You can also install the driver and PSW for hardware support.
* [Get them here](https://01.org/intel-software-guard-extensions/downloads)

# Building
First, load the sgx sdk environment into your shell
~~~
$ . /opt/intel/sgxsdk/environment
~~~
To build, create a build directory and run cmake to generate the makefiles
~~~
$ mkdir sgx-netting-build && cd sgx-netting-build
$ cmake /path/to/source/folder -DSGX_MODE=SIM
$ make
~~~
Where /path/to/source/folder is the relative/absolute path to this repo.

SGX_MODE can be 'HW'

# Run
The built executable 'app' is under sgx-netting-build/bin. Run it as such:
~~~
$ . /opt/intel/sgxsdk/environment # load the sgx sdk environment if not loaded
$ cd sgx-netting-build/bin
$ ./app
~~~

# Ubuntu 16.04 the 'make everything work'
~~~
sudo apt-get install build-essential python
wget https://download.01.org/intel-sgx/linux-1.9/sgx_linux_ubuntu16.04.1_x64_sdk_1.9.100.39124.bin
sh sgx_linux_ubuntu16.04.1_x64_sdk_1.9.100.39124.bin # choose install directory - /opt/intel
. /opt/intel/sgxsdk/environment # source the sgxsdk environment into the shell
git clone git@github.com:olegabu/sgx-netting.git
pushd sgx-netting && git checkout uglydev && popd
mkdir sgx-netting-build
cd sgx-netting-build
cmake ../sgx-netting -DSGX_MODE=SIM
make -j 10
~~~

# REST

bin/rest_sgx is the rest server binary.

By default it listens on 0.0.0.0:8080.

usage:
rest_sgx [port] [threads]

# Docker

There is a Dockerfile for running the rest server under docker.

To build it, from the source directory run:
~~~
docker build -t sgx .
~~~

Then run it as:
~~~
docker run -t -p 8080:80 sgx
~~~~
This binds the server to the local port 8080.

To keep the state of the enclave (i.e. its cryptographic state, so it can decrypt inputs), reuse the same container.

# Tests

There are 2 tests that can be run using CMake CTest.

Do not forget to load the SGX env first.

To run the tests,  go to the cmake build directory and:
~~~
ctest --verbose
~~~


# Todo
Not use the enclave_private.pem in the git repo for signing the enclave and use the 2-step method for signing the enclave.

