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
1. put the library into the enclave to run the algo.
*Deliverables*: an executable that establishes an enclave and runs the algo from the library. Input and outputs are 
still clear text.
1. create a service that receives encrypted input as rows to the matrix one by one, calculates once it's received all
   inputs and makes results available for the parties to query.
*Deliverables*: an executable with an http endpoint to receive inputs and respond to queries for results
1. add remote attestation query endpoint
1. put in a docker container 