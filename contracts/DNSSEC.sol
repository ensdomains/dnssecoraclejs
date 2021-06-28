pragma solidity *;
import '@ensdomains/ens-contracts/contracts/dnssec-oracle/DNSSECImpl.sol';
import '@ensdomains/ens-contracts/contracts/dnssec-oracle/algorithms/RSASHA256Algorithm.sol';
import '@ensdomains/ens-contracts/contracts/dnssec-oracle/algorithms/P256SHA256Algorithm.sol';
import '@ensdomains/ens-contracts/contracts/dnssec-oracle/algorithms/DummyAlgorithm.sol';
import '@ensdomains/ens-contracts/contracts/dnssec-oracle/digests/SHA1Digest.sol';
import '@ensdomains/ens-contracts/contracts/dnssec-oracle/digests/SHA256Digest.sol';
import '@ensdomains/ens-contracts/contracts/dnssec-oracle/digests/DummyDigest.sol';
