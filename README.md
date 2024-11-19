# Decentralized Actors
An authenticated actor messaging system in an untrusted P2P context.

## Objective
A decentralized messaging layer to enable peer-to-peer communication between participants that are generally unable to accept inbound connections due to NAT or firewall restrictions.

## Approach
The general architecture consists of cloud-hosted "Router Peers" which maintain a P2P network of publicly accessible machines. This network is responsible for routing messages between "Client Peers".