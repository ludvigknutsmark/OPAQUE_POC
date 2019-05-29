# OPAQUE PAKE Protocol Proof-of-concept

## OBVIOUSLY DON'T USE THIS IS PRODUCTION

## What is OPAQUE?
[Draft paper](https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00)

It's an asymmetric PAKE protocol. Basically a user can prove that he knows a password without the server storing the password, or even data derived from that password. The idea is the same as [Secure Remote Password](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)


## Why?
I wanted to understand the protocol, so I hacked together a client/server in Python as I read the paper.