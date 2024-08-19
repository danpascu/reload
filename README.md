
### The RELOAD protocol

RELOAD stands for REsource LOcation And Discovery and is a peer-to-peer (P2P)
signaling protocol that provides its clients with an abstract storage and
messaging service between a set of cooperating peers that form an overlay
network.

RELOAD is designed to support a P2P Session Initiation Protocol (P2PSIP)
network, but can be utilized by other applications with similar requirements
by defining new usages that specify the kinds of data that need to be stored
for a particular application. 

RELOAD defines a security model based on a certificate enrollment service
that provides unique identities. NAT traversal is a fundamental service of
the protocol. RELOAD also allows access from "client" nodes that do not
need to route traffic or store data for others.

RELOAD is described in RFC 6940. For more details see docs/overview

This project also includes a standalone DTLS-over-ICE implementation.


### Funding

This project has received funding through [NGI0 Discovery] and [NGI0 Entrust],
both funds established by [NLnet] with financial support from the European
Commission's [Next Generation Internet] program under grant agreements
No 825322 and 101069594.

Learn more at the [NLnet] project pages for [Blink RELOAD] and [SIP RELOAD].

[NLnet]: https://nlnet.nl
[Next Generation Internet]: https://ngi.eu
[NGI0 Discovery]: https://nlnet.nl/discovery
[NGI0 Entrust]: https://nlnet.nl/entrust
[Blink RELOAD]: https://nlnet.nl/project/BlinkRELOAD
[SIP RELOAD]: https://nlnet.nl/project/SIP-RELOAD

