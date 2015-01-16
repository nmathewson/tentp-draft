### TENTP - Trivial Encrypted Network Transport Protocol (DRAFT)

WARNING: The TENTP Specification and the accompanying reference code are
PRELIMINARY AND SHOULD NOT BE USED.

The Trivial Encrypted Network Transport Protocol (TENTP) is a lightweight
alternative to TLS.  It has a different design focus and feature set as
documented below, and is released in the hopes that it will be useful to other
parties.

Overall design requirements:
 * Easy to implement securely, given the cryptographic primitives.
 * Hard to accidentally write a less secure implementation that interoperates.
 * Existing good implementations of the cryptographic primitives must already
   exist.
 * No MUST-implement patent or otherwise encumbered components.
 * All data-formats specified in a machine-readable grammar (trunnel).

Feature set:
 * A secure, authenticated transport for stream data over any network transport
   that provides reliable in-order delivery.  The base protocol only
   authenticates the server identity.
 * Versioning.
 * Not abuse-able for DDoS amplification.  (TCP/IP based, with client speaks
   first).
 * Automatic rekey during session for forward secrecy.
 * Authenticated close.
 * Authenticated per-record padding.
 * No "read blocked on write" or "write blocked on read" conditions.
 * Performance comparable to TLS with modern cryptographic primitives.
 * No timestamps and client-fingerprinting opportunities.
 * Optional client authentication.
 * Optional protocol obfuscation, in a similar manner to the obfs4 protocol.
   * Entire stream is indistinguishable from random data.
   * Active-discovery resistant.

Pending features:
 * (SHOULD) DoS resistance. (XXX: This may be met with the current design?)
 * (SHOULD) Provable secure.
 * (MAYBE) Support different underlying crypto primitives.  (XXX: Currently
    possible, would require adding 1 more round trip to the handshake.)
 * (MAYBE) Post Quantum forward-secrecy. (XXX: The V1 handshake can accomodate
   this via NTRUEncrypt similar to the basket handshake, needs specifying,
   has patent issues.)
 * (MAYBE) Support for big curves. (XXX: Possible, the V1 handshake allows for
   a fairly large payload).
 * (UNLIKELY) SNI.
 * (UNLIKELY) Post Quantum authentication. (XXX: Possible, but requires a PQ
   signature primitive that performs well without AVX2.)
 * (MAYBE) Minimize round-trips. (XXX: The V1 handshake is currently 1 round
   trip, not including the TCP handshake, so this is met?)

Unlikely to ever be supported:
 * Support for transports that do not provide reliable in-order delivery, such
   as UDP.
 * Compression.
 * Alerts.
 * Record fragmentation/reassembly.
