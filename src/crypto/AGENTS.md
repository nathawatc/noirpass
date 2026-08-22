# Crypto Ownership

Own Secret Service session transport cryptography under `src/crypto/`: algorithm negotiation,
Diffie-Hellman validation, wire encoding, cipher lifetime, and zeroization. At-rest OpenPGP is owned
by [`../gpg/AGENTS.md`](../gpg/AGENTS.md).

## Required Protocol

Support the specification identifiers exactly:

- `plain`: no additional transport encryption; D-Bus socket protections remain the transport boundary.
- `dh-ietf1024-sha256-aes128-cbc-pkcs7`: RFC 2409 Second Oakley 1024-bit MODP group. D-Bus DH
  public integers use unsigned big-endian integer encoding and are not fixed-width; the internal
  shared secret passed to HKDF is left-padded to the group's 128-byte width.

For the DH algorithm:

- Derive the session key with HKDF-SHA256, no salt, and empty info.
- Encrypt/decrypt payloads with AES-128-CBC and PKCS#7 padding.
- Preserve the exact byte order, widths, algorithm identifier, IV handling, and ciphertext framing
  required by Secret Service clients. Do not substitute a modern group, KDF, AEAD, or backend without
  an explicit protocol/design change and compatibility plan.

## Hostile Input and Memory

- Treat every client-provided algorithm, DH public value, IV, ciphertext length, and padding byte as
  hostile. Validate lengths and DH range before arithmetic, allocation, or decryption.
- Reject malformed/truncated values deterministically; do not accept ambiguous encodings.
- Keep DH private/shared/session keys and plaintext in zeroizing storage wherever this layer controls
  their lifetime. Do not log secret bytes or move plaintext into ordinary long-lived structures.
- Keep transport crypto independent from at-rest OpenPGP encryption; changing one layer must not
  silently change the other.

Pure handshake, encoding, invalid-input, and round-trip tests belong beside this layer. D-Bus sender
and session ownership rules belong to [`../service/AGENTS.md`](../service/AGENTS.md).
