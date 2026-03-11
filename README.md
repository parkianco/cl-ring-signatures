# cl-ring-signatures

Pure Common Lisp ring signatures and MuSig2 aggregate Schnorr signatures with **zero external dependencies**.

## Features

- **Ring signatures**: Anonymous signatures within a group
- **Linkable rings**: Detect double-signing
- **MLSAG**: Multilayer Linkable Spontaneous Anonymous Group
- **MuSig2**: Aggregate Schnorr signatures
- **Pure Common Lisp**: No CFFI, no external libraries

## Installation

```lisp
(asdf:load-system :cl-ring-signatures)
```

## Quick Start

```lisp
(use-package :cl-ring-signatures)

;; Create ring signature
(let* ((ring-pubkeys (list pk1 pk2 pk3 pk4))
       (signer-index 2)  ; We are pk3
       (secret-key sk3))
  ;; Sign
  (let ((sig (ring-sign message ring-pubkeys signer-index secret-key)))
    ;; Verify - cannot tell which key signed
    (ring-verify message sig ring-pubkeys)))
```

## API Reference

### Ring Signatures

- `(ring-sign message pubkeys signer-index secret-key)` - Create ring signature
- `(ring-verify message signature pubkeys)` - Verify ring signature

### Linkable Ring Signatures

- `(lsag-sign message pubkeys signer-index secret-key)` - Linkable signature
- `(lsag-verify message signature pubkeys)` - Verify linkable signature
- `(lsag-link-p sig1 sig2)` - Check if signatures link (same signer)

### MuSig2

- `(musig2-aggregate-keys pubkeys)` - Aggregate public keys
- `(musig2-sign keypairs message)` - Multi-party signing

## Testing

```lisp
(asdf:test-system :cl-ring-signatures)
```

## License

BSD-3-Clause

Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
