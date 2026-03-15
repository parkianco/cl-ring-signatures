;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;; ============================================================================
;;;; package.lisp - Package definitions for cl-ring-signatures
;;;; ============================================================================

(defpackage #:cl-ring-signatures
  (:use #:cl)
  (:nicknames #:ring-sig)
  (:documentation
   "Pure Common Lisp implementation of ring signatures and MuSig2.

Ring signatures allow a signer to sign a message on behalf of a group (ring)
without revealing which member actually signed. Implements:

- Basic Ring Signatures (Rivest-Shamir-Tauman)
- Linkable Ring Signatures (LRS) - detect double-signing
- MLSAG (Multi-layered Linkable Spontaneous Anonymous Group)
- CLSAG (Compact Linkable Spontaneous Anonymous Group) - 20% more efficient
- Triptych (logarithmic signature size)
- MuSig2 (BIP327 aggregate Schnorr signatures)

All operations are pure functions with no external dependencies.")

  ;; Ring Signature Types
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ring-signatures-timing
   #:ring-signatures-batch-process
   #:ring-signatures-health-check#:ring-signature
           #:ring-params
           #:key-image)

  ;; Basic Ring Signatures
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ring-signatures-timing
   #:ring-signatures-batch-process
   #:ring-signatures-health-check#:ring-sign
           #:ring-verify)

  ;; Linkable Ring Signatures
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ring-signatures-timing
   #:ring-signatures-batch-process
   #:ring-signatures-health-check#:lrs-sign
           #:lrs-verify
           #:lrs-link)

  ;; MLSAG (Multi-layered)
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ring-signatures-timing
   #:ring-signatures-batch-process
   #:ring-signatures-health-check#:mlsag-sign
           #:mlsag-verify
           #:mlsag-key-images)

  ;; CLSAG (Compact)
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ring-signatures-timing
   #:ring-signatures-batch-process
   #:ring-signatures-health-check#:clsag-sign
           #:clsag-verify
           #:clsag-key-image)

  ;; Triptych
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ring-signatures-timing
   #:ring-signatures-batch-process
   #:ring-signatures-health-check#:triptych-sign
           #:triptych-verify
           #:triptych-linking-tag)

  ;; Key Image Generation
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ring-signatures-timing
   #:ring-signatures-batch-process
   #:ring-signatures-health-check#:generate-key-image
           #:key-images-linked-p)

  ;; Ring Member Selection
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ring-signatures-timing
   #:ring-signatures-batch-process
   #:ring-signatures-health-check#:select-ring-members
           #:random-ring-selection
           #:decoy-selection-gamma)

  ;; Anonymity Analysis
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ring-signatures-timing
   #:ring-signatures-batch-process
   #:ring-signatures-health-check#:ring-entropy
           #:effective-anonymity-set
           #:ring-age-distribution)

  ;; MuSig2 Types
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ring-signatures-timing
   #:ring-signatures-batch-process
   #:ring-signatures-health-check#:musig2-session
           #:make-musig2-session
           #:musig2-session-p
           #:musig2-session-aggregate-pubkey)

  ;; MuSig2 Key Aggregation
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ring-signatures-timing
   #:ring-signatures-batch-process
   #:ring-signatures-health-check#:musig2-aggregate-pubkeys)

  ;; MuSig2 Signing Protocol
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ring-signatures-timing
   #:ring-signatures-batch-process
   #:ring-signatures-health-check#:musig2-generate-nonces
           #:musig2-aggregate-nonces
           #:musig2-partial-sign
           #:musig2-aggregate-sigs)

  ;; MuSig2 High-Level API
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ring-signatures-timing
   #:ring-signatures-batch-process
   #:ring-signatures-health-check#:musig2-sign
           #:musig2-verify)

  ;; EC Primitives (for interoperability)
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ring-signatures-timing
   #:ring-signatures-batch-process
   #:ring-signatures-health-check#:+secp256k1-n+
           #:+secp256k1-p+
           #:+secp256k1-g+
           #:point-add
           #:point-mul
           #:point-compress
           #:point-decompress
           #:sha256
           #:bytes-to-integer
           #:integer-to-bytes
           #:generate-random-bytes))

(defpackage #:cl-ring-signatures.test
  (:use #:cl #:cl-ring-signatures)
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ring-signatures-timing
   #:ring-signatures-batch-process
   #:ring-signatures-health-check#:run-all-tests))
