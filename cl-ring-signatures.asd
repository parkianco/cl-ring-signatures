;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;; ============================================================================
;;;; cl-ring-signatures.asd - Ring Signatures and MuSig2 for Common Lisp
;;;; ============================================================================

(asdf:defsystem #:cl-ring-signatures
  :description "Pure Common Lisp ring signatures and MuSig2 aggregate Schnorr signatures"
  :author "Parkian Company LLC"
  :license "Apache-2.0"
  :version "0.1.0"
  :serial t
  :components ((:file "package")
               (:module "src"
                :serial t
                :components ((:file "primitives")
                             (:file "ring-sig"))))
  :in-order-to ((asdf:test-op (test-op #:cl-ring-signatures/test))))

(asdf:defsystem #:cl-ring-signatures/test
  :description "Tests for cl-ring-signatures"
  :depends-on (#:cl-ring-signatures)
  :serial t
  :components ()
  :perform (asdf:test-op (o c)
             (format t "~%No tests defined yet~%")))
