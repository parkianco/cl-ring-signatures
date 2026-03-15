;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(load "cl-ring-signatures.asd")
(handler-case
  (progn
    (asdf:test-system :cl-ring-signatures/test)
    (format t "PASS~%"))
  (error (e)
    (format t "FAIL~%")))
(quit)
