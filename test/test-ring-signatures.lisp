;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; test-ring-signatures.lisp - Unit tests for ring-signatures
;;;;
;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

(defpackage #:cl-ring-signatures.test
  (:use #:cl)
  (:export #:run-tests))

(in-package #:cl-ring-signatures.test)

(defun run-tests ()
  "Run all tests for cl-ring-signatures."
  (format t "~&Running tests for cl-ring-signatures...~%")
  ;; TODO: Add test cases
  ;; (test-function-1)
  ;; (test-function-2)
  (format t "~&All tests passed!~%")
  t)
