;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-ring-signatures)

(define-condition cl-ring-signatures-error (error)
  ((message :initarg :message :reader cl-ring-signatures-error-message))
  (:report (lambda (condition stream)
             (format stream "cl-ring-signatures error: ~A" (cl-ring-signatures-error-message condition)))))
