;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-ring-signatures)

;;; Core types for cl-ring-signatures
(deftype cl-ring-signatures-id () '(unsigned-byte 64))
(deftype cl-ring-signatures-status () '(member :ready :active :error :shutdown))
