;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;; ============================================================================
;;;; primitives.lisp - EC and cryptographic primitives for ring signatures
;;;; ============================================================================
;;;;
;;;; Pure Common Lisp implementation of secp256k1 elliptic curve operations
;;;; and SHA-256 hash function. Zero external dependencies.
;;;;
;;;; ============================================================================

(in-package #:cl-ring-signatures)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; secp256k1 Curve Parameters
;;; ============================================================================

(defconstant +secp256k1-p+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  "Prime field modulus p for secp256k1.")

(defconstant +secp256k1-n+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  "Order of the generator point n for secp256k1.")

(defconstant +secp256k1-gx+
  #x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  "Generator point x-coordinate.")

(defconstant +secp256k1-gy+
  #x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
  "Generator point y-coordinate.")

;;; GLV Endomorphism Parameters
(defconstant +secp256k1-lambda+
  #x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72)

(defconstant +secp256k1-beta+
  #x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE)

(defconstant +glv-a1+ #x3086D221A7D46BCDE86C90E49284EB15)
(defconstant +glv-b1+ (- #xE4437ED6010E88286F547FA90ABFE4C3))
(defconstant +glv-a2+ #x114CA50F7A8E2F3F657C1108D9D44CFD8)
(defconstant +glv-b2+ #x3086D221A7D46BCDE86C90E49284EB15)
(defconstant +secp256k1-half-n+ (ash +secp256k1-n+ -1))

;;; ============================================================================
;;; Byte Conversion Utilities
;;; ============================================================================

(defun bytes-to-integer (bytes &key (big-endian t))
  "Convert byte array to integer."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes)
           (type boolean big-endian)
           (optimize (speed 3) (safety 1)))
  (let ((result 0))
    (declare (type integer result))
    (if big-endian
        (loop for byte of-type (unsigned-byte 8) across bytes
              do (setf result (+ (ash result 8) byte)))
        (loop for i of-type fixnum from (1- (length bytes)) downto 0
              do (setf result (+ (ash result 8) (aref bytes i)))))
    result))

(defun integer-to-bytes (integer n-bytes &key (big-endian t))
  "Convert integer to byte array of specified length."
  (declare (type integer integer)
           (type fixnum n-bytes)
           (type boolean big-endian)
           (optimize (speed 3) (safety 1)))
  (let ((result (make-array n-bytes :element-type '(unsigned-byte 8) :initial-element 0)))
    (if big-endian
        (loop for i from (1- n-bytes) downto 0
              for j from 0
              do (setf (aref result j) (ldb (byte 8 (* i 8)) integer)))
        (loop for i from 0 below n-bytes
              do (setf (aref result i) (ldb (byte 8 (* i 8)) integer))))
    result))

;;; ============================================================================
;;; SHA-256 Implementation
;;; ============================================================================

(declaim (type (simple-array (unsigned-byte 32) (64)) +sha256-k+))
(defparameter +sha256-k+
  (make-array 64 :element-type '(unsigned-byte 32)
              :initial-contents
              '(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
                #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
                #xd807aa98 #x12835b01 #x243185be #x550c7dc3
                #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
                #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
                #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
                #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
                #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
                #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
                #x650a7354 #x766a0abb #x81c2c92e #x92722c85
                #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
                #xd192e819 #xd6990624 #xf40e3585 #x106aa070
                #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
                #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
                #x748f82ee #x78a5636f #x84c87814 #x8cc70208
                #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)))

(defmacro u32 (x)
  `(logand #xFFFFFFFF ,x))

(declaim (inline u32-rotr))
(defun u32-rotr (x n)
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 31) n)
           (optimize (speed 3) (safety 0)))
  (logior (ash x (- n)) (u32 (ash x (- 32 n)))))

(defun sha256 (data)
  "Compute SHA-256 hash of DATA. Returns 32-byte array."
  (declare (optimize (speed 3) (safety 1)))
  (let* ((data (if (stringp data)
                   (map '(vector (unsigned-byte 8)) #'char-code data)
                   data))
         (len (length data))
         (bit-len (* len 8))
         ;; Padding: message || 1 || 0s || length (64-bit BE)
         (padded-len (* 64 (ceiling (+ len 9) 64)))
         (padded (make-array padded-len :element-type '(unsigned-byte 8) :initial-element 0))
         ;; Initial hash values
         (h (make-array 8 :element-type '(unsigned-byte 32)
                        :initial-contents '(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
                                           #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)))
         (w (make-array 64 :element-type '(unsigned-byte 32) :initial-element 0)))
    (declare (type (simple-array (unsigned-byte 8) (*)) data padded)
             (type (simple-array (unsigned-byte 32) (8)) h)
             (type (simple-array (unsigned-byte 32) (64)) w))
    ;; Copy data and add padding
    (replace padded data)
    (setf (aref padded len) #x80)
    ;; Append length in big-endian
    (loop for i from 0 below 8
          do (setf (aref padded (+ padded-len -8 i))
                   (ldb (byte 8 (* (- 7 i) 8)) bit-len)))
    ;; Process each 64-byte block
    (loop for block-start from 0 below padded-len by 64
          do (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
                   (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
               (declare (type (unsigned-byte 32) a b c d e f g hh))
               ;; Prepare message schedule
               (loop for i from 0 below 16
                     for j = (+ block-start (* i 4))
                     do (setf (aref w i)
                              (logior (ash (aref padded j) 24)
                                      (ash (aref padded (+ j 1)) 16)
                                      (ash (aref padded (+ j 2)) 8)
                                      (aref padded (+ j 3)))))
               (loop for i from 16 below 64
                     do (let* ((w15 (aref w (- i 15)))
                               (w2 (aref w (- i 2)))
                               (s0 (logxor (u32-rotr w15 7) (u32-rotr w15 18) (ash w15 -3)))
                               (s1 (logxor (u32-rotr w2 17) (u32-rotr w2 19) (ash w2 -10))))
                          (setf (aref w i) (u32 (+ (aref w (- i 16)) s0 (aref w (- i 7)) s1)))))
               ;; 64 rounds
               (loop for i from 0 below 64
                     do (let* ((s1 (logxor (u32-rotr e 6) (u32-rotr e 11) (u32-rotr e 25)))
                               (ch (logxor (logand e f) (logand (lognot e) g)))
                               (temp1 (u32 (+ hh s1 ch (aref +sha256-k+ i) (aref w i))))
                               (s0 (logxor (u32-rotr a 2) (u32-rotr a 13) (u32-rotr a 22)))
                               (maj (logxor (logand a b) (logand a c) (logand b c)))
                               (temp2 (u32 (+ s0 maj))))
                          (setf hh g g f f e e (u32 (+ d temp1))
                                d c c b b a a (u32 (+ temp1 temp2)))))
               ;; Add to hash
               (setf (aref h 0) (u32 (+ (aref h 0) a))
                     (aref h 1) (u32 (+ (aref h 1) b))
                     (aref h 2) (u32 (+ (aref h 2) c))
                     (aref h 3) (u32 (+ (aref h 3) d))
                     (aref h 4) (u32 (+ (aref h 4) e))
                     (aref h 5) (u32 (+ (aref h 5) f))
                     (aref h 6) (u32 (+ (aref h 6) g))
                     (aref h 7) (u32 (+ (aref h 7) hh)))))
    ;; Output hash
    (let ((out (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 8
            for hi = (aref h i)
            do (setf (aref out (* i 4)) (ldb (byte 8 24) hi)
                     (aref out (+ (* i 4) 1)) (ldb (byte 8 16) hi)
                     (aref out (+ (* i 4) 2)) (ldb (byte 8 8) hi)
                     (aref out (+ (* i 4) 3)) (ldb (byte 8 0) hi)))
      out)))

;;; ============================================================================
;;; Tagged Hash (BIP340)
;;; ============================================================================

(defun compute-tag-hash (tag)
  "Compute SHA256(tag) for tagged hash construction."
  (sha256 (if (stringp tag)
              (map '(vector (unsigned-byte 8)) #'char-code tag)
              tag)))

(defun tagged-hash (tag message)
  "Compute BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || message)."
  (let ((tag-hash (if (stringp tag) (compute-tag-hash tag) tag)))
    (sha256 (concatenate '(vector (unsigned-byte 8))
                         tag-hash tag-hash message))))

;;; ============================================================================
;;; Modular Arithmetic
;;; ============================================================================

(defun mod-inverse (a m)
  "Compute modular inverse of A modulo M using extended Euclidean algorithm."
  (declare (type integer a m)
           (optimize (speed 3) (safety 1)))
  (let ((m0 m) (x0 0) (x1 1))
    (when (= m 1)
      (return-from mod-inverse 0))
    (setf a (mod a m))
    (loop while (> a 1)
          do (let ((q (floor a m)))
               (psetf m (mod a m) a m)
               (psetf x0 (- x1 (* q x0)) x1 x0)))
    (when (< x1 0)
      (incf x1 m0))
    x1))

(declaim (inline mod-n))
(defun mod-n (x)
  "Reduce X modulo secp256k1 order n."
  (mod x +secp256k1-n+))

(defun mod-sqrt (n p)
  "Compute modular square root of N modulo prime P."
  (declare (type integer n p)
           (optimize (speed 3) (safety 1)))
  ;; For secp256k1, p = 3 (mod 4), so sqrt(n) = n^((p+1)/4)
  (when (or (zerop n) (= n 1))
    (return-from mod-sqrt n))
  ;; Check if n is quadratic residue
  (unless (= (mod (expt-mod n (ash (1- p) -1) p) p) 1)
    (return-from mod-sqrt nil))
  ;; p = 3 (mod 4) case
  (when (= (mod p 4) 3)
    (return-from mod-sqrt (expt-mod n (ash (1+ p) -2) p)))
  ;; Tonelli-Shanks for general case
  (tonelli-shanks n p))

(defun expt-mod (base exp modulus)
  "Compute (base^exp) mod modulus."
  (declare (type integer base exp modulus)
           (optimize (speed 3) (safety 1)))
  (let ((result 1)
        (base (mod base modulus)))
    (loop while (plusp exp)
          do (when (oddp exp)
               (setf result (mod (* result base) modulus)))
             (setf exp (ash exp -1))
             (setf base (mod (* base base) modulus)))
    result))

(defun tonelli-shanks (n p)
  "Tonelli-Shanks algorithm for modular square root."
  (let ((q (1- p)) (s 0))
    (loop while (evenp q)
          do (incf s) (setf q (ash q -1)))
    (let ((z 2))
      (loop while (= (expt-mod z (ash (1- p) -1) p) 1)
            do (incf z))
      (let ((m s)
            (c (expt-mod z q p))
            (t-val (expt-mod n q p))
            (r (expt-mod n (ash (1+ q) -1) p)))
        (loop
          (when (= t-val 1) (return r))
          (let ((i 1) (temp (mod (* t-val t-val) p)))
            (loop while (and (< i m) (/= temp 1))
                  do (incf i) (setf temp (mod (* temp temp) p)))
            (let ((b (expt-mod c (ash 1 (- m i 1)) p)))
              (setf m i)
              (setf c (mod (* b b) p))
              (setf t-val (mod (* t-val c) p))
              (setf r (mod (* r b) p)))))))))

;;; ============================================================================
;;; Projective Point Representation
;;; ============================================================================

(defstruct (proj-point (:constructor %make-proj-point))
  "Point in Jacobian projective coordinates (X:Y:Z) = (X/Z^2, Y/Z^3)."
  (x 0 :type integer)
  (y 0 :type integer)
  (z 1 :type integer))

(defun make-proj-point (x y &optional (z 1))
  (%make-proj-point :x x :y y :z z))

(defun proj-point-infinity ()
  (make-proj-point 1 1 0))

(defun proj-point-infinity-p (p)
  (zerop (proj-point-z p)))

(defun affine-to-proj (x y)
  (make-proj-point x y 1))

(defun proj-to-affine (p)
  "Convert projective point to affine coordinates."
  (when (proj-point-infinity-p p)
    (error "Cannot convert point at infinity to affine"))
  (let* ((z (proj-point-z p))
         (z-inv (mod-inverse z +secp256k1-p+))
         (z-inv-2 (mod (* z-inv z-inv) +secp256k1-p+))
         (z-inv-3 (mod (* z-inv-2 z-inv) +secp256k1-p+)))
    (values (mod (* (proj-point-x p) z-inv-2) +secp256k1-p+)
            (mod (* (proj-point-y p) z-inv-3) +secp256k1-p+))))

;;; ============================================================================
;;; Point Arithmetic
;;; ============================================================================

(defun proj-point-double (p)
  "Double a point in projective coordinates."
  (when (proj-point-infinity-p p)
    (return-from proj-point-double (proj-point-infinity)))
  (when (zerop (proj-point-y p))
    (return-from proj-point-double (proj-point-infinity)))
  (let* ((x (proj-point-x p))
         (y (proj-point-y p))
         (z (proj-point-z p))
         (prime +secp256k1-p+)
         (y2 (mod (* y y) prime))
         (s (mod (* 4 x y2) prime))
         (m (mod (* 3 x x) prime))
         (x-new (mod (- (* m m) (* 2 s)) prime))
         (y-new (mod (- (* m (- s x-new)) (* 8 y2 y2)) prime))
         (z-new (mod (* 2 y z) prime)))
    (make-proj-point x-new y-new z-new)))

(defun proj-point-add (p1 p2)
  "Add two points in projective coordinates."
  (when (proj-point-infinity-p p1) (return-from proj-point-add p2))
  (when (proj-point-infinity-p p2) (return-from proj-point-add p1))
  (let* ((x1 (proj-point-x p1)) (y1 (proj-point-y p1)) (z1 (proj-point-z p1))
         (x2 (proj-point-x p2)) (y2 (proj-point-y p2)) (z2 (proj-point-z p2))
         (prime +secp256k1-p+)
         (z1-2 (mod (* z1 z1) prime))
         (z2-2 (mod (* z2 z2) prime))
         (u1 (mod (* x1 z2-2) prime))
         (u2 (mod (* x2 z1-2) prime))
         (s1 (mod (* y1 z2 z2-2) prime))
         (s2 (mod (* y2 z1 z1-2) prime))
         (h (mod (- u2 u1) prime))
         (r (mod (- s2 s1) prime)))
    (when (zerop h)
      (if (zerop r)
          (return-from proj-point-add (proj-point-double p1))
          (return-from proj-point-add (proj-point-infinity))))
    (let* ((h2 (mod (* h h) prime))
           (h3 (mod (* h h2) prime))
           (x-new (mod (- (* r r) h3 (* 2 u1 h2)) prime))
           (y-new (mod (- (* r (- (* u1 h2) x-new)) (* s1 h3)) prime))
           (z-new (mod (* h z1 z2) prime)))
      (make-proj-point x-new y-new z-new))))

(defun proj-point-neg (p)
  "Negate a point."
  (if (proj-point-infinity-p p)
      (proj-point-infinity)
      (make-proj-point (proj-point-x p)
                       (mod (- +secp256k1-p+ (proj-point-y p)) +secp256k1-p+)
                       (proj-point-z p))))

;;; ============================================================================
;;; GLV Scalar Multiplication
;;; ============================================================================

(defun glv-decompose (k)
  "Decompose scalar k into (k1, k2) where k = k1 + k2*lambda (mod n)."
  (let* ((n +secp256k1-n+)
         (c1 (round (* +glv-b2+ k) n))
         (c2 (round (* (- +glv-b1+) k) n))
         (k1 (mod (- k (* c1 +glv-a1+) (* c2 +glv-a2+)) n))
         (k2 (mod (- (* (- c1) +glv-b1+) (* c2 +glv-b2+)) n)))
    (when (> k1 +secp256k1-half-n+) (decf k1 n))
    (when (> k2 +secp256k1-half-n+) (decf k2 n))
    (values k1 k2)))

(defun glv-endomorphism (p)
  "Apply GLV endomorphism: (x, y) -> (beta*x, y)."
  (if (proj-point-infinity-p p)
      (proj-point-infinity)
      (make-proj-point (mod (* +secp256k1-beta+ (proj-point-x p)) +secp256k1-p+)
                       (proj-point-y p)
                       (proj-point-z p))))

(defun glv-scalar-multiply (k p)
  "Compute k*P using GLV decomposition."
  (when (zerop k)
    (return-from glv-scalar-multiply (proj-point-infinity)))
  (multiple-value-bind (k1 k2) (glv-decompose k)
    (let* ((neg-k1 (minusp k1))
           (neg-k2 (minusp k2))
           (k1 (abs k1))
           (k2 (abs k2))
           (p1 (if neg-k1 (proj-point-neg p) p))
           (p2-base (glv-endomorphism p))
           (p2 (if neg-k2 (proj-point-neg p2-base) p2-base))
           (p1-plus-p2 (proj-point-add p1 p2))
           (result (proj-point-infinity))
           (n-bits (max (integer-length k1) (integer-length k2))))
      (loop for i from (1- n-bits) downto 0
            for b1 = (logbitp i k1)
            for b2 = (logbitp i k2)
            do (setf result (proj-point-double result))
               (cond ((and b1 b2) (setf result (proj-point-add result p1-plus-p2)))
                     (b1 (setf result (proj-point-add result p1)))
                     (b2 (setf result (proj-point-add result p2)))))
      result)))

;;; ============================================================================
;;; Public Point API
;;; ============================================================================

(defvar +secp256k1-g+
  (affine-to-proj +secp256k1-gx+ +secp256k1-gy+)
  "Generator point G for secp256k1.")

(defun point-mul (point scalar)
  "Multiply a point by a scalar."
  (glv-scalar-multiply scalar point))

(defun point-add (p1 p2)
  "Add two points."
  (proj-point-add p1 p2))

(defun point-compress (point)
  "Compress a point to 33-byte SEC1 format."
  (if (proj-point-infinity-p point)
      (make-array 33 :element-type '(unsigned-byte 8) :initial-element 0)
      (multiple-value-bind (x y) (proj-to-affine point)
        (let ((result (make-array 33 :element-type '(unsigned-byte 8))))
          (setf (aref result 0) (if (evenp y) #x02 #x03))
          (replace result (integer-to-bytes x 32) :start1 1)
          result))))

(defun point-decompress (compressed)
  "Decompress a 33-byte SEC1 compressed point."
  (let* ((prefix (aref compressed 0))
         (x (bytes-to-integer (subseq compressed 1)))
         (y-squared (mod (+ (* x x x) 7) +secp256k1-p+))
         (y (mod-sqrt y-squared +secp256k1-p+)))
    (when (or (and (= prefix #x02) (oddp y))
              (and (= prefix #x03) (evenp y)))
      (setf y (- +secp256k1-p+ y)))
    (affine-to-proj x y)))

(defun point-to-x-only (point)
  "Extract 32-byte x-only public key from point."
  (let ((compressed (point-compress point)))
    (subseq compressed 1)))

(defun x-only-to-point (x-only-bytes)
  "Convert 32-byte x-only key to point (with even Y)."
  (point-decompress (concatenate '(vector (unsigned-byte 8))
                                 (vector #x02) x-only-bytes)))

(defun point-has-odd-y (point)
  "Check if point has odd Y coordinate."
  (multiple-value-bind (x y) (proj-to-affine point)
    (declare (ignore x))
    (oddp y)))

;;; ============================================================================
;;; Random Bytes Generation
;;; ============================================================================

(defun generate-random-bytes (n)
  "Generate N random bytes using implementation-specific PRNG.
   NOTE: For cryptographic use, replace with system RNG."
  (let ((bytes (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n)
      (setf (aref bytes i) (random 256)))
    bytes))

;;; ============================================================================
;;; Constant-Time Operations
;;; ============================================================================

(defun constant-time-bytes= (a b)
  "Constant-time byte array comparison."
  (declare (type (simple-array (unsigned-byte 8) (*)) a b)
           (optimize (speed 3) (safety 0)))
  (when (/= (length a) (length b))
    (return-from constant-time-bytes= nil))
  (let ((diff 0))
    (declare (type (unsigned-byte 8) diff))
    (loop for i from 0 below (length a)
          do (setf diff (logior diff (logxor (aref a i) (aref b i)))))
    (zerop diff)))

;;; ============================================================================
;;; Schnorr Primitives (for MuSig2)
;;; ============================================================================

(defun schnorr-pubkey-from-privkey (privkey)
  "Derive 32-byte x-only public key from 32-byte private key."
  (let* ((d (bytes-to-integer privkey))
         (p (point-mul +secp256k1-g+ d)))
    (point-to-x-only p)))

(defun schnorr-verify (signature message pubkey)
  "Verify a BIP340 Schnorr signature."
  (declare (type (simple-array (unsigned-byte 8) (64)) signature)
           (type (simple-array (unsigned-byte 8) (32)) message pubkey))
  (let* ((r-bytes (subseq signature 0 32))
         (s-bytes (subseq signature 32 64))
         (r (bytes-to-integer r-bytes))
         (s (bytes-to-integer s-bytes))
         (p (x-only-to-point pubkey)))
    ;; Check s < n
    (when (>= s +secp256k1-n+)
      (return-from schnorr-verify nil))
    ;; e = H(r || P || m)
    (let* ((challenge-data (concatenate '(vector (unsigned-byte 8))
                                        r-bytes pubkey message))
           (e (mod-n (bytes-to-integer (tagged-hash "BIP0340/challenge" challenge-data))))
           ;; R = s*G - e*P
           (sg (point-mul +secp256k1-g+ s))
           (ep (point-mul p e))
           (r-point (proj-point-add sg (proj-point-neg ep))))
      ;; Verify R is not infinity and has even Y
      (when (proj-point-infinity-p r-point)
        (return-from schnorr-verify nil))
      (when (point-has-odd-y r-point)
        (return-from schnorr-verify nil))
      ;; Verify x(R) = r
      (let ((rx (point-to-x-only r-point)))
        (constant-time-bytes= rx r-bytes)))))
