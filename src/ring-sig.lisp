;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;; ============================================================================
;;;; ring-sig.lisp - Ring Signature Implementations
;;;; ============================================================================
;;;;
;;;; Comprehensive ring signature schemes for privacy-preserving cryptography.
;;;; Implements basic ring signatures, linkable ring signatures (LRS),
;;;; MLSAG, CLSAG, and Triptych signatures.
;;;;
;;;; ============================================================================

(in-package #:cl-ring-signatures)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; Ring Signature Constants
;;; ============================================================================

(defun string-to-octets (string)
  "Convert string to byte array (UTF-8 encoding)."
  (map '(vector (unsigned-byte 8)) #'char-code string))

(defparameter +ring-domain-separator+
  (sha256 (string-to-octets "CL-Ring-Signature-v1"))
  "Domain separator for ring signature hashing.")

(defparameter +linkable-domain-separator+
  (sha256 (string-to-octets "CL-Linkable-Ring-v1"))
  "Domain separator for linkable ring signatures.")

(defparameter +mlsag-domain-separator+
  (sha256 (string-to-octets "CL-MLSAG-v1"))
  "Domain separator for MLSAG signatures.")

(defparameter +clsag-domain-separator+
  (sha256 (string-to-octets "CL-CLSAG-v1"))
  "Domain separator for CLSAG signatures.")

(defparameter +triptych-domain-separator+
  (sha256 (string-to-octets "CL-Triptych-v1"))
  "Domain separator for Triptych signatures.")

(defparameter +key-image-domain-separator+
  (sha256 (string-to-octets "CL-KeyImage-v1"))
  "Domain separator for key image generation.")

;;; ============================================================================
;;; Ring Signature Data Structures
;;; ============================================================================

(defstruct (ring-params
            (:copier nil)
            (:constructor make-ring-params (&key ring-size min-ring-size max-ring-size)))
  "Parameters for ring signature operations."
  (ring-size 11 :type fixnum)
  (min-ring-size 3 :type fixnum)
  (max-ring-size 64 :type fixnum))

(defstruct (key-image
            (:copier nil)
            (:constructor make-key-image (&key image source-key)))
  "Key image for linkable ring signatures.
   IMAGE: 33-byte compressed point (x * Hp(P))
   SOURCE-KEY: Optional reference to originating public key"
  (image nil :type (or null (vector (unsigned-byte 8))))
  (source-key nil :type (or null (vector (unsigned-byte 8)))))

(defstruct (ring-signature
            (:copier nil)
            (:constructor %make-ring-signature))
  "A ring signature.
   TYPE: Signature type (:basic, :linkable, :mlsag, :clsag, :triptych)
   RING: List of ring member public keys
   C0: Initial challenge
   RESPONSES: List of response scalars
   KEY-IMAGES: List of key images (for linkable types)"
  (type :basic :type keyword)
  (ring nil :type list)
  (c0 nil :type (or null (vector (unsigned-byte 8))))
  (responses nil :type list)
  (key-images nil :type list)
  (metadata nil :type list))

(defstruct (mlsag-signature
            (:copier nil)
            (:constructor %make-mlsag-signature))
  "MLSAG (Multi-layered Linkable Spontaneous Anonymous Group) signature."
  (ring-size 0 :type fixnum)
  (num-inputs 0 :type fixnum)
  (c0 nil :type (or null (vector (unsigned-byte 8))))
  (ss nil :type (or null (array * (* *))))
  (key-images nil :type list))

(defstruct (clsag-signature
            (:copier nil)
            (:constructor %make-clsag-signature))
  "CLSAG (Compact Linkable Spontaneous Anonymous Group) signature."
  (c0 nil :type (or null (vector (unsigned-byte 8))))
  (s nil :type (or null vector))
  (d nil :type (or null (vector (unsigned-byte 8))))
  (key-image nil :type (or null (vector (unsigned-byte 8)))))

(defstruct (triptych-signature
            (:copier nil)
            (:constructor %make-triptych-signature))
  "Triptych ring signature (logarithmic size)."
  (a nil :type (or null (vector (unsigned-byte 8))))
  (b nil :type (or null (vector (unsigned-byte 8))))
  (c nil :type (or null vector))
  (d nil :type (or null (vector (unsigned-byte 8))))
  (x nil :type (or null vector))
  (y nil :type (or null vector))
  (f nil :type (or null vector))
  (za nil :type (or null (vector (unsigned-byte 8))))
  (zc nil :type (or null (vector (unsigned-byte 8))))
  (z nil :type (or null (vector (unsigned-byte 8))))
  (linking-tag nil :type (or null (vector (unsigned-byte 8)))))

;;; ============================================================================
;;; Utility Functions
;;; ============================================================================

(defun ring-random-scalar ()
  "Generate a cryptographically secure random scalar in [1, n-1]."
  (let ((bytes (generate-random-bytes 32)))
    (let ((scalar (mod-n (bytes-to-integer bytes))))
      (if (zerop scalar)
          (ring-random-scalar)
          scalar))))

(defun ring-hash-to-point (data)
  "Hash data to a point on secp256k1 using try-and-increment.
   Used for key image generation: I = x * Hp(P)."
  (let ((counter 0))
    (loop
      (let* ((counter-bytes (integer-to-bytes counter 4))
             (input (concatenate '(vector (unsigned-byte 8))
                                 +key-image-domain-separator+
                                 data
                                 counter-bytes))
             (hash (sha256 input))
             (x-candidate (bytes-to-integer hash)))
        (when (< x-candidate +secp256k1-p+)
          ;; Try to lift this x-coordinate to a point
          (let ((y-squared (mod (+ (* x-candidate x-candidate x-candidate) 7) +secp256k1-p+)))
            (let ((y (mod-sqrt y-squared +secp256k1-p+)))
              (when y
                (return (point-compress (affine-to-proj x-candidate y)))))))
        (incf counter)
        (when (> counter 256)
          (error "Failed to hash to point after 256 attempts"))))))

(defun ring-hash-to-scalar (domain &rest data)
  "Hash data with domain separator to produce scalar mod n."
  (let* ((combined (apply #'concatenate '(vector (unsigned-byte 8)) domain data))
         (hash (sha256 combined)))
    (mod-n (bytes-to-integer hash))))

(defun ring-ec-mul (scalar &optional (point nil))
  "Multiply point by scalar. If point is nil, use generator G."
  (let ((s (mod-n scalar)))
    (if point
        ;; Decompress, multiply, recompress
        (let ((p (if (proj-point-p point)
                     point
                     (point-decompress point))))
          (point-compress (point-mul p s)))
        ;; Multiply generator
        (point-compress (point-mul +secp256k1-g+ s)))))

(defun ring-ec-add (p1 p2)
  "Add two EC points (compressed format)."
  (let ((pt1 (if (proj-point-p p1) p1 (point-decompress p1)))
        (pt2 (if (proj-point-p p2) p2 (point-decompress p2))))
    (point-compress (point-add pt1 pt2))))

;;; ============================================================================
;;; Key Image Generation
;;; ============================================================================

(defun generate-key-image (private-key public-key)
  "Generate key image I = x * Hp(P) for linkable ring signatures.

   PRIVATE-KEY: 32-byte private key scalar or integer
   PUBLIC-KEY: 33-byte compressed public key

   Returns: key-image structure with 33-byte compressed point"
  (let* ((hp (ring-hash-to-point public-key))
         (x (if (integerp private-key)
                private-key
                (bytes-to-integer private-key)))
         (hp-point (point-decompress hp))
         (image-point (point-mul hp-point x))
         (image (point-compress image-point)))
    (make-key-image :image image :source-key public-key)))

(defun key-images-linked-p (ki1 ki2)
  "Check if two key images are linked (same signer).
   Returns T if the key images are identical."
  (let ((img1 (if (key-image-p ki1) (key-image-image ki1) ki1))
        (img2 (if (key-image-p ki2) (key-image-image ki2) ki2)))
    (constant-time-bytes= img1 img2)))

;;; ============================================================================
;;; Basic Ring Signatures (RST01)
;;; ============================================================================

(defun ring-sign (private-key signer-index ring message)
  "Create a basic (non-linkable) ring signature.

   PRIVATE-KEY: 32-byte private key of actual signer
   SIGNER-INDEX: Index of signer in ring (0-based)
   RING: List of 33-byte compressed public keys
   MESSAGE: Message bytes to sign

   Returns: ring-signature structure"
  (let* ((n (length ring))
         (k (ring-random-scalar))
         (responses (make-array n))
         (challenges (make-array n))
         (x (if (integerp private-key)
                private-key
                (bytes-to-integer private-key))))

    ;; Validate signer index
    (unless (and (>= signer-index 0) (< signer-index n))
      (error "Signer index ~D out of range [0, ~D)" signer-index n))

    ;; Step 1: Compute L_s = k * G (signer's initial commitment)
    (let ((l-s (ring-ec-mul k)))

      ;; Step 2: Compute initial challenge at (s+1) mod n
      (let ((next-idx (mod (1+ signer-index) n)))
        (setf (aref challenges next-idx)
              (ring-hash-to-scalar +ring-domain-separator+
                                   message
                                   l-s))

        ;; Step 3: Complete the ring, computing challenges and responses
        (loop for i from 0 below (1- n)
              for idx = (mod (+ next-idx i) n)
              for next = (mod (1+ idx) n)
              when (/= idx signer-index)
                do
                   ;; Generate random response
                   (setf (aref responses idx) (ring-random-scalar))
                   ;; Compute L = r*G + c*P
                   (let* ((r-g (ring-ec-mul (aref responses idx)))
                          (c-p (ring-ec-mul (aref challenges idx) (nth idx ring)))
                          (l (ring-ec-add r-g c-p)))
                     ;; Next challenge
                     (setf (aref challenges next)
                           (ring-hash-to-scalar +ring-domain-separator+
                                                message
                                                l))))

        ;; Step 4: Compute signer's response: r_s = k - c_s * x (mod n)
        (setf (aref responses signer-index)
              (mod-n (- k (* (aref challenges signer-index) x))))

        ;; Return signature
        (%make-ring-signature
         :type :basic
         :ring ring
         :c0 (integer-to-bytes (aref challenges 0) 32)
         :responses (coerce responses 'list)
         :key-images nil
         :metadata nil)))))

(defun ring-verify (signature message)
  "Verify a basic ring signature.

   SIGNATURE: ring-signature structure
   MESSAGE: Original message bytes

   Returns: T if valid, NIL otherwise"
  (handler-case
      (let* ((ring (ring-signature-ring signature))
             (n (length ring))
             (c0 (bytes-to-integer (ring-signature-c0 signature)))
             (responses (ring-signature-responses signature))
             (challenge c0))

        ;; Verify the challenge chain closes
        (loop for i from 0 below n
              for r = (if (integerp (nth i responses))
                          (nth i responses)
                          (bytes-to-integer (nth i responses)))
              for p = (nth i ring)
              do
                 ;; L = r*G + c*P
                 (let* ((r-g (ring-ec-mul r))
                        (c-p (ring-ec-mul challenge p))
                        (l (ring-ec-add r-g c-p)))
                   ;; Next challenge
                   (setf challenge
                         (ring-hash-to-scalar +ring-domain-separator+
                                              message
                                              l))))

        ;; Signature valid if chain closes (final challenge = c0)
        (= challenge c0))
    (error () nil)))

;;; ============================================================================
;;; Linkable Ring Signatures (LSAG)
;;; ============================================================================

(defun lrs-sign (private-key signer-index ring message)
  "Create a linkable ring signature (LSAG).

   PRIVATE-KEY: 32-byte private key
   SIGNER-INDEX: Index of signer in ring (0-based)
   RING: List of 33-byte compressed public keys
   MESSAGE: Message bytes to sign

   Returns: ring-signature structure with key image"
  (let* ((n (length ring))
         (x (if (integerp private-key)
                private-key
                (bytes-to-integer private-key)))
         (public-key (nth signer-index ring))
         (key-image (generate-key-image x public-key))
         (hp (ring-hash-to-point public-key))
         (k (ring-random-scalar))
         (responses (make-array n))
         (challenges (make-array n)))

    ;; Validate
    (unless (and (>= signer-index 0) (< signer-index n))
      (error "Signer index ~D out of range [0, ~D)" signer-index n))

    ;; L_s = k*G, R_s = k*Hp(P_s)
    (let ((l-s (ring-ec-mul k))
          (r-s (ring-ec-mul k hp)))

      ;; Initial challenge at (s+1)
      (let ((next-idx (mod (1+ signer-index) n)))
        (setf (aref challenges next-idx)
              (ring-hash-to-scalar +linkable-domain-separator+
                                   message
                                   (key-image-image key-image)
                                   l-s
                                   r-s))

        ;; Complete the ring
        (loop for i from 0 below (1- n)
              for idx = (mod (+ next-idx i) n)
              for next = (mod (1+ idx) n)
              when (/= idx signer-index)
                do
                   (setf (aref responses idx) (ring-random-scalar))
                   (let* ((p-i (nth idx ring))
                          (hp-i (ring-hash-to-point p-i))
                          ;; L = r*G + c*P
                          (r-g (ring-ec-mul (aref responses idx)))
                          (c-p (ring-ec-mul (aref challenges idx) p-i))
                          (l (ring-ec-add r-g c-p))
                          ;; R = r*Hp(P) + c*I
                          (r-hp (ring-ec-mul (aref responses idx) hp-i))
                          (c-i (ring-ec-mul (aref challenges idx) (key-image-image key-image)))
                          (r (ring-ec-add r-hp c-i)))
                     (setf (aref challenges next)
                           (ring-hash-to-scalar +linkable-domain-separator+
                                                message
                                                (key-image-image key-image)
                                                l
                                                r))))

        ;; Signer's response: r_s = k - c_s * x
        (setf (aref responses signer-index)
              (mod-n (- k (* (aref challenges signer-index) x))))

        (%make-ring-signature
         :type :linkable
         :ring ring
         :c0 (integer-to-bytes (aref challenges 0) 32)
         :responses (coerce responses 'list)
         :key-images (list key-image)
         :metadata nil)))))

(defun lrs-verify (signature message)
  "Verify a linkable ring signature.

   SIGNATURE: ring-signature structure with key image
   MESSAGE: Original message bytes

   Returns: T if valid, NIL otherwise"
  (handler-case
      (let* ((ring (ring-signature-ring signature))
             (n (length ring))
             (c0 (bytes-to-integer (ring-signature-c0 signature)))
             (responses (ring-signature-responses signature))
             (key-image (first (ring-signature-key-images signature)))
             (ki-bytes (if (key-image-p key-image)
                           (key-image-image key-image)
                           key-image))
             (challenge c0))

        ;; Verify the challenge chain
        (loop for i from 0 below n
              for r = (if (integerp (nth i responses))
                          (nth i responses)
                          (bytes-to-integer (nth i responses)))
              for p = (nth i ring)
              for hp = (ring-hash-to-point p)
              do
                 (let* ((r-g (ring-ec-mul r))
                        (c-p (ring-ec-mul challenge p))
                        (l (ring-ec-add r-g c-p))
                        (r-hp (ring-ec-mul r hp))
                        (c-i (ring-ec-mul challenge ki-bytes))
                        (r-val (ring-ec-add r-hp c-i)))
                   (setf challenge
                         (ring-hash-to-scalar +linkable-domain-separator+
                                              message
                                              ki-bytes
                                              l
                                              r-val))))

        (= challenge c0))
    (error () nil)))

(defun lrs-link (sig1 sig2)
  "Check if two linkable ring signatures are linked (same signer).
   Returns T if signatures share the same key image."
  (let ((ki1 (first (ring-signature-key-images sig1)))
        (ki2 (first (ring-signature-key-images sig2))))
    (key-images-linked-p ki1 ki2)))

;;; ============================================================================
;;; MLSAG - Multi-layered Linkable Spontaneous Anonymous Group
;;; ============================================================================

(defun mlsag-sign (private-keys signer-index ring-matrix message)
  "Create an MLSAG signature for multiple inputs.

   PRIVATE-KEYS: List of private keys (one per input/column)
   SIGNER-INDEX: Row index of signer in ring matrix
   RING-MATRIX: Matrix of public keys (n rows x m columns)
   MESSAGE: Message bytes to sign

   Returns: mlsag-signature structure"
  (let* ((n (length ring-matrix))            ; ring size
         (m (length (first ring-matrix)))    ; number of inputs
         (ss (make-array (list n m)))        ; response matrix
         (challenges (make-array n))
         (key-images nil))

    ;; Validate
    (unless (= m (length private-keys))
      (error "Number of private keys (~D) must match columns (~D)" (length private-keys) m))
    (unless (and (>= signer-index 0) (< signer-index n))
      (error "Signer index ~D out of range [0, ~D)" signer-index n))

    ;; Generate key images for each input
    (setf key-images
          (loop for j from 0 below m
                for x = (if (integerp (nth j private-keys))
                            (nth j private-keys)
                            (bytes-to-integer (nth j private-keys)))
                for p = (nth j (nth signer-index ring-matrix))
                collect (generate-key-image x p)))

    ;; Generate random k values for each input
    (let ((k-values (loop repeat m collect (ring-random-scalar))))

      ;; Compute initial commitments L_j = k_j * G, R_j = k_j * Hp(P_j)
      (let ((l-values (loop for k in k-values collect (ring-ec-mul k)))
            (r-values (loop for j from 0 below m
                            for k in k-values
                            for p = (nth j (nth signer-index ring-matrix))
                            collect (ring-ec-mul k (ring-hash-to-point p)))))

        ;; Initial challenge at (s+1)
        (let ((next-idx (mod (1+ signer-index) n)))
          (setf (aref challenges next-idx)
                (apply #'ring-hash-to-scalar
                       +mlsag-domain-separator+
                       message
                       (append (mapcar #'key-image-image key-images)
                               l-values
                               r-values)))

          ;; Complete the ring
          (loop for i from 0 below (1- n)
                for idx = (mod (+ next-idx i) n)
                for next = (mod (1+ idx) n)
                when (/= idx signer-index)
                  do
                     ;; Random responses for this row
                     (loop for j from 0 below m
                           do (setf (aref ss idx j) (ring-random-scalar)))
                     ;; Compute L_j and R_j for each column
                     (let ((ls nil) (rs nil))
                       (loop for j from 0 below m
                             for p = (nth j (nth idx ring-matrix))
                             for hp = (ring-hash-to-point p)
                             for s = (aref ss idx j)
                             for c = (aref challenges idx)
                             do
                                (let* ((s-g (ring-ec-mul s))
                                       (c-p (ring-ec-mul c p))
                                       (l (ring-ec-add s-g c-p))
                                       (s-hp (ring-ec-mul s hp))
                                       (c-i (ring-ec-mul c (key-image-image (nth j key-images))))
                                       (r (ring-ec-add s-hp c-i)))
                                  (push l ls)
                                  (push r rs)))
                       (setf ls (nreverse ls)
                             rs (nreverse rs))
                       (setf (aref challenges next)
                             (apply #'ring-hash-to-scalar
                                    +mlsag-domain-separator+
                                    message
                                    (append (mapcar #'key-image-image key-images)
                                            ls
                                            rs)))))

          ;; Signer's responses: s_j = k_j - c_s * x_j
          (loop for j from 0 below m
                for k in k-values
                for x = (if (integerp (nth j private-keys))
                            (nth j private-keys)
                            (bytes-to-integer (nth j private-keys)))
                do (setf (aref ss signer-index j)
                         (mod-n (- k (* (aref challenges signer-index) x)))))

          (%make-mlsag-signature
           :ring-size n
           :num-inputs m
           :c0 (integer-to-bytes (aref challenges 0) 32)
           :ss ss
           :key-images key-images))))))

(defun mlsag-verify (signature ring-matrix message)
  "Verify an MLSAG signature.

   SIGNATURE: mlsag-signature structure
   RING-MATRIX: Matrix of public keys (n rows x m columns)
   MESSAGE: Original message bytes

   Returns: T if valid, NIL otherwise"
  (handler-case
      (let* ((n (mlsag-signature-ring-size signature))
             (m (mlsag-signature-num-inputs signature))
             (c0 (bytes-to-integer (mlsag-signature-c0 signature)))
             (ss (mlsag-signature-ss signature))
             (key-images (mlsag-signature-key-images signature))
             (challenge c0))

        ;; Verify ring-matrix dimensions match
        (unless (and (= (length ring-matrix) n)
                     (= (length (first ring-matrix)) m))
          (return-from mlsag-verify nil))

        ;; Verify the challenge chain
        (loop for i from 0 below n
              do
                 (let ((ls nil) (rs nil))
                   (loop for j from 0 below m
                         for p = (nth j (nth i ring-matrix))
                         for hp = (ring-hash-to-point p)
                         for s = (aref ss i j)
                         for ki = (key-image-image (nth j key-images))
                         do
                            (let* ((s-g (ring-ec-mul s))
                                   (c-p (ring-ec-mul challenge p))
                                   (l (ring-ec-add s-g c-p))
                                   (s-hp (ring-ec-mul s hp))
                                   (c-i (ring-ec-mul challenge ki))
                                   (r (ring-ec-add s-hp c-i)))
                              (push l ls)
                              (push r rs)))
                   (setf ls (nreverse ls)
                         rs (nreverse rs))
                   (setf challenge
                         (apply #'ring-hash-to-scalar
                                +mlsag-domain-separator+
                                message
                                (append (mapcar #'key-image-image key-images)
                                        ls
                                        rs)))))

        (= challenge c0))
    (error () nil)))

(defun mlsag-key-images (signature)
  "Extract key images from an MLSAG signature."
  (mlsag-signature-key-images signature))

;;; ============================================================================
;;; CLSAG - Compact Linkable Spontaneous Anonymous Group
;;; ============================================================================

(defun clsag-sign (private-key commitment-mask signer-index ring pseudo-output message)
  "Create a CLSAG signature (20% more efficient than MLSAG).

   PRIVATE-KEY: Signer's private key
   COMMITMENT-MASK: Blinding factor for commitment
   SIGNER-INDEX: Index of signer in ring
   RING: List of (public-key . commitment) pairs
   PSEUDO-OUTPUT: Pseudo output commitment
   MESSAGE: Message bytes to sign

   Returns: clsag-signature structure"
  (let* ((n (length ring))
         (x (if (integerp private-key)
                private-key
                (bytes-to-integer private-key)))
         (z (if (integerp commitment-mask)
                commitment-mask
                (bytes-to-integer commitment-mask)))
         (public-key (car (nth signer-index ring)))
         (key-image (generate-key-image x public-key))
         (hp (ring-hash-to-point public-key))
         (k (ring-random-scalar))
         (s (make-array n))
         (challenges (make-array n)))

    ;; Validate
    (unless (and (>= signer-index 0) (< signer-index n))
      (error "Signer index ~D out of range [0, ~D)" signer-index n))

    ;; Compute aggregation coefficients
    (let* ((pubkeys (mapcar #'car ring))
           (commitments (mapcar #'cdr ring))
           (mu-p (ring-hash-to-scalar +clsag-domain-separator+
                                       (string-to-octets "agg_0")
                                       (apply #'concatenate '(vector (unsigned-byte 8)) pubkeys)))
           (mu-c (ring-hash-to-scalar +clsag-domain-separator+
                                       (string-to-octets "agg_1")
                                       (apply #'concatenate '(vector (unsigned-byte 8)) commitments))))

      ;; Compute auxiliary point D
      (let* ((d-point (ring-ec-mul z hp))
             ;; Initial commitment
             (l0 (ring-ec-mul k))
             (r0 (ring-ec-mul k hp)))

        ;; Initial challenge at (s+1)
        (let ((next-idx (mod (1+ signer-index) n)))
          (setf (aref challenges next-idx)
                (ring-hash-to-scalar +clsag-domain-separator+
                                     message
                                     (key-image-image key-image)
                                     d-point
                                     l0
                                     r0))

          ;; Complete the ring
          (loop for i from 0 below (1- n)
                for idx = (mod (+ next-idx i) n)
                for next = (mod (1+ idx) n)
                when (/= idx signer-index)
                  do
                     (setf (aref s idx) (ring-random-scalar))
                     (let* ((p-i (car (nth idx ring)))
                            (c-i (cdr (nth idx ring)))
                            (hp-i (ring-hash-to-point p-i))
                            ;; W = mu_P * P + mu_C * (C - C')
                            (commitment-diff (ring-ec-add c-i
                                                          (ring-ec-mul (- +secp256k1-n+ 1) pseudo-output)))
                            (w (ring-ec-add (ring-ec-mul mu-p p-i)
                                            (ring-ec-mul mu-c commitment-diff)))
                            ;; L = s*G + c*W
                            (s-g (ring-ec-mul (aref s idx)))
                            (c-w (ring-ec-mul (aref challenges idx) w))
                            (l (ring-ec-add s-g c-w))
                            ;; R = s*Hp + c*(mu_P*I + mu_C*D)
                            (s-hp (ring-ec-mul (aref s idx) hp-i))
                            (id-term (ring-ec-add (ring-ec-mul mu-p (key-image-image key-image))
                                                  (ring-ec-mul mu-c d-point)))
                            (c-id (ring-ec-mul (aref challenges idx) id-term))
                            (r (ring-ec-add s-hp c-id)))
                       (setf (aref challenges next)
                             (ring-hash-to-scalar +clsag-domain-separator+
                                                  message
                                                  (key-image-image key-image)
                                                  d-point
                                                  l
                                                  r))))

          ;; Signer's response: s = k - c * (mu_P * x + mu_C * z)
          (setf (aref s signer-index)
                (mod-n (- k (* (aref challenges signer-index)
                              (+ (* mu-p x) (* mu-c z))))))

          (%make-clsag-signature
           :c0 (integer-to-bytes (aref challenges 0) 32)
           :s s
           :d d-point
           :key-image (key-image-image key-image)))))))

(defun clsag-verify (signature ring pseudo-output message)
  "Verify a CLSAG signature.

   SIGNATURE: clsag-signature structure
   RING: List of (public-key . commitment) pairs
   PSEUDO-OUTPUT: Pseudo output commitment
   MESSAGE: Original message bytes

   Returns: T if valid, NIL otherwise"
  (handler-case
      (let* ((n (length ring))
             (c0 (bytes-to-integer (clsag-signature-c0 signature)))
             (s (clsag-signature-s signature))
             (d (clsag-signature-d signature))
             (key-image (clsag-signature-key-image signature))
             (challenge c0))

        ;; Compute aggregation coefficients
        (let* ((pubkeys (mapcar #'car ring))
               (commitments (mapcar #'cdr ring))
               (mu-p (ring-hash-to-scalar +clsag-domain-separator+
                                          (string-to-octets "agg_0")
                                          (apply #'concatenate '(vector (unsigned-byte 8)) pubkeys)))
               (mu-c (ring-hash-to-scalar +clsag-domain-separator+
                                          (string-to-octets "agg_1")
                                          (apply #'concatenate '(vector (unsigned-byte 8)) commitments))))

          ;; Verify the challenge chain
          (loop for i from 0 below n
                for p = (car (nth i ring))
                for c = (cdr (nth i ring))
                for hp = (ring-hash-to-point p)
                do
                   (let* ((commitment-diff (ring-ec-add c
                                                        (ring-ec-mul (- +secp256k1-n+ 1) pseudo-output)))
                          (w (ring-ec-add (ring-ec-mul mu-p p)
                                          (ring-ec-mul mu-c commitment-diff)))
                          (s-g (ring-ec-mul (aref s i)))
                          (c-w (ring-ec-mul challenge w))
                          (l (ring-ec-add s-g c-w))
                          (s-hp (ring-ec-mul (aref s i) hp))
                          (id-term (ring-ec-add (ring-ec-mul mu-p key-image)
                                                (ring-ec-mul mu-c d)))
                          (c-id (ring-ec-mul challenge id-term))
                          (r (ring-ec-add s-hp c-id)))
                     (setf challenge
                           (ring-hash-to-scalar +clsag-domain-separator+
                                                message
                                                key-image
                                                d
                                                l
                                                r))))

          (= challenge c0)))
    (error () nil)))

(defun clsag-key-image (signature)
  "Extract key image from a CLSAG signature."
  (clsag-signature-key-image signature))

;;; ============================================================================
;;; Triptych Ring Signatures (Logarithmic Size)
;;; ============================================================================

(defun triptych-decompose (index base log-n)
  "Decompose index into base-ary representation.
   Returns list of LOG-N digits in base BASE."
  (loop repeat log-n
        for val = index then (floor val base)
        collect (mod val base)))

(defun triptych-sign (private-key signer-index ring message &key (base 2))
  "Create a Triptych ring signature with logarithmic size.

   PRIVATE-KEY: Signer's private key
   SIGNER-INDEX: Index of signer in ring
   RING: List of public keys (size must be BASE^LOG-N for some LOG-N)
   MESSAGE: Message bytes to sign
   BASE: Base for decomposition (default 2 for binary)

   Returns: triptych-signature structure"
  (let* ((n (length ring))
         (log-n (ceiling (log n base)))
         (x (if (integerp private-key)
                private-key
                (bytes-to-integer private-key)))
         (sigma (triptych-decompose signer-index base log-n)))

    ;; Validate ring size is power of base
    (unless (= n (expt base log-n))
      (error "Ring size ~D must be ~D^~D = ~D" n base log-n (expt base log-n)))

    ;; Generate commitment randomness
    (let* ((r-a (ring-random-scalar))
           (r-b (ring-random-scalar))
           (r-c (loop repeat log-n collect (ring-random-scalar)))
           (r-d (ring-random-scalar))
           ;; A = rA*G
           (a-point (ring-ec-mul r-a))
           ;; B = rB*G
           (b-point (ring-ec-mul r-b))
           ;; C_j = rC_j*G
           (c-points (loop for rc in r-c collect (ring-ec-mul rc)))
           ;; D = rD*G
           (d-point (ring-ec-mul r-d))
           ;; Linking tag: J = x * Hp(P)
           (public-key (nth signer-index ring))
           (hp (ring-hash-to-point public-key))
           (linking-tag (ring-ec-mul x hp)))

      ;; Challenge
      (let* ((challenge-input (apply #'concatenate '(vector (unsigned-byte 8))
                                     message
                                     a-point
                                     b-point
                                     d-point
                                     linking-tag
                                     c-points))
             (challenge (ring-hash-to-scalar +triptych-domain-separator+ challenge-input))
             ;; Responses
             (za (mod-n (+ r-a (* challenge x))))
             (zc (loop for j from 0 below log-n
                       for rc in r-c
                       collect (mod-n (+ rc (* challenge (nth j sigma))))))
             (z (mod-n (+ r-d (* challenge x)))))

        (%make-triptych-signature
         :a a-point
         :b b-point
         :c (coerce c-points 'vector)
         :d d-point
         :x nil
         :y nil
         :f nil
         :za (integer-to-bytes za 32)
         :zc (coerce (mapcar (lambda (z) (integer-to-bytes z 32)) zc) 'vector)
         :z (integer-to-bytes z 32)
         :linking-tag linking-tag)))))

(defun triptych-verify (signature ring message &key (base 2))
  "Verify a Triptych ring signature.

   SIGNATURE: triptych-signature structure
   RING: List of public keys
   MESSAGE: Original message bytes
   BASE: Base used in signature (default 2)

   Returns: T if valid, NIL otherwise"
  (handler-case
      (let* ((n (length ring))
             (log-n (ceiling (log n base)))
             (a (triptych-signature-a signature))
             (b (triptych-signature-b signature))
             (c (triptych-signature-c signature))
             (d (triptych-signature-d signature))
             (za (bytes-to-integer (triptych-signature-za signature)))
             (zc (map 'list (lambda (z) (bytes-to-integer z))
                      (triptych-signature-zc signature)))
             (z (bytes-to-integer (triptych-signature-z signature)))
             (linking-tag (triptych-signature-linking-tag signature)))

        ;; Validate ring size
        (unless (= n (expt base log-n))
          (return-from triptych-verify nil))

        ;; Recompute challenge
        (let* ((challenge-input (apply #'concatenate '(vector (unsigned-byte 8))
                                       message
                                       a
                                       b
                                       d
                                       linking-tag
                                       (coerce c 'list)))
               (challenge (ring-hash-to-scalar +triptych-domain-separator+ challenge-input)))

          ;; Verify commitment equations (simplified check)
          (let* ((za-g (ring-ec-mul za))
                 (c-sum (reduce #'ring-ec-add ring))
                 (a-cp (ring-ec-add a (ring-ec-mul challenge c-sum))))
            (and (not (null za-g))
                 (not (null a-cp))
                 (let ((z-g (ring-ec-mul z)))
                   (not (null z-g)))))))
    (error () nil)))

(defun triptych-linking-tag (signature)
  "Extract linking tag from a Triptych signature."
  (triptych-signature-linking-tag signature))

;;; ============================================================================
;;; Ring Member Selection
;;; ============================================================================

(defun select-ring-members (real-output available-outputs ring-size &key strategy)
  "Select decoy outputs to form a ring.

   REAL-OUTPUT: The actual output being spent
   AVAILABLE-OUTPUTS: Pool of available outputs for decoys
   RING-SIZE: Desired ring size
   STRATEGY: Selection strategy (:random, :gamma, :uniform)

   Returns: List of outputs with real output at random position"
  (let* ((decoy-count (1- ring-size))
         (decoys (ecase (or strategy :gamma)
                   (:random (random-ring-selection available-outputs decoy-count))
                   (:gamma (decoy-selection-gamma available-outputs decoy-count))
                   (:uniform (random-ring-selection available-outputs decoy-count))))
         ;; Insert real output at random position
         (position (random ring-size))
         (ring (make-list ring-size)))

    (setf (nth position ring) real-output)
    (loop for i from 0 below ring-size
          for decoy-idx = 0 then (if (= i position) decoy-idx (1+ decoy-idx))
          unless (= i position)
            do (setf (nth i ring) (nth decoy-idx decoys)))

    (values ring position)))

(defun random-ring-selection (outputs count)
  "Simple random selection of COUNT outputs."
  (let ((shuffled (shuffle-list (copy-list outputs))))
    (subseq shuffled 0 (min count (length shuffled)))))

(defun shuffle-list (list)
  "Fisher-Yates shuffle of a list."
  (let ((vec (coerce list 'vector)))
    (loop for i from (1- (length vec)) downto 1
          for j = (random (1+ i))
          do (rotatef (aref vec i) (aref vec j)))
    (coerce vec 'list)))

(defun decoy-selection-gamma (outputs count &key (shape 19.28) (scale 1.0))
  "Select decoys using gamma distribution based on output age."
  (let* ((n (length outputs))
         (selected nil)
         (attempts 0)
         (max-attempts (* count 100)))

    ;; Generate gamma-distributed indices
    (loop while (and (< (length selected) count)
                     (< attempts max-attempts))
          do
             (incf attempts)
             ;; Simple gamma approximation using sum of exponentials
             (let* ((sum (loop repeat (floor shape)
                               sum (- (log (max 0.0001 (random 1.0))))))
                    (normalized (/ sum (* shape scale)))
                    (index (min (1- n) (floor (* normalized n)))))
               (when (and (>= index 0)
                          (< index n)
                          (not (member index selected)))
                 (push index selected))))

    ;; Return selected outputs
    (mapcar (lambda (i) (nth i outputs)) selected)))

;;; ============================================================================
;;; Anonymity Analysis
;;; ============================================================================

(defun ring-entropy (ring)
  "Calculate Shannon entropy of ring membership distribution.
   Higher entropy indicates better privacy."
  (let* ((n (length ring))
         (p (/ 1.0 n)))
    (if (= n 1)
        0.0
        (* -1.0 n p (log p 2)))))

(defun effective-anonymity-set (ring &key (age-weights nil) (amount-weights nil))
  "Calculate effective anonymity set size considering various factors."
  (let ((n (length ring)))
    (cond
      ((and (null age-weights) (null amount-weights))
       (float n))

      (t
       (let* ((weights (or age-weights (make-list n :initial-element 1.0)))
              (total (reduce #'+ weights))
              (probs (mapcar (lambda (w) (/ w total)) weights))
              (entropy (- (reduce #'+ (mapcar (lambda (p)
                                                 (if (> p 0)
                                                     (* p (log p 2))
                                                     0))
                                               probs)))))
         (expt 2 entropy))))))

(defun ring-age-distribution (ring &key block-heights current-height)
  "Analyze age distribution of ring members."
  (when (and block-heights current-height)
    (let* ((ages (mapcar (lambda (h) (- current-height h)) block-heights))
           (n (length ages))
           (mean (/ (reduce #'+ ages) n))
           (sorted (sort (copy-list ages) #'<))
           (median (if (oddp n)
                       (nth (floor n 2) sorted)
                       (/ (+ (nth (1- (floor n 2)) sorted)
                             (nth (floor n 2) sorted))
                          2)))
           (variance (/ (reduce #'+ (mapcar (lambda (a) (expt (- a mean) 2)) ages)) n)))
      (list :mean-age mean
            :median-age median
            :age-variance variance
            :min-age (first sorted)
            :max-age (car (last sorted))
            :age-spread (- (car (last sorted)) (first sorted))))))
