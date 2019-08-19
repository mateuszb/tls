;;;; package.lisp

(defpackage tls
  (:use #:cl :cffi)
  (:export
   :with-tls-context
   :connect
   :accept
   :make-tls-context
   :load-cert
   :load-key
   :make-tls-stream
   :ssl-do-handshake
   :tls-read-char-sequence
   :tls-read-byte-sequence
   :tls-read
   :tls-write
   :tls-wants-read
   :tls-wants-write
   :tls-zero-return
   :tls-set-hostname
   :+SSL-ERROR-WANT-READ+
   :+SSL-ERROR-WANT-WRITE+
   :+SSL-ERROR-ZERO-RETURN+))
