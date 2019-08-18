;;;; package.lisp

(defpackage tls
  (:use #:cl :cffi)
  (:export
   :with-tls-context
   :connect
   :make-tls-context))
