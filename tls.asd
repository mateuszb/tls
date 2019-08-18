(asdf:defsystem tls
  :description "TLS client and server socket stream for use with the reactor"
  :author "Mateusz Berezecki <mateuszb@fastmail.fm>"
  :license  "BSD"
  :version "0.0.1"
  :defsystem-depends-on
  (
   "cffi"
   "cffi-grovel"
   "alien-ring"
   "socket"
   )
  :serial t
  :depends-on ("cffi")
  :components ((:file "package")
               (:file "tls")
	       (:cffi-grovel-file "grovel" :depends-on ("package"))))
