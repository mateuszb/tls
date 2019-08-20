(in-package :tls)

(defvar *context*)

(define-foreign-library libssl
  (t (:or "libssl.so" "libssl.so.3")))
(use-foreign-library libssl)
(load-foreign-library 'libssl)

(define-foreign-library libcrypto
  (t (:or "libcrypto.so")))
(use-foreign-library libcrypto)
(load-foreign-library 'libcrypto)

(defcfun (tls-client-method "TLS_client_method") :pointer)
(defcfun (tls-server-method "TLS_server_method") :pointer)

(defcfun (ssl-set-msg-cb "SSL_set_msg_callback") :void
  (ssl :pointer)
  (cb :pointer))

(defcfun (ssl-ctrl "SSL_ctrl") :long
  (ssl :pointer)
  (cmd :int)
  (larg :long)
  (parg :pointer))

(defcfun (bio-new-fp "BIO_new_fp") :pointer
  (fp :pointer)
  (flags :int))

(defcfun (ssl-ctx-new "SSL_CTX_new") :pointer
  (method :pointer))

(defcfun (ssl-ctx-use-cert-file "SSL_CTX_use_certificate_file") :int
  (ctx :pointer)
  (file :string)
  (type :int))

(defcfun (ssl-ctx-use-private-key-file "SSL_CTX_use_PrivateKey_file") :int
  (ctx :pointer)
  (file :string)
  (type :int))

(defcfun (ssl-ctx-set-verify "SSL_CTX_set_verify") :void
  (ctx :pointer)
  (mode :int)
  (cb :pointer))

(defcfun (ssl-ctx-set-verify-depth "SSL_CTX_set_verify_depth") :void
  (ctx :pointer)
  (depth :int))

(defcfun (ssl-ctx-set-options "SSL_CTX_set_options") :void
  (ctx :pointer)
  (flags :long))

(defcfun (ssl-ctx-load-verify-locations "SSL_CTX_load_verify_locations") :int
  (ctx :pointer)
  (cafile :string)
  (capath :string))

(defcfun (ssl-new "SSL_new") :pointer
  (ctx :pointer))

(defcfun (ssl-set-fd "SSL_set_fd") :int
  (tls :pointer)
  (fd :int))

(defcfun (ssl-accept "SSL_accept") :int
  (ssl :pointer))

(defcfun (ssl-connect "SSL_connect") :int
  (ssl :pointer))

(defcfun (ssl-set-connect-state "SSL_set_connect_state") :void
  (ssl :pointer))

(defcfun (ssl-set-accept-state "SSL_set_accept_state") :void
  (ssl :pointer))

(defcfun (ssl-do-handshake "SSL_do_handshake") :int
  (ssl :pointer))

(defcfun (ssl-has-pending "SSL_has_pending") :int
  (ssl :pointer))

(defcfun (ssl-pending "SSL_pending") :int
  (ssl :pointer))

(defcfun (ssl-get-wr-bio "SSL_get_wbio") :pointer
  (ssl :pointer))

(defcfun (ssl-get-rd-bio "SSL_get_rbio") :pointer
  (ssl :pointer))

(defcfun (ssl-get-error "SSL_get_error") :int
  (ssl :pointer)
  (ret :int))

(defcfun (ssl-set-host-name "SSL_set_tlsext_host_name") :int
  (ssl :pointer)
  (name :string))

(defcfun (bio-new-ssl "BIO_new_ssl") :pointer
  (ssl-ctx :pointer)
  (client :int))

(defcfun (bio-write "BIO_write") :int
  (bio :pointer)
  (buf :pointer)
  (num :int))

(defcfun (bio-read "BIO_read") :int
  (bio :pointer)
  (buf :pointer)
  (num :int))

(defcfun (bio-ctrl "BIO_ctrl") :long
  (bio :pointer)
  (cmd :int)
  (larg :long)
  (parg :pointer))

(defun bio-do-handshake (bio)
  (bio-ctrl bio +BIO-C-DO-STATE-MACHINE+ 0 (null-pointer)))

(defun bio-flush (bio)
  (bio-ctrl bio +BIO-CTRL-FLUSH+ 0 (null-pointer)))

(defun bio-set-ssl (bio ssl close-p)
  (bio-ctrl bio +BIO-C-SET-SSL+ close-p ssl))

(defun get-client-method ()
  (tls-client-method))

(defun get-server-method ()
  (tls-server-method))

(defun make-tls-context (cafile capath server)
  (let ((ssl-ctx (ssl-ctx-new (if server (get-server-method) (get-client-method)))))
    (ssl-ctx-set-verify ssl-ctx +SSL-VERIFY-PEER+ (null-pointer))
    (ssl-ctx-set-verify-depth ssl-ctx 10)
    (ssl-ctx-set-options ssl-ctx (logior +SSL-OP-NO-SSL2+ +SSL-OP-NO-SSL3+ +SSL-OP-NO-COMPRESSION+))
    (ssl-ctx-load-verify-locations ssl-ctx
			   (if cafile cafile (null-pointer))
			   (if capath capath (null-pointer)))
    ssl-ctx))

(defun load-cert (certpath)
  (ssl-ctx-use-cert-file *context* certpath +SSL-FILETYPE-PEM+))

(defun load-key (keypath)
  (ssl-ctx-use-private-key-file *context* keypath +SSL-FILETYPE-PEM+))

(defun connect (fd)
  (let* ((ssl (ssl-new *context*)))
    (ssl-set-fd ssl fd)
    (ssl-set-connect-state ssl)
    ssl))

(defun accept (fd)
  (let* ((ssl (ssl-new *context*)))
    (ssl-set-fd ssl fd)
    (ssl-accept ssl)
    ;(ssl-set-accept-state ssl)
    ssl))

(defun has-pending-p (ssl)
  (eq 1 (ssl-has-pending ssl)))

(defun pending-bytes (ssl)
  (ssl-pending ssl))

(defmacro with-tls-context (ctx &body body)
  `(let ((*context* ,ctx))
     ,@body))

(define-condition tls-wants-read ()
  ((partial-read :initform 0 :initarg :partial-read)))

(define-condition tls-wants-write ()
  ((partial-write :initform 0 :initarg :partial-write)))

(define-condition tls-zero-return () ())

(defclass tls-stream ()
  ((context :initform nil :initarg :context :reader tls-stream-context)
   (ssl :initform nil :initarg :ssl :reader tls-stream-ssl)
   (bio :initform nil :initarg :bio :reader tls-stream-bio)
   (rxring :initform nil :initarg :rxring :reader tls-stream-rx-ring)
   (txring :initform nil :initarg :txring :reader tls-stream-tx-ring)))

(defun make-tls-stream (context ssl)
  (let ((instance
	 (make-instance 'tls-stream
			:context context
			:ssl ssl
			:bio (bio-new-ssl context 1)
			:rxring (alien-ring:make-ring-buffer 8192)
			:txring (alien-ring:make-ring-buffer 8192))))
    (with-slots (bio) instance
      (bio-set-ssl bio ssl 1))
    instance))

(defun tls-read (tls)
  (with-slots (rxring) tls
    (let* ((navail (if (has-pending-p (tls-stream-ssl tls))
		       (pending-bytes (tls-stream-ssl tls)) 0))
	   (wrlocs (alien-ring:ring-buffer-write-locations rxring navail))
	   (alien (alien-ring:ring-buffer-alien rxring))
	   (bio (tls-stream-bio tls)))
      (loop for loc in wrlocs
	 do
	   #+tls-debug
	   (format t "bytes pending: ~a~%" (ssl-pending (tls-stream-ssl tls)))
	   (let ((nread (bio-read bio (inc-pointer alien (car loc)) (cdr loc))))
	     #+tls-debug(format t "bio-read returned ~a~%" nread)
	     (cond
	       ((> nread 0)
		(alien-ring::ring-buffer-advance-wr rxring nread)
		nread)
	       ((<= nread 0)
		(let ((code (ssl-get-error (tls-stream-ssl tls) nread)))
		  (cond
		    ((= code +SSL-ERROR-WANT-READ+)
		     (error (make-condition 'tls-wants-read)))
		    ((= code +SSL-ERROR-WANT-WRITE+)
		     (error (make-condition 'tls-wants-write)))
		    ((= code +SSL-ERROR-ZERO-RETURN+)
		     (error (make-condition 'tls-zero-return))))))))))))

(defun tls-write (tls)
  (with-slots (txring) tls
    (let* ((ndata (alien-ring:ring-buffer-size txring))
	   (alien (alien-ring:ring-buffer-alien txring))
	   (bio (tls-stream-bio tls))
	   (total-written 0))
      #+tls-debug
      (format t "alien buffer has ~a bytes to send~%" ndata)
      (when (zerop ndata)
	(inspect txring))
      (when (> ndata 0)
	(let ((rdlocs (alien-ring::ring-buffer-read-locations txring ndata)))
	  #+tls-debug
	  (format t "read locations: ~a~%" rdlocs)
	  (loop for loc in rdlocs
	     do
	       #+tls-debug
	       (format t "bio write of length ~a~%" (cdr loc))
	       (let ((nwritten (bio-write bio (inc-pointer alien (car loc)) (cdr loc))))
		 (cond
		   ((> nwritten 0)
		    (alien-ring::ring-buffer-advance-rd txring nwritten)
		    #+tls-debug
		    (format t "tls-write wrote ~a bytes~%" nwritten)
		    (incf total-written nwritten))
		   
		   ((<= nwritten 0)
		    (let ((code (ssl-get-error (tls-stream-ssl tls) nwritten)))
		      (cond
			((= code +SSL-ERROR-WANT-READ+) (error (make-condition 'tls-wants-read)))
			((= code +SSL-ERROR-WANT-WRITE+) (error (make-condition 'tls-wants-write)))
			((= code +SSL-ERROR-SYSCALL+) (error 'syscall-error))
			(t (error (format nil "error with status ~a~%" code)))))))))))
      total-written)))

(defun tls-read-line (tls-stream line-ending)
  #+off
  (handler-case (tls-read tls-stream)
    (tls-wants-read () t))
  (alien-ring:ring-buffer-read-line (tls-stream-rx-ring tls-stream) line-ending))

(defun tls-write-line (tls-stream str &optional (line-ending '(#\newline)))
  (with-slots (txring) tls-stream
    (alien-ring:ring-buffer-write-char-sequence txring str)
    (alien-ring:ring-buffer-write-char-sequence txring line-ending)
    (tls-write tls-stream)
    (bio-flush (ssl-get-wr-bio (tls-stream-ssl tls-stream)))))

(defun tls-read-char (tls-stream)
  (alien-ring:ring-buffer-read-char (tls-stream-rx-ring tls-stream)))

(defun tls-peek-char (tls-stream &optional (offset 0))
  (alien-ring:ring-buffer-peek-char (tls-stream-rx-ring tls-stream) offset))

(defun tls-read-char-sequence (tls-stream &optional n)
  (alien-ring::ring-buffer-read-char-sequence (tls-stream-rx-ring tls-stream) n))

(defun tls-read-byte-sequence (tls-stream &optional n)
  (let* ((navail (tls-stream-read-bytes-available tls-stream))
	 (requested (if n (min navail n) navail))
	 (seq (alien-ring::ring-buffer-read-byte-sequence
	       (tls-stream-rx-ring tls-stream) requested)))
    (unless (zerop (length seq))
      (make-array requested :element-type '(unsigned-byte 8)
		  :initial-contents seq))))

(defun tls-write-byte-sequence (tls-stream seq)
  (let* ((ringbuf (tls-stream-tx-ring tls-stream)))
    (alien-ring::ring-buffer-write-byte-sequence ringbuf seq)
    (let ((nwritten (tls-write tls-stream)))
      (bio-flush (ssl-get-wr-bio (tls-stream-ssl tls-stream)))
      nwritten)))

(defun tls-write-char-sequence (tls-stream seq)
  (alien-ring::ring-buffer-write-char-sequence (tls-stream-tx-ring tls-stream) seq)
  (let ((nwritten (tls-write tls-stream)))
    (bio-flush (ssl-get-wr-bio (tls-stream-ssl tls-stream)))
    nwritten))

(defun tls-read-token (tls-stream)
  (alien-ring:ring-buffer-read-token (tls-stream-rx-ring tls-stream)))

(defun tls-stream-read-bytes-available (tls-stream)
  (alien-ring::ring-buffer-size (tls-stream-rx-ring tls-stream)))

(defun tls-set-hostname (tls-stream hostname)
  (ssl-set-host-name (tls-stream-ssl tls-stream) hostname))

