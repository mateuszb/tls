(in-package :tls)

(include "openssl/ssl.h"
	 "openssl/err.h")

(constant (+SSL-FILETYPE-PEM+ "SSL_FILETYPE_PEM"))
(constant (+TLS1.3-VERSION+ "TLS1_3_VERSION"))
(constant (+TLS1.2-VERSION+ "TLS1_2_VERSION"))
(constant (+SSL-VERIFY-PEER+ "SSL_VERIFY_PEER"))
(constant (+SSL-VERIFY-NONE+ "SSL_VERIFY_NONE"))
(constant (+SSL-OP-NO-SSL2+ "SSL_OP_NO_SSLv2"))
(constant (+SSL-OP-NO-SSL3+ "SSL_OP_NO_SSLv3"))
(constant (+SSL-OP-NO-COMPRESSION+ "SSL_OP_NO_COMPRESSION"))
(constant (+SSL-ERROR-WANT-READ+ "SSL_ERROR_WANT_READ"))
(constant (+SSL-ERROR-WANT-WRITE+ "SSL_ERROR_WANT_WRITE"))
(constant (+BIO-CTRL-FLUSH+ "BIO_CTRL_FLUSH"))
(constant (+BIO-C-SET-SSL+ "BIO_C_SET_SSL"))
(constant (+BIO-C-DO-STATE-MACHINE+ "BIO_C_DO_STATE_MACHINE"))