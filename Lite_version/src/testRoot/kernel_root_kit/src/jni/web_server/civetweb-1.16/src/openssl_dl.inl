/* Copyright (c) 2013-2021 the Civetweb developers
 * Copyright (c) 2004-2013 Sergey Lyubka
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


typedef struct ssl_st SSL;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct x509_name X509_NAME;
typedef struct asn1_integer ASN1_INTEGER;
typedef struct bignum BIGNUM;
typedef struct ossl_init_settings_st OPENSSL_INIT_SETTINGS;
typedef struct evp_md EVP_MD;
typedef struct x509 X509;


#define SSL_CTRL_OPTIONS (32)
#define SSL_CTRL_CLEAR_OPTIONS (77)
#define SSL_CTRL_SET_ECDH_AUTO (94)

#define OPENSSL_INIT_NO_LOAD_SSL_STRINGS 0x00100000L
#define OPENSSL_INIT_LOAD_SSL_STRINGS 0x00200000L
#define OPENSSL_INIT_LOAD_CRYPTO_STRINGS 0x00000002L

#define SSL_VERIFY_NONE (0)
#define SSL_VERIFY_PEER (1)
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT (2)
#define SSL_VERIFY_CLIENT_ONCE (4)

#define SSL_OP_ALL (0x80000BFFul)

#define SSL_OP_NO_SSLv2 (0x01000000ul)
#define SSL_OP_NO_SSLv3 (0x02000000ul)
#define SSL_OP_NO_TLSv1 (0x04000000ul)
#define SSL_OP_NO_TLSv1_2 (0x08000000ul)
#define SSL_OP_NO_TLSv1_1 (0x10000000ul)
#define SSL_OP_NO_TLSv1_3 (0x20000000ul)
#define SSL_OP_SINGLE_DH_USE (0x00100000ul)
#define SSL_OP_CIPHER_SERVER_PREFERENCE (0x00400000ul)
#define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION (0x00010000ul)
#define SSL_OP_NO_COMPRESSION (0x00020000ul)
#define SSL_OP_NO_RENEGOTIATION (0x40000000ul)

#define SSL_CB_HANDSHAKE_START (0x10)
#define SSL_CB_HANDSHAKE_DONE (0x20)

#define SSL_ERROR_NONE (0)
#define SSL_ERROR_SSL (1)
#define SSL_ERROR_WANT_READ (2)
#define SSL_ERROR_WANT_WRITE (3)
#define SSL_ERROR_WANT_X509_LOOKUP (4)
#define SSL_ERROR_SYSCALL (5) /* see errno */
#define SSL_ERROR_ZERO_RETURN (6)
#define SSL_ERROR_WANT_CONNECT (7)
#define SSL_ERROR_WANT_ACCEPT (8)

#define TLSEXT_TYPE_server_name (0)
#define TLSEXT_NAMETYPE_host_name (0)
#define SSL_TLSEXT_ERR_OK (0)
#define SSL_TLSEXT_ERR_ALERT_WARNING (1)
#define SSL_TLSEXT_ERR_ALERT_FATAL (2)
#define SSL_TLSEXT_ERR_NOACK (3)

#define SSL_SESS_CACHE_BOTH (3)

enum ssl_func_category {
	TLS_Mandatory, /* required for HTTPS */
	TLS_ALPN,      /* required for Application Layer Protocol Negotiation */
	TLS_END_OF_LIST
};

/* Check if all TLS functions/features are available */
static int tls_feature_missing[TLS_END_OF_LIST] = {0};

struct ssl_func {
	const char *name;                /* SSL function name */
	enum ssl_func_category required; /* Mandatory or optional */
	void (*ptr)(void);               /* Function pointer */
};


#if (defined(OPENSSL_API_1_1) || defined(OPENSSL_API_3_0))                     \
    && !defined(NO_SSL_DL)

#define SSL_free (*(void (*)(SSL *))ssl_sw[0].ptr)
#define SSL_accept (*(int (*)(SSL *))ssl_sw[1].ptr)
#define SSL_connect (*(int (*)(SSL *))ssl_sw[2].ptr)
#define SSL_read (*(int (*)(SSL *, void *, int))ssl_sw[3].ptr)
#define SSL_write (*(int (*)(SSL *, const void *, int))ssl_sw[4].ptr)
#define SSL_get_error (*(int (*)(SSL *, int))ssl_sw[5].ptr)
#define SSL_set_fd (*(int (*)(SSL *, SOCKET))ssl_sw[6].ptr)
#define SSL_new (*(SSL * (*)(SSL_CTX *)) ssl_sw[7].ptr)
#define SSL_CTX_new (*(SSL_CTX * (*)(SSL_METHOD *)) ssl_sw[8].ptr)
#define TLS_server_method (*(SSL_METHOD * (*)(void)) ssl_sw[9].ptr)
#define OPENSSL_init_ssl                                                       \
	(*(int (*)(uint64_t opts,                                                  \
	           const OPENSSL_INIT_SETTINGS *settings))ssl_sw[10]               \
	      .ptr)
#define SSL_CTX_use_PrivateKey_file                                            \
	(*(int (*)(SSL_CTX *, const char *, int))ssl_sw[11].ptr)
#define SSL_CTX_use_certificate_file                                           \
	(*(int (*)(SSL_CTX *, const char *, int))ssl_sw[12].ptr)
#define SSL_CTX_set_default_passwd_cb                                          \
	(*(void (*)(SSL_CTX *, mg_callback_t))ssl_sw[13].ptr)
#define SSL_CTX_free (*(void (*)(SSL_CTX *))ssl_sw[14].ptr)
#define SSL_CTX_use_certificate_chain_file                                     \
	(*(int (*)(SSL_CTX *, const char *))ssl_sw[15].ptr)
#define TLS_client_method (*(SSL_METHOD * (*)(void)) ssl_sw[16].ptr)
#define SSL_pending (*(int (*)(SSL *))ssl_sw[17].ptr)
#define SSL_CTX_set_verify                                                     \
	(*(void (*)(SSL_CTX *,                                                     \
	            int,                                                           \
	            int (*verify_callback)(int, X509_STORE_CTX *)))ssl_sw[18]      \
	      .ptr)
#define SSL_shutdown (*(int (*)(SSL *))ssl_sw[19].ptr)
#define SSL_CTX_load_verify_locations                                          \
	(*(int (*)(SSL_CTX *, const char *, const char *))ssl_sw[20].ptr)
#define SSL_CTX_set_default_verify_paths (*(int (*)(SSL_CTX *))ssl_sw[21].ptr)
#define SSL_CTX_set_verify_depth (*(void (*)(SSL_CTX *, int))ssl_sw[22].ptr)
#define SSL_get_peer_certificate (*(X509 * (*)(SSL *)) ssl_sw[23].ptr)
#define SSL_get_version (*(const char *(*)(SSL *))ssl_sw[24].ptr)
#define SSL_get_current_cipher (*(SSL_CIPHER * (*)(SSL *)) ssl_sw[25].ptr)
#define SSL_CIPHER_get_name                                                    \
	(*(const char *(*)(const SSL_CIPHER *))ssl_sw[26].ptr)
#define SSL_CTX_check_private_key (*(int (*)(SSL_CTX *))ssl_sw[27].ptr)
#define SSL_CTX_set_session_id_context                                         \
	(*(int (*)(SSL_CTX *, const unsigned char *, unsigned int))ssl_sw[28].ptr)
#define SSL_CTX_ctrl (*(long (*)(SSL_CTX *, int, long, void *))ssl_sw[29].ptr)
#define SSL_CTX_set_cipher_list                                                \
	(*(int (*)(SSL_CTX *, const char *))ssl_sw[30].ptr)
#define SSL_CTX_set_options                                                    \
	(*(unsigned long (*)(SSL_CTX *, unsigned long))ssl_sw[31].ptr)
#define SSL_CTX_set_info_callback                                              \
	(*(void (*)(SSL_CTX * ctx, void (*callback)(const SSL *, int, int)))       \
	      ssl_sw[32]                                                           \
	          .ptr)
#define SSL_get_ex_data (*(char *(*)(const SSL *, int))ssl_sw[33].ptr)
#define SSL_set_ex_data (*(void (*)(SSL *, int, char *))ssl_sw[34].ptr)
#define SSL_CTX_callback_ctrl                                                  \
	(*(long (*)(SSL_CTX *, int, void (*)(void)))ssl_sw[35].ptr)
#define SSL_get_servername                                                     \
	(*(const char *(*)(const SSL *, int type))ssl_sw[36].ptr)
#define SSL_set_SSL_CTX (*(SSL_CTX * (*)(SSL *, SSL_CTX *)) ssl_sw[37].ptr)
#define SSL_ctrl (*(long (*)(SSL *, int, long, void *))ssl_sw[38].ptr)
#define SSL_CTX_set_alpn_protos                                                \
	(*(int (*)(SSL_CTX *, const unsigned char *, unsigned))ssl_sw[39].ptr)
typedef int (*tSSL_alpn_select_cb)(SSL *ssl,
                                   const unsigned char **out,
                                   unsigned char *outlen,
                                   const unsigned char *in,
                                   unsigned int inlen,
                                   void *arg);
#define SSL_CTX_set_alpn_select_cb                                             \
	(*(void (*)(SSL_CTX *, tSSL_alpn_select_cb, void *))ssl_sw[40].ptr)
typedef int (*tSSL_next_protos_advertised_cb)(SSL *ssl,
                                              const unsigned char **out,
                                              unsigned int *outlen,
                                              void *arg);
#define SSL_CTX_set_next_protos_advertised_cb                                  \
	(*(void (*)(SSL_CTX *, tSSL_next_protos_advertised_cb, void *))ssl_sw[41]  \
	      .ptr)

#define SSL_CTX_set_timeout (*(long (*)(SSL_CTX *, long))ssl_sw[42].ptr)

#define SSL_CTX_clear_options(ctx, op)                                         \
	SSL_CTX_ctrl((ctx), SSL_CTRL_CLEAR_OPTIONS, (op), NULL)
#define SSL_CTX_set_ecdh_auto(ctx, onoff)                                      \
	SSL_CTX_ctrl(ctx, SSL_CTRL_SET_ECDH_AUTO, onoff, NULL)

#define SSL_CTRL_SET_TLSEXT_SERVERNAME_CB 53
#define SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG 54
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define SSL_CTX_set_tlsext_servername_callback(ctx, cb)                        \
	SSL_CTX_callback_ctrl(ctx,                                                 \
	                      SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,                   \
	                      (void (*)(void))cb)
#define SSL_set_tlsext_host_name(ctx, arg)                                     \
	SSL_ctrl(ctx, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, (void *)arg)

#define X509_get_notBefore(x) ((x)->cert_info->validity->notBefore)
#define X509_get_notAfter(x) ((x)->cert_info->validity->notAfter)

#define SSL_set_app_data(s, arg) (SSL_set_ex_data(s, 0, (char *)arg))
#define SSL_get_app_data(s) (SSL_get_ex_data(s, 0))

#define SSL_CTX_sess_set_cache_size(ctx, size) SSL_CTX_ctrl(ctx, 42, size, NULL)
#define SSL_CTX_set_session_cache_mode(ctx, mode)                              \
	SSL_CTX_ctrl(ctx, 44, mode, NULL)


#define ERR_get_error (*(unsigned long (*)(void))crypto_sw[0].ptr)
#define ERR_error_string (*(char *(*)(unsigned long, char *))crypto_sw[1].ptr)
#define CONF_modules_unload (*(void (*)(int))crypto_sw[2].ptr)
#define X509_free (*(void (*)(X509 *))crypto_sw[3].ptr)
#define X509_get_subject_name (*(X509_NAME * (*)(X509 *)) crypto_sw[4].ptr)
#define X509_get_issuer_name (*(X509_NAME * (*)(X509 *)) crypto_sw[5].ptr)
#define X509_NAME_oneline                                                      \
	(*(char *(*)(X509_NAME *, char *, int))crypto_sw[6].ptr)
#define X509_get_serialNumber (*(ASN1_INTEGER * (*)(X509 *)) crypto_sw[7].ptr)
#define EVP_get_digestbyname                                                   \
	(*(const EVP_MD *(*)(const char *))crypto_sw[8].ptr)
#define EVP_Digest                                                             \
	(*(int (*)(                                                                \
	    const void *, size_t, void *, unsigned int *, const EVP_MD *, void *)) \
	      crypto_sw[9]                                                         \
	          .ptr)
#define i2d_X509 (*(int (*)(X509 *, unsigned char **))crypto_sw[10].ptr)
#define BN_bn2hex (*(char *(*)(const BIGNUM *a))crypto_sw[11].ptr)
#define ASN1_INTEGER_to_BN                                                     \
	(*(BIGNUM * (*)(const ASN1_INTEGER *ai, BIGNUM *bn)) crypto_sw[12].ptr)
#define BN_free (*(void (*)(const BIGNUM *a))crypto_sw[13].ptr)
#define CRYPTO_free (*(void (*)(void *addr))crypto_sw[14].ptr)
#define ERR_clear_error (*(void (*)(void))crypto_sw[15].ptr)

#define OPENSSL_free(a) CRYPTO_free(a)

#define OPENSSL_REMOVE_THREAD_STATE()

/* init_ssl_ctx() function updates this array.
 * It loads SSL library dynamically and changes NULLs to the actual addresses
 * of respective functions. The macros above (like SSL_connect()) are really
 * just calling these functions indirectly via the pointer. */
static struct ssl_func ssl_sw[] = {
    {"SSL_free", TLS_Mandatory, NULL},
    {"SSL_accept", TLS_Mandatory, NULL},
    {"SSL_connect", TLS_Mandatory, NULL},
    {"SSL_read", TLS_Mandatory, NULL},
    {"SSL_write", TLS_Mandatory, NULL},
    {"SSL_get_error", TLS_Mandatory, NULL},
    {"SSL_set_fd", TLS_Mandatory, NULL},
    {"SSL_new", TLS_Mandatory, NULL},
    {"SSL_CTX_new", TLS_Mandatory, NULL},
    {"TLS_server_method", TLS_Mandatory, NULL},
    {"OPENSSL_init_ssl", TLS_Mandatory, NULL},
    {"SSL_CTX_use_PrivateKey_file", TLS_Mandatory, NULL},
    {"SSL_CTX_use_certificate_file", TLS_Mandatory, NULL},
    {"SSL_CTX_set_default_passwd_cb", TLS_Mandatory, NULL},
    {"SSL_CTX_free", TLS_Mandatory, NULL},
    {"SSL_CTX_use_certificate_chain_file", TLS_Mandatory, NULL},
    {"TLS_client_method", TLS_Mandatory, NULL},
    {"SSL_pending", TLS_Mandatory, NULL},
    {"SSL_CTX_set_verify", TLS_Mandatory, NULL},
    {"SSL_shutdown", TLS_Mandatory, NULL},
    {"SSL_CTX_load_verify_locations", TLS_Mandatory, NULL},
    {"SSL_CTX_set_default_verify_paths", TLS_Mandatory, NULL},
    {"SSL_CTX_set_verify_depth", TLS_Mandatory, NULL},
#if defined(OPENSSL_API_3_0)
    {"SSL_get1_peer_certificate", TLS_Mandatory, NULL},
#else
    {"SSL_get_peer_certificate", TLS_Mandatory, NULL},
#endif
    {"SSL_get_version", TLS_Mandatory, NULL},
    {"SSL_get_current_cipher", TLS_Mandatory, NULL},
    {"SSL_CIPHER_get_name", TLS_Mandatory, NULL},
    {"SSL_CTX_check_private_key", TLS_Mandatory, NULL},
    {"SSL_CTX_set_session_id_context", TLS_Mandatory, NULL},
    {"SSL_CTX_ctrl", TLS_Mandatory, NULL},
    {"SSL_CTX_set_cipher_list", TLS_Mandatory, NULL},
    {"SSL_CTX_set_options", TLS_Mandatory, NULL},
    {"SSL_CTX_set_info_callback", TLS_Mandatory, NULL},
    {"SSL_get_ex_data", TLS_Mandatory, NULL},
    {"SSL_set_ex_data", TLS_Mandatory, NULL},
    {"SSL_CTX_callback_ctrl", TLS_Mandatory, NULL},
    {"SSL_get_servername", TLS_Mandatory, NULL},
    {"SSL_set_SSL_CTX", TLS_Mandatory, NULL},
    {"SSL_ctrl", TLS_Mandatory, NULL},
    {"SSL_CTX_set_alpn_protos", TLS_ALPN, NULL},
    {"SSL_CTX_set_alpn_select_cb", TLS_ALPN, NULL},
    {"SSL_CTX_set_next_protos_advertised_cb", TLS_ALPN, NULL},
    {"SSL_CTX_set_timeout", TLS_Mandatory, NULL},
    {NULL, TLS_END_OF_LIST, NULL}};


/* Similar array as ssl_sw. These functions could be located in different
 * lib. */
static struct ssl_func crypto_sw[] = {
    {"ERR_get_error", TLS_Mandatory, NULL},
    {"ERR_error_string", TLS_Mandatory, NULL},
    {"CONF_modules_unload", TLS_Mandatory, NULL},
    {"X509_free", TLS_Mandatory, NULL},
    {"X509_get_subject_name", TLS_Mandatory, NULL},
    {"X509_get_issuer_name", TLS_Mandatory, NULL},
    {"X509_NAME_oneline", TLS_Mandatory, NULL},
    {"X509_get_serialNumber", TLS_Mandatory, NULL},
    {"EVP_get_digestbyname", TLS_Mandatory, NULL},
    {"EVP_Digest", TLS_Mandatory, NULL},
    {"i2d_X509", TLS_Mandatory, NULL},
    {"BN_bn2hex", TLS_Mandatory, NULL},
    {"ASN1_INTEGER_to_BN", TLS_Mandatory, NULL},
    {"BN_free", TLS_Mandatory, NULL},
    {"CRYPTO_free", TLS_Mandatory, NULL},
    {"ERR_clear_error", TLS_Mandatory, NULL},
    {NULL, TLS_END_OF_LIST, NULL}};
#endif


#if defined(OPENSSL_API_1_0)

#define SSL_free (*(void (*)(SSL *))ssl_sw[0].ptr)
#define SSL_accept (*(int (*)(SSL *))ssl_sw[1].ptr)
#define SSL_connect (*(int (*)(SSL *))ssl_sw[2].ptr)
#define SSL_read (*(int (*)(SSL *, void *, int))ssl_sw[3].ptr)
#define SSL_write (*(int (*)(SSL *, const void *, int))ssl_sw[4].ptr)
#define SSL_get_error (*(int (*)(SSL *, int))ssl_sw[5].ptr)
#define SSL_set_fd (*(int (*)(SSL *, SOCKET))ssl_sw[6].ptr)
#define SSL_new (*(SSL * (*)(SSL_CTX *)) ssl_sw[7].ptr)
#define SSL_CTX_new (*(SSL_CTX * (*)(SSL_METHOD *)) ssl_sw[8].ptr)
#define SSLv23_server_method (*(SSL_METHOD * (*)(void)) ssl_sw[9].ptr)
#define SSL_library_init (*(int (*)(void))ssl_sw[10].ptr)
#define SSL_CTX_use_PrivateKey_file                                            \
	(*(int (*)(SSL_CTX *, const char *, int))ssl_sw[11].ptr)
#define SSL_CTX_use_certificate_file                                           \
	(*(int (*)(SSL_CTX *, const char *, int))ssl_sw[12].ptr)
#define SSL_CTX_set_default_passwd_cb                                          \
	(*(void (*)(SSL_CTX *, mg_callback_t))ssl_sw[13].ptr)
#define SSL_CTX_free (*(void (*)(SSL_CTX *))ssl_sw[14].ptr)
#define SSL_load_error_strings (*(void (*)(void))ssl_sw[15].ptr)
#define SSL_CTX_use_certificate_chain_file                                     \
	(*(int (*)(SSL_CTX *, const char *))ssl_sw[16].ptr)
#define SSLv23_client_method (*(SSL_METHOD * (*)(void)) ssl_sw[17].ptr)
#define SSL_pending (*(int (*)(SSL *))ssl_sw[18].ptr)
#define SSL_CTX_set_verify                                                     \
	(*(void (*)(SSL_CTX *,                                                     \
	            int,                                                           \
	            int (*verify_callback)(int, X509_STORE_CTX *)))ssl_sw[19]      \
	      .ptr)
#define SSL_shutdown (*(int (*)(SSL *))ssl_sw[20].ptr)
#define SSL_CTX_load_verify_locations                                          \
	(*(int (*)(SSL_CTX *, const char *, const char *))ssl_sw[21].ptr)
#define SSL_CTX_set_default_verify_paths (*(int (*)(SSL_CTX *))ssl_sw[22].ptr)
#define SSL_CTX_set_verify_depth (*(void (*)(SSL_CTX *, int))ssl_sw[23].ptr)
#define SSL_get_peer_certificate (*(X509 * (*)(SSL *)) ssl_sw[24].ptr)
#define SSL_get_version (*(const char *(*)(SSL *))ssl_sw[25].ptr)
#define SSL_get_current_cipher (*(SSL_CIPHER * (*)(SSL *)) ssl_sw[26].ptr)
#define SSL_CIPHER_get_name                                                    \
	(*(const char *(*)(const SSL_CIPHER *))ssl_sw[27].ptr)
#define SSL_CTX_check_private_key (*(int (*)(SSL_CTX *))ssl_sw[28].ptr)
#define SSL_CTX_set_session_id_context                                         \
	(*(int (*)(SSL_CTX *, const unsigned char *, unsigned int))ssl_sw[29].ptr)
#define SSL_CTX_ctrl (*(long (*)(SSL_CTX *, int, long, void *))ssl_sw[30].ptr)
#define SSL_CTX_set_cipher_list                                                \
	(*(int (*)(SSL_CTX *, const char *))ssl_sw[31].ptr)
#define SSL_CTX_set_info_callback                                              \
	(*(void (*)(SSL_CTX *, void (*callback)(const SSL *, int, int)))ssl_sw[32] \
	      .ptr)
#define SSL_get_ex_data (*(char *(*)(const SSL *, int))ssl_sw[33].ptr)
#define SSL_set_ex_data (*(void (*)(SSL *, int, char *))ssl_sw[34].ptr)
#define SSL_CTX_callback_ctrl                                                  \
	(*(long (*)(SSL_CTX *, int, void (*)(void)))ssl_sw[35].ptr)
#define SSL_get_servername                                                     \
	(*(const char *(*)(const SSL *, int type))ssl_sw[36].ptr)
#define SSL_set_SSL_CTX (*(SSL_CTX * (*)(SSL *, SSL_CTX *)) ssl_sw[37].ptr)
#define SSL_ctrl (*(long (*)(SSL *, int, long, void *))ssl_sw[38].ptr)
#define SSL_CTX_set_alpn_protos                                                \
	(*(int (*)(SSL_CTX *, const unsigned char *, unsigned))ssl_sw[39].ptr)
typedef int (*tSSL_alpn_select_cb)(SSL *ssl,
                                   const unsigned char **out,
                                   unsigned char *outlen,
                                   const unsigned char *in,
                                   unsigned int inlen,
                                   void *arg);
#define SSL_CTX_set_alpn_select_cb                                             \
	(*(void (*)(SSL_CTX *, tSSL_alpn_select_cb, void *))ssl_sw[40].ptr)
typedef int (*tSSL_next_protos_advertised_cb)(SSL *ssl,
                                              const unsigned char **out,
                                              unsigned int *outlen,
                                              void *arg);
#define SSL_CTX_set_next_protos_advertised_cb                                  \
	(*(void (*)(SSL_CTX *, tSSL_next_protos_advertised_cb, void *))ssl_sw[41]  \
	      .ptr)

#define SSL_CTX_set_timeout (*(long (*)(SSL_CTX *, long))ssl_sw[42].ptr)


#define SSL_CTX_set_options(ctx, op)                                           \
	SSL_CTX_ctrl((ctx), SSL_CTRL_OPTIONS, (op), NULL)
#define SSL_CTX_clear_options(ctx, op)                                         \
	SSL_CTX_ctrl((ctx), SSL_CTRL_CLEAR_OPTIONS, (op), NULL)
#define SSL_CTX_set_ecdh_auto(ctx, onoff)                                      \
	SSL_CTX_ctrl(ctx, SSL_CTRL_SET_ECDH_AUTO, onoff, NULL)

#define SSL_CTRL_SET_TLSEXT_SERVERNAME_CB 53
#define SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG 54
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define SSL_CTX_set_tlsext_servername_callback(ctx, cb)                        \
	SSL_CTX_callback_ctrl(ctx,                                                 \
	                      SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,                   \
	                      (void (*)(void))cb)
#define SSL_set_tlsext_host_name(ctx, arg)                                     \
	SSL_ctrl(ctx, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, (void *)arg)

#define X509_get_notBefore(x) ((x)->cert_info->validity->notBefore)
#define X509_get_notAfter(x) ((x)->cert_info->validity->notAfter)

#define SSL_set_app_data(s, arg) (SSL_set_ex_data(s, 0, (char *)arg))
#define SSL_get_app_data(s) (SSL_get_ex_data(s, 0))

#define SSL_CTX_sess_set_cache_size(ctx, size) SSL_CTX_ctrl(ctx, 42, size, NULL)
#define SSL_CTX_set_session_cache_mode(ctx, mode)                              \
	SSL_CTX_ctrl(ctx, 44, mode, NULL)


#define CRYPTO_num_locks (*(int (*)(void))crypto_sw[0].ptr)
#define CRYPTO_set_locking_callback                                            \
	(*(void (*)(void (*)(int, int, const char *, int)))crypto_sw[1].ptr)
#define CRYPTO_set_id_callback                                                 \
	(*(void (*)(unsigned long (*)(void)))crypto_sw[2].ptr)
#define ERR_get_error (*(unsigned long (*)(void))crypto_sw[3].ptr)
#define ERR_error_string (*(char *(*)(unsigned long, char *))crypto_sw[4].ptr)
#define ERR_remove_state (*(void (*)(unsigned long))crypto_sw[5].ptr)
#define ERR_free_strings (*(void (*)(void))crypto_sw[6].ptr)
#define ENGINE_cleanup (*(void (*)(void))crypto_sw[7].ptr)
#define CONF_modules_unload (*(void (*)(int))crypto_sw[8].ptr)
#define CRYPTO_cleanup_all_ex_data (*(void (*)(void))crypto_sw[9].ptr)
#define EVP_cleanup (*(void (*)(void))crypto_sw[10].ptr)
#define X509_free (*(void (*)(X509 *))crypto_sw[11].ptr)
#define X509_get_subject_name (*(X509_NAME * (*)(X509 *)) crypto_sw[12].ptr)
#define X509_get_issuer_name (*(X509_NAME * (*)(X509 *)) crypto_sw[13].ptr)
#define X509_NAME_oneline                                                      \
	(*(char *(*)(X509_NAME *, char *, int))crypto_sw[14].ptr)
#define X509_get_serialNumber (*(ASN1_INTEGER * (*)(X509 *)) crypto_sw[15].ptr)
#define i2c_ASN1_INTEGER                                                       \
	(*(int (*)(ASN1_INTEGER *, unsigned char **))crypto_sw[16].ptr)
#define EVP_get_digestbyname                                                   \
	(*(const EVP_MD *(*)(const char *))crypto_sw[17].ptr)
#define EVP_Digest                                                             \
	(*(int (*)(                                                                \
	    const void *, size_t, void *, unsigned int *, const EVP_MD *, void *)) \
	      crypto_sw[18]                                                        \
	          .ptr)
#define i2d_X509 (*(int (*)(X509 *, unsigned char **))crypto_sw[19].ptr)
#define BN_bn2hex (*(char *(*)(const BIGNUM *a))crypto_sw[20].ptr)
#define ASN1_INTEGER_to_BN                                                     \
	(*(BIGNUM * (*)(const ASN1_INTEGER *ai, BIGNUM *bn)) crypto_sw[21].ptr)
#define BN_free (*(void (*)(const BIGNUM *a))crypto_sw[22].ptr)
#define CRYPTO_free (*(void (*)(void *addr))crypto_sw[23].ptr)
#define ERR_clear_error (*(void (*)(void))crypto_sw[24].ptr)

#define OPENSSL_free(a) CRYPTO_free(a)

/* use here ERR_remove_state,
 * while on some platforms function is not included into library due to
 * deprication */
#define OPENSSL_REMOVE_THREAD_STATE() ERR_remove_state(0)

/* init_ssl_ctx() function updates this array.
 * It loads SSL library dynamically and changes NULLs to the actual addresses
 * of respective functions. The macros above (like SSL_connect()) are really
 * just calling these functions indirectly via the pointer. */
static struct ssl_func ssl_sw[] = {
    {"SSL_free", TLS_Mandatory, NULL},
    {"SSL_accept", TLS_Mandatory, NULL},
    {"SSL_connect", TLS_Mandatory, NULL},
    {"SSL_read", TLS_Mandatory, NULL},
    {"SSL_write", TLS_Mandatory, NULL},
    {"SSL_get_error", TLS_Mandatory, NULL},
    {"SSL_set_fd", TLS_Mandatory, NULL},
    {"SSL_new", TLS_Mandatory, NULL},
    {"SSL_CTX_new", TLS_Mandatory, NULL},
    {"SSLv23_server_method", TLS_Mandatory, NULL},
    {"SSL_library_init", TLS_Mandatory, NULL},
    {"SSL_CTX_use_PrivateKey_file", TLS_Mandatory, NULL},
    {"SSL_CTX_use_certificate_file", TLS_Mandatory, NULL},
    {"SSL_CTX_set_default_passwd_cb", TLS_Mandatory, NULL},
    {"SSL_CTX_free", TLS_Mandatory, NULL},
    {"SSL_load_error_strings", TLS_Mandatory, NULL},
    {"SSL_CTX_use_certificate_chain_file", TLS_Mandatory, NULL},
    {"SSLv23_client_method", TLS_Mandatory, NULL},
    {"SSL_pending", TLS_Mandatory, NULL},
    {"SSL_CTX_set_verify", TLS_Mandatory, NULL},
    {"SSL_shutdown", TLS_Mandatory, NULL},
    {"SSL_CTX_load_verify_locations", TLS_Mandatory, NULL},
    {"SSL_CTX_set_default_verify_paths", TLS_Mandatory, NULL},
    {"SSL_CTX_set_verify_depth", TLS_Mandatory, NULL},
    {"SSL_get_peer_certificate", TLS_Mandatory, NULL},
    {"SSL_get_version", TLS_Mandatory, NULL},
    {"SSL_get_current_cipher", TLS_Mandatory, NULL},
    {"SSL_CIPHER_get_name", TLS_Mandatory, NULL},
    {"SSL_CTX_check_private_key", TLS_Mandatory, NULL},
    {"SSL_CTX_set_session_id_context", TLS_Mandatory, NULL},
    {"SSL_CTX_ctrl", TLS_Mandatory, NULL},
    {"SSL_CTX_set_cipher_list", TLS_Mandatory, NULL},
    {"SSL_CTX_set_info_callback", TLS_Mandatory, NULL},
    {"SSL_get_ex_data", TLS_Mandatory, NULL},
    {"SSL_set_ex_data", TLS_Mandatory, NULL},
    {"SSL_CTX_callback_ctrl", TLS_Mandatory, NULL},
    {"SSL_get_servername", TLS_Mandatory, NULL},
    {"SSL_set_SSL_CTX", TLS_Mandatory, NULL},
    {"SSL_ctrl", TLS_Mandatory, NULL},
    {"SSL_CTX_set_alpn_protos", TLS_ALPN, NULL},
    {"SSL_CTX_set_alpn_select_cb", TLS_ALPN, NULL},
    {"SSL_CTX_set_next_protos_advertised_cb", TLS_ALPN, NULL},
    {"SSL_CTX_set_timeout", TLS_Mandatory, NULL},
    {NULL, TLS_END_OF_LIST, NULL}};


/* Similar array as ssl_sw. These functions could be located in different
 * lib. */
static struct ssl_func crypto_sw[] = {
    {"CRYPTO_num_locks", TLS_Mandatory, NULL},
    {"CRYPTO_set_locking_callback", TLS_Mandatory, NULL},
    {"CRYPTO_set_id_callback", TLS_Mandatory, NULL},
    {"ERR_get_error", TLS_Mandatory, NULL},
    {"ERR_error_string", TLS_Mandatory, NULL},
    {"ERR_remove_state", TLS_Mandatory, NULL},
    {"ERR_free_strings", TLS_Mandatory, NULL},
    {"ENGINE_cleanup", TLS_Mandatory, NULL},
    {"CONF_modules_unload", TLS_Mandatory, NULL},
    {"CRYPTO_cleanup_all_ex_data", TLS_Mandatory, NULL},
    {"EVP_cleanup", TLS_Mandatory, NULL},
    {"X509_free", TLS_Mandatory, NULL},
    {"X509_get_subject_name", TLS_Mandatory, NULL},
    {"X509_get_issuer_name", TLS_Mandatory, NULL},
    {"X509_NAME_oneline", TLS_Mandatory, NULL},
    {"X509_get_serialNumber", TLS_Mandatory, NULL},
    {"i2c_ASN1_INTEGER", TLS_Mandatory, NULL},
    {"EVP_get_digestbyname", TLS_Mandatory, NULL},
    {"EVP_Digest", TLS_Mandatory, NULL},
    {"i2d_X509", TLS_Mandatory, NULL},
    {"BN_bn2hex", TLS_Mandatory, NULL},
    {"ASN1_INTEGER_to_BN", TLS_Mandatory, NULL},
    {"BN_free", TLS_Mandatory, NULL},
    {"CRYPTO_free", TLS_Mandatory, NULL},
    {"ERR_clear_error", TLS_Mandatory, NULL},
    {NULL, TLS_END_OF_LIST, NULL}};
#endif /* OPENSSL_API_1_0 */
