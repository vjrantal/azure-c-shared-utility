tlsio_openssl
=============

## Overview

tlsio_openssl implements a tls adapter for the OpenSSL TLS library.


## References

[TLS Protocol (RFC2246)](https://www.ietf.org/rfc/rfc2246.txt)

[TLS Protocol (generic information)](https://en.wikipedia.org/wiki/Transport_Layer_Security)

[OpenSSL (https://www.openssl.org/)]

## Exposed API

```c
MOCKABLE_FUNCTION(, int, tlsio_openssl_init);
MOCKABLE_FUNCTION(, void, tlsio_openssl_deinit);
MOCKABLE_FUNCTION(, const IO_INTERFACE_DESCRIPTION*, tlsio_openssl_get_interface_description);
```

### tlsio_openssl_init

```c
extern int tlsio_openssl_init(void);
```

**SRS_TLSIO_OPENSSL_01_089: [** `tlsio_openssl_init` shall call `SSL_library_init` to initialize OpenSSL. **]**
**SRS_TLSIO_OPENSSL_01_090: [** The return value for `SSL_library_init` shall be ignored. **]**
**SRS_TLSIO_OPENSSL_01_091: [** `tlsio_openssl_init` shall also call `SSL_load_error_strings` and `OpenSSL_add_all_algorithms`. **]**

**SRS_TLSIO_OPENSSL_01_093: [** `tlsio_openssl_init` shall call `CRYPTO_num_locks` to get the number of locks that need to be statically configured. **]**
**SRS_TLSIO_OPENSSL_01_092: [** An array that can hold the handles for the required number of locks shall be allocated. **]**
**SRS_TLSIO_OPENSSL_01_094: [** If allocating the memory for the lock handles fails then `tlsio_openssl_init` shall return a non-zero value. **]**
**SRS_TLSIO_OPENSSL_01_095: [** The required number of locks shall be allocated by calling `Lock_Init`. **]**
**SRS_TLSIO_OPENSSL_01_096: [** If any `Lock_Init` call fails, `tlsio_openssl_init` shall return a non-zero value. **]**

**SRS_TLSIO_OPENSSL_01_097: [** A static locks locking callback that handles the lock and unlock requests shall be installed by calling `CRYPTO_set_locking_callback`. **]**

**SRS_TLSIO_OPENSSL_01_105: [** `tlsio_openssl_init` shall install 3 callbacks for dynamic locks: **]**
**SRS_TLSIO_OPENSSL_01_106: [** A callback for creating a dynamic lock shall be installed by calling `CRYPTO_set_dynlock_create_callback`. **]**
**SRS_TLSIO_OPENSSL_01_107: [** A callback for locking/unlocking using a dynamic lock shall be installed by calling `CRYPTO_set_dynlock_lock_callback`. **]**
**SRS_TLSIO_OPENSSL_01_108: [** A callback for destroying a dynamic lock shall be installed by calling `CRYPTO_set_dynlock_destroy_callback`. **]**

### static locks callback (openssl_static_locks_lock_unlock_cb)

```c
void openssl_static_locks_lock_unlock_cb(int lock_mode, int lock_index, const char * file, int line);
```

**SRS_TLSIO_OPENSSL_01_112: [** If the `lock_index` argument is negative, `openssl_static_locks_lock_unlock_cb` shall not do any lock/unlock action. **]** 
**SRS_TLSIO_OPENSSL_01_113: [** If the `lock_index` argument is greater than or equal to the number of locks allocated in `tlsio_openssl_init`, `openssl_static_locks_lock_unlock_cb` shall not do any lock/unlock action. **]**
**SRS_TLSIO_OPENSSL_01_114: [** If `lock_mode` & CRYPTO_LOCK is non-zero then the lock identified by `lock_index` shall be locked by calling `Lock`. **]**
**SRS_TLSIO_OPENSSL_01_115: [** If `lock_mode` & CRYPTO_LOCK is zero then the lock identified by `lock_index` shall be released by calling `Unlock`. **]**

### dynamic locks create callback (openssl_dynamic_locks_create_cb)

```c
struct CRYPTO_dynlock_value* openssl_dynamic_locks_create_cb(const char* file, int line);
```

**SRS_TLSIO_OPENSSL_01_116: [** `openssl_dynamic_locks_create_cb` shall allocate memory for a new fynamic lock structure that shall hold a lock handle. **]**
**SRS_TLSIO_OPENSSL_01_117: [** If allocating memory fails, `openssl_dynamic_locks_create_cb` shall return NULL. **]**
**SRS_TLSIO_OPENSSL_01_118: [** `openssl_dynamic_locks_create_cb` shall allocate a new lock by calling `Lock_Init`. **]**
**SRS_TLSIO_OPENSSL_01_119: [** If creating the new lock fails, `openssl_dynamic_locks_create_cb` shall return NULL. **]**

### dynamic locks lock/unlock callback (openssl_dynamic_locks_lock_unlock_cb)

```c
void openssl_dynamic_locks_lock_unlock_cb(int lock_mode, struct CRYPTO_dynlock_value* dynlock_value, const char* file, int line);
```
**SRS_TLSIO_OPENSSL_01_120: [** `openssl_dynamic_locks_lock_unlock_cb` shall do nothing if dynlock_value is NULL. **]**
**SRS_TLSIO_OPENSSL_01_121: [** If `lock_mode` & CRYPTO_LOCK is non-zero, `openssl_dynamic_locks_lock_unlock_cb` shall lock the lock identified by `dynlock_value` by calling `Lock`. **]**  
**SRS_TLSIO_OPENSSL_01_122: [** If `lock_mode` & CRYPTO_LOCK is zero, `openssl_dynamic_locks_lock_unlock_cb` shall release the lock identified by `dynlock_value` by calling `Unlock`. **]**

### dynamic locks destroy callback (openssl_dynamic_locks_destroy_cb)

```c
void openssl_dynamic_locks_destroy_cb(struct CRYPTO_dynlock_value* dynlock_value, const char* file, int line);
```

**SRS_TLSIO_OPENSSL_01_123: [** If `dynlock_value` is NULL, `openssl_dynamic_locks_destroy_cb` shall do nothing. **]**
**SRS_TLSIO_OPENSSL_01_124: [** `openssl_dynamic_locks_destroy_cb` shall free the lock allocated in the dynamic lock create callback by calling `Lock_Deinit`. **]**
**SRS_TLSIO_OPENSSL_01_125: [** `openssl_dynamic_locks_destroy_cb` shall free the memory for the dynamic lock structure allocated in the dynamic lock create callback. **]**  

### tlsio_openssl_deinit

```c
extern void tlsio_openssl_deinit(void);
```

**SRS_TLSIO_OPENSSL_01_099: [** `tlsio_openssl_deinit` shall clear the static locks callback by calling `CRYPTO_set_locking_callback` with a NULL argument. **]**
**SRS_TLSIO_OPENSSL_01_109: [** `tlsio_openssl_deinit` shall clear the dynamic locks create callbacks by calling `CRYPTO_set_dynlock_create_callback` with a NULL argument. **]**
**SRS_TLSIO_OPENSSL_01_110: [** `tlsio_openssl_deinit` shall clear the dynamic locks lock/unlock callbacks by calling `CRYPTO_set_dynlock_lock_callback` with a NULL argument. **]**
**SRS_TLSIO_OPENSSL_01_111: [** `tlsio_openssl_deinit` shall clear the dynamic locks destroy callbacks by calling `CRYPTO_set_dynlock_destroy_callback` with a NULL argument. **]**
**SRS_TLSIO_OPENSSL_01_100: [** `tlsio_openssl_deinit` free all the locks allocated in `tlsio_openssl_init` by calling `Lock_Deinit`. **]**  
**SRS_TLSIO_OPENSSL_01_101: [** `tlsio_openssl_deinit` free the memory for the lock handles array allocated in `tlsio_openssl_init`. **]**
**SRS_TLSIO_OPENSSL_01_102: [** `tlsio_openssl_deinit` shall free the error strings by calling `ERR_free_strings`. **]**
**SRS_TLSIO_OPENSSL_01_103: [** `tlsio_openssl_deinit` shall remove all algorithms added in 'tlsio_openssl_init' by calling `EVP_cleanup`. **]**
**SRS_TLSIO_OPENSSL_01_104: [** `tlsio_openssl_deinit` shall remove the error queue by calling `ERR_remove_state` with 0 as argument. **]**
**SRS_TLSIO_OPENSSL_01_098: [** For versions 1.0.2 of OpenSSL, `tlsio_openssl_deinit` shall also call `SSL_COMP_free_compression_methods`. **]** 

### tlsio_openssl_create

`tlsio_openssl_create` is the implementation provided via `tlsio_openssl_get_interface_description` for the `concrete_io_create` member.

```c
extern CONCRETE_IO_HANDLE tlsio_openssl_create(void* io_create_parameters);
```

**SRS_TLSIO_OPENSSL_01_001: [** `tlsio_openssl_create` shall create an instance of tlsio_openssl and return a non-NULL handle to it. **]**
**SRS_TLSIO_OPENSSL_01_001: [** If the argument `io_create_parameters` is NULL then `tlsio_openssl_create` shall return NULL. **]**
**SRS_TLSIO_OPENSSL_01_002: [** `io_create_parameters` shall be used as a `TLSIO_CONFIG\*`. **]**
**SRS_TLSIO_OPENSSL_01_003: [** If the `hostname` field in the `TLSIO_CONFIG` structure is NULL then `tlsio_openssl_create` shall return NULL. **]**
**SRS_TLSIO_OPENSSL_01_004: [** If allocating memory for the new tlsio_openssl instance fails then `tlsio_openssl_create` shall return NULL. **]**
**SRS_TLSIO_OPENSSL_01_005: [** The members `hostname` and `port` shall be copied for later use (they are needed when the IO is opened). **]**

**SRS_TLSIO_OPENSSL_01_009: [** `tlsio_openssl_create` shall obtain the socket IO interface to be used by calling `socketio_get_interface_description`. **]**
**SRS_TLSIO_OPENSSL_01_010: [** If `socketio_get_interface_description` fails then `tlsio_openssl_create` shall fail and return NULL. **]**
**SRS_TLSIO_OPENSSL_01_011: [** `tlsio_openssl_create` shall create the socket IO instance by calling `xio_create` with the already obtained socket IO interface and the socket IO configuration filled in as described below: **]**

**SRS_TLSIO_OPENSSL_01_012: [** - `hostname` shall be set to the hostname field passed in `TLSIO_CONFIG`. **]**
**SRS_TLSIO_OPENSSL_01_013: [** - `port` shall be set to the port field passed in `TLSIO_CONFIG`. **]**
**SRS_TLSIO_OPENSSL_01_014: [** - `accepted_socket` shall be set to NULL. **]**

**SRS_TLSIO_OPENSSL_01_015: [** If `xio_create` fails then `tlsio_openssl_create` shall fail and return NULL. **]**

### tlsio_openssl_destroy

`tlsio_openssl_destroy` is the implementation provided via `tlsio_openssl_get_interface_description` for the `concrete_io_destroy` member.

```c
extern void tlsio_openssl_destroy(CONCRETE_IO_HANDLE tls_io);
```

**SRS_TLSIO_OPENSSL_01_006: [** `tlsio_openssl_destroy` shall free all resources associated with the tlsio_openssl instance. **]**
**SRS_TLSIO_OPENSSL_01_007: [** If tls_io is NULL, `tlsio_openssl_destroy` shall do nothing. **]** 
**SRS_TLSIO_OPENSSL_01_008: [** `tlsio_openssl_destroy` shall free the hostname copied by `tlsio_openssl_create`. **]**
**SRS_TLSIO_OPENSSL_01_016: [** `tlsio_openssl_destroy` shall destroy the socket IO created in `tlsio_openssl_create`. **]**

### tlsio_openssl_open

`tlsio_openssl_open` is the implementation provided via `tlsio_openssl_get_interface_description` for the `concrete_io_open` member.

```c
extern int tlsio_openssl_open(CONCRETE_IO_HANDLE tls_io, ON_IO_OPEN_COMPLETE on_io_open_complete, ON_BYTES_RECEIVED on_bytes_received, ON_IO_ERROR on_io_error, void* callback_context);
```

**SRS_TLSIO_OPENSSL_01_017: [** `tlsio_openssl_open` shall create an OpenSSL context by calling `SSL_CTX_new`. **]**
**SRS_TLSIO_OPENSSL_01_018: [** On success, `tlsio_openssl_open` shall return 0. **]**
**SRS_TLSIO_OPENSSL_01_019: [** If any of the arguments `tls_io`, `on_io_open_complete`, `on_io_error` or or `on_bytes_received` is NULL then `tlsio_openssl_open` shall return a non-zero value. **]**
**SRS_TLSIO_OPENSSL_01_020: [** The argument passed to `SSL_CTX_new` shall be the OpenSSL TLS method specifying the TLS version to be used. **]**
**SRS_TLSIO_OPENSSL_01_021: [** By default (if not otherwise specified by using `tlsio_openssl_set_option`) the TLS version shall be autonegociated by using TLS_method as method. **]**
**SRS_TLSIO_OPENSSL_01_022: [** If version 1.1 was explictly specified by using `tlsio_openssl_set_option`, the method shall be TLSv1_1_method. **]**
**SRS_TLSIO_OPENSSL_01_023: [** If version 1.2 was explictly specified by using `tlsio_openssl_set_option`, the method shall be TLSv1_2_method. **]**
**SRS_TLSIO_OPENSSL_01_024: [** If `SSL_CTX_new` fails, tlsio_openssl_open shall return a non-zero value. **]**

The certificate passed through the `TrustedCerts` option shall be added to the OpenSSL certificates store:

**SRS_TLSIO_OPENSSL_01_025: [** The OpenSSL certificate store associated with the SSL context shall be obtained by `SSL_CTX_get_cert_store`. **]**
**SRS_TLSIO_OPENSSL_01_026: [** If `SSL_CTX_get_cert_store` fails then `tlsio_openssl_open` shall return a non-zero value. **]**
**SRS_TLSIO_OPENSSL_01_027: [** A new memory BIO shall be created to load the certificate in by calling `BIO_new_mem_buf` and passing the `TrustedCerts` payload to it. **]**
**SRS_TLSIO_OPENSSL_01_028: [** If `BIO_new_mem_buf` fails then `tlsio_openssl_open` shall return a non-zero value. **]**

**SRS_TLSIO_OPENSSL_01_029: [** The following shall be repeated until all certificates passed via `TrustedCerts` are read: **]**
**SRS_TLSIO_OPENSSL_01_030: [** The X509 certificate shall be read from the BIO by using `PEM_read_bio_X509`. **]**
**SRS_TLSIO_OPENSSL_01_031: [** If `PEM_read_bio_X509` fails then `tlsio_openssl_open` shall return a non-zero value. **]**
**SRS_TLSIO_OPENSSL_01_032: [** The certificate shall be added to the OpenSSL context store by calling `X509_STORE_add_cert` and passing the certificate as argument. **]**
**SRS_TLSIO_OPENSSL_01_033: [** The certificate and memory BIO shall be freed after the certificate has been added to the store. **]**

**SRS_TLSIO_OPENSSL_01_034: [** If an X509 certificate has been specified via `SetOption`, then the certificate shall be used for client authentication by calling `x509_openssl_add_credentials`. **]**
**SRS_TLSIO_OPENSSL_01_035: [** If `x509_openssl_add_credentials` fails then `tlsio_openssl_open` shall fail and return a non-zero value. **]**

**SRS_TLSIO_OPENSSL_01_036: [** If a validation callback has been set via `SetOption` then `SSL_CTX_set_cert_verify_callback` shall be called, setting up the validation callback and the validation callback context that were setup via SetOption calls. **]**
**SRS_TLSIO_OPENSSL_01_037: [** 2 memory BIOs shall be created in order to pass send/received from the socket to/from OpenSSL. **]**
**SRS_TLSIO_OPENSSL_01_038: [** If creating the memory BIOs fails then `tlsio_openssl_open` shall fail and return a non-zero value. **]**
**SRS_TLSIO_OPENSSL_01_039: [** The memory BIOs shall be setup by calling `SSL_set_bio`. **]**

**SRS_TLSIO_OPENSSL_01_040: [** `tlsio_openssl_open` shall setup the peer verification mode to `SSL_VERIFY_PEER` by calling `SSL_CTX_set_verify`. **]**
**SRS_TLSIO_OPENSSL_01_041: [** Default CA certificate paths shall be specified to be used by calling `SSL_CTX_set_default_verify_paths`. **]**
**SRS_TLSIO_OPENSSL_01_042: [** If `SSL_CTX_set_default_verify_paths` fails, `tlsio_openssl` shall ignore the failure. **]**

**SRS_TLSIO_OPENSSL_01_043: [** `tlsio_openssl_open` shall create a new OpenSSL instance from the context that was already built by calling `SSL_new`. **]**
**SRS_TLSIO_OPENSSL_01_044: [** If `SSL_new` fails, `tlsio_openssl_open` shall fail and return a non-zero value. **]**
**SRS_TLSIO_OPENSSL_01_045: [** `tlsio_openssl_open` shall setup the OpenSSL instance to work in client mode by calling `SSL_set_connect_state`. **]**

### tlsio_openssl_close

`tlsio_openssl_close` is the implementation provided via `tlsio_openssl_get_interface_description` for the `concrete_io_close` member.

```c
extern int tlsio_openssl_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context);
```

**SRS_TLSIO_OPENSSL_01_046: [** `tlsio_openssl_close` shall close the openssl tls IO if an open action is either pending or has completed successfully (if the IO is open). **]**
**SRS_TLSIO_OPENSSL_01_047: [** On success `tlsio_openssl_close` shall return 0. **]** 
**SRS_TLSIO_OPENSSL_01_048: [** If the argument `tls_io` is NULL, `tlsio_openssl_close` shall fail and return a non-zero value. **]**
**SRS_TLSIO_OPENSSL_01_049: [** If the IO was not open before, `tlsio_openssl_close` shall fail and return a non-zero value. **]**
**SRS_TLSIO_OPENSSL_01_050: [** `tlsio_openssl_close` shall close the underlying socket connection by calling xio_close. **]**
**SRS_TLSIO_OPENSSL_01_051: [** If `tlsio_openssl_close` fails then `tlsio_openssl_close` shall fail and return a non-zero value. **]**
**SRS_TLSIO_OPENSSL_01_052: [** `tlsio_openssl_close` shall free the SSL instance created in `tlsio_openssl_open`. **]**
**SRS_TLSIO_OPENSSL_01_053: [** `tlsio_openssl_close` shall free the SSL context created in `tlsio_openssl_open`. **]**
**SRS_TLSIO_OPENSSL_01_054: [** If `on_io_close_complete` is non-NULL, on a succesfull close, the callback `on_io_close_complete` shall be called, while passing callback_context as the context argument. **]** 

### tlsio_openssl_send

`tlsio_openssl_send` is the implementation provided via `tlsio_openssl_get_interface_description` for the `concrete_io_send` member.

```c
extern int tlsio_openssl_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context);
```

**SRS_TLSIO_OPENSSL_01_055: [** `tlsio_openssl_send` shall send `size` bytes pointed to by `buffer` and on success it shall return 0. **]**
**SRS_TLSIO_OPENSSL_01_056: [** If `tls_io` or `buffer` is NULL, `tlsio_openssl_send` shall return a non-zero value. **]**
**SRS_TLSIO_OPENSSL_01_057: [** If `size` is zero, `tlsio_openssl_send` shall return a non-zero value. **]**
**SRS_TLSIO_OPENSSL_01_058: [** The `on_send_complete` argument shall be optional. **]**
**SRS_TLSIO_OPENSSL_01_059: [** If the IO is not open or is in error, `tlsio_openssl_send` shall fail and return a non-zero value. **]**  
**SRS_TLSIO_OPENSSL_01_060: [** `tlsio_openssl_send` shall call `SSL_write` to pass the bytes to be encrypted and sent to OpenSSL. **]**
**SRS_TLSIO_OPENSSL_01_061: [** If `SSL_write` fails, then `tlsio_openssl_send` shall return a non-zero value. **]**

### tlsio_openssl_dowork

`tlsio_openssl_dowork` is the implementation provided via `tlsio_openssl_get_interface_description` for the `concrete_io_dowork` member.

```c
extern void tlsio_openssl_dowork(CONCRETE_IO_HANDLE tls_io);
```

**SRS_TLSIO_OPENSSL_01_063: [** If `tls_io` is NULL, `tlsio_openssl_dowork` shall do nothing. **]**
**SRS_TLSIO_OPENSSL_01_064: [** If the IO is not opened or in error, `tlsio_openssl_dowork` shall return without performing any actions. **]**
**SRS_TLSIO_OPENSSL_01_065: [** `tlsio_openssl_dowork` shall call `xio_dowork` to schedule all the work needed to be done by the underlying socket IO layer. **]**

**SRS_TLSIO_OPENSSL_01_066: [** If the IO state is IN_HANDSHAKE, `SSL_do_handshake` shall be called passing the SSL instance created in `tlsio_openssl_dowork`. **]**
**SRS_TLSIO_OPENSSL_01_067: [** If `SSL_do_handshake` returns 1, the IO shall be considered OPEN and the on_io_open_complete callbacks passed in `tlsio_openssl_open` shall be called with `IO_OPEN_OK`. **]**
**SRS_TLSIO_OPENSSL_01_068: [** If `SSL_do_handshake` returns 0, the on_io_open_complete callbacks passed in `tlsio_openssl_open` shall be called with `IO_OPEN_ERROR`. In this case the IO shall be considered `NOT_OPENED` (subsequent calls to open shall succeed). **]**

**SRS_TLSIO_OPENSSL_01_069: [** If the IO is either `IN_HANDSHAKE` or `OPEN`, `tlsio_openssl_dowork` shall pump any bytes out to the socket by performing the following: **]**

**SRS_TLSIO_OPENSSL_01_070: [** Get the bytes that are pending to be sent by calling `BIO_ctrl_pending` on the output BIO created in `tlsio_openssl_open`. **]**
**SRS_TLSIO_OPENSSL_01_071: [** If `BIO_ctrl_pending` returned a positive value then enough memory shall be allocated to accomodate the data that can be read from the BIO. **]**
**SRS_TLSIO_OPENSSL_01_072: [** If allocating the memory fails, the IO shall be considered in error and the error shall be indicated by calling the on_io_error callback passed to `tlsio_openssl_open`. **]**
**SRS_TLSIO_OPENSSL_01_073: [** The pending bytes shall be read from the out BIO by calling `BIO_read`. **]**
**SRS_TLSIO_OPENSSL_01_074: [** If `BIO_read` fails (the returns value is not the amount of bytes that was requested) the IO shall be considered in error and the error shall be indicated by calling the on_io_error callback passed to `tlsio_openssl_open`. **]**
**SRS_TLSIO_OPENSSL_01_075: [** The bytes extracted from the BIO shall be given to the underlying layer by calling `xio_send`. **]**
**SRS_TLSIO_OPENSSL_01_076: [** If `xio_send` fails the IO shall be considered in error and the error shall be indicated by calling the on_io_error callback passed to `tlsio_openssl_open`. **]**

### Underlying socket on_io_open_complete

**SRS_TLSIO_OPENSSL_01_077: [** If the underlying socket `on_io_open_complete` (given to `xio_create`) is called when the IO is not in the OPENING_UNDERLYING_IO state, an error shall be indicated by calling the on_io_error callback passed in `tlsio_openssl_open`. **]**

**SRS_TLSIO_OPENSSL_01_078: [** `on_io_open_complete` shall start the TLS handshake by calling `SSL_do_handshake` for the SSL instance created in `tlsio_openssl_open`. **]**

**SRS_TLSIO_OPENSSL_01_079: [** If `SSL_do_handshake` returns 1, the IO shall be considered OPEN and the on_io_open_complete callbacks passed in `tlsio_openssl_open` shall be called with `IO_OPEN_OK`. **]**

**SRS_TLSIO_OPENSSL_01_080: [** If `SSL_do_handshake` returns 0, the on_io_open_complete callbacks passed in `tlsio_openssl_open` shall be called with `IO_OPEN_ERROR`. In this case the IO shall be considered `NOT_OPENED` (subsequent calls to open shall succeed). **]**

### Underlying socket on_bytes_received

**SRS_TLSIO_OPENSSL_01_081: [** When the underlying socket `on_bytes_received` callback is called (given to `xio_create`) the bytes indicated in the `buffer` argument shall be written to the in BIO used to communicate with OpenSSL by calling BIO_write. **]**
**SRS_TLSIO_OPENSSL_01_082: [** If the `buffer` argument is NULL then an error shall be indicated by triggering the `on_io_error` callback. **]** 
**SRS_TLSIO_OPENSSL_01_083: [** If the `size` argument is 0 then an error shall be indicated by triggering the `on_io_error` callback. **]**
**SRS_TLSIO_OPENSSL_01_084: [** The arguments for BIO_write shall be: the SSL instance created in `tlsio_openssl_open`, and the `buffer` and `size` arguments. **]**
**SRS_TLSIO_OPENSSL_01_085: [** If `BIO_write` fails (the number of written bytes does not equal size) then an error shall be indicated by triggering the `on_io_error` callback. **]**

**SRS_TLSIO_OPENSSL_01_086: [** If the IO is `OPEN` then bytes shall be decoded from the TLS instance by calling `SSL_read`. The amount of bytes attempted to be decoded shall be 64. **]**
**SRS_TLSIO_OPENSSL_01_087: [** If `SSL_read` returns a negative value then an error shall be indicated by triggering the `on_io_error` callback. **]**
**SRS_TLSIO_OPENSSL_01_088: [** If `SSL_read` returns a positive value, the number of bytes returned by SSL_read shall be indicated as received by a call to the `on_bytes_received` callback passed in `tlsio_openssl_open`. **]**

### tlsio_openssl_setoption

`tlsio_openssl_setoption` is the implementation provided via `tlsio_openssl_get_interface_description` for the `concrete_io_setoption` member.

```c
extern int tlsio_openssl_setoption(CONCRETE_IO_HANDLE tls_io, const char* option_name, const void* value);
```

**SRS_TLSIO_OPENSSL_01_126: [** If any of the arguments `tls_io` or `option_name` is NULL `tlsio_openssl_setoption` shall return a non-zero value. **]**
**SRS_TLSIO_OPENSSL_01_127: [** If the `option_name` argument indicates an option that is not handled by tlsio_openssl, then `tlsio_openssl_setoption` shall return a non-zero value. **]**
**SRS_TLSIO_OPENSSL_01_128: [** If the option was handled by tlsio_openssl, then `tlsio_openssl_setoption` shall return 0. **]**

Options that shall be handled by tlsio_openssl:

**SRS_TLSIO_OPENSSL_01_129: [** - `TrustedCerts` - a char\* that shall be saved by tlsio_openssl as it shall be passed to OpenSSL when the IO is open. **]**
**SRS_TLSIO_OPENSSL_01_130: [** If copying the char\* passed in value fails then `tlsio_openssl_setoption` shall return a non-zero value. **]**
**SRS_TLSIO_OPENSSL_01_131: [** If a previous TrustedCerts option was saved, then the previous value shall be freed. **]**
**SRS_TLSIO_OPENSSL_01_132: [** A NULL value shall be allowed for `TrustedCerts`, in which case the previously stored `TrustedCerts` option value shall be cleared. **]**

### tlsio_openssl_clone_option

`tlsio_openssl_clone_option` is the implementation provided to the option handler instance created as part of `tlsio_openssl_retrieve_options`.

```c
extern void* tlsio_openssl_clone_option(const char* name, const void* value);
```

**SRS_TLSIO_OPENSSL_01_140: [** If the name or value arguments are NULL, tlsio_cyclonessl_clone_option shall return NULL. **]**

**SRS_TLSIO_OPENSSL_01_141: [** `tlsio_openssl_clone_option` shall clone the option named `TrustedCerts` by calling `mallocAndStrcpy_s`. **]** **SRS_TLSIO_OPENSSL_01_142: [** On success it shall return a non-NULL pointer to the cloned option. **]**
**SRS_TLSIO_OPENSSL_01_143: [** If `mallocAndStrcpy_s` for `TrustedCerts` fails, `tlsio_openssl_clone_option` shall return NULL. **]**

### tlsio_openssl_destroy_option

`tlsio_openssl_destroy_option` is the implementation provided to the option handler instance created as part of `tlsio_openssl_retrieve_options`.

```c
extern void wsio_destroy_option(const char* name, const void* value);
```

**SRS_TLSIO_OPENSSL_01_138: [** If any of the arguments is NULL, `tlsio_openssl_destroy_option` shall do nothing. **]**
**SRS_TLSIO_OPENSSL_01_139: [** If the option name is `TrustedCerts`, `tlsio_cyclonessl_destroy_option` shall free the char\* option indicated by value. **]**

### tlsio_openssl_retrieve_options

`tlsio_openssl_retrieve_options` is the implementation provided via `tlsio_openssl_get_interface_description` for the `concrete_io_retrieveoptions` member.

```c
OPTIONHANDLER_HANDLE tlsio_openssl_retrieveoptions(CONCRETE_IO_HANDLE tls_io)
```

`tlsio_openssl_retrieveoptions` produces an `OPTIONHANDLER_HANDLE`. 

**SRS_TLSIO_OPENSSL_01_133: [** If parameter handle is `NULL` then `tlsio_openssl_retrieve_options` shall fail and return NULL. **]**
**SRS_TLSIO_OPENSSL_01_134: [** `tlsio_openssl_retrieve_options` shall produce an `OPTIONHANDLER_HANDLE`. **]**
**SRS_TLSIO_OPENSSL_01_135: [** If producing the `OPTIONHANDLER_HANDLE` fails then `tlsio_openssl_retrieve_options` shall fail and return NULL. **]** 
**SRS_TLSIO_OPENSSL_01_136: [** `tlsio_openssl_retrieve_options` shall add to it the options: **]**
**SRS_TLSIO_OPENSSL_01_137: [**  - `TrustedCerts` **]**

### tlsio_openssl_get_interface_description

```c
extern const IO_INTERFACE_DESCRIPTION* tlsio_openssl_get_interface_description(void);
```

**SRS_TLSIO_OPENSSL_01_062: [** tlsio_openssl_get_interface_description shall return a pointer to an IO_INTERFACE_DESCRIPTION structure that contains pointers to the functions: tlsio_openssl_retrieveoptions, tlsio_openssl_create, tlsio_openssl_destroy, tlsio_openssl_open, tlsio_openssl_close, tlsio_openssl_send and tlsio_openssl_dowork.  **]**

### States

The OpenSSL TLS IO can be in one of the following states:
- NOT_CONNECTED - no open has been called or close has been called
- OPENING_UNDERLYING_IO - open has been called, but the underlying socket IO is not yet open.
- IN_HANDSHAKE - the underlying IO has been opened, TLS handshake is in progress
- OPEN - TLS handshake complete, send/receive actions can be preformed
- ERROR - an unrecoverable error occured, IO needs to be closed by the caller