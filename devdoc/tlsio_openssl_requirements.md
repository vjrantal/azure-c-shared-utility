tlsio_arduino
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

MOCKABLE_FUNCTION(, CONCRETE_IO_HANDLE, tlsio_openssl_create, void*, io_create_parameters);
MOCKABLE_FUNCTION(, void, tlsio_openssl_destroy, CONCRETE_IO_HANDLE, tls_io);
MOCKABLE_FUNCTION(, int, tlsio_openssl_open, CONCRETE_IO_HANDLE, tls_io, ON_IO_OPEN_COMPLETE, on_io_open_complete, void*, on_io_open_complete_context, ON_BYTES_RECEIVED, on_bytes_received, void*, on_bytes_received_context, ON_IO_ERROR, on_io_error, void*, on_io_error_context);
MOCKABLE_FUNCTION(, int, tlsio_openssl_close, CONCRETE_IO_HANDLE, tls_io, ON_IO_CLOSE_COMPLETE, on_io_close_complete, void*, callback_context);
MOCKABLE_FUNCTION(, int, tlsio_openssl_send, CONCRETE_IO_HANDLE, tls_io, const void*, buffer, size_t, size, ON_SEND_COMPLETE, on_send_complete, void*, callback_context);
MOCKABLE_FUNCTION(, void, tlsio_openssl_dowork, CONCRETE_IO_HANDLE, tls_io);
MOCKABLE_FUNCTION(, int, tlsio_openssl_setoption, CONCRETE_IO_HANDLE, tls_io, const char*, optionName, const void*, value);

MOCKABLE_FUNCTION(, const IO_INTERFACE_DESCRIPTION*, tlsio_openssl_get_interface_description);
```

### tlsio_openssl_create

```c
extern CONCRETE_IO_HANDLE tlsio_openssl_create(void* io_create_parameters);
```

**SRS_TLSIO_OPENSSL_01_001: [** tlsio_openssl_create shall create an instance of tlsio_openssl and return a non-NULL handle to it. **]**
**SRS_TLSIO_OPENSSL_01_001: [** If the argument io_create_parameters is NULL then wsio_create shall return NULL. **]**
**SRS_TLSIO_OPENSSL_01_002: [** io_create_parameters shall be used as a TLSIO_CONFIG\*. **]**
**SRS_TLSIO_OPENSSL_01_003: [** If the hostname field in the TLSIO_CONFIG structure is NULL then tlsio_openssl_create shall return NULL. **]**
**SRS_TLSIO_OPENSSL_01_004: [** If allocating memory for the new tlsio_openssl instance fails then tlsio_openssl_create shall return NULL. **]**
**SRS_TLSIO_OPENSSL_01_005: [** The members hostname and port shall be copied for later use (they are needed when the IO is opened). **]**

Note: the socket IO creation is subject to move out of TLS IO, but it has to be done for all the TLS adapters as a future step.

**SRS_TLSIO_OPENSSL_01_009: [** tlsio_openssl_create shall optain the socket IO interface to be used by calling socketio_get_interface_description. **]**
**SRS_TLSIO_OPENSSL_01_010: [** If socketio_get_interface_description fails then tlsio_openssl_create shall fail and return NULL. **]**
**SRS_TLSIO_OPENSSL_01_011: [** tlsio_openssl_create shall create the socket IO instance by calling xio_create with the already obtained socket IO interface and the socket IO configuration filled in as described below: **]**

**SRS_TLSIO_OPENSSL_01_012: [** - hostname shall be set to the hostname field passed in TLSIO_CONFIG. **]**
**SRS_TLSIO_OPENSSL_01_013: [** - port shall be set to the port field passed in TLSIO_CONFIG. **]**
**SRS_TLSIO_OPENSSL_01_014: [** - accepted_socket shall be set to NULL. **]**

**SRS_TLSIO_OPENSSL_01_015: [** If xio_create fails then tlsio_openssl_create shall fail and return NULL. **]**

### tlsio_openssl_destroy

```c
extern void tlsio_openssl_destroy(CONCRETE_IO_HANDLE tls_io);
```

**SRS_TLSIO_OPENSSL_01_006: [** tlsio_openssl_destroy shall free all resources associated with the tlsio_openssl instance. **]**
**SRS_TLSIO_OPENSSL_01_007: [** If tls_io is NULL, tlsio_openssl shall do nothing. **]** 
**SRS_TLSIO_OPENSSL_01_008: [** tlsio_openssl_destroy shall free the hostname copied by tlsio_openssl_create. **]**
**SRS_TLSIO_OPENSSL_01_016: [** tlsio_openssl_destroy shall destroy the socket IO created in tlsio_openssl_create. **]**

### tlsio_openssl_open

```c
extern int tlsio_openssl_open(CONCRETE_IO_HANDLE tls_io, ON_IO_OPEN_COMPLETE on_io_open_complete, ON_BYTES_RECEIVED on_bytes_received, ON_IO_ERROR on_io_error, void* callback_context);
```

tlsio_openssl_open shall create an OpenSSL context by calling SSL_CTX_new.
On success, tlsio_openssl_open shall return 0.
If any of the arguments tls_io, on_io_open_complete, or on_bytes_received is NULL then tlsio_openssl_open shall return a non-zero value.
The argument passed to SSL_CTX_new shall be the OpenSSL TLS method specifying the TLS version to be used.
By default (if not otherwise specified by using tlsio_openssl_set_option) the TLS version shall be autonegociated by using TLS_method as method.
If version 1.1 was explictly specified by using tlsio_openssl_set_option, the method shall be TLSv1_1_method.
If version 1.2 was explictly specified by using tlsio_openssl_set_option, the method shall be TLSv1_2_method.
If SSL_CTX_new fails, tlsio_openssl_open shall return a non-zero value.

The certificate passed through the TrustedCerts option shall be added to the OpenSSL certificates store:

The OpenSSL certificate store associated with the SSL context shall be obtained by SSL_CTX_get_cert_store.
If SSL_CTX_get_cert_store fails then tlsio_openssl_open shall return a non-zero value.
A new memory BIO shall be created to load the certificate in by calling BIO_new_mem_buf and passing the TrustedCerts payload to it.
If BIO_new_mem_buf fails then tlsio_openssl_open shall return a non-zero value.

The following shall be repeated until all certificates passed via TrustedCerts are read:
The X509 certificate shall be read from the BIO by using PEM_read_bio_X509.
If PEM_read_bio_X509 fails then tlsio_openssl_open shall return a non-zero value.
The certificate shall be added to the OpenSSL context store by calling X509_STORE_add_cert and passing the certificate as argument.
The certificate and memory BIO shall be freed after the certificate has been added to the store.

### tlsio_openssl_close

```c
extern int tlsio_openssl_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context);
```

tlsio_openssl_close shall close the openssl tls IO if an open action is either pending or has completed successfully (if the IO is open).
On success tlsio_openssl_close shall return 0. 

### tlsio_openssl_send

```c
extern int tlsio_openssl_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context);
```

### tlsio_openssl_dowork

```c
extern void tlsio_openssl_dowork(CONCRETE_IO_HANDLE tls_io);
```

### tlsio_openssl_setoption

```c
extern int tlsio_openssl_setoption(CONCRETE_IO_HANDLE tls_io, const char* option_name, const void* value);
```

### tlsio_openssl_clone_option

```c
extern void* tlsio_openssl_clone_option(const char* name, const void* value);
```

### tlsio_openssl_destroy_option

```c
extern void wsio_destroy_option(const char* name, const void* value);
```

### tlsio_openssl_retrieveoptions

```c
OPTIONHANDLER_HANDLE tlsio_openssl_retrieveoptions(CONCRETE_IO_HANDLE tls_io)
```

### tlsio_openssl_get_interface_description

```c
extern const IO_INTERFACE_DESCRIPTION* tlsio_openssl_get_interface_description(void);
```

tlsio_openssl_get_interface_description shall return a pointer to an IO_INTERFACE_DESCRIPTION structure that contains pointers to the functions: tlsio_openssl_retrieveoptions, tlsio_openssl_create, tlsio_openssl_destroy, tlsio_openssl_open, tlsio_openssl_close, tlsio_openssl_send and tlsio_openssl_dowork. 
