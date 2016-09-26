tlsio_arduino
=============

## Overview

tlsio_openssl implements a tls adapter for the OpenSSL TLS library.


## References

[TLS Protocol (RFC2246)](https://www.ietf.org/rfc/rfc2246.txt)

[TLS Protocol (generic information)](https://en.wikipedia.org/wiki/Transport_Layer_Security)

## Exposed API

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

### tlsio_openssl_create

```c
extern CONCRETE_IO_HANDLE tlsio_openssl_create(void* io_create_parameters);
```

tlsio_openssl_create shall create an instance of a tlsio_openssl and return a non-NULL handle to it.
If the argument io_create_parameters is NULL then wsio_create shall return NULL.
io_create_parameters shall be used as a TLSIO_CONFIG* .
If the hostname field in the TLSIO_CONFIG structure is NULL then tlsio_openssl_create shall return NULL.
If allocating memory for the new tlsio_openssl instance fails then tlsio_openssl_create shall return NULL.
The members hostname and port shall be copied for later use (they are needed when the IO is opened). 

### tlsio_openssl_destroy

```c
extern void tlsio_openssl_destroy(CONCRETE_IO_HANDLE tls_io);
```

tlsio_openssl_destroy shall free all resources associated with the tlsio_openssl instance.
If tls_io is NULL, tlsio_openssl shall do nothing. 
tlsio_openssl shall . 

### tlsio_openssl_open

```c
extern int tlsio_openssl_open(CONCRETE_IO_HANDLE tls_io, ON_IO_OPEN_COMPLETE on_io_open_complete, ON_BYTES_RECEIVED on_bytes_received, ON_IO_ERROR on_io_error, void* callback_context);
```

tlsio_openssl_open shall create an OpenSSL context .
On success, tlsio_openssl_open shall return 0.
If any of the arguments tls_io, on_io_open_complete, or on_bytes_received is NULL then tlsio_openssl_open shall return a non-zero value.

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
