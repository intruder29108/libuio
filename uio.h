/*
 * uio.h
 * lists the exported functions.
 *
 */
#ifndef __UIO_H__
#define __UIO_H__


typedef void* libuio_handle_t;
typedef void* libuio_dev_handle_t;

int uio_init(libuio_handle_t *handle, bool verbose);
void uio_dump(libuio_handle_t handle);

libuio_dev_handle_t uio_device_open(libuio_handle_t handle, const char *name);
void uio_device_close(libuio_dev_handle_t handle);
int uio_attach_event(libuio_dev_handle_t handle, int vector);
int uio_detach_event(libuio_dev_handle_t handle, int vector);

int uio_device_map_all(libuio_dev_handle_t handle);
void *uio_device_mapped_addr(libuio_dev_handle_t handle, int idx);

#endif
