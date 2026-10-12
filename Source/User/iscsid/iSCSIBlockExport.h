/*
 * Copyright (c) 2026, LunLink contributors
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __ISCSI_BLOCK_EXPORT_H__
#define __ISCSI_BLOCK_EXPORT_H__

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

/*! A block export publishes block devices to the local machine without any
 *  kernel code.  Each device appears as a regular file of a single-directory
 *  NFSv3 file system that is served over a local (AF_UNIX) socket.  macOS
 *  mounts that file system with its built-in NFS client, and the files are
 *  then attached as raw disk images, which yields ordinary /dev/disk nodes. */
typedef struct __iSCSIBlockExport * iSCSIBlockExportRef;

/*! Returned by the I/O callbacks when the backing device is temporarily
 *  unavailable (e.g., the iSCSI session is being re-established).  The NFS
 *  client is told to retry the request later rather than fail it. */
#define kiSCSIBlockExportErrorTryLater  (-2)

/*! Callbacks that perform the I/O for an exported device. Offsets and lengths
 *  are in bytes and need not be aligned to the block size of the device.
 *  Callbacks are invoked concurrently from multiple threads and return 0 on
 *  success, an errno value or kiSCSIBlockExportErrorTryLater. */
typedef struct iSCSIBlockExportCallbacks {

    /*! User-defined data passed to each callback. */
    void * info;

    int (*read)(void * info,uint64_t offset,uint32_t length,void * buffer);

    /*! If sync is true the data must be on stable storage upon return. */
    int (*write)(void * info,uint64_t offset,uint32_t length,const void * buffer,bool sync);

    /*! Commits all previously written data to stable storage. */
    int (*flush)(void * info);

    /*! Called once the device was removed and no I/O is in flight (may be NULL). */
    void (*release)(void * info);

} iSCSIBlockExportCallbacks;

/*! Creates a block export that listens on a local socket.
 *  @param socketPath path of the AF_UNIX socket (created; must be short
 *  enough to fit into a sockaddr_un).
 *  @return a new export or NULL (errno is set). */
iSCSIBlockExportRef iSCSIBlockExportCreate(const char * socketPath);

/*! Stops serving, removes all devices and frees the export. */
void iSCSIBlockExportRelease(iSCSIBlockExportRef exportRef);

/*! Gets the path of the socket the export listens on. */
const char * iSCSIBlockExportGetSocketPath(iSCSIBlockExportRef exportRef);

/*! Gets the name of the exported directory (the path to pass to mount_nfs). */
const char * iSCSIBlockExportGetExportPath(iSCSIBlockExportRef exportRef);

/*! Adds a device to the export.
 *  @param name the file name of the device within the exported directory.
 *  @param size the size of the device, in bytes.
 *  @param readOnly true to refuse writes.
 *  @param callbacks the I/O callbacks (copied).
 *  @return 0 or an errno value. */
int iSCSIBlockExportAddDevice(iSCSIBlockExportRef exportRef,
                              const char * name,
                              uint64_t size,
                              bool readOnly,
                              const iSCSIBlockExportCallbacks * callbacks);

/*! Removes a device from the export.  Blocks until in-flight I/O for the
 *  device has completed; further requests fail with a stale handle error.
 *  @return 0 or an errno value. */
int iSCSIBlockExportRemoveDevice(iSCSIBlockExportRef exportRef,const char * name);

/*! Gets the number of client connections (0 when nothing has it mounted). */
int iSCSIBlockExportGetClientCount(iSCSIBlockExportRef exportRef);

#endif /* defined(__ISCSI_BLOCK_EXPORT_H__) */
