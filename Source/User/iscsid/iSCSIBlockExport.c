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

#include "iSCSIBlockExport.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* This file implements the subset of ONC RPC (RFC 5531), the MOUNT protocol
 * and NFS version 3 (RFC 1813) that the macOS NFS client needs in order to
 * mount a flat, fixed directory of regular files and to read and write them. */

/*! Largest READ or WRITE the server accepts in a single request. */
#define kMaxTransferSize    (1u << 20)

/*! Largest RPC record accepted from a client. */
#define kMaxRecordSize      (kMaxTransferSize + 4096)

/*! Number of threads that process requests. */
#define kWorkerCount        16

/*! Number of requests that may be queued or in progress at once. */
#define kMaxInflight        64

/*! Name under which the directory of devices is exported. */
static const char kExportPath[] = "/iscsi";

/*! File identifier of the exported directory. */
static const uint64_t kRootFileId = 1;

enum {
    kRPCCall = 0,
    kRPCReply = 1,
    kRPCVersion = 2,
    kRPCAuthSys = 1,

    kRPCAcceptSuccess = 0,
    kRPCAcceptProgUnavail = 1,
    kRPCAcceptProgMismatch = 2,
    kRPCAcceptProcUnavail = 3,
    kRPCAcceptGarbageArgs = 4,

    kProgramMount = 100005,
    kProgramNFS = 100003,
};

enum {
    NFS3_OK = 0,
    NFS3ERR_NOENT = 2,
    NFS3ERR_IO = 5,
    NFS3ERR_ACCES = 13,
    NFS3ERR_NOTDIR = 20,
    NFS3ERR_ISDIR = 21,
    NFS3ERR_INVAL = 22,
    NFS3ERR_FBIG = 27,
    NFS3ERR_ROFS = 30,
    NFS3ERR_STALE = 70,
    NFS3ERR_BADHANDLE = 10001,
    NFS3ERR_NOTSUPP = 10004,
    NFS3ERR_JUKEBOX = 10008,
};

enum {
    kAccessRead = 0x01,
    kAccessLookup = 0x02,
    kAccessModify = 0x04,
    kAccessExtend = 0x08,
    kAccessDelete = 0x10,
    kAccessExecute = 0x20,
};

struct Device {
    struct Device * next;
    uint64_t fileId;
    char name[256];
    uint64_t size;
    bool readOnly;
    bool removed;
    uint32_t inflight;
    iSCSIBlockExportCallbacks callbacks;
};

struct Connection {
    struct Connection * next;
    struct __iSCSIBlockExport * exportRef;
    int fd;
    pthread_mutex_t writeLock;
    /*! One reference is held by the receive thread, one by each request. */
    int references;
};

struct Request {
    struct Request * next;
    struct Connection * connection;
    uint8_t * data;
    uint32_t length;
};

struct __iSCSIBlockExport {
    char socketPath[sizeof(((struct sockaddr_un *)0)->sun_path)];
    int listenFd;

    /*! Identifies the socket file, so as not to remove that of another
     *  instance later on. */
    ino_t socketInode;

    /*! Written to in order to make the accept thread exit. */
    int wakePipe[2];
    pthread_t acceptThread;
    pthread_t workers[kWorkerCount];

    /*! Protects everything below. */
    pthread_mutex_t lock;
    pthread_cond_t deviceCond;
    pthread_cond_t queueCond;
    pthread_cond_t inflightCond;

    bool stopping;
    struct Device * devices;
    uint64_t nextFileId;
    struct Connection * connections;
    int connectionCount;
    struct Request * queueHead, * queueTail;
    int inflight;

    uid_t owner;
    gid_t group;
    uint8_t handleSecret[8];
    uint8_t writeVerifier[8];
    uint64_t fileSystemId;
    struct timespec createTime;
    struct timespec directoryTime;
};

/*! Credentials and target of a single call. */
struct Call {
    struct __iSCSIBlockExport * exportRef;
    uint32_t xid;
    uint32_t program, version, procedure;
    uid_t uid;
    bool hasCredentials;
};

#pragma mark - XDR

struct XDRIn {
    const uint8_t * cursor;
    const uint8_t * end;
    bool error;
};

struct XDROut {
    uint8_t * data;
    size_t length;
    size_t capacity;
};

static uint32_t XDRGet32(struct XDRIn * in)
{
    if(in->error || in->end - in->cursor < 4) {
        in->error = true;
        return 0;
    }
    uint32_t value;
    memcpy(&value,in->cursor,4);
    in->cursor += 4;
    return ntohl(value);
}

static uint64_t XDRGet64(struct XDRIn * in)
{
    uint64_t high = XDRGet32(in);
    uint64_t low = XDRGet32(in);
    return (high << 32) | low;
}

/*! Gets a pointer to fixed-length opaque data (advances past padding). */
static const uint8_t * XDRGetFixed(struct XDRIn * in,uint32_t length)
{
    uint32_t padded = (length + 3) & ~3u;

    if(in->error || padded < length || (size_t)(in->end - in->cursor) < padded) {
        in->error = true;
        return NULL;
    }
    const uint8_t * data = in->cursor;
    in->cursor += padded;
    return data;
}

/*! Gets a pointer to variable-length opaque data and its length. */
static const uint8_t * XDRGetOpaque(struct XDRIn * in,uint32_t * length)
{
    *length = XDRGet32(in);
    return XDRGetFixed(in,*length);
}

static void XDRReserve(struct XDROut * out,size_t extra)
{
    if(out->length + extra <= out->capacity)
        return;

    size_t capacity = out->capacity ? out->capacity : 512;
    while(capacity < out->length + extra)
        capacity *= 2;

    out->data = realloc(out->data,capacity);
    out->capacity = capacity;
}

static void XDRPut32(struct XDROut * out,uint32_t value)
{
    XDRReserve(out,4);
    value = htonl(value);
    memcpy(out->data + out->length,&value,4);
    out->length += 4;
}

static void XDRPut64(struct XDROut * out,uint64_t value)
{
    XDRPut32(out,(uint32_t)(value >> 32));
    XDRPut32(out,(uint32_t)value);
}

static void XDRPutFixed(struct XDROut * out,const void * data,uint32_t length)
{
    uint32_t padded = (length + 3) & ~3u;
    XDRReserve(out,padded);
    memcpy(out->data + out->length,data,length);
    memset(out->data + out->length + length,0,padded - length);
    out->length += padded;
}

static void XDRPutOpaque(struct XDROut * out,const void * data,uint32_t length)
{
    XDRPut32(out,length);
    XDRPutFixed(out,data,length);
}

static void XDRPutTime(struct XDROut * out,const struct timespec * time)
{
    XDRPut32(out,(uint32_t)time->tv_sec);
    XDRPut32(out,(uint32_t)time->tv_nsec);
}

#pragma mark - Devices

/*! Looks up a device by file identifier and marks it busy. */
static struct Device * DeviceAcquire(iSCSIBlockExportRef exportRef,uint64_t fileId)
{
    struct Device * device;

    pthread_mutex_lock(&exportRef->lock);
    for(device = exportRef->devices; device; device = device->next) {
        if(device->fileId == fileId && !device->removed) {
            device->inflight++;
            break;
        }
    }
    pthread_mutex_unlock(&exportRef->lock);
    return device;
}

static void DeviceRelease(iSCSIBlockExportRef exportRef,struct Device * device)
{
    pthread_mutex_lock(&exportRef->lock);
    if(--device->inflight == 0 && device->removed)
        pthread_cond_broadcast(&exportRef->deviceCond);
    pthread_mutex_unlock(&exportRef->lock);
}

/*! Snapshot of the attributes of the directory or one of its files. */
struct Attributes {
    bool directory;
    uint64_t fileId;
    uint64_t size;
    uint32_t mode;
    struct timespec modifyTime;
};

static void AttributesForRoot(iSCSIBlockExportRef exportRef,struct Attributes * attributes)
{
    attributes->directory = true;
    attributes->fileId = kRootFileId;
    attributes->size = 512;
    attributes->mode = 0700;

    pthread_mutex_lock(&exportRef->lock);
    attributes->modifyTime = exportRef->directoryTime;
    pthread_mutex_unlock(&exportRef->lock);
}

static void AttributesForDevice(iSCSIBlockExportRef exportRef,
                                const struct Device * device,
                                struct Attributes * attributes)
{
    // The attributes of a device never change.  In particular the times
    // are constant so that the NFS client does not conclude that the file
    // was modified behind its back and drop its cached state.
    attributes->directory = false;
    attributes->fileId = device->fileId;
    attributes->size = device->size;
    attributes->mode = device->readOnly ? 0400 : 0600;
    attributes->modifyTime = exportRef->createTime;
}

static void PutAttributes(struct XDROut * out,
                          iSCSIBlockExportRef exportRef,
                          const struct Attributes * attributes)
{
    XDRPut32(out,attributes->directory ? 2 : 1);    // type (NF3DIR, NF3REG)
    XDRPut32(out,attributes->mode);
    XDRPut32(out,attributes->directory ? 2 : 1);    // nlink
    XDRPut32(out,exportRef->owner);
    XDRPut32(out,exportRef->group);
    XDRPut64(out,attributes->size);
    XDRPut64(out,attributes->size);                 // used
    XDRPut32(out,0);                                // rdev
    XDRPut32(out,0);
    XDRPut64(out,exportRef->fileSystemId);
    XDRPut64(out,attributes->fileId);
    XDRPutTime(out,&attributes->modifyTime);        // atime
    XDRPutTime(out,&attributes->modifyTime);        // mtime
    XDRPutTime(out,&attributes->modifyTime);        // ctime
}

/*! Writes a post_op_attr (attributes may be NULL). */
static void PutPostOpAttributes(struct XDROut * out,
                                iSCSIBlockExportRef exportRef,
                                const struct Attributes * attributes)
{
    if(!attributes) {
        XDRPut32(out,0);
        return;
    }
    XDRPut32(out,1);
    PutAttributes(out,exportRef,attributes);
}

/*! Writes wcc_data without pre-operation attributes. */
static void PutWCCData(struct XDROut * out,
                       iSCSIBlockExportRef exportRef,
                       const struct Attributes * attributes)
{
    XDRPut32(out,0);
    PutPostOpAttributes(out,exportRef,attributes);
}

static void PutFileHandle(struct XDROut * out,iSCSIBlockExportRef exportRef,uint64_t fileId)
{
    XDRPut32(out,16);
    XDRPutFixed(out,exportRef->handleSecret,8);
    XDRPut64(out,fileId);
}

/*! Reads a file handle.  Returns an NFS status and the file identifier. */
static uint32_t GetFileHandle(struct XDRIn * in,iSCSIBlockExportRef exportRef,uint64_t * fileId)
{
    uint32_t length;
    const uint8_t * handle = XDRGetOpaque(in,&length);

    if(!handle || length != 16)
        return NFS3ERR_BADHANDLE;

    if(memcmp(handle,exportRef->handleSecret,8) != 0)
        return NFS3ERR_STALE;

    struct XDRIn idIn = { handle + 8, handle + 16, false };
    *fileId = XDRGet64(&idIn);
    return NFS3_OK;
}

/*! Resolves a file handle to attributes.  If the handle refers to a device
 *  the device is returned busy and the caller must release it. */
static uint32_t ResolveFileHandle(struct XDRIn * in,
                                  iSCSIBlockExportRef exportRef,
                                  struct Device ** device,
                                  struct Attributes * attributes)
{
    uint64_t fileId = 0;
    uint32_t status = GetFileHandle(in,exportRef,&fileId);
    *device = NULL;

    if(status != NFS3_OK)
        return status;

    if(fileId == kRootFileId) {
        AttributesForRoot(exportRef,attributes);
        return NFS3_OK;
    }

    if(!(*device = DeviceAcquire(exportRef,fileId)))
        return NFS3ERR_STALE;

    AttributesForDevice(exportRef,*device,attributes);
    return NFS3_OK;
}

static bool CallerMayAccess(const struct Call * call)
{
    return call->hasCredentials && (call->uid == call->exportRef->owner || call->uid == 0);
}

static uint32_t StatusForIOError(int error)
{
    if(error == 0)
        return NFS3_OK;
    if(error == kiSCSIBlockExportErrorTryLater)
        return NFS3ERR_JUKEBOX;
    if(error == EROFS)
        return NFS3ERR_ROFS;
    if(error == EACCES || error == EPERM)
        return NFS3ERR_ACCES;
    return NFS3ERR_IO;
}

#pragma mark - NFS procedures

/*! Result of a procedure: the encoded reply plus optional bulk data that is
 *  sent as variable-length opaque data after the reply (used by READ). */
struct Result {
    struct XDROut out;
    void * bulk;
    uint32_t bulkLength;
};

static void NFSGetAttr(const struct Call * call,struct XDRIn * in,struct Result * result)
{
    struct Device * device;
    struct Attributes attributes;
    uint32_t status = ResolveFileHandle(in,call->exportRef,&device,&attributes);

    XDRPut32(&result->out,status);
    if(status == NFS3_OK)
        PutAttributes(&result->out,call->exportRef,&attributes);

    if(device)
        DeviceRelease(call->exportRef,device);
}

static void NFSSetAttr(const struct Call * call,struct XDRIn * in,struct Result * result)
{
    struct Device * device;
    struct Attributes attributes;
    uint32_t status = ResolveFileHandle(in,call->exportRef,&device,&attributes);

    // sattr3: mode, uid, gid, size, atime, mtime (each is optional)
    bool setSize = false;
    uint64_t size = 0;

    if(XDRGet32(in)) XDRGet32(in);                  // mode
    if(XDRGet32(in)) XDRGet32(in);                  // uid
    if(XDRGet32(in)) XDRGet32(in);                  // gid
    if((setSize = XDRGet32(in))) size = XDRGet64(in);
    if(XDRGet32(in) == 2) XDRGet64(in);             // atime (set to client time)
    if(XDRGet32(in) == 2) XDRGet64(in);             // mtime (set to client time)

    // Everything but a change of size is silently ignored
    if(status == NFS3_OK) {
        if(in->error)
            status = NFS3ERR_INVAL;
        else if(setSize && (attributes.directory || size != attributes.size))
            status = NFS3ERR_ACCES;
    }

    XDRPut32(&result->out,status);
    PutWCCData(&result->out,call->exportRef,(status == NFS3ERR_STALE || status == NFS3ERR_BADHANDLE) ? NULL : &attributes);

    if(device)
        DeviceRelease(call->exportRef,device);
}

static void NFSLookup(const struct Call * call,struct XDRIn * in,struct Result * result)
{
    iSCSIBlockExportRef exportRef = call->exportRef;
    uint64_t directoryId = 0;
    uint32_t status = GetFileHandle(in,exportRef,&directoryId);

    uint32_t nameLength = 0;
    const uint8_t * name = XDRGetOpaque(in,&nameLength);

    struct Attributes rootAttributes, attributes;
    AttributesForRoot(exportRef,&rootAttributes);
    bool found = false;

    if(status == NFS3_OK) {
        if(directoryId != kRootFileId)
            status = NFS3ERR_NOTDIR;
        else if(!name)
            status = NFS3ERR_INVAL;
        else if(!CallerMayAccess(call))
            status = NFS3ERR_ACCES;
        else if((nameLength == 1 && name[0] == '.') ||
                (nameLength == 2 && name[0] == '.' && name[1] == '.')) {
            attributes = rootAttributes;
            found = true;
        }
        else {
            pthread_mutex_lock(&exportRef->lock);
            for(struct Device * device = exportRef->devices; device; device = device->next) {
                if(!device->removed && strlen(device->name) == nameLength &&
                   memcmp(device->name,name,nameLength) == 0) {
                    AttributesForDevice(exportRef,device,&attributes);
                    found = true;
                    break;
                }
            }
            pthread_mutex_unlock(&exportRef->lock);

            if(!found)
                status = NFS3ERR_NOENT;
        }
    }

    XDRPut32(&result->out,status);

    if(status == NFS3_OK) {
        PutFileHandle(&result->out,exportRef,attributes.fileId);
        PutPostOpAttributes(&result->out,exportRef,&attributes);
    }
    PutPostOpAttributes(&result->out,exportRef,(directoryId == kRootFileId) ? &rootAttributes : NULL);
}

static void NFSAccess(const struct Call * call,struct XDRIn * in,struct Result * result)
{
    struct Device * device;
    struct Attributes attributes;
    uint32_t status = ResolveFileHandle(in,call->exportRef,&device,&attributes);
    uint32_t requested = XDRGet32(in);
    uint32_t allowed = 0;

    if(status == NFS3_OK && CallerMayAccess(call)) {
        if(attributes.directory)
            allowed = kAccessRead | kAccessLookup | kAccessExecute;
        else if(device && device->readOnly)
            allowed = kAccessRead;
        else
            allowed = kAccessRead | kAccessModify | kAccessExtend;
    }

    XDRPut32(&result->out,status);
    PutPostOpAttributes(&result->out,call->exportRef,(status == NFS3_OK) ? &attributes : NULL);

    if(status == NFS3_OK)
        XDRPut32(&result->out,requested & allowed);

    if(device)
        DeviceRelease(call->exportRef,device);
}

static void NFSRead(const struct Call * call,struct XDRIn * in,struct Result * result)
{
    struct Device * device;
    struct Attributes attributes;
    uint32_t status = ResolveFileHandle(in,call->exportRef,&device,&attributes);
    uint64_t offset = XDRGet64(in);
    uint32_t count = XDRGet32(in);
    void * buffer = NULL;
    bool eof = false;

    if(status == NFS3_OK) {
        if(in->error)
            status = NFS3ERR_INVAL;
        else if(!device)
            status = NFS3ERR_ISDIR;
        else if(!CallerMayAccess(call))
            status = NFS3ERR_ACCES;
    }

    if(status == NFS3_OK) {
        if(offset >= device->size) {
            count = 0;
            eof = true;
        }
        else {
            if(count > kMaxTransferSize)
                count = kMaxTransferSize;

            if(count >= device->size - offset) {
                count = (uint32_t)(device->size - offset);
                eof = true;
            }
        }

        if(count > 0) {
            if(!(buffer = malloc(count)))
                status = NFS3ERR_IO;
            else
                status = StatusForIOError(device->callbacks.read(device->callbacks.info,offset,count,buffer));
        }
    }

    XDRPut32(&result->out,status);
    PutPostOpAttributes(&result->out,call->exportRef,
                        (status == NFS3ERR_STALE || status == NFS3ERR_BADHANDLE) ? NULL : &attributes);

    if(status == NFS3_OK) {
        XDRPut32(&result->out,count);
        XDRPut32(&result->out,eof);
        result->bulk = buffer;
        result->bulkLength = count;
    }
    else
        free(buffer);

    if(device)
        DeviceRelease(call->exportRef,device);
}

static void NFSWrite(const struct Call * call,struct XDRIn * in,struct Result * result)
{
    struct Device * device;
    struct Attributes attributes;
    uint32_t status = ResolveFileHandle(in,call->exportRef,&device,&attributes);
    uint64_t offset = XDRGet64(in);
    uint32_t count = XDRGet32(in);
    uint32_t stable = XDRGet32(in);
    uint32_t length = 0;
    const uint8_t * data = XDRGetOpaque(in,&length);

    if(status == NFS3_OK) {
        if(in->error || !data || length < count)
            status = NFS3ERR_INVAL;
        else if(!device)
            status = NFS3ERR_ISDIR;
        else if(!CallerMayAccess(call))
            status = NFS3ERR_ACCES;
        else if(device->readOnly)
            status = NFS3ERR_ROFS;
        else if(offset > device->size || count > device->size - offset)
            status = NFS3ERR_FBIG;
        else if(count > 0)
            status = StatusForIOError(device->callbacks.write(device->callbacks.info,offset,count,data,stable != 0));
    }

    XDRPut32(&result->out,status);
    PutWCCData(&result->out,call->exportRef,
               (status == NFS3ERR_STALE || status == NFS3ERR_BADHANDLE) ? NULL : &attributes);

    if(status == NFS3_OK) {
        XDRPut32(&result->out,count);
        XDRPut32(&result->out,stable ? 2 : 0);      // FILE_SYNC or UNSTABLE
        XDRPutFixed(&result->out,call->exportRef->writeVerifier,8);
    }

    if(device)
        DeviceRelease(call->exportRef,device);
}

static void NFSCommit(const struct Call * call,struct XDRIn * in,struct Result * result)
{
    struct Device * device;
    struct Attributes attributes;
    uint32_t status = ResolveFileHandle(in,call->exportRef,&device,&attributes);

    if(status == NFS3_OK) {
        if(!device)
            status = NFS3ERR_ISDIR;
        else if(!CallerMayAccess(call))
            status = NFS3ERR_ACCES;
        else if(!device->readOnly)
            status = StatusForIOError(device->callbacks.flush(device->callbacks.info));
    }

    XDRPut32(&result->out,status);
    PutWCCData(&result->out,call->exportRef,
               (status == NFS3ERR_STALE || status == NFS3ERR_BADHANDLE) ? NULL : &attributes);

    if(status == NFS3_OK)
        XDRPutFixed(&result->out,call->exportRef->writeVerifier,8);

    if(device)
        DeviceRelease(call->exportRef,device);
}

/*! Handles both READDIR and READDIRPLUS. */
static void NFSReadDir(const struct Call * call,struct XDRIn * in,struct Result * result,bool plus)
{
    iSCSIBlockExportRef exportRef = call->exportRef;
    uint64_t directoryId = 0;
    uint32_t status = GetFileHandle(in,exportRef,&directoryId);
    uint64_t cookie = XDRGet64(in);
    XDRGet64(in);                                   // cookie verifier
    uint32_t limit = XDRGet32(in);                  // count or dircount

    if(plus)
        limit = XDRGet32(in);                       // maxcount

    if(status == NFS3_OK) {
        if(in->error)
            status = NFS3ERR_INVAL;
        else if(directoryId != kRootFileId)
            status = NFS3ERR_NOTDIR;
        else if(!CallerMayAccess(call))
            status = NFS3ERR_ACCES;
    }

    struct Attributes rootAttributes;
    AttributesForRoot(exportRef,&rootAttributes);

    XDRPut32(&result->out,status);
    PutPostOpAttributes(&result->out,exportRef,(directoryId == kRootFileId) ? &rootAttributes : NULL);

    if(status != NFS3_OK)
        return;

    XDRPut64(&result->out,0);                       // cookie verifier

    // The cookie of an entry is its position in the listing: "." and ".."
    // come first and are followed by the devices in order of creation.
    if(limit < 1024)
        limit = 1024;

    size_t start = result->out.length;
    bool eof = true;
    uint64_t position = 0;

    pthread_mutex_lock(&exportRef->lock);
    struct Device * device = NULL;

    for(;;) {
        const char * name;
        struct Attributes attributes;
        position++;

        if(position == 1 || position == 2) {
            name = (position == 1) ? "." : "..";
            attributes = rootAttributes;
        }
        else {
            device = (position == 3) ? exportRef->devices : device->next;

            while(device && device->removed)
                device = device->next;

            if(!device)
                break;

            name = device->name;
            AttributesForDevice(exportRef,device,&attributes);
        }

        // The position of a device is not stable across removals, so
        // cookies of devices are derived from their unique identifiers
        uint64_t entryCookie = (position <= 2) ? position : attributes.fileId + 2;

        if(entryCookie <= cookie)
            continue;

        if(result->out.length - start + strlen(name) + 160 > limit) {
            eof = false;
            break;
        }

        XDRPut32(&result->out,1);                   // an entry follows
        XDRPut64(&result->out,attributes.fileId);
        XDRPutOpaque(&result->out,name,(uint32_t)strlen(name));
        XDRPut64(&result->out,entryCookie);

        if(plus) {
            PutPostOpAttributes(&result->out,exportRef,&attributes);
            XDRPut32(&result->out,1);               // a handle follows
            PutFileHandle(&result->out,exportRef,attributes.fileId);
        }
    }
    pthread_mutex_unlock(&exportRef->lock);

    XDRPut32(&result->out,0);                       // no more entries
    XDRPut32(&result->out,eof);
}

static void NFSFSStat(const struct Call * call,struct XDRIn * in,struct Result * result)
{
    iSCSIBlockExportRef exportRef = call->exportRef;
    uint64_t fileId = 0;
    uint32_t status = GetFileHandle(in,exportRef,&fileId);

    struct Attributes rootAttributes;
    AttributesForRoot(exportRef,&rootAttributes);

    uint64_t totalBytes = 0, totalFiles = 1;

    pthread_mutex_lock(&exportRef->lock);
    for(struct Device * device = exportRef->devices; device; device = device->next) {
        totalBytes += device->size;
        totalFiles++;
    }
    pthread_mutex_unlock(&exportRef->lock);

    XDRPut32(&result->out,status);
    PutPostOpAttributes(&result->out,exportRef,(status == NFS3_OK) ? &rootAttributes : NULL);

    if(status != NFS3_OK)
        return;

    XDRPut64(&result->out,totalBytes);              // tbytes
    XDRPut64(&result->out,0);                       // fbytes
    XDRPut64(&result->out,0);                       // abytes
    XDRPut64(&result->out,totalFiles);              // tfiles
    XDRPut64(&result->out,0);                       // ffiles
    XDRPut64(&result->out,0);                       // afiles
    XDRPut32(&result->out,0);                       // invarsec
}

static void NFSFSInfo(const struct Call * call,struct XDRIn * in,struct Result * result)
{
    iSCSIBlockExportRef exportRef = call->exportRef;
    uint64_t fileId = 0;
    uint32_t status = GetFileHandle(in,exportRef,&fileId);

    struct Attributes rootAttributes;
    AttributesForRoot(exportRef,&rootAttributes);

    XDRPut32(&result->out,status);
    PutPostOpAttributes(&result->out,exportRef,(status == NFS3_OK) ? &rootAttributes : NULL);

    if(status != NFS3_OK)
        return;

    XDRPut32(&result->out,kMaxTransferSize);        // rtmax
    XDRPut32(&result->out,kMaxTransferSize);        // rtpref
    XDRPut32(&result->out,512);                     // rtmult
    XDRPut32(&result->out,kMaxTransferSize);        // wtmax
    XDRPut32(&result->out,kMaxTransferSize);        // wtpref
    XDRPut32(&result->out,512);                     // wtmult
    XDRPut32(&result->out,8192);                    // dtpref
    XDRPut64(&result->out,INT64_MAX);               // maxfilesize
    XDRPut32(&result->out,0);                       // time_delta
    XDRPut32(&result->out,1);
    XDRPut32(&result->out,0x08);                    // properties (FSF3_HOMOGENEOUS)
}

static void NFSPathConf(const struct Call * call,struct XDRIn * in,struct Result * result)
{
    struct Device * device;
    struct Attributes attributes;
    uint32_t status = ResolveFileHandle(in,call->exportRef,&device,&attributes);

    XDRPut32(&result->out,status);
    PutPostOpAttributes(&result->out,call->exportRef,(status == NFS3_OK) ? &attributes : NULL);

    if(status == NFS3_OK) {
        XDRPut32(&result->out,1);                   // linkmax
        XDRPut32(&result->out,255);                 // name_max
        XDRPut32(&result->out,1);                   // no_trunc
        XDRPut32(&result->out,1);                   // chown_restricted
        XDRPut32(&result->out,0);                   // case_insensitive
        XDRPut32(&result->out,1);                   // case_preserving
    }

    if(device)
        DeviceRelease(call->exportRef,device);
}

/*! Refuses a procedure that would modify the directory.  The reply consists
 *  of a status followed by a number of empty weak cache consistency records. */
static void NFSRefuse(struct Result * result,uint32_t status,int postOpCount,int wccCount)
{
    XDRPut32(&result->out,status);

    for(int index = 0; index < postOpCount; index++)
        XDRPut32(&result->out,0);

    for(int index = 0; index < wccCount; index++) {
        XDRPut32(&result->out,0);
        XDRPut32(&result->out,0);
    }
}

/*! Dispatches an NFS call. Returns an RPC accept status. */
static uint32_t DispatchNFS(const struct Call * call,struct XDRIn * in,struct Result * result)
{
    if(call->version != 3)
        return kRPCAcceptProgMismatch;

    switch(call->procedure) {
        case 0:  break;                                             // NULL
        case 1:  NFSGetAttr(call,in,result); break;
        case 2:  NFSSetAttr(call,in,result); break;
        case 3:  NFSLookup(call,in,result); break;
        case 4:  NFSAccess(call,in,result); break;
        case 5:  NFSRefuse(result,NFS3ERR_INVAL,1,0); break;        // READLINK
        case 6:  NFSRead(call,in,result); break;
        case 7:  NFSWrite(call,in,result); break;
        case 8:                                                     // CREATE
        case 9:                                                     // MKDIR
        case 10:                                                    // SYMLINK
        case 11:                                                    // MKNOD
        case 12:                                                    // REMOVE
        case 13: NFSRefuse(result,NFS3ERR_ACCES,0,1); break;        // RMDIR
        case 14: NFSRefuse(result,NFS3ERR_ACCES,0,2); break;        // RENAME
        case 15: NFSRefuse(result,NFS3ERR_ACCES,1,1); break;        // LINK
        case 16: NFSReadDir(call,in,result,false); break;
        case 17: NFSReadDir(call,in,result,true); break;
        case 18: NFSFSStat(call,in,result); break;
        case 19: NFSFSInfo(call,in,result); break;
        case 20: NFSPathConf(call,in,result); break;
        case 21: NFSCommit(call,in,result); break;
        default: return kRPCAcceptProcUnavail;
    }
    return kRPCAcceptSuccess;
}

/*! Dispatches a call of the MOUNT protocol. Returns an RPC accept status. */
static uint32_t DispatchMount(const struct Call * call,struct XDRIn * in,struct Result * result)
{
    if(call->version != 3)
        return kRPCAcceptProgMismatch;

    switch(call->procedure) {
        case 0:                                                     // NULL
        case 3:                                                     // UMNT
        case 4:                                                     // UMNTALL
            break;
        case 1: {                                                   // MNT
            uint32_t length = 0;
            const uint8_t * path = XDRGetOpaque(in,&length);

            if(!path || length != strlen(kExportPath) || memcmp(path,kExportPath,length) != 0)
                XDRPut32(&result->out,2);                           // MNT3ERR_NOENT
            else if(!CallerMayAccess(call))
                XDRPut32(&result->out,13);                          // MNT3ERR_ACCES
            else {
                XDRPut32(&result->out,0);
                PutFileHandle(&result->out,call->exportRef,kRootFileId);
                XDRPut32(&result->out,1);                           // one authentication flavor
                XDRPut32(&result->out,kRPCAuthSys);
            }
            break;
        }
        case 2:                                                     // DUMP
            XDRPut32(&result->out,0);
            break;
        case 5:                                                     // EXPORT
            XDRPut32(&result->out,1);
            XDRPutOpaque(&result->out,kExportPath,(uint32_t)strlen(kExportPath));
            XDRPut32(&result->out,0);                               // no groups
            XDRPut32(&result->out,0);                               // no more exports
            break;
        default:
            return kRPCAcceptProcUnavail;
    }
    return kRPCAcceptSuccess;
}

#pragma mark - RPC transport

static bool ReadFully(int fd,void * buffer,size_t length)
{
    uint8_t * cursor = buffer;

    while(length > 0) {
        ssize_t count = read(fd,cursor,length);

        if(count == 0)
            return false;

        if(count < 0) {
            if(errno == EINTR)
                continue;
            return false;
        }
        cursor += count;
        length -= (size_t)count;
    }
    return true;
}

static bool WriteFully(int fd,struct iovec * vectors,int count)
{
    while(count > 0) {
        ssize_t written = writev(fd,vectors,count);

        if(written < 0) {
            if(errno == EINTR)
                continue;
            return false;
        }

        while(count > 0 && (size_t)written >= vectors->iov_len) {
            written -= vectors->iov_len;
            vectors++;
            count--;
        }

        if(count > 0) {
            vectors->iov_base = (uint8_t *)vectors->iov_base + written;
            vectors->iov_len -= (size_t)written;
        }
    }
    return true;
}

static void ConnectionRelease(struct Connection * connection)
{
    iSCSIBlockExportRef exportRef = connection->exportRef;

    pthread_mutex_lock(&exportRef->lock);
    bool last = (--connection->references == 0);

    if(last) {
        struct Connection ** link = &exportRef->connections;

        while(*link && *link != connection)
            link = &(*link)->next;

        if(*link)
            *link = connection->next;

        exportRef->connectionCount--;
        pthread_cond_broadcast(&exportRef->inflightCond);
    }
    pthread_mutex_unlock(&exportRef->lock);

    if(last) {
        close(connection->fd);
        pthread_mutex_destroy(&connection->writeLock);
        free(connection);
    }
}

/*! Decodes and executes a call and sends the reply. */
static void ProcessRequest(struct Request * request)
{
    struct Connection * connection = request->connection;
    struct XDRIn in = { request->data, request->data + request->length, false };

    struct Call call;
    memset(&call,0,sizeof(call));
    call.exportRef = connection->exportRef;
    call.xid = XDRGet32(&in);

    uint32_t messageType = XDRGet32(&in);
    uint32_t rpcVersion = XDRGet32(&in);
    call.program = XDRGet32(&in);
    call.version = XDRGet32(&in);
    call.procedure = XDRGet32(&in);

    // Credentials (only AUTH_SYS carries a user identifier)
    uint32_t flavor = XDRGet32(&in);
    uint32_t credentialLength = 0;
    const uint8_t * credential = XDRGetOpaque(&in,&credentialLength);

    if(credential && flavor == kRPCAuthSys) {
        struct XDRIn credentialIn = { credential, credential + credentialLength, false };
        uint32_t machineLength;
        XDRGet32(&credentialIn);                    // stamp
        XDRGetOpaque(&credentialIn,&machineLength); // machine name
        call.uid = XDRGet32(&credentialIn);
        call.hasCredentials = !credentialIn.error;
    }

    // Verifier (ignored)
    uint32_t verifierLength = 0;
    XDRGet32(&in);
    XDRGetOpaque(&in,&verifierLength);

    // Malformed calls and anything that isn't a call are dropped
    if(in.error || messageType != kRPCCall)
        return;

    struct Result result;
    memset(&result,0,sizeof(result));

    // Reply header: record marker (filled in below), xid, REPLY
    XDRPut32(&result.out,0);
    XDRPut32(&result.out,call.xid);
    XDRPut32(&result.out,kRPCReply);

    if(rpcVersion != kRPCVersion) {
        XDRPut32(&result.out,1);                    // MSG_DENIED
        XDRPut32(&result.out,0);                    // RPC_MISMATCH
        XDRPut32(&result.out,kRPCVersion);
        XDRPut32(&result.out,kRPCVersion);
    }
    else {
        XDRPut32(&result.out,0);                    // MSG_ACCEPTED
        XDRPut32(&result.out,0);                    // verifier: AUTH_NONE
        XDRPut32(&result.out,0);

        size_t statusOffset = result.out.length;
        XDRPut32(&result.out,kRPCAcceptSuccess);

        uint32_t acceptStatus;

        if(call.program == kProgramNFS)
            acceptStatus = DispatchNFS(&call,&in,&result);
        else if(call.program == kProgramMount)
            acceptStatus = DispatchMount(&call,&in,&result);
        else
            acceptStatus = kRPCAcceptProgUnavail;

        if(acceptStatus != kRPCAcceptSuccess) {
            free(result.bulk);
            result.bulk = NULL;
            result.out.length = statusOffset;
            XDRPut32(&result.out,acceptStatus);

            if(acceptStatus == kRPCAcceptProgMismatch) {
                XDRPut32(&result.out,3);            // lowest version supported
                XDRPut32(&result.out,3);            // highest version supported
            }
        }
    }

    // Bulk data is sent as opaque<>: a length followed by the data and padding
    static const uint8_t padding[4] = { 0, 0, 0, 0 };
    struct iovec vectors[3];
    int vectorCount = 1;
    size_t total = result.out.length - 4;

    if(result.bulk) {
        XDRPut32(&result.out,result.bulkLength);
        total += 4;

        if(result.bulkLength > 0) {
            vectors[vectorCount].iov_base = result.bulk;
            vectors[vectorCount].iov_len = result.bulkLength;
            vectorCount++;
            total += result.bulkLength;

            if(result.bulkLength & 3) {
                vectors[vectorCount].iov_base = (void *)padding;
                vectors[vectorCount].iov_len = 4 - (result.bulkLength & 3);
                total += vectors[vectorCount].iov_len;
                vectorCount++;
            }
        }
    }

    uint32_t marker = htonl(0x80000000u | (uint32_t)total);
    memcpy(result.out.data,&marker,4);
    vectors[0].iov_base = result.out.data;
    vectors[0].iov_len = result.out.length;

    pthread_mutex_lock(&connection->writeLock);
    if(!WriteFully(connection->fd,vectors,vectorCount))
        shutdown(connection->fd,SHUT_RDWR);
    pthread_mutex_unlock(&connection->writeLock);

    free(result.bulk);
    free(result.out.data);
}

static void * WorkerMain(void * context)
{
    iSCSIBlockExportRef exportRef = context;
    pthread_setname_np("iscsid.nfs.worker");

    for(;;) {
        pthread_mutex_lock(&exportRef->lock);

        while(!exportRef->queueHead && !exportRef->stopping)
            pthread_cond_wait(&exportRef->queueCond,&exportRef->lock);

        struct Request * request = exportRef->queueHead;

        if(!request) {
            pthread_mutex_unlock(&exportRef->lock);
            return NULL;
        }

        if(!(exportRef->queueHead = request->next))
            exportRef->queueTail = NULL;

        pthread_mutex_unlock(&exportRef->lock);

        ProcessRequest(request);

        pthread_mutex_lock(&exportRef->lock);
        exportRef->inflight--;
        pthread_cond_broadcast(&exportRef->inflightCond);
        pthread_mutex_unlock(&exportRef->lock);

        ConnectionRelease(request->connection);
        free(request->data);
        free(request);
    }
}

/*! Receives RPC records from a client and queues them for the workers. */
static void * ConnectionMain(void * context)
{
    struct Connection * connection = context;
    iSCSIBlockExportRef exportRef = connection->exportRef;
    pthread_setname_np("iscsid.nfs.receive");

    for(;;) {
        uint8_t * record = NULL;
        uint32_t recordLength = 0;
        bool complete = false;

        // A record is made up of one or more fragments
        while(!complete) {
            uint32_t marker;

            if(!ReadFully(connection->fd,&marker,4))
                break;

            marker = ntohl(marker);
            uint32_t fragmentLength = marker & 0x7fffffffu;

            if(fragmentLength > kMaxRecordSize - recordLength)
                break;

            uint8_t * grown = realloc(record,recordLength + fragmentLength + 1);

            if(!grown)
                break;

            record = grown;

            if(!ReadFully(connection->fd,record + recordLength,fragmentLength))
                break;

            recordLength += fragmentLength;
            complete = (marker & 0x80000000u) != 0;
        }

        if(!complete) {
            free(record);
            break;
        }

        struct Request * request = calloc(1,sizeof(struct Request));
        request->connection = connection;
        request->data = record;
        request->length = recordLength;

        pthread_mutex_lock(&exportRef->lock);

        while(exportRef->inflight >= kMaxInflight && !exportRef->stopping)
            pthread_cond_wait(&exportRef->inflightCond,&exportRef->lock);

        if(exportRef->stopping) {
            pthread_mutex_unlock(&exportRef->lock);
            free(record);
            free(request);
            break;
        }

        connection->references++;
        exportRef->inflight++;

        if(exportRef->queueTail)
            exportRef->queueTail->next = request;
        else
            exportRef->queueHead = request;

        exportRef->queueTail = request;
        pthread_cond_signal(&exportRef->queueCond);
        pthread_mutex_unlock(&exportRef->lock);
    }

    shutdown(connection->fd,SHUT_RDWR);
    ConnectionRelease(connection);
    return NULL;
}

static void * AcceptMain(void * context)
{
    iSCSIBlockExportRef exportRef = context;
    pthread_setname_np("iscsid.nfs.accept");

    for(;;) {
        struct pollfd fds[2] = {
            { .fd = exportRef->listenFd, .events = POLLIN },
            { .fd = exportRef->wakePipe[0], .events = POLLIN }
        };

        if(poll(fds,2,-1) < 0) {
            if(errno == EINTR)
                continue;
            return NULL;
        }

        // The export is being released
        if(fds[1].revents)
            return NULL;

        int fd = accept(exportRef->listenFd,NULL,NULL);

        if(fd < 0) {
            if(errno == EINTR || errno == ECONNABORTED || errno == EAGAIN)
                continue;
            return NULL;
        }

        // The listening socket does not block; its connections do
        int enable = 1;
        fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0) & ~O_NONBLOCK);
        fcntl(fd,F_SETFD,FD_CLOEXEC);
        setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&enable,sizeof(enable));

        struct Connection * connection = calloc(1,sizeof(struct Connection));
        connection->exportRef = exportRef;
        connection->fd = fd;
        connection->references = 1;
        pthread_mutex_init(&connection->writeLock,NULL);

        pthread_mutex_lock(&exportRef->lock);

        if(exportRef->stopping) {
            pthread_mutex_unlock(&exportRef->lock);
            close(fd);
            free(connection);
            return NULL;
        }

        connection->next = exportRef->connections;
        exportRef->connections = connection;
        exportRef->connectionCount++;
        pthread_mutex_unlock(&exportRef->lock);

        pthread_t thread;
        pthread_attr_t attributes;
        pthread_attr_init(&attributes);
        pthread_attr_setdetachstate(&attributes,PTHREAD_CREATE_DETACHED);

        if(pthread_create(&thread,&attributes,ConnectionMain,connection) != 0) {
            shutdown(fd,SHUT_RDWR);
            ConnectionRelease(connection);
        }
        pthread_attr_destroy(&attributes);
    }
}

#pragma mark - Public interface

iSCSIBlockExportRef iSCSIBlockExportCreate(const char * socketPath)
{
    struct sockaddr_un address;
    memset(&address,0,sizeof(address));
    address.sun_family = AF_UNIX;

    if(!socketPath || strlen(socketPath) >= sizeof(address.sun_path)) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    strlcpy(address.sun_path,socketPath,sizeof(address.sun_path));

    int fd = socket(AF_UNIX,SOCK_STREAM,0);

    if(fd < 0)
        return NULL;

    unlink(socketPath);

    // The socket is only ever to be used by the owner of this process
    mode_t mask = umask(0177);
    int error = 0;

    if(bind(fd,(struct sockaddr *)&address,(socklen_t)SUN_LEN(&address)) != 0 || listen(fd,16) != 0)
        error = errno;

    umask(mask);

    if(error) {
        close(fd);
        errno = error;
        return NULL;
    }

    iSCSIBlockExportRef exportRef = calloc(1,sizeof(struct __iSCSIBlockExport));
    strlcpy(exportRef->socketPath,socketPath,sizeof(exportRef->socketPath));
    exportRef->listenFd = fd;

    struct stat socketStatus;

    if(stat(socketPath,&socketStatus) == 0)
        exportRef->socketInode = socketStatus.st_ino;

    if(pipe(exportRef->wakePipe) != 0) {
        error = errno;
        close(fd);
        free(exportRef);
        errno = error;
        return NULL;
    }

    fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0) | O_NONBLOCK);
    fcntl(fd,F_SETFD,FD_CLOEXEC);
    fcntl(exportRef->wakePipe[0],F_SETFD,FD_CLOEXEC);
    fcntl(exportRef->wakePipe[1],F_SETFD,FD_CLOEXEC);
    exportRef->nextFileId = kRootFileId + 1;
    exportRef->owner = getuid();
    exportRef->group = getgid();

    arc4random_buf(exportRef->handleSecret,sizeof(exportRef->handleSecret));
    arc4random_buf(exportRef->writeVerifier,sizeof(exportRef->writeVerifier));
    arc4random_buf(&exportRef->fileSystemId,sizeof(exportRef->fileSystemId));

    clock_gettime(CLOCK_REALTIME,&exportRef->createTime);
    exportRef->directoryTime = exportRef->createTime;

    pthread_mutex_init(&exportRef->lock,NULL);
    pthread_cond_init(&exportRef->deviceCond,NULL);
    pthread_cond_init(&exportRef->queueCond,NULL);
    pthread_cond_init(&exportRef->inflightCond,NULL);

    for(int index = 0; index < kWorkerCount; index++)
        pthread_create(&exportRef->workers[index],NULL,WorkerMain,exportRef);

    pthread_create(&exportRef->acceptThread,NULL,AcceptMain,exportRef);
    return exportRef;
}

void iSCSIBlockExportRelease(iSCSIBlockExportRef exportRef)
{
    if(!exportRef)
        return;

    // Stop accepting clients and disconnect the existing ones
    pthread_mutex_lock(&exportRef->lock);
    exportRef->stopping = true;

    for(struct Connection * connection = exportRef->connections; connection; connection = connection->next)
        shutdown(connection->fd,SHUT_RDWR);

    pthread_cond_broadcast(&exportRef->queueCond);
    pthread_cond_broadcast(&exportRef->inflightCond);
    pthread_mutex_unlock(&exportRef->lock);

    // Wake up the accept thread
    char byte = 0;
    (void)write(exportRef->wakePipe[1],&byte,1);

    pthread_join(exportRef->acceptThread,NULL);
    close(exportRef->listenFd);
    close(exportRef->wakePipe[0]);
    close(exportRef->wakePipe[1]);

    // Remove the socket, unless another instance has put its own in place
    struct stat status;

    if(stat(exportRef->socketPath,&status) == 0 && status.st_ino == exportRef->socketInode)
        unlink(exportRef->socketPath);

    for(int index = 0; index < kWorkerCount; index++)
        pthread_join(exportRef->workers[index],NULL);

    // Wait for the receive threads to notice that their sockets are gone
    pthread_mutex_lock(&exportRef->lock);
    while(exportRef->connectionCount > 0)
        pthread_cond_wait(&exportRef->inflightCond,&exportRef->lock);

    struct Device * device = exportRef->devices;
    exportRef->devices = NULL;
    pthread_mutex_unlock(&exportRef->lock);

    while(device) {
        struct Device * next = device->next;

        if(device->callbacks.release)
            device->callbacks.release(device->callbacks.info);

        free(device);
        device = next;
    }

    pthread_mutex_destroy(&exportRef->lock);
    pthread_cond_destroy(&exportRef->deviceCond);
    pthread_cond_destroy(&exportRef->queueCond);
    pthread_cond_destroy(&exportRef->inflightCond);
    free(exportRef);
}

const char * iSCSIBlockExportGetSocketPath(iSCSIBlockExportRef exportRef)
{
    return exportRef->socketPath;
}

const char * iSCSIBlockExportGetExportPath(iSCSIBlockExportRef exportRef)
{
    return kExportPath;
}

/*! Changes the modification time of the directory, which makes the NFS
 *  client discard its cached listing. Must be called with the lock held. */
static void TouchDirectory(iSCSIBlockExportRef exportRef)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME,&now);

    // The time must change even if the clock did not advance
    if(now.tv_sec < exportRef->directoryTime.tv_sec ||
       (now.tv_sec == exportRef->directoryTime.tv_sec && now.tv_nsec <= exportRef->directoryTime.tv_nsec)) {
        now = exportRef->directoryTime;

        if(++now.tv_nsec >= 1000000000) {
            now.tv_nsec = 0;
            now.tv_sec++;
        }
    }
    exportRef->directoryTime = now;
}

int iSCSIBlockExportAddDevice(iSCSIBlockExportRef exportRef,
                              const char * name,
                              uint64_t size,
                              bool readOnly,
                              const iSCSIBlockExportCallbacks * callbacks)
{
    if(!exportRef || !name || !callbacks || !callbacks->read || !callbacks->write || !callbacks->flush)
        return EINVAL;

    size_t nameLength = strlen(name);

    if(nameLength == 0 || nameLength >= sizeof(((struct Device *)0)->name) || strchr(name,'/') ||
       strcmp(name,".") == 0 || strcmp(name,"..") == 0)
        return EINVAL;

    struct Device * device = calloc(1,sizeof(struct Device));
    strlcpy(device->name,name,sizeof(device->name));
    device->size = size;
    device->readOnly = readOnly;
    device->callbacks = *callbacks;

    pthread_mutex_lock(&exportRef->lock);

    // Devices are kept in order of creation
    struct Device ** link = &exportRef->devices;

    while(*link) {
        if(strcmp((*link)->name,name) == 0) {
            pthread_mutex_unlock(&exportRef->lock);
            free(device);
            return EEXIST;
        }
        link = &(*link)->next;
    }

    device->fileId = exportRef->nextFileId++;
    *link = device;
    TouchDirectory(exportRef);
    pthread_mutex_unlock(&exportRef->lock);
    return 0;
}

int iSCSIBlockExportRemoveDevice(iSCSIBlockExportRef exportRef,const char * name)
{
    if(!exportRef || !name)
        return EINVAL;

    pthread_mutex_lock(&exportRef->lock);

    struct Device ** link = &exportRef->devices;

    while(*link && (strcmp((*link)->name,name) != 0 || (*link)->removed))
        link = &(*link)->next;

    struct Device * device = *link;

    if(!device) {
        pthread_mutex_unlock(&exportRef->lock);
        return ENOENT;
    }

    // New requests for the device are refused from here on
    device->removed = true;

    while(device->inflight > 0)
        pthread_cond_wait(&exportRef->deviceCond,&exportRef->lock);

    // Other devices may have been unlinked while the lock was dropped
    for(link = &exportRef->devices; *link != device; link = &(*link)->next);

    *link = device->next;
    TouchDirectory(exportRef);
    pthread_mutex_unlock(&exportRef->lock);

    if(device->callbacks.release)
        device->callbacks.release(device->callbacks.info);

    free(device);
    return 0;
}

int iSCSIBlockExportGetClientCount(iSCSIBlockExportRef exportRef)
{
    pthread_mutex_lock(&exportRef->lock);
    int count = exportRef->connectionCount;
    pthread_mutex_unlock(&exportRef->lock);
    return count;
}
