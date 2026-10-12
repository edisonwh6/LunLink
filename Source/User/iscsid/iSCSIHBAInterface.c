/*
 * Copyright (c) 2016, Nareg Sinenian
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

/* A user-space iSCSI host bus adapter.
 *
 * This file replaces the kernel extension of earlier versions.  It owns the
 * TCP connections to the targets and implements the full feature phase of
 * iSCSI (RFC 7143) at error recovery level 0: command windowing, immediate
 * and unsolicited data, R2T handling, Data-In reassembly, digests, NOP
 * keep-alives and asynchronous messages.  Login, logout and discovery are
 * carried out by the session layer on top of the PDU send/receive functions.
 *
 * Each activated connection has a receive thread, which dispatches PDUs from
 * the target, and a transmit thread, which answers R2Ts and NOP-Ins and
 * watches over the health of the connection.  SCSI tasks are submitted by the
 * threads that call iSCSIHBAInterfaceExecuteSCSI().
 *
 * Lock order: the send lock of a connection or the lock of the interface may
 * be held when the lock of a session is taken, never the other way round. */

#include "iSCSIHBAInterface.h"
#include "iSCSICRC32C.h"
#include "iSCSILog.h"
#include "iSCSIRFC3720Defaults.h"

#include <sys/uio.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

/*! Time allowed for a TCP connection to be established. */
static const int kConnectTimeoutSec = 5;

/*! Time for which a connection that the system turns away is attempted
 *  again (see ConnectToPortal). */
static const int kLocalNetworkGraceSec = 12;

/*! Time allowed for a PDU to be sent or received during login and logout. */
static const int kLoginIOTimeoutSec = 15;

/*! Time allowed for a PDU to be sent in the full feature phase. */
static const int kSendTimeoutSec = 30;

/*! A NOP-Out is sent if nothing was received for this long. */
static const int kPingIntervalSec = 5;

/*! The connection is dropped if nothing was received for this long after
 *  a NOP-Out was sent. */
static const int kPingTimeoutSec = 10;

/*! The connection is dropped if a task did not complete in this time. */
static const int kTaskTimeoutSec = 120;

/*! Time a task waits for a session to be recovered before the caller is
 *  told to try again later. */
static const int kRecoveryHoldSec = 5;

/*! Number of times a task is resubmitted after connection failures. */
static const int kTaskMaxRetries = 8;

/*! Largest data segment accepted from a target regardless of negotiation. */
static const UInt32 kMaxDataSegmentLength = 16 * 1024 * 1024;

#define kTaskTableSize 256

enum {
    kBHSSize = 48,

    kOpNOPOut = 0x00,
    kOpSCSICommand = 0x01,
    kOpDataOut = 0x05,

    kOpNOPIn = 0x20,
    kOpSCSIResponse = 0x21,
    kOpTaskMgmtResponse = 0x22,
    kOpDataIn = 0x25,
    kOpR2T = 0x31,
    kOpAsyncMessage = 0x32,
    kOpReject = 0x3f,

    kOpImmediate = 0x40,
    kFlagFinal = 0x80,
    kFlagRead = 0x40,
    kFlagWrite = 0x20,
    kFlagStatus = 0x01,
    kTaskAttributeSimple = 0x01,

    kReservedTag = 0xffffffff
};

struct Session;

/*! A request from the target for a burst of write data. */
struct R2T {
    struct R2T * next;
    UInt32 initiatorTaskTag;
    UInt32 targetTransferTag;
    UInt8 LUN[8];
    UInt32 offset;
    UInt32 length;
};

/*! A NOP-In from the target that must be answered. */
struct NOPReply {
    struct NOPReply * next;
    UInt32 targetTransferTag;
    UInt8 LUN[8];
};

struct Connection {
    ConnectionIdentifier connectionId;
    struct Session * session;
    int fd;

    CFStringRef portalAddress;
    CFStringRef portalPort;
    CFStringRef hostInterface;

    /*! Serializes writes to the socket. */
    pthread_mutex_t sendLock;

    // Negotiated parameters
    bool useHeaderDigest;
    bool useDataDigest;
    bool useIFMarker;
    bool useOFMarker;
    UInt16 IFMarkInt;
    UInt16 OFMarkInt;
    UInt32 maxSendDataSegmentLength;
    UInt32 maxRecvDataSegmentLength;

    // The remaining fields are protected by the session lock
    UInt32 expStatSN;

    /*! The HBA drives the connection (full feature phase). */
    bool active;

    /*! The connection broke and awaits its release. */
    bool failed;

    /*! Set to make the threads of the connection exit. */
    bool stopping;

    bool threadsRunning;
    bool receiveExited;
    pthread_t receiveThread;
    pthread_t transmitThread;
    pthread_cond_t transmitCond;

    /*! Written to in order to wake up the receive thread. */
    int wakePipe[2];

    struct R2T * r2tHead, * r2tTail;
    struct NOPReply * nopHead, * nopTail;

    time_t lastReceiveTime;
    bool pingOutstanding;
    UInt32 pingTaskTag;

    /*! Number of threads that are about to send on the connection, which
     *  keeps it from being destroyed underneath them. */
    int pins;
};

struct Task {
    struct Task * next;
    UInt32 initiatorTaskTag;
    struct Connection * connection;
    enum iSCSIHBADataDirection direction;
    UInt8 * buffer;
    UInt32 length;
    time_t startTime;

    /*! Number of threads that currently use the buffer of the task. */
    int users;

    /*! The task is finished: either the target completed it or it must be
     *  submitted again (requeue). */
    bool done;
    bool requeue;

    /*! Transport-level error (for tasks that are done but not requeued). */
    errno_t error;

    iSCSIHBASCSIResult result;
    pthread_cond_t cond;
};

struct Session {
    SessionIdentifier sessionId;
    struct __iSCSIHBAInterface * interface;
    CFStringRef targetIQN;

    pthread_mutex_t lock;
    pthread_cond_t cond;

    enum iSCSIHBASessionState state;
    struct Connection * connections[kiSCSIMaxConnectionsPerSession];

    /*! Number of threads inside iSCSIHBAInterfaceExecuteSCSI(). */
    int users;

    UInt32 cmdSN;
    UInt32 expCmdSN;
    UInt32 maxCmdSN;

    UInt32 nextTaskTag;
    struct Task * tasks[kTaskTableSize];

    // Negotiated parameters
    UInt16 defaultTime2Retain;
    UInt16 defaultTime2Wait;
    UInt8 errorRecoveryLevel;
    UInt32 maxConnections;
    bool immediateData;
    bool initialR2T;
    bool dataPDUInOrder;
    bool dataSequenceInOrder;
    UInt16 maxOutstandingR2T;
    UInt32 maxBurstLength;
    UInt32 firstBurstLength;
    TargetSessionIdentifier targetSessionId;
    TargetPortalGroupTag targetPortalGroupTag;

    iSCSIHBASessionStatistics statistics;
};

struct Notification {
    struct Notification * next;
    enum iSCSIHBANotificationTypes type;
    iSCSIHBANotificationMessage message;
};

struct __iSCSIHBAInterface {
    CFAllocatorRef allocator;
    iSCSIHBANotificationCallBack callback;
    iSCSIHBANotificationContext notifyContext;

    pthread_mutex_t lock;
    struct Session * sessions[kiSCSIMaxSessions];

    CFRunLoopSourceRef source;
    CFRunLoopRef runLoop;
    struct Notification * notifyHead, * notifyTail;
};

#pragma mark - Helpers

static inline UInt32 Get32(const UInt8 * bytes)
{
    return ((UInt32)bytes[0] << 24) | ((UInt32)bytes[1] << 16) | ((UInt32)bytes[2] << 8) | bytes[3];
}

static inline void Put32(UInt8 * bytes,UInt32 value)
{
    bytes[0] = (UInt8)(value >> 24);
    bytes[1] = (UInt8)(value >> 16);
    bytes[2] = (UInt8)(value >> 8);
    bytes[3] = (UInt8)value;
}

/*! Serial number comparison (RFC 1982): true if a is later than b. */
static inline bool SerialGreater(UInt32 a,UInt32 b)
{
    return (SInt32)(a - b) > 0;
}

static time_t MonotonicSeconds(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC,&now);
    return now.tv_sec;
}

/*! Waits on a condition for at most the given number of milliseconds. */
static void WaitCondition(pthread_cond_t * cond,pthread_mutex_t * mutex,long milliseconds)
{
    struct timespec interval = { milliseconds / 1000, (milliseconds % 1000) * 1000000L };
    pthread_cond_timedwait_relative_np(cond,mutex,&interval);
}

static void SetSocketTimeouts(int fd,int seconds)
{
    struct timeval timeout = { seconds, 0 };
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
}

static errno_t ReadFully(int fd,void * buffer,size_t length)
{
    UInt8 * cursor = buffer;

    while(length > 0) {
        ssize_t count = recv(fd,cursor,length,0);

        if(count == 0)
            return ECONNRESET;

        if(count < 0) {
            if(errno == EINTR)
                continue;
            return (errno == EAGAIN) ? ETIMEDOUT : errno;
        }
        cursor += count;
        length -= (size_t)count;
    }
    return 0;
}

static errno_t WriteFully(int fd,struct iovec * vectors,int count)
{
    while(count > 0) {
        ssize_t written = writev(fd,vectors,count);

        if(written < 0) {
            if(errno == EINTR)
                continue;
            return (errno == EAGAIN) ? ETIMEDOUT : errno;
        }

        while(count > 0 && (size_t)written >= vectors->iov_len) {
            written -= vectors->iov_len;
            vectors++;
            count--;
        }

        if(count > 0) {
            vectors->iov_base = (UInt8 *)vectors->iov_base + written;
            vectors->iov_len -= (size_t)written;
        }
    }
    return 0;
}

/*! Sends a PDU.  The length of the data segment is written to the header;
 *  digests are added as negotiated.  The caller holds the send lock. */
static errno_t ConnectionSendPDU(struct Connection * connection,
                                 UInt8 * bhs,
                                 const void * data,
                                 UInt32 length)
{
    static const UInt8 padding[4] = { 0, 0, 0, 0 };
    struct iovec vectors[5];
    int count = 0;
    UInt32 headerDigest, dataDigest;

    bhs[4] = 0;
    bhs[5] = (UInt8)(length >> 16);
    bhs[6] = (UInt8)(length >> 8);
    bhs[7] = (UInt8)length;

    vectors[count].iov_base = bhs;
    vectors[count].iov_len = kBHSSize;
    count++;

    if(connection->useHeaderDigest) {
        headerDigest = CFSwapInt32HostToLittle(iSCSICRC32C(0,bhs,kBHSSize));
        vectors[count].iov_base = &headerDigest;
        vectors[count].iov_len = sizeof(headerDigest);
        count++;
    }

    if(data && length > 0) {
        UInt32 paddingLength = (4 - (length & 3)) & 3;

        vectors[count].iov_base = (void *)data;
        vectors[count].iov_len = length;
        count++;

        if(paddingLength > 0) {
            vectors[count].iov_base = (void *)padding;
            vectors[count].iov_len = paddingLength;
            count++;
        }

        if(connection->useDataDigest) {
            dataDigest = iSCSICRC32C(0,data,length);
            dataDigest = CFSwapInt32HostToLittle(iSCSICRC32C(dataDigest,padding,paddingLength));
            vectors[count].iov_base = &dataDigest;
            vectors[count].iov_len = sizeof(dataDigest);
            count++;
        }
    }
    return WriteFully(connection->fd,vectors,count);
}

/*! Receives the header of a PDU and verifies the header digest. Additional
 *  header segments are discarded. */
static errno_t ConnectionReceiveHeader(struct Connection * connection,UInt8 * bhs,UInt32 * dataLength)
{
    errno_t error;

    if((error = ReadFully(connection->fd,bhs,kBHSSize)))
        return error;

    UInt32 digest = iSCSICRC32C(0,bhs,kBHSSize);
    UInt32 ahsLength = (UInt32)bhs[4] * 4;

    while(ahsLength > 0) {
        UInt8 scratch[256];
        UInt32 chunk = (ahsLength < sizeof(scratch)) ? ahsLength : sizeof(scratch);

        if((error = ReadFully(connection->fd,scratch,chunk)))
            return error;

        digest = iSCSICRC32C(digest,scratch,chunk);
        ahsLength -= chunk;
    }

    if(connection->useHeaderDigest) {
        UInt32 received;

        if((error = ReadFully(connection->fd,&received,sizeof(received))))
            return error;

        if(CFSwapInt32LittleToHost(received) != digest) {
            iSCSILogError("header digest mismatch (sid %u, cid %u)",
                          connection->session->sessionId,(unsigned)connection->connectionId);
            return EBADMSG;
        }
    }

    *dataLength = ((UInt32)bhs[5] << 16) | ((UInt32)bhs[6] << 8) | bhs[7];

    if(*dataLength > kMaxDataSegmentLength)
        return EMSGSIZE;

    return 0;
}

/*! Receives the data segment of a PDU into a buffer (or discards it if the
 *  buffer is NULL), including padding, and verifies the data digest. */
static errno_t ConnectionReceiveData(struct Connection * connection,void * buffer,UInt32 length)
{
    errno_t error;
    UInt32 digest = 0;
    UInt8 scratch[4096];

    if(length == 0)
        return 0;

    if(buffer) {
        if((error = ReadFully(connection->fd,buffer,length)))
            return error;

        if(connection->useDataDigest)
            digest = iSCSICRC32C(0,buffer,length);
    }
    else {
        UInt32 remaining = length;

        while(remaining > 0) {
            UInt32 chunk = (remaining < sizeof(scratch)) ? remaining : sizeof(scratch);

            if((error = ReadFully(connection->fd,scratch,chunk)))
                return error;

            digest = iSCSICRC32C(digest,scratch,chunk);
            remaining -= chunk;
        }
    }

    UInt32 paddingLength = (4 - (length & 3)) & 3;

    if(paddingLength > 0) {
        if((error = ReadFully(connection->fd,scratch,paddingLength)))
            return error;

        digest = iSCSICRC32C(digest,scratch,paddingLength);
    }

    if(connection->useDataDigest) {
        UInt32 received;

        if((error = ReadFully(connection->fd,&received,sizeof(received))))
            return error;

        if(CFSwapInt32LittleToHost(received) != digest) {
            iSCSILogError("data digest mismatch (sid %u, cid %u)",
                          connection->session->sessionId,(unsigned)connection->connectionId);
            return EBADMSG;
        }
    }
    return 0;
}

#pragma mark - Notifications

static void InterfacePostNotification(iSCSIHBAInterfaceRef interface,
                                      enum iSCSIHBANotificationTypes type,
                                      const iSCSIHBANotificationMessage * message)
{
    struct Notification * notification = calloc(1,sizeof(struct Notification));
    notification->type = type;
    notification->message = *message;
    notification->message.notificationType = (UInt8)type;

    pthread_mutex_lock(&interface->lock);

    if(interface->notifyTail)
        interface->notifyTail->next = notification;
    else
        interface->notifyHead = notification;

    interface->notifyTail = notification;

    CFRunLoopSourceRef source = interface->source;
    CFRunLoopRef runLoop = interface->runLoop;
    pthread_mutex_unlock(&interface->lock);

    if(source && runLoop) {
        CFRunLoopSourceSignal(source);
        CFRunLoopWakeUp(runLoop);
    }
}

/*! Delivers queued notifications on the run loop of the session layer. */
static void InterfaceDeliverNotifications(void * info)
{
    iSCSIHBAInterfaceRef interface = info;

    for(;;) {
        pthread_mutex_lock(&interface->lock);
        struct Notification * notification = interface->notifyHead;

        if(notification && !(interface->notifyHead = notification->next))
            interface->notifyTail = NULL;

        pthread_mutex_unlock(&interface->lock);

        if(!notification)
            return;

        if(interface->callback)
            interface->callback(interface,notification->type,&notification->message,interface->notifyContext.info);

        free(notification);
    }
}

#pragma mark - Sessions and tasks

/*! Looks up a session. The interface lock must not be held. */
static struct Session * InterfaceGetSession(iSCSIHBAInterfaceRef interface,SessionIdentifier sessionId)
{
    if(!interface || sessionId >= kiSCSIMaxSessions)
        return NULL;

    pthread_mutex_lock(&interface->lock);
    struct Session * session = interface->sessions[sessionId];
    pthread_mutex_unlock(&interface->lock);
    return session;
}

/*! Looks up a session and locks it.  Unlike a session obtained with
 *  InterfaceGetSession(), which may only be used by the thread that also
 *  manages the life of the session, the session cannot be released by
 *  another thread before its lock is given up again. */
static struct Session * InterfaceLockSession(iSCSIHBAInterfaceRef interface,SessionIdentifier sessionId)
{
    if(!interface || sessionId >= kiSCSIMaxSessions)
        return NULL;

    pthread_mutex_lock(&interface->lock);
    struct Session * session = interface->sessions[sessionId];

    if(session)
        pthread_mutex_lock(&session->lock);

    pthread_mutex_unlock(&interface->lock);
    return session;
}

static struct Connection * SessionGetConnection(struct Session * session,ConnectionIdentifier connectionId)
{
    if(!session || connectionId >= kiSCSIMaxConnectionsPerSession)
        return NULL;

    return session->connections[connectionId];
}

/*! Gets an active connection of a session (session lock held). */
static struct Connection * SessionGetActiveConnection(struct Session * session)
{
    for(UInt32 index = 0; index < kiSCSIMaxConnectionsPerSession; index++) {
        struct Connection * connection = session->connections[index];

        if(connection && connection->active && !connection->failed)
            return connection;
    }
    return NULL;
}

static struct Task * SessionFindTask(struct Session * session,UInt32 initiatorTaskTag)
{
    struct Task * task = session->tasks[initiatorTaskTag % kTaskTableSize];

    while(task && task->initiatorTaskTag != initiatorTaskTag)
        task = task->next;

    return task;
}

static void SessionRemoveTask(struct Session * session,struct Task * task)
{
    struct Task ** link = &session->tasks[task->initiatorTaskTag % kTaskTableSize];

    while(*link && *link != task)
        link = &(*link)->next;

    if(*link)
        *link = task->next;

    task->next = NULL;
}

/*! Allocates an initiator task tag (session lock held). */
static UInt32 SessionAllocateTaskTag(struct Session * session)
{
    for(;;) {
        UInt32 tag = session->nextTaskTag++;

        if(tag != kReservedTag && !SessionFindTask(session,tag))
            return tag;
    }
}

/*! Finishes a task and wakes up its owner (session lock held). */
static void SessionFinishTask(struct Session * session,struct Task * task,bool requeue,errno_t error)
{
    SessionRemoveTask(session,task);
    task->requeue = requeue;
    task->error = error;
    task->done = true;
    pthread_cond_broadcast(&task->cond);
}

/*! Finishes all tasks of a session, or only those of one connection if a
 *  connection is specified (session lock held). */
static void SessionFinishAllTasks(struct Session * session,
                                  struct Connection * connection,
                                  bool requeue,
                                  errno_t error)
{
    for(unsigned int bucket = 0; bucket < kTaskTableSize; bucket++) {
        struct Task * task = session->tasks[bucket];

        while(task) {
            struct Task * next = task->next;

            if(!connection || task->connection == connection)
                SessionFinishTask(session,task,requeue,error);

            task = next;
        }
    }
}

/*! Updates the command window from the fields of a target PDU (session
 *  lock held). */
static void SessionUpdateCommandWindow(struct Session * session,UInt32 expCmdSN,UInt32 maxCmdSN)
{
    // Per RFC 7143 both values are ignored if MaxCmdSN is less than ExpCmdSN - 1
    if((SInt32)(maxCmdSN - expCmdSN + 1) < 0)
        return;

    bool changed = false;

    if(SerialGreater(maxCmdSN,session->maxCmdSN)) {
        session->maxCmdSN = maxCmdSN;
        changed = true;
    }

    if(SerialGreater(expCmdSN,session->expCmdSN))
        session->expCmdSN = expCmdSN;

    if(changed)
        pthread_cond_broadcast(&session->cond);
}

/*! Called when a connection breaks.  Tasks are held back until the session
 *  layer has re-established the session.  May be called from any thread
 *  without locks held. */
static void ConnectionFail(struct Connection * connection,errno_t reason)
{
    struct Session * session = connection->session;

    pthread_mutex_lock(&session->lock);

    if(connection->failed || !connection->active) {
        pthread_mutex_unlock(&session->lock);
        return;
    }

    connection->failed = true;
    connection->stopping = true;

    // Wakes up any thread that is blocked on the socket
    shutdown(connection->fd,SHUT_RDWR);
    pthread_cond_broadcast(&connection->transmitCond);

    SessionFinishAllTasks(session,connection,true,0);

    if(session->state == kiSCSIHBASessionStateActive && !SessionGetActiveConnection(session))
        session->state = kiSCSIHBASessionStateRecovering;

    bool notify = (session->state != kiSCSIHBASessionStateClosing);
    pthread_cond_broadcast(&session->cond);
    pthread_mutex_unlock(&session->lock);

    iSCSILogWarning("connection lost (sid %u, cid %u): %s",session->sessionId,
                    (unsigned)connection->connectionId,strerror(reason));

    if(notify) {
        iSCSIHBANotificationMessage message;
        memset(&message,0,sizeof(message));
        message.sessionId = session->sessionId;
        message.connectionId = connection->connectionId;
        message.parameter1 = (UInt64)reason;
        InterfacePostNotification(session->interface,kiSCSIHBANotificationTimeout,&message);
    }
}

#pragma mark - Receive thread

/*! Processes the sequence numbers that are common to target PDUs (session
 *  lock held). */
static void ConnectionUpdateSequenceNumbers(struct Connection * connection,const UInt8 * bhs,bool advancesStatSN)
{
    if(advancesStatSN) {
        UInt32 statSN = Get32(bhs + 24);

        if(!SerialGreater(connection->expStatSN,statSN + 1))
            connection->expStatSN = statSN + 1;
    }
    SessionUpdateCommandWindow(connection->session,Get32(bhs + 28),Get32(bhs + 32));
}

static errno_t ConnectionProcessDataIn(struct Connection * connection,const UInt8 * bhs,UInt32 dataLength)
{
    struct Session * session = connection->session;
    UInt32 offset = Get32(bhs + 40);
    bool hasStatus = (bhs[1] & kFlagStatus) != 0;
    UInt8 * destination = NULL;

    pthread_mutex_lock(&session->lock);
    struct Task * task = SessionFindTask(session,Get32(bhs + 16));

    if(task && task->direction == kiSCSIHBADataRead &&
       offset <= task->length && dataLength <= task->length - offset) {
        destination = task->buffer + offset;
        task->users++;
    }
    else if(task) {
        iSCSILogError("Data-In outside of the buffer of a task (sid %u)",session->sessionId);
        task = NULL;
    }
    pthread_mutex_unlock(&session->lock);

    // The data is received straight into the buffer of the task
    errno_t error = ConnectionReceiveData(connection,destination,dataLength);

    pthread_mutex_lock(&session->lock);

    if(task) {
        task->users--;

        // The task may have been finished by another thread in the meantime
        if(!error && !task->done) {
            if(offset + dataLength > task->result.transferred)
                task->result.transferred = offset + dataLength;

            if(hasStatus) {
                task->result.status = bhs[3];
                session->statistics.bytesRead += task->result.transferred;
                session->statistics.tasksCompleted++;
                SessionFinishTask(session,task,false,0);
            }
        }
        pthread_cond_broadcast(&task->cond);
    }

    if(!error)
        ConnectionUpdateSequenceNumbers(connection,bhs,hasStatus);

    pthread_mutex_unlock(&session->lock);
    return error;
}

static void ConnectionProcessSCSIResponse(struct Connection * connection,
                                          const UInt8 * bhs,
                                          const UInt8 * data,
                                          UInt32 dataLength)
{
    struct Session * session = connection->session;

    pthread_mutex_lock(&session->lock);
    struct Task * task = SessionFindTask(session,Get32(bhs + 16));

    if(task) {
        // A response other than "command completed at target" means that
        // the target could not deliver the command to the logical unit
        if(bhs[2] != 0x00)
            SessionFinishTask(session,task,false,EIO);
        else {
            task->result.status = bhs[3];

            if(dataLength >= 2) {
                UInt32 senseLength = ((UInt32)data[0] << 8) | data[1];

                if(senseLength > dataLength - 2)
                    senseLength = dataLength - 2;

                if(senseLength > sizeof(task->result.sense))
                    senseLength = sizeof(task->result.sense);

                memcpy(task->result.sense,data + 2,senseLength);
                task->result.senseLength = (UInt16)senseLength;
            }

            // For writes the amount transferred follows from the residual
            if(task->direction == kiSCSIHBADataWrite) {
                UInt32 residual = (bhs[1] & 0x02) ? Get32(bhs + 44) : 0;
                task->result.transferred = (residual < task->length) ? task->length - residual : 0;
                session->statistics.bytesWritten += task->result.transferred;
            }
            else
                session->statistics.bytesRead += task->result.transferred;

            session->statistics.tasksCompleted++;
            SessionFinishTask(session,task,false,0);
        }
    }

    ConnectionUpdateSequenceNumbers(connection,bhs,true);
    pthread_mutex_unlock(&session->lock);
}

static void ConnectionProcessR2T(struct Connection * connection,const UInt8 * bhs)
{
    struct Session * session = connection->session;
    struct R2T * r2t = calloc(1,sizeof(struct R2T));

    r2t->initiatorTaskTag = Get32(bhs + 16);
    r2t->targetTransferTag = Get32(bhs + 20);
    memcpy(r2t->LUN,bhs + 8,8);
    r2t->offset = Get32(bhs + 40);
    r2t->length = Get32(bhs + 44);

    pthread_mutex_lock(&session->lock);

    if(connection->r2tTail)
        connection->r2tTail->next = r2t;
    else
        connection->r2tHead = r2t;

    connection->r2tTail = r2t;

    ConnectionUpdateSequenceNumbers(connection,bhs,false);
    pthread_cond_broadcast(&connection->transmitCond);
    pthread_mutex_unlock(&session->lock);
}

static void ConnectionProcessNOPIn(struct Connection * connection,const UInt8 * bhs)
{
    struct Session * session = connection->session;
    UInt32 initiatorTaskTag = Get32(bhs + 16);
    UInt32 targetTransferTag = Get32(bhs + 20);

    pthread_mutex_lock(&session->lock);

    // A NOP-In with a valid target transfer tag is a ping from the target
    if(targetTransferTag != kReservedTag) {
        struct NOPReply * reply = calloc(1,sizeof(struct NOPReply));
        reply->targetTransferTag = targetTransferTag;
        memcpy(reply->LUN,bhs + 8,8);

        if(connection->nopTail)
            connection->nopTail->next = reply;
        else
            connection->nopHead = reply;

        connection->nopTail = reply;
        pthread_cond_broadcast(&connection->transmitCond);
    }

    ConnectionUpdateSequenceNumbers(connection,bhs,initiatorTaskTag != kReservedTag);
    pthread_mutex_unlock(&session->lock);
}

/*! Returns an error if the event requires the connection to be dropped. */
static errno_t ConnectionProcessAsyncMessage(struct Connection * connection,const UInt8 * bhs)
{
    struct Session * session = connection->session;
    UInt8 event = bhs[36];

    pthread_mutex_lock(&session->lock);
    ConnectionUpdateSequenceNumbers(connection,bhs,true);
    pthread_mutex_unlock(&session->lock);

    iSCSILogInfo("asynchronous message, event %u (sid %u, cid %u)",event,
                 session->sessionId,(unsigned)connection->connectionId);

    switch(event) {
        // SCSI asynchronous event (e.g., a change of the logical units)
        case kiSCSIPDUAsyncMsgSCSIAsyncMsg: {
            iSCSIHBANotificationAsyncMessage message;
            memset(&message,0,sizeof(message));
            message.asyncEvent = event;
            memcpy(&message.LUN,bhs + 8,8);
            message.LUN = CFSwapInt64BigToHost(message.LUN);
            message.sessionId = session->sessionId;
            message.connectionId = connection->connectionId;
            InterfacePostNotification(session->interface,kiSCSIHBANotificationAsyncMessage,
                                      (iSCSIHBANotificationMessage *)&message);
            return 0;
        }
        // The target asks for a logout, announces that it is going to drop
        // connections or wants to renegotiate parameters.  In each case the
        // session is re-established from scratch, which achieves the same.
        case kiSCSIPDUAsyncMsgLogout:
        case kiSCSIPDUAsynMsgDropConnection:
        case kiSCSIPDUAsyncMsgDropAllConnections:
        case kiSCSIPDUAsyncMsgNegotiateParams:
            return ECONNRESET;
        default:
            return 0;
    }
}

static void ConnectionProcessReject(struct Connection * connection,
                                    const UInt8 * bhs,
                                    const UInt8 * data,
                                    UInt32 dataLength)
{
    struct Session * session = connection->session;

    iSCSILogError("target rejected a PDU, reason %#x (sid %u, cid %u)",bhs[2],
                  session->sessionId,(unsigned)connection->connectionId);

    pthread_mutex_lock(&session->lock);

    // The data segment holds the header of the PDU that was rejected
    if(dataLength >= kBHSSize) {
        UInt8 opCode = data[0] & 0x3f;
        struct Task * task = SessionFindTask(session,Get32(data + 16));

        if(task && (opCode == kOpSCSICommand || opCode == kOpDataOut))
            SessionFinishTask(session,task,false,EIO);
    }

    ConnectionUpdateSequenceNumbers(connection,bhs,true);
    pthread_mutex_unlock(&session->lock);
}

static void * ConnectionReceiveMain(void * context)
{
    struct Connection * connection = context;
    struct Session * session = connection->session;
    errno_t error = 0;

    pthread_setname_np("iscsid.receive");

    for(;;) {
        struct pollfd fds[2] = {
            { .fd = connection->fd, .events = POLLIN },
            { .fd = connection->wakePipe[0], .events = POLLIN }
        };

        // Wait at a PDU boundary so that the connection can be handed back
        // to the session layer without losing the framing
        if(poll(fds,2,-1) < 0) {
            if(errno == EINTR)
                continue;

            error = errno ? errno : EIO;
            break;
        }

        pthread_mutex_lock(&session->lock);
        bool stopping = connection->stopping;
        pthread_mutex_unlock(&session->lock);

        if(stopping) {
            error = 0;
            break;
        }

        if(!(fds[0].revents & (POLLIN | POLLHUP | POLLERR)))
            continue;

        UInt8 bhs[kBHSSize];
        UInt32 dataLength = 0;

        if((error = ConnectionReceiveHeader(connection,bhs,&dataLength)))
            break;

        UInt8 opCode = bhs[0] & 0x3f;

        if(opCode == kOpDataIn)
            error = ConnectionProcessDataIn(connection,bhs,dataLength);
        else {
            UInt8 * data = NULL;

            if(dataLength > 0 && !(data = malloc(dataLength))) {
                error = ENOMEM;
                break;
            }

            if(!(error = ConnectionReceiveData(connection,data,dataLength))) {
                switch(opCode) {
                    case kOpSCSIResponse:
                        ConnectionProcessSCSIResponse(connection,bhs,data,dataLength); break;
                    case kOpR2T:
                        ConnectionProcessR2T(connection,bhs); break;
                    case kOpNOPIn:
                        ConnectionProcessNOPIn(connection,bhs); break;
                    case kOpAsyncMessage:
                        error = ConnectionProcessAsyncMessage(connection,bhs); break;
                    case kOpReject:
                        ConnectionProcessReject(connection,bhs,data,dataLength); break;
                    default:
                        // Other PDUs (e.g., task management responses) carry
                        // nothing of interest besides the sequence numbers
                        pthread_mutex_lock(&session->lock);
                        ConnectionUpdateSequenceNumbers(connection,bhs,true);
                        pthread_mutex_unlock(&session->lock);
                        break;
                }
            }
            free(data);
        }

        if(error)
            break;

        // Any PDU proves that the connection is alive
        pthread_mutex_lock(&session->lock);
        connection->lastReceiveTime = MonotonicSeconds();
        connection->pingOutstanding = false;
        pthread_mutex_unlock(&session->lock);
    }

    if(error)
        ConnectionFail(connection,error);

    pthread_mutex_lock(&session->lock);
    connection->receiveExited = true;
    pthread_cond_broadcast(&connection->transmitCond);
    pthread_mutex_unlock(&session->lock);
    return NULL;
}

#pragma mark - Transmit thread

/*! Sends the Data-Out PDUs for a range of the data of a task. The send lock
 *  is held by the caller. */
static errno_t ConnectionSendDataOut(struct Connection * connection,
                                     UInt32 initiatorTaskTag,
                                     UInt32 targetTransferTag,
                                     const UInt8 * LUN,
                                     const UInt8 * buffer,
                                     UInt32 offset,
                                     UInt32 length,
                                     UInt32 expStatSN)
{
    UInt32 dataSN = 0;
    UInt32 maxLength = connection->maxSendDataSegmentLength;

    while(length > 0) {
        UInt32 chunk = (length < maxLength) ? length : maxLength;
        UInt8 bhs[kBHSSize];
        memset(bhs,0,sizeof(bhs));

        bhs[0] = kOpDataOut;
        bhs[1] = (chunk == length) ? kFlagFinal : 0;
        memcpy(bhs + 8,LUN,8);
        Put32(bhs + 16,initiatorTaskTag);
        Put32(bhs + 20,targetTransferTag);
        Put32(bhs + 28,expStatSN);
        Put32(bhs + 36,dataSN++);
        Put32(bhs + 40,offset);

        errno_t error = ConnectionSendPDU(connection,bhs,buffer + offset,chunk);

        if(error)
            return error;

        offset += chunk;
        length -= chunk;
    }
    return 0;
}

static errno_t ConnectionAnswerR2T(struct Connection * connection,struct R2T * r2t)
{
    struct Session * session = connection->session;
    errno_t error = 0;

    pthread_mutex_lock(&connection->sendLock);
    pthread_mutex_lock(&session->lock);

    struct Task * task = SessionFindTask(session,r2t->initiatorTaskTag);
    UInt32 expStatSN = connection->expStatSN;

    if(task && (task->direction != kiSCSIHBADataWrite || r2t->offset > task->length ||
                r2t->length > task->length - r2t->offset || r2t->length == 0)) {
        iSCSILogError("invalid R2T (sid %u)",session->sessionId);
        SessionFinishTask(session,task,false,EIO);
        task = NULL;
    }

    if(task)
        task->users++;

    pthread_mutex_unlock(&session->lock);

    if(task) {
        error = ConnectionSendDataOut(connection,r2t->initiatorTaskTag,r2t->targetTransferTag,
                                      r2t->LUN,task->buffer,r2t->offset,r2t->length,expStatSN);

        pthread_mutex_lock(&session->lock);
        task->users--;
        pthread_cond_broadcast(&task->cond);
        pthread_mutex_unlock(&session->lock);
    }

    pthread_mutex_unlock(&connection->sendLock);
    return error;
}

/*! Sends a NOP-Out, either as a reply to a NOP-In of the target or as a ping. */
static errno_t ConnectionSendNOPOut(struct Connection * connection,
                                    UInt32 initiatorTaskTag,
                                    UInt32 targetTransferTag,
                                    const UInt8 * LUN)
{
    struct Session * session = connection->session;
    UInt8 bhs[kBHSSize];
    memset(bhs,0,sizeof(bhs));

    bhs[0] = kOpNOPOut | kOpImmediate;
    bhs[1] = kFlagFinal;

    if(LUN)
        memcpy(bhs + 8,LUN,8);

    Put32(bhs + 16,initiatorTaskTag);
    Put32(bhs + 20,targetTransferTag);

    pthread_mutex_lock(&connection->sendLock);
    pthread_mutex_lock(&session->lock);
    Put32(bhs + 24,session->cmdSN);
    Put32(bhs + 28,connection->expStatSN);
    pthread_mutex_unlock(&session->lock);

    errno_t error = ConnectionSendPDU(connection,bhs,NULL,0);
    pthread_mutex_unlock(&connection->sendLock);
    return error;
}

static void * ConnectionTransmitMain(void * context)
{
    struct Connection * connection = context;
    struct Session * session = connection->session;
    errno_t error = 0;

    pthread_setname_np("iscsid.transmit");
    pthread_mutex_lock(&session->lock);

    while(!connection->stopping && !error) {
        struct R2T * r2t = connection->r2tHead;
        struct NOPReply * reply = connection->nopHead;

        if(r2t) {
            if(!(connection->r2tHead = r2t->next))
                connection->r2tTail = NULL;

            pthread_mutex_unlock(&session->lock);
            error = ConnectionAnswerR2T(connection,r2t);
            free(r2t);
            pthread_mutex_lock(&session->lock);
            continue;
        }

        if(reply) {
            if(!(connection->nopHead = reply->next))
                connection->nopTail = NULL;

            pthread_mutex_unlock(&session->lock);
            error = ConnectionSendNOPOut(connection,kReservedTag,reply->targetTransferTag,reply->LUN);
            free(reply);
            pthread_mutex_lock(&session->lock);
            continue;
        }

        // Check on the health of the connection
        time_t now = MonotonicSeconds();
        time_t idle = now - connection->lastReceiveTime;

        if(connection->pingOutstanding && idle >= kPingIntervalSec + kPingTimeoutSec) {
            error = ETIMEDOUT;
            break;
        }

        for(unsigned int bucket = 0; bucket < kTaskTableSize && !error; bucket++) {
            for(struct Task * task = session->tasks[bucket]; task; task = task->next) {
                if(task->connection == connection && now - task->startTime >= kTaskTimeoutSec) {
                    iSCSILogError("task timed out (sid %u)",session->sessionId);
                    error = ETIMEDOUT;
                    break;
                }
            }
        }

        if(error)
            break;

        if(!connection->pingOutstanding && idle >= kPingIntervalSec) {
            connection->pingOutstanding = true;
            connection->pingTaskTag = SessionAllocateTaskTag(session);
            UInt32 tag = connection->pingTaskTag;

            pthread_mutex_unlock(&session->lock);
            error = ConnectionSendNOPOut(connection,tag,kReservedTag,NULL);
            pthread_mutex_lock(&session->lock);
            continue;
        }

        WaitCondition(&connection->transmitCond,&session->lock,1000);
    }

    bool stopping = connection->stopping;
    pthread_mutex_unlock(&session->lock);

    if(error && !stopping)
        ConnectionFail(connection,error);

    return NULL;
}

#pragma mark - Connection management

/*! Stops the threads of a connection (if any).  The socket is left intact
 *  unless the connection failed. */
static void ConnectionStopThreads(struct Connection * connection)
{
    struct Session * session = connection->session;

    pthread_mutex_lock(&session->lock);
    bool running = connection->threadsRunning;
    connection->threadsRunning = false;
    connection->stopping = true;
    connection->active = false;
    pthread_cond_broadcast(&connection->transmitCond);
    pthread_mutex_unlock(&session->lock);

    if(!running)
        return;

    char byte = 0;
    (void)write(connection->wakePipe[1],&byte,1);

    // The receive thread stops at the next PDU boundary.  If the target
    // stalls in the middle of a PDU the socket has to be shut down.
    pthread_mutex_lock(&session->lock);
    time_t deadline = MonotonicSeconds() + 5;

    while(!connection->receiveExited && MonotonicSeconds() < deadline)
        WaitCondition(&connection->transmitCond,&session->lock,200);

    if(!connection->receiveExited) {
        connection->failed = true;
        shutdown(connection->fd,SHUT_RDWR);
    }
    pthread_mutex_unlock(&session->lock);

    pthread_join(connection->receiveThread,NULL);
    pthread_join(connection->transmitThread,NULL);

    close(connection->wakePipe[0]);
    close(connection->wakePipe[1]);
    connection->wakePipe[0] = connection->wakePipe[1] = -1;

    pthread_mutex_lock(&session->lock);

    while(connection->r2tHead) {
        struct R2T * r2t = connection->r2tHead;
        connection->r2tHead = r2t->next;
        free(r2t);
    }
    connection->r2tTail = NULL;

    while(connection->nopHead) {
        struct NOPReply * reply = connection->nopHead;
        connection->nopHead = reply->next;
        free(reply);
    }
    connection->nopTail = NULL;
    pthread_mutex_unlock(&session->lock);
}

static void ConnectionDestroy(struct Connection * connection)
{
    struct Session * session = connection->session;

    ConnectionStopThreads(connection);

    // Wait for threads that were about to submit a task on the connection
    pthread_mutex_lock(&session->lock);
    while(connection->pins > 0)
        pthread_cond_wait(&session->cond,&session->lock);
    pthread_mutex_unlock(&session->lock);

    if(connection->fd >= 0)
        close(connection->fd);

    if(connection->portalAddress)
        CFRelease(connection->portalAddress);

    if(connection->portalPort)
        CFRelease(connection->portalPort);

    if(connection->hostInterface)
        CFRelease(connection->hostInterface);

    pthread_mutex_destroy(&connection->sendLock);
    pthread_cond_destroy(&connection->transmitCond);
    free(connection);
}

/*! Makes one attempt to open a TCP connection to a portal. */
static errno_t ConnectToPortalOnce(const struct sockaddr_storage * remoteAddress,
                                   const struct sockaddr_storage * localAddress,
                                   int * fdOut)
{
    int fd = socket(remoteAddress->ss_family,SOCK_STREAM,IPPROTO_TCP);

    if(fd < 0)
        return errno;

    int enable = 1;
    setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&enable,sizeof(enable));
    setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&enable,sizeof(enable));
    setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&enable,sizeof(enable));

    // Bind to the address of a particular interface if one was specified
    bool bindRequired = false;

    if(localAddress->ss_family == AF_INET)
        bindRequired = ((const struct sockaddr_in *)localAddress)->sin_addr.s_addr != htonl(INADDR_ANY);
    else if(localAddress->ss_family == AF_INET6)
        bindRequired = !IN6_IS_ADDR_UNSPECIFIED(&((const struct sockaddr_in6 *)localAddress)->sin6_addr);

    if(bindRequired) {
        struct sockaddr_storage address = *localAddress;

        if(address.ss_family == AF_INET) {
            ((struct sockaddr_in *)&address)->sin_port = 0;
            address.ss_len = sizeof(struct sockaddr_in);
        }
        else {
            ((struct sockaddr_in6 *)&address)->sin6_port = 0;
            address.ss_len = sizeof(struct sockaddr_in6);
        }

        if(bind(fd,(const struct sockaddr *)&address,address.ss_len) != 0) {
            errno_t error = errno;
            close(fd);
            return error;
        }
    }

    socklen_t addressLength = (remoteAddress->ss_family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                                                    : sizeof(struct sockaddr_in);

    // Connect without blocking so that the attempt can be timed out
    int flags = fcntl(fd,F_GETFL,0);
    fcntl(fd,F_SETFL,flags | O_NONBLOCK);

    errno_t error = 0;

    if(connect(fd,(const struct sockaddr *)remoteAddress,addressLength) != 0) {
        if(errno != EINPROGRESS)
            error = errno;
        else {
            struct pollfd pollFd = { .fd = fd, .events = POLLOUT };
            int ready;

            do {
                ready = poll(&pollFd,1,kConnectTimeoutSec * 1000);
            } while(ready < 0 && errno == EINTR);

            if(ready == 0)
                error = ETIMEDOUT;
            else if(ready < 0)
                error = errno;
            else {
                socklen_t errorLength = sizeof(error);
                getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&errorLength);
            }
        }
    }

    if(error) {
        close(fd);
        return error;
    }

    fcntl(fd,F_SETFL,flags);
    SetSocketTimeouts(fd,kLoginIOTimeoutSec);

    *fdOut = fd;
    return 0;
}

/*! Opens a TCP connection to a portal.
 *
 *  macOS lets a program reach the local network only with the consent of the
 *  user.  Until that is given, and each time that it meets an executable it
 *  has not seen before, it turns the connection away at once (the host is
 *  said to be unreachable) while it looks into the matter, or asks.  The
 *  attempt that set this off is lost, so an attempt that is turned away is
 *  repeated for a while: long enough for the system to make up its mind and
 *  for the user to answer the question. */
static errno_t ConnectToPortal(const struct sockaddr_storage * remoteAddress,
                               const struct sockaddr_storage * localAddress,
                               int * fdOut)
{
    const time_t deadline = MonotonicSeconds() + kLocalNetworkGraceSec;
    errno_t error;

    for(;;) {
        const time_t started = MonotonicSeconds();
        error = ConnectToPortalOnce(remoteAddress,localAddress,fdOut);

        // A host that is truly out of reach takes its time to say so
        if(error != EHOSTUNREACH || MonotonicSeconds() - started > 1 || MonotonicSeconds() >= deadline)
            break;

        usleep(500 * 1000);
    }
    return error;
}

/*! Creates a connection for a session (the session lock is not held). */
static errno_t SessionCreateConnection(struct Session * session,
                                       CFStringRef portalAddress,
                                       CFStringRef portalPort,
                                       CFStringRef hostInterface,
                                       const struct sockaddr_storage * remoteAddress,
                                       const struct sockaddr_storage * localAddress,
                                       ConnectionIdentifier * connectionId)
{
    *connectionId = kiSCSIInvalidConnectionId;

    int fd = -1;
    errno_t error = ConnectToPortal(remoteAddress,localAddress,&fd);

    if(error)
        return error;

    struct Connection * connection = calloc(1,sizeof(struct Connection));
    connection->session = session;
    connection->fd = fd;
    connection->wakePipe[0] = connection->wakePipe[1] = -1;
    connection->portalAddress = CFStringCreateCopy(kCFAllocatorDefault,portalAddress);
    connection->portalPort = CFStringCreateCopy(kCFAllocatorDefault,portalPort);
    connection->hostInterface = CFStringCreateCopy(kCFAllocatorDefault,hostInterface);
    connection->maxSendDataSegmentLength = kRFC3720_MaxRecvDataSegmentLength;
    connection->maxRecvDataSegmentLength = kRFC3720_MaxRecvDataSegmentLength;
    pthread_mutex_init(&connection->sendLock,NULL);
    pthread_cond_init(&connection->transmitCond,NULL);

    pthread_mutex_lock(&session->lock);

    ConnectionIdentifier index;
    for(index = 0; index < kiSCSIMaxConnectionsPerSession; index++)
        if(!session->connections[index])
            break;

    if(index < kiSCSIMaxConnectionsPerSession) {
        connection->connectionId = index;
        session->connections[index] = connection;
    }
    pthread_mutex_unlock(&session->lock);

    if(index == kiSCSIMaxConnectionsPerSession) {
        ConnectionDestroy(connection);
        return EAGAIN;
    }

    *connectionId = index;
    return 0;
}

#pragma mark - Public interface: life cycle

iSCSIHBAInterfaceRef iSCSIHBAInterfaceCreate(CFAllocatorRef allocator,
                                             iSCSIHBANotificationCallBack callback,
                                             iSCSIHBANotificationContext * context)
{
    iSCSIHBAInterfaceRef interface = calloc(1,sizeof(struct __iSCSIHBAInterface));

    if(!interface)
        return NULL;

    interface->allocator = allocator;
    interface->callback = callback;

    if(context)
        interface->notifyContext = *context;

    pthread_mutex_init(&interface->lock,NULL);

    CFRunLoopSourceContext sourceContext;
    memset(&sourceContext,0,sizeof(sourceContext));
    sourceContext.info = interface;
    sourceContext.perform = InterfaceDeliverNotifications;
    interface->source = CFRunLoopSourceCreate(kCFAllocatorDefault,0,&sourceContext);

    return interface;
}

void iSCSIHBAInterfaceRelease(iSCSIHBAInterfaceRef interface)
{
    if(!interface)
        return;

    for(SessionIdentifier sessionId = 0; sessionId < kiSCSIMaxSessions; sessionId++)
        iSCSIHBAInterfaceReleaseSession(interface,sessionId);

    CFRunLoopSourceInvalidate(interface->source);
    CFRelease(interface->source);

    while(interface->notifyHead) {
        struct Notification * notification = interface->notifyHead;
        interface->notifyHead = notification->next;
        free(notification);
    }

    pthread_mutex_destroy(&interface->lock);
    free(interface);
}

void iSCSIHBAInterfaceScheduleWithRunloop(iSCSIHBAInterfaceRef interface,
                                          CFRunLoopRef runLoop,
                                          CFStringRef runLoopMode)
{
    pthread_mutex_lock(&interface->lock);
    interface->runLoop = runLoop;
    pthread_mutex_unlock(&interface->lock);

    CFRunLoopAddSource(runLoop,interface->source,runLoopMode);
    CFRunLoopSourceSignal(interface->source);
}

void iSCSIHBAInterfaceUnscheduleWithRunloop(iSCSIHBAInterfaceRef interface,
                                            CFRunLoopRef runLoop,
                                            CFStringRef runLoopMode)
{
    CFRunLoopRemoveSource(runLoop,interface->source,runLoopMode);

    pthread_mutex_lock(&interface->lock);
    interface->runLoop = NULL;
    pthread_mutex_unlock(&interface->lock);
}

#pragma mark - Public interface: sessions and connections

IOReturn iSCSIHBAInterfaceCreateSession(iSCSIHBAInterfaceRef interface,
                                        CFStringRef targetIQN,
                                        CFStringRef portalAddress,
                                        CFStringRef portalPort,
                                        CFStringRef hostInterface,
                                        const struct sockaddr_storage * remoteAddress,
                                        const struct sockaddr_storage * localAddress,
                                        SessionIdentifier * sessionId,
                                        ConnectionIdentifier * connectionId)
{
    if(!interface || !targetIQN || !portalAddress || !portalPort || !hostInterface ||
       !remoteAddress || !localAddress || !sessionId || !connectionId)
        return EINVAL;

    *sessionId = kiSCSIInvalidSessionId;
    *connectionId = kiSCSIInvalidConnectionId;

    struct Session * session = calloc(1,sizeof(struct Session));
    session->interface = interface;
    session->targetIQN = CFStringCreateCopy(kCFAllocatorDefault,targetIQN);
    session->state = kiSCSIHBASessionStateLogin;
    pthread_mutex_init(&session->lock,NULL);
    pthread_cond_init(&session->cond,NULL);

    session->dataPDUInOrder = kRFC3720_DataPDUInOrder;
    session->dataSequenceInOrder = kRFC3720_DataSequenceInOrder;
    session->defaultTime2Retain = kRFC3720_DefaultTime2Retain;
    session->defaultTime2Wait = kRFC3720_DefaultTime2Wait;
    session->errorRecoveryLevel = kRFC3720_ErrorRecoveryLevel;
    session->firstBurstLength = kRFC3720_FirstBurstLength;
    session->immediateData = kRFC3720_ImmediateData;
    session->initialR2T = kRFC3720_InitialR2T;
    session->maxBurstLength = kRFC3720_MaxBurstLength;
    session->maxConnections = kRFC3720_MaxConnections;
    session->maxOutstandingR2T = kRFC3720_MaxOutstandingR2T;
    session->nextTaskTag = 1;

    // Find a free session slot
    pthread_mutex_lock(&interface->lock);

    SessionIdentifier index;
    for(index = 0; index < kiSCSIMaxSessions; index++)
        if(!interface->sessions[index])
            break;

    if(index < kiSCSIMaxSessions) {
        session->sessionId = index;
        interface->sessions[index] = session;
    }
    pthread_mutex_unlock(&interface->lock);

    errno_t error = EAGAIN;

    if(index < kiSCSIMaxSessions)
        error = SessionCreateConnection(session,portalAddress,portalPort,hostInterface,
                                        remoteAddress,localAddress,connectionId);
    if(error) {
        if(index < kiSCSIMaxSessions) {
            pthread_mutex_lock(&interface->lock);
            interface->sessions[index] = NULL;
            pthread_mutex_unlock(&interface->lock);
        }

        CFRelease(session->targetIQN);
        pthread_mutex_destroy(&session->lock);
        pthread_cond_destroy(&session->cond);
        free(session);
        return error;
    }

    *sessionId = index;
    return 0;
}

IOReturn iSCSIHBAInterfaceReleaseSession(iSCSIHBAInterfaceRef interface,
                                         SessionIdentifier sessionId)
{
    if(!interface || sessionId >= kiSCSIMaxSessions)
        return EINVAL;

    // Make the session unreachable for new tasks
    pthread_mutex_lock(&interface->lock);
    struct Session * session = interface->sessions[sessionId];
    interface->sessions[sessionId] = NULL;
    pthread_mutex_unlock(&interface->lock);

    if(!session)
        return ENOENT;

    pthread_mutex_lock(&session->lock);
    session->state = kiSCSIHBASessionStateClosing;
    SessionFinishAllTasks(session,NULL,false,ENXIO);
    pthread_cond_broadcast(&session->cond);
    pthread_mutex_unlock(&session->lock);

    for(UInt32 index = 0; index < kiSCSIMaxConnectionsPerSession; index++) {
        if(session->connections[index]) {
            ConnectionDestroy(session->connections[index]);
            session->connections[index] = NULL;
        }
    }

    // Wait for the threads that were executing tasks to leave
    pthread_mutex_lock(&session->lock);
    while(session->users > 0)
        pthread_cond_wait(&session->cond,&session->lock);
    pthread_mutex_unlock(&session->lock);

    CFRelease(session->targetIQN);
    pthread_mutex_destroy(&session->lock);
    pthread_cond_destroy(&session->cond);
    free(session);
    return 0;
}

IOReturn iSCSIHBAInterfaceSetSessionParameter(iSCSIHBAInterfaceRef interface,
                                              SessionIdentifier sessionId,
                                              enum iSCSIHBASessionParameters parameter,
                                              void * paramVal,
                                              size_t paramSize)
{
    struct Session * session = InterfaceGetSession(interface,sessionId);

    if(!session || !paramVal)
        return EINVAL;

    // Callers pass values of different widths; widen them first
    UInt64 value = 0;

    switch(paramSize) {
        case 1: value = *(UInt8 *)paramVal; break;
        case 2: value = *(UInt16 *)paramVal; break;
        case 4: value = *(UInt32 *)paramVal; break;
        case 8: value = *(UInt64 *)paramVal; break;
        default: return EINVAL;
    }

    IOReturn result = 0;
    pthread_mutex_lock(&session->lock);

    switch(parameter) {
        case kiSCSIHBASODataPDUInOrder: session->dataPDUInOrder = (value != 0); break;
        case kiSCSIHBASODataSequenceInOrder: session->dataSequenceInOrder = (value != 0); break;
        case kiSCSIHBASODefaultTime2Retain: session->defaultTime2Retain = (UInt16)value; break;
        case kiSCSIHBASODefaultTime2Wait: session->defaultTime2Wait = (UInt16)value; break;
        case kiSCSIHBASOErrorRecoveryLevel: session->errorRecoveryLevel = (UInt8)value; break;
        case kiSCSIHBASOFirstBurstLength: session->firstBurstLength = (UInt32)value; break;
        case kiSCSIHBASOImmediateData: session->immediateData = (value != 0); break;
        case kiSCSIHBASOMaxConnections: session->maxConnections = (UInt32)value; break;
        case kiSCSIHBASOMaxOutstandingR2T: session->maxOutstandingR2T = (UInt16)value; break;
        case kiSCSIHBASOMaxBurstLength: session->maxBurstLength = (UInt32)value; break;
        case kiSCSIHBASOInitialR2T: session->initialR2T = (value != 0); break;
        case kiSCSIHBASOTargetPortalGroupTag: session->targetPortalGroupTag = (TargetPortalGroupTag)value; break;
        case kiSCSIHBASOTargetSessionId: session->targetSessionId = (TargetSessionIdentifier)value; break;
        default: result = EINVAL; break;
    }
    pthread_mutex_unlock(&session->lock);
    return result;
}

IOReturn iSCSIHBAInterfaceGetSessionParameter(iSCSIHBAInterfaceRef interface,
                                              SessionIdentifier sessionId,
                                              enum iSCSIHBASessionParameters parameter,
                                              void * paramVal,
                                              size_t paramSize)
{
    if(!paramVal)
        return EINVAL;

    struct Session * session = InterfaceLockSession(interface,sessionId);

    if(!session)
        return EINVAL;

    UInt64 value = 0;
    IOReturn result = 0;

    switch(parameter) {
        case kiSCSIHBASODataPDUInOrder: value = session->dataPDUInOrder; break;
        case kiSCSIHBASODataSequenceInOrder: value = session->dataSequenceInOrder; break;
        case kiSCSIHBASODefaultTime2Retain: value = session->defaultTime2Retain; break;
        case kiSCSIHBASODefaultTime2Wait: value = session->defaultTime2Wait; break;
        case kiSCSIHBASOErrorRecoveryLevel: value = session->errorRecoveryLevel; break;
        case kiSCSIHBASOFirstBurstLength: value = session->firstBurstLength; break;
        case kiSCSIHBASOImmediateData: value = session->immediateData; break;
        case kiSCSIHBASOMaxConnections: value = session->maxConnections; break;
        case kiSCSIHBASOMaxOutstandingR2T: value = session->maxOutstandingR2T; break;
        case kiSCSIHBASOMaxBurstLength: value = session->maxBurstLength; break;
        case kiSCSIHBASOInitialR2T: value = session->initialR2T; break;
        case kiSCSIHBASOTargetPortalGroupTag: value = session->targetPortalGroupTag; break;
        case kiSCSIHBASOTargetSessionId: value = session->targetSessionId; break;
        default: result = EINVAL; break;
    }
    pthread_mutex_unlock(&session->lock);

    if(result)
        return result;

    switch(paramSize) {
        case 1: *(UInt8 *)paramVal = (UInt8)value; break;
        case 2: *(UInt16 *)paramVal = (UInt16)value; break;
        case 4: *(UInt32 *)paramVal = (UInt32)value; break;
        case 8: *(UInt64 *)paramVal = value; break;
        default: return EINVAL;
    }
    return 0;
}

IOReturn iSCSIHBAInterfaceCreateConnection(iSCSIHBAInterfaceRef interface,
                                           SessionIdentifier sessionId,
                                           CFStringRef portalAddress,
                                           CFStringRef portalPort,
                                           CFStringRef hostInterface,
                                           const struct sockaddr_storage * remoteAddress,
                                           const struct sockaddr_storage * localAddress,
                                           ConnectionIdentifier * connectionId)
{
    struct Session * session = InterfaceGetSession(interface,sessionId);

    if(!session || !portalAddress || !portalPort || !hostInterface ||
       !remoteAddress || !localAddress || !connectionId)
        return EINVAL;

    return SessionCreateConnection(session,portalAddress,portalPort,hostInterface,
                                   remoteAddress,localAddress,connectionId);
}

IOReturn iSCSIHBAInterfaceReleaseConnection(iSCSIHBAInterfaceRef interface,
                                            SessionIdentifier sessionId,
                                            ConnectionIdentifier connectionId)
{
    struct Session * session = InterfaceGetSession(interface,sessionId);
    struct Connection * connection = SessionGetConnection(session,connectionId);

    if(!connection)
        return EINVAL;

    ConnectionStopThreads(connection);

    pthread_mutex_lock(&session->lock);
    session->connections[connectionId] = NULL;

    // Tasks of a connection that is released while healthy are retried on
    // the remaining connections
    SessionFinishAllTasks(session,connection,true,0);

    if(session->state == kiSCSIHBASessionStateActive && !SessionGetActiveConnection(session))
        session->state = kiSCSIHBASessionStateRecovering;

    pthread_cond_broadcast(&session->cond);
    pthread_mutex_unlock(&session->lock);

    ConnectionDestroy(connection);
    return 0;
}

IOReturn iSCSIHBAInterfaceSetConnectionParameter(iSCSIHBAInterfaceRef interface,
                                                 SessionIdentifier sessionId,
                                                 ConnectionIdentifier connectionId,
                                                 enum iSCSIHBAConnectionParameters parameter,
                                                 void * paramVal,
                                                 size_t paramSize)
{
    struct Session * session = InterfaceGetSession(interface,sessionId);
    struct Connection * connection = SessionGetConnection(session,connectionId);

    if(!connection || !paramVal)
        return EINVAL;

    UInt64 value = 0;

    switch(paramSize) {
        case 1: value = *(UInt8 *)paramVal; break;
        case 2: value = *(UInt16 *)paramVal; break;
        case 4: value = *(UInt32 *)paramVal; break;
        case 8: value = *(UInt64 *)paramVal; break;
        default: return EINVAL;
    }

    IOReturn result = 0;
    pthread_mutex_lock(&session->lock);

    switch(parameter) {
        case kiSCSIHBACOIFMarkInt: connection->IFMarkInt = (UInt16)value; break;
        case kiSCSIHBACOOFMarkInt: connection->OFMarkInt = (UInt16)value; break;
        case kiSCSIHBACOUseIFMarker: connection->useIFMarker = (value != 0); break;
        case kiSCSIHBACOUseOFMarker: connection->useOFMarker = (value != 0); break;
        case kiSCSIHBACOUseDataDigest: connection->useDataDigest = (value != 0); break;
        case kiSCSIHBACOUseHeaderDigest: connection->useHeaderDigest = (value != 0); break;
        case kiSCSIHBACOMaxRecvDataSegmentLength: connection->maxRecvDataSegmentLength = (UInt32)value; break;
        case kiSCSIHBACOMaxSendDataSegmentLength: connection->maxSendDataSegmentLength = (UInt32)value; break;
        case kiSCSIHBACOInitialExpStatSN: connection->expStatSN = (UInt32)value; break;
        default: result = EINVAL; break;
    }
    pthread_mutex_unlock(&session->lock);
    return result;
}

IOReturn iSCSIHBAInterfaceGetConnectionParameter(iSCSIHBAInterfaceRef interface,
                                                 SessionIdentifier sessionId,
                                                 ConnectionIdentifier connectionId,
                                                 enum iSCSIHBAConnectionParameters parameter,
                                                 void * paramVal,
                                                 size_t paramSize)
{
    if(!paramVal)
        return EINVAL;

    struct Session * session = InterfaceLockSession(interface,sessionId);
    struct Connection * connection = SessionGetConnection(session,connectionId);

    if(!connection) {
        if(session)
            pthread_mutex_unlock(&session->lock);
        return EINVAL;
    }

    UInt64 value = 0;
    IOReturn result = 0;

    switch(parameter) {
        case kiSCSIHBACOIFMarkInt: value = connection->IFMarkInt; break;
        case kiSCSIHBACOOFMarkInt: value = connection->OFMarkInt; break;
        case kiSCSIHBACOUseIFMarker: value = connection->useIFMarker; break;
        case kiSCSIHBACOUseOFMarker: value = connection->useOFMarker; break;
        case kiSCSIHBACOUseDataDigest: value = connection->useDataDigest; break;
        case kiSCSIHBACOUseHeaderDigest: value = connection->useHeaderDigest; break;
        case kiSCSIHBACOMaxRecvDataSegmentLength: value = connection->maxRecvDataSegmentLength; break;
        case kiSCSIHBACOMaxSendDataSegmentLength: value = connection->maxSendDataSegmentLength; break;
        case kiSCSIHBACOInitialExpStatSN: value = connection->expStatSN; break;
        default: result = EINVAL; break;
    }
    pthread_mutex_unlock(&session->lock);

    if(result)
        return result;

    switch(paramSize) {
        case 1: *(UInt8 *)paramVal = (UInt8)value; break;
        case 2: *(UInt16 *)paramVal = (UInt16)value; break;
        case 4: *(UInt32 *)paramVal = (UInt32)value; break;
        case 8: *(UInt64 *)paramVal = value; break;
        default: return EINVAL;
    }
    return 0;
}

#pragma mark - Public interface: PDU exchange outside of the full feature phase

IOReturn iSCSIHBAInterfaceSend(iSCSIHBAInterfaceRef interface,
                               SessionIdentifier sessionId,
                               ConnectionIdentifier connectionId,
                               iSCSIPDUInitiatorBHS * bhs,
                               void * data,
                               size_t length)
{
    struct Session * session = InterfaceGetSession(interface,sessionId);
    struct Connection * connection = SessionGetConnection(session,connectionId);

    if(!connection || !bhs || length > kMaxDataSegmentLength)
        return EINVAL;

    pthread_mutex_lock(&connection->sendLock);
    pthread_mutex_lock(&session->lock);

    if(connection->active || connection->failed) {
        pthread_mutex_unlock(&session->lock);
        pthread_mutex_unlock(&connection->sendLock);
        return connection->failed ? ENOTCONN : EBUSY;
    }

    // Set the command sequence number and expected status sequence number
    if((bhs->opCodeAndDeliveryMarker & 0x3f) != kOpDataOut) {
        bhs->cmdSN = CFSwapInt32HostToBig(session->cmdSN);

        if(!(bhs->opCodeAndDeliveryMarker & kiSCSIPDUImmediateDeliveryFlag))
            session->cmdSN++;
    }
    bhs->expStatSN = CFSwapInt32HostToBig(connection->expStatSN);
    pthread_mutex_unlock(&session->lock);

    errno_t error = ConnectionSendPDU(connection,(UInt8 *)bhs,data,(UInt32)length);
    pthread_mutex_unlock(&connection->sendLock);
    return error;
}

IOReturn iSCSIHBAInterfaceReceive(iSCSIHBAInterfaceRef interface,
                                  SessionIdentifier sessionId,
                                  ConnectionIdentifier connectionId,
                                  iSCSIPDUTargetBHS * bhs,
                                  void * * data,
                                  size_t * length)
{
    struct Session * session = InterfaceGetSession(interface,sessionId);
    struct Connection * connection = SessionGetConnection(session,connectionId);

    if(!connection || !bhs || !data || !length)
        return EINVAL;

    *data = NULL;
    *length = 0;

    pthread_mutex_lock(&session->lock);
    bool busy = connection->active;
    bool failed = connection->failed;
    pthread_mutex_unlock(&session->lock);

    if(busy || failed)
        return failed ? ENOTCONN : EBUSY;

    UInt32 dataLength = 0;
    errno_t error = ConnectionReceiveHeader(connection,(UInt8 *)bhs,&dataLength);

    if(error)
        return error;

    // The buffer is terminated so that it can be parsed as text
    UInt8 * buffer = NULL;

    if(dataLength > 0) {
        if(!(buffer = calloc(1,(size_t)dataLength + 4)))
            return ENOMEM;

        if((error = ConnectionReceiveData(connection,buffer,dataLength))) {
            free(buffer);
            return error;
        }
    }

    // Outside of the full feature phase the sequence numbers of the target
    // are authoritative (the session may be new or may have been reinstated)
    const UInt8 * raw = (const UInt8 *)bhs;
    UInt8 opCode = raw[0] & 0x3f;

    pthread_mutex_lock(&session->lock);

    if(!(opCode == kOpDataIn && !(raw[1] & kFlagStatus))) {
        if(opCode != kOpR2T && !(opCode == kOpNOPIn && Get32(raw + 16) == kReservedTag))
            connection->expStatSN = Get32(raw + 24) + 1;

        session->expCmdSN = Get32(raw + 28);
        session->maxCmdSN = Get32(raw + 32);
    }
    pthread_mutex_unlock(&session->lock);

    *data = buffer;
    *length = dataLength;
    return 0;
}

#pragma mark - Public interface: activation

IOReturn iSCSIHBAInterfaceActivateConnection(iSCSIHBAInterfaceRef interface,
                                             SessionIdentifier sessionId,
                                             ConnectionIdentifier connectionId)
{
    struct Session * session = InterfaceGetSession(interface,sessionId);
    struct Connection * connection = SessionGetConnection(session,connectionId);

    if(!connection)
        return EINVAL;

    pthread_mutex_lock(&session->lock);

    if(connection->active || connection->failed) {
        pthread_mutex_unlock(&session->lock);
        return connection->failed ? ENOTCONN : 0;
    }

    if(pipe(connection->wakePipe) != 0) {
        pthread_mutex_unlock(&session->lock);
        return errno;
    }

    // Receiving blocks indefinitely from here on (the transmit thread
    // watches over the connection) but sending must not
    struct timeval noTimeout = { 0, 0 };
    struct timeval sendTimeout = { kSendTimeoutSec, 0 };
    setsockopt(connection->fd,SOL_SOCKET,SO_RCVTIMEO,&noTimeout,sizeof(noTimeout));
    setsockopt(connection->fd,SOL_SOCKET,SO_SNDTIMEO,&sendTimeout,sizeof(sendTimeout));

    connection->stopping = false;
    connection->receiveExited = false;
    connection->pingOutstanding = false;
    connection->lastReceiveTime = MonotonicSeconds();
    connection->active = true;
    connection->threadsRunning = true;

    pthread_create(&connection->receiveThread,NULL,ConnectionReceiveMain,connection);
    pthread_create(&connection->transmitThread,NULL,ConnectionTransmitMain,connection);

    if(session->state == kiSCSIHBASessionStateRecovering) {
        session->statistics.recoveries++;
        iSCSILogInfo("session recovered (sid %u)",session->sessionId);
    }

    session->state = kiSCSIHBASessionStateActive;
    pthread_cond_broadcast(&session->cond);
    pthread_mutex_unlock(&session->lock);
    return 0;
}

IOReturn iSCSIHBAInterfaceActivateAllConnections(iSCSIHBAInterfaceRef interface,
                                                 SessionIdentifier sessionId)
{
    struct Session * session = InterfaceGetSession(interface,sessionId);

    if(!session)
        return EINVAL;

    for(ConnectionIdentifier index = 0; index < kiSCSIMaxConnectionsPerSession; index++)
        if(session->connections[index])
            iSCSIHBAInterfaceActivateConnection(interface,sessionId,index);

    return 0;
}

IOReturn iSCSIHBAInterfaceDeactivateConnection(iSCSIHBAInterfaceRef interface,
                                               SessionIdentifier sessionId,
                                               ConnectionIdentifier connectionId)
{
    struct Session * session = InterfaceGetSession(interface,sessionId);
    struct Connection * connection = SessionGetConnection(session,connectionId);

    if(!connection)
        return EINVAL;

    ConnectionStopThreads(connection);

    pthread_mutex_lock(&session->lock);

    // Tasks move over to the remaining connections; if there are none the
    // session is on its way out
    if(SessionGetActiveConnection(session))
        SessionFinishAllTasks(session,connection,true,0);
    else {
        session->state = kiSCSIHBASessionStateClosing;
        SessionFinishAllTasks(session,NULL,false,ENXIO);
    }

    pthread_cond_broadcast(&session->cond);
    bool failed = connection->failed;
    pthread_mutex_unlock(&session->lock);

    // PDUs are exchanged synchronously again (e.g., for the logout)
    if(!failed)
        SetSocketTimeouts(connection->fd,kLoginIOTimeoutSec);

    return 0;
}

IOReturn iSCSIHBAInterfaceDeactivateAllConnections(iSCSIHBAInterfaceRef interface,
                                                   SessionIdentifier sessionId)
{
    struct Session * session = InterfaceGetSession(interface,sessionId);

    if(!session)
        return EINVAL;

    iSCSIHBAInterfaceCloseSession(interface,sessionId);

    for(ConnectionIdentifier index = 0; index < kiSCSIMaxConnectionsPerSession; index++)
        if(session->connections[index])
            iSCSIHBAInterfaceDeactivateConnection(interface,sessionId,index);

    return 0;
}

#pragma mark - Public interface: queries

IOReturn iSCSIHBAInterfaceGetConnection(iSCSIHBAInterfaceRef interface,
                                        SessionIdentifier sessionId,
                                        ConnectionIdentifier * connectionId)
{
    if(!connectionId)
        return EINVAL;

    *connectionId = kiSCSIInvalidConnectionId;

    struct Session * session = InterfaceLockSession(interface,sessionId);

    if(!session)
        return EINVAL;

    // Prefer a connection that is still usable
    for(ConnectionIdentifier index = 0; index < kiSCSIMaxConnectionsPerSession; index++) {
        if(session->connections[index] && !session->connections[index]->failed) {
            *connectionId = index;
            break;
        }
    }
    pthread_mutex_unlock(&session->lock);

    return (*connectionId == kiSCSIInvalidConnectionId) ? ENOTCONN : 0;
}

IOReturn iSCSIHBAInterfaceGetNumConnections(iSCSIHBAInterfaceRef interface,
                                            SessionIdentifier sessionId,
                                            UInt32 * numConnections)
{
    if(!numConnections)
        return EINVAL;

    *numConnections = 0;

    struct Session * session = InterfaceLockSession(interface,sessionId);

    if(!session)
        return EINVAL;

    for(ConnectionIdentifier index = 0; index < kiSCSIMaxConnectionsPerSession; index++)
        if(session->connections[index])
            (*numConnections)++;

    pthread_mutex_unlock(&session->lock);
    return 0;
}

SessionIdentifier iSCSIHBAInterfaceGetSessionIdForTargetIQN(iSCSIHBAInterfaceRef interface,
                                                            CFStringRef targetIQN)
{
    if(!interface || !targetIQN)
        return kiSCSIInvalidSessionId;

    SessionIdentifier sessionId = kiSCSIInvalidSessionId;
    pthread_mutex_lock(&interface->lock);

    // Sessions that never made it past the login (discovery sessions and
    // logins in progress) are not associated with their target yet
    for(SessionIdentifier index = 0; index < kiSCSIMaxSessions; index++) {
        struct Session * session = interface->sessions[index];

        if(!session)
            continue;

        pthread_mutex_lock(&session->lock);
        bool established = (session->state != kiSCSIHBASessionStateLogin);
        pthread_mutex_unlock(&session->lock);

        if(established && CFStringCompare(session->targetIQN,targetIQN,0) == kCFCompareEqualTo) {
            sessionId = index;
            break;
        }
    }
    pthread_mutex_unlock(&interface->lock);
    return sessionId;
}

ConnectionIdentifier iSCSIHBAInterfaceGetConnectionIdForPortalAddress(iSCSIHBAInterfaceRef interface,
                                                                      SessionIdentifier sessionId,
                                                                      CFStringRef portalAddress)
{
    if(!portalAddress)
        return kiSCSIInvalidConnectionId;

    struct Session * session = InterfaceLockSession(interface,sessionId);

    if(!session)
        return kiSCSIInvalidConnectionId;

    ConnectionIdentifier connectionId = kiSCSIInvalidConnectionId;

    for(ConnectionIdentifier index = 0; index < kiSCSIMaxConnectionsPerSession; index++) {
        struct Connection * connection = session->connections[index];

        if(connection && CFStringCompare(connection->portalAddress,portalAddress,
                                         kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            connectionId = index;
            break;
        }
    }
    pthread_mutex_unlock(&session->lock);
    return connectionId;
}

IOReturn iSCSIHBAInterfaceGetSessionIds(iSCSIHBAInterfaceRef interface,
                                        SessionIdentifier * sessionIds,
                                        UInt16 * sessionCount)
{
    if(!interface || !sessionIds || !sessionCount)
        return EINVAL;

    *sessionCount = 0;
    pthread_mutex_lock(&interface->lock);

    for(SessionIdentifier index = 0; index < kiSCSIMaxSessions; index++) {
        struct Session * session = interface->sessions[index];

        if(!session)
            continue;

        pthread_mutex_lock(&session->lock);
        bool established = (session->state != kiSCSIHBASessionStateLogin);
        pthread_mutex_unlock(&session->lock);

        if(established)
            sessionIds[(*sessionCount)++] = index;
    }
    pthread_mutex_unlock(&interface->lock);
    return 0;
}

IOReturn iSCSIHBAInterfaceGetConnectionIds(iSCSIHBAInterfaceRef interface,
                                           SessionIdentifier sessionId,
                                           ConnectionIdentifier * connectionIds,
                                           UInt32 * connectionCount)
{
    if(!connectionIds || !connectionCount)
        return EINVAL;

    *connectionCount = 0;

    struct Session * session = InterfaceLockSession(interface,sessionId);

    if(!session)
        return EINVAL;

    for(ConnectionIdentifier index = 0; index < kiSCSIMaxConnectionsPerSession; index++)
        if(session->connections[index])
            connectionIds[(*connectionCount)++] = index;

    pthread_mutex_unlock(&session->lock);
    return 0;
}

CFStringRef iSCSIHBAInterfaceCreateTargetIQNForSessionId(iSCSIHBAInterfaceRef interface,
                                                         SessionIdentifier sessionId)
{
    if(!interface || sessionId >= kiSCSIMaxSessions)
        return NULL;

    CFStringRef targetIQN = NULL;
    pthread_mutex_lock(&interface->lock);

    if(interface->sessions[sessionId])
        targetIQN = CFStringCreateCopy(kCFAllocatorDefault,interface->sessions[sessionId]->targetIQN);

    pthread_mutex_unlock(&interface->lock);
    return targetIQN;
}

/*! Copies one of the strings that describe the portal of a connection. */
static CFStringRef ConnectionCopyString(iSCSIHBAInterfaceRef interface,
                                        SessionIdentifier sessionId,
                                        ConnectionIdentifier connectionId,
                                        int which)
{
    struct Session * session = InterfaceLockSession(interface,sessionId);
    struct Connection * connection = SessionGetConnection(session,connectionId);
    CFStringRef string = NULL;

    if(connection) {
        CFStringRef source = (which == 0) ? connection->portalAddress :
                             (which == 1) ? connection->portalPort : connection->hostInterface;
        string = CFStringCreateCopy(kCFAllocatorDefault,source);
    }

    if(session)
        pthread_mutex_unlock(&session->lock);

    return string;
}

CFStringRef iSCSIHBAInterfaceCreatePortalAddressForConnectionId(iSCSIHBAInterfaceRef interface,
                                                                SessionIdentifier sessionId,
                                                                ConnectionIdentifier connectionId)
{
    return ConnectionCopyString(interface,sessionId,connectionId,0);
}

CFStringRef iSCSIHBAInterfaceCreatePortalPortForConnectionId(iSCSIHBAInterfaceRef interface,
                                                             SessionIdentifier sessionId,
                                                             ConnectionIdentifier connectionId)
{
    return ConnectionCopyString(interface,sessionId,connectionId,1);
}

CFStringRef iSCSIHBAInterfaceCreateHostInterfaceForConnectionId(iSCSIHBAInterfaceRef interface,
                                                                SessionIdentifier sessionId,
                                                                ConnectionIdentifier connectionId)
{
    return ConnectionCopyString(interface,sessionId,connectionId,2);
}

enum iSCSIHBASessionState iSCSIHBAInterfaceGetSessionState(iSCSIHBAInterfaceRef interface,
                                                           SessionIdentifier sessionId)
{
    struct Session * session = InterfaceLockSession(interface,sessionId);

    if(!session)
        return kiSCSIHBASessionStateInvalid;

    enum iSCSIHBASessionState state = session->state;
    pthread_mutex_unlock(&session->lock);
    return state;
}

void iSCSIHBAInterfaceCloseSession(iSCSIHBAInterfaceRef interface,
                                   SessionIdentifier sessionId)
{
    struct Session * session = InterfaceLockSession(interface,sessionId);

    if(!session)
        return;

    session->state = kiSCSIHBASessionStateClosing;
    SessionFinishAllTasks(session,NULL,false,ENXIO);
    pthread_cond_broadcast(&session->cond);
    pthread_mutex_unlock(&session->lock);
}

IOReturn iSCSIHBAInterfaceGetSessionStatistics(iSCSIHBAInterfaceRef interface,
                                               SessionIdentifier sessionId,
                                               iSCSIHBASessionStatistics * statistics)
{
    if(!statistics)
        return EINVAL;

    struct Session * session = InterfaceLockSession(interface,sessionId);

    if(!session)
        return EINVAL;

    *statistics = session->statistics;
    pthread_mutex_unlock(&session->lock);
    return 0;
}

#pragma mark - Public interface: SCSI tasks

/*! Submits a task on a connection: sends the command along with immediate
 *  and unsolicited data.  The send lock of the connection is held; the
 *  session lock is not. */
static errno_t ConnectionSubmitTask(struct Connection * connection,
                                    struct Task * task,
                                    UInt64 LUN,
                                    const UInt8 * cdb,
                                    UInt8 cdbLength,
                                    UInt32 cmdSN,
                                    UInt32 expStatSN,
                                    bool immediateData,
                                    bool initialR2T,
                                    UInt32 firstBurstLength)
{
    UInt8 bhs[kBHSSize];
    UInt8 rawLUN[8];
    UInt64 bigLUN = CFSwapInt64HostToBig(LUN);
    memcpy(rawLUN,&bigLUN,8);
    memset(bhs,0,sizeof(bhs));

    // Work out how much data accompanies the command: immediate data is
    // part of the command PDU, further unsolicited data follows in Data-Out
    // PDUs.  Whatever remains is sent when the target asks for it (R2T).
    UInt32 immediateLength = 0, unsolicitedLength = 0;

    if(task->direction == kiSCSIHBADataWrite) {
        UInt32 burst = (task->length < firstBurstLength) ? task->length : firstBurstLength;

        if(immediateData)
            immediateLength = (burst < connection->maxSendDataSegmentLength) ? burst
                                                                             : connection->maxSendDataSegmentLength;
        unsolicitedLength = initialR2T ? immediateLength : burst;
    }

    bhs[0] = kOpSCSICommand;
    bhs[1] = kTaskAttributeSimple;

    if(unsolicitedLength == immediateLength)
        bhs[1] |= kFlagFinal;

    if(task->direction == kiSCSIHBADataRead)
        bhs[1] |= kFlagRead;
    else if(task->direction == kiSCSIHBADataWrite)
        bhs[1] |= kFlagWrite;

    memcpy(bhs + 8,rawLUN,8);
    Put32(bhs + 16,task->initiatorTaskTag);
    Put32(bhs + 20,task->length);
    Put32(bhs + 24,cmdSN);
    Put32(bhs + 28,expStatSN);
    memcpy(bhs + 32,cdb,cdbLength);

    errno_t error = ConnectionSendPDU(connection,bhs,task->buffer,immediateLength);

    if(!error && unsolicitedLength > immediateLength)
        error = ConnectionSendDataOut(connection,task->initiatorTaskTag,kReservedTag,rawLUN,
                                      task->buffer,immediateLength,
                                      unsolicitedLength - immediateLength,expStatSN);
    return error;
}

errno_t iSCSIHBAInterfaceExecuteSCSI(iSCSIHBAInterfaceRef interface,
                                     SessionIdentifier sessionId,
                                     UInt64 LUN,
                                     const UInt8 * cdb,
                                     UInt8 cdbLength,
                                     enum iSCSIHBADataDirection direction,
                                     void * buffer,
                                     UInt32 length,
                                     iSCSIHBASCSIResult * result)
{
    if(!interface || !cdb || cdbLength == 0 || cdbLength > 16 || !result ||
       sessionId >= kiSCSIMaxSessions || (length > 0 && !buffer))
        return EINVAL;

    if(length == 0)
        direction = kiSCSIHBADataNone;

    // Pin the session so that it cannot go away underneath this thread
    pthread_mutex_lock(&interface->lock);
    struct Session * session = interface->sessions[sessionId];

    if(session) {
        pthread_mutex_lock(&session->lock);
        session->users++;
        pthread_mutex_unlock(&session->lock);
    }
    pthread_mutex_unlock(&interface->lock);

    if(!session)
        return ENXIO;

    struct Task task;
    errno_t error = 0;
    int attempts = 0;
    time_t holdDeadline = MonotonicSeconds() + kRecoveryHoldSec;
    time_t windowDeadline = MonotonicSeconds() + kTaskTimeoutSec;

    memset(&task,0,sizeof(task));
    pthread_cond_init(&task.cond,NULL);

    for(;;) {
        struct Connection * connection = NULL;

        // Wait for the session to be operational and for the target to
        // open its command window
        pthread_mutex_lock(&session->lock);

        for(;;) {
            if(session->state == kiSCSIHBASessionStateActive) {
                if((connection = SessionGetActiveConnection(session)) &&
                   !SerialGreater(session->cmdSN,session->maxCmdSN)) {
                    connection->pins++;
                    break;
                }
            }
            else if(session->state != kiSCSIHBASessionStateRecovering) {
                error = ENXIO;
                break;
            }

            time_t now = MonotonicSeconds();

            if(now >= ((session->state == kiSCSIHBASessionStateActive) ? windowDeadline : holdDeadline)) {
                error = EAGAIN;
                break;
            }
            WaitCondition(&session->cond,&session->lock,1000);
        }
        pthread_mutex_unlock(&session->lock);

        if(error)
            break;

        // Commands must reach the target in the order of their sequence
        // numbers, hence the number is assigned with the send lock held
        pthread_mutex_lock(&connection->sendLock);
        pthread_mutex_lock(&session->lock);

        if(session->state != kiSCSIHBASessionStateActive || !connection->active || connection->failed ||
           session->connections[connection->connectionId] != connection ||
           SerialGreater(session->cmdSN,session->maxCmdSN)) {
            connection->pins--;
            pthread_cond_broadcast(&session->cond);
            pthread_mutex_unlock(&session->lock);
            pthread_mutex_unlock(&connection->sendLock);
            continue;
        }

        memset(&task.result,0,sizeof(task.result));
        task.initiatorTaskTag = SessionAllocateTaskTag(session);
        task.connection = connection;
        task.direction = direction;
        task.buffer = buffer;
        task.length = length;
        task.startTime = MonotonicSeconds();
        task.done = false;
        task.requeue = false;
        task.error = 0;
        task.next = session->tasks[task.initiatorTaskTag % kTaskTableSize];
        session->tasks[task.initiatorTaskTag % kTaskTableSize] = &task;

        UInt32 cmdSN = session->cmdSN++;
        UInt32 expStatSN = connection->expStatSN;
        bool immediateData = session->immediateData;
        bool initialR2T = session->initialR2T;
        UInt32 firstBurstLength = session->firstBurstLength;
        pthread_mutex_unlock(&session->lock);

        errno_t sendError = ConnectionSubmitTask(connection,&task,LUN,cdb,cdbLength,cmdSN,expStatSN,
                                                 immediateData,initialR2T,firstBurstLength);
        pthread_mutex_unlock(&connection->sendLock);

        // A connection that cannot be written to is broken; this requeues
        // the task (and all others of the connection)
        if(sendError)
            ConnectionFail(connection,sendError);

        pthread_mutex_lock(&session->lock);
        connection->pins--;
        pthread_cond_broadcast(&session->cond);

        // In the unlikely event that the connection was released rather
        // than failed the task is still pending; take it back
        if(sendError && !task.done)
            SessionFinishTask(session,&task,true,0);

        while(!task.done || task.users > 0)
            pthread_cond_wait(&task.cond,&session->lock);

        pthread_mutex_unlock(&session->lock);

        if(!task.requeue) {
            error = task.error;
            break;
        }

        if(++attempts > kTaskMaxRetries) {
            error = EIO;
            break;
        }
    }

    pthread_cond_destroy(&task.cond);

    if(!error)
        *result = task.result;

    pthread_mutex_lock(&session->lock);
    session->users--;
    pthread_cond_broadcast(&session->cond);
    pthread_mutex_unlock(&session->lock);

    return error;
}
