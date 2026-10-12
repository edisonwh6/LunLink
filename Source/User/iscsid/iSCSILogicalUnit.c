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

#include "iSCSILogicalUnit.h"
#include "iSCSIBlockExport.h"
#include "iSCSILog.h"

#include <pthread.h>
#include <unistd.h>

/*! Largest transfer of a single READ or WRITE command, in bytes, unless the
 *  logical unit asks for less. */
static const UInt32 kMaxTransferBytes = 1024 * 1024;

/*! Number of times a command is retried for conditions that are expected
 *  to clear (e.g., a unit attention). */
static const int kCommandMaxRetries = 6;

enum {
    kSCSITestUnitReady = 0x00,
    kSCSIInquiry = 0x12,
    kSCSIModeSense6 = 0x1a,
    kSCSIReadCapacity10 = 0x25,
    kSCSIRead10 = 0x28,
    kSCSIWrite10 = 0x2a,
    kSCSISynchronizeCache10 = 0x35,
    kSCSIRead16 = 0x88,
    kSCSIWrite16 = 0x8a,
    kSCSISynchronizeCache16 = 0x91,
    kSCSIServiceActionIn16 = 0x9e,
    kSCSIReportLUNs = 0xa0,

    kSCSIStatusGood = 0x00,
    kSCSIStatusCheckCondition = 0x02,
    kSCSIStatusConditionMet = 0x04,
    kSCSIStatusBusy = 0x08,
    kSCSIStatusReservationConflict = 0x18,
    kSCSIStatusTaskSetFull = 0x28,

    kSenseNoSense = 0x0,
    kSenseRecoveredError = 0x1,
    kSenseNotReady = 0x2,
    kSenseIllegalRequest = 0x5,
    kSenseUnitAttention = 0x6,
    kSenseDataProtect = 0x7,
    kSenseAbortedCommand = 0xb
};

struct __iSCSILogicalUnit {
    iSCSIHBAInterfaceRef interface;
    SessionIdentifier sessionId;
    iSCSILogicalUnitInfo info;

    /*! Largest number of blocks per READ or WRITE command. */
    UInt32 maxTransferBlocks;

    /*! SYNCHRONIZE CACHE turned out not to be supported. */
    bool flushUnsupported;

    // Writes that must be on stable storage, to a unit that cannot bypass
    // its cache for individual writes, are followed by a flush of the
    // cache.  Flushes are shared: a write is covered by any flush that
    // started after the write completed.  A write takes a ticket when it
    // completes and waits for a flush that covers the ticket.
    pthread_mutex_t flushLock;
    pthread_cond_t flushCond;
    UInt64 flushTicket;
    UInt64 flushedTicket;
    bool flushInProgress;

    /*! Serializes writes that are not aligned to the block size (these have
     *  to read, modify and write back whole blocks). */
    pthread_mutex_t unalignedLock;
};

static inline void Put16(UInt8 * bytes,UInt16 value)
{
    bytes[0] = (UInt8)(value >> 8);
    bytes[1] = (UInt8)value;
}

static inline void Put32(UInt8 * bytes,UInt32 value)
{
    bytes[0] = (UInt8)(value >> 24);
    bytes[1] = (UInt8)(value >> 16);
    bytes[2] = (UInt8)(value >> 8);
    bytes[3] = (UInt8)value;
}

static inline void Put64(UInt8 * bytes,UInt64 value)
{
    Put32(bytes,(UInt32)(value >> 32));
    Put32(bytes + 4,(UInt32)value);
}

static inline UInt32 Get32(const UInt8 * bytes)
{
    return ((UInt32)bytes[0] << 24) | ((UInt32)bytes[1] << 16) | ((UInt32)bytes[2] << 8) | bytes[3];
}

static inline UInt64 Get64(const UInt8 * bytes)
{
    return ((UInt64)Get32(bytes) << 32) | Get32(bytes + 4);
}

/*! Executes a SCSI command and translates its outcome into an error code.
 *  Conditions that are transient are retried.
 *  @param transferred the number of bytes transferred (may be NULL).
 *  @param senseKey the sense key of a failed command (may be NULL).
 *  @return 0, an errno value, or kiSCSIBlockExportErrorTryLater. */
static int ExecuteCommand(iSCSIHBAInterfaceRef interface,
                          SessionIdentifier sessionId,
                          UInt64 LUN,
                          const UInt8 * cdb,
                          UInt8 cdbLength,
                          enum iSCSIHBADataDirection direction,
                          void * buffer,
                          UInt32 length,
                          UInt32 * transferred,
                          UInt8 * senseKey)
{
    if(senseKey)
        *senseKey = kSenseNoSense;

    for(int attempt = 0; ; attempt++) {
        iSCSIHBASCSIResult result;
        errno_t error = iSCSIHBAInterfaceExecuteSCSI(interface,sessionId,LUN,cdb,cdbLength,
                                                     direction,buffer,length,&result);
        if(error == EAGAIN)
            return kiSCSIBlockExportErrorTryLater;

        if(error)
            return error;

        if(transferred)
            *transferred = result.transferred;

        bool retry = false;
        int outcome = EIO;

        switch(result.status) {
            case kSCSIStatusGood:
            case kSCSIStatusConditionMet:
                return 0;

            case kSCSIStatusBusy:
            case kSCSIStatusTaskSetFull:
                retry = true;
                usleep(200 * 1000);
                break;

            case kSCSIStatusReservationConflict:
                outcome = EACCES;
                break;

            case kSCSIStatusCheckCondition: {
                UInt8 key = kSenseNoSense, asc = 0, ascq = 0;

                // Sense data comes in a fixed or a descriptor format
                if(result.senseLength >= 14 && (result.sense[0] & 0x7e) == 0x70) {
                    key = result.sense[2] & 0x0f;
                    asc = result.sense[12];
                    ascq = result.sense[13];
                }
                else if(result.senseLength >= 4 && (result.sense[0] & 0x7e) == 0x72) {
                    key = result.sense[1] & 0x0f;
                    asc = result.sense[2];
                    ascq = result.sense[3];
                }
                else if(result.senseLength >= 3 && (result.sense[0] & 0x7e) == 0x70)
                    key = result.sense[2] & 0x0f;

                if(senseKey)
                    *senseKey = key;

                switch(key) {
                    case kSenseNoSense:
                    case kSenseRecoveredError:
                        return 0;

                    // Reported once after events such as a reset or a login
                    case kSenseUnitAttention:
                    case kSenseAbortedCommand:
                        retry = true;
                        break;

                    case kSenseNotReady:
                        // "Becoming ready" and friends clear by themselves
                        if(asc == 0x04 && (ascq == 0x01 || ascq == 0x04 || ascq == 0x07 || ascq == 0x08)) {
                            retry = true;
                            sleep(1);
                        }
                        else
                            outcome = ENXIO;
                        break;

                    case kSenseIllegalRequest:
                        outcome = EINVAL;
                        break;

                    case kSenseDataProtect:
                        outcome = (asc == 0x27) ? EROFS : EACCES;
                        break;

                    default:
                        outcome = EIO;
                        break;
                }

                if(!retry && key != kSenseIllegalRequest)
                    iSCSILogError("SCSI command %#04x failed: sense key %#x, asc %#04x, ascq %#04x (sid %u)",
                                  cdb[0],key,asc,ascq,sessionId);
                break;
            }
            default:
                iSCSILogError("SCSI command %#04x failed: status %#04x (sid %u)",cdb[0],result.status,sessionId);
                break;
        }

        if(!retry || attempt >= kCommandMaxRetries)
            return outcome;
    }
}

#pragma mark - Discovery of logical units

/*! Copies a space-padded ASCII field of INQUIRY data, trimming blanks. */
static void CopyInquiryString(char * destination,size_t capacity,const UInt8 * source,size_t length)
{
    while(length > 0 && (source[length - 1] == ' ' || source[length - 1] == 0))
        length--;

    while(length > 0 && *source == ' ') {
        source++;
        length--;
    }

    if(length >= capacity)
        length = capacity - 1;

    for(size_t index = 0; index < length; index++)
        destination[index] = (source[index] >= 0x20 && source[index] < 0x7f) ? (char)source[index] : '?';

    destination[length] = '\0';
}

/*! Queries a logical unit and creates an object for it if it is a disk. */
static iSCSILogicalUnitRef LogicalUnitCreate(iSCSIHBAInterfaceRef interface,
                                             SessionIdentifier sessionId,
                                             UInt64 LUN)
{
    UInt8 cdb[16];
    UInt8 data[255];
    UInt32 transferred = 0;

    // Standard inquiry: only connected direct-access devices are of interest
    memset(cdb,0,sizeof(cdb));
    memset(data,0,sizeof(data));
    cdb[0] = kSCSIInquiry;
    cdb[4] = 96;

    if(ExecuteCommand(interface,sessionId,LUN,cdb,6,kiSCSIHBADataRead,data,96,&transferred,NULL) != 0 ||
       transferred < 36)
        return NULL;

    UInt8 qualifier = data[0] >> 5;
    UInt8 deviceType = data[0] & 0x1f;

    if(qualifier != 0 || (deviceType != 0x00 && deviceType != 0x0e))
        return NULL;

    iSCSILogicalUnitRef unit = calloc(1,sizeof(struct __iSCSILogicalUnit));
    unit->interface = interface;
    unit->sessionId = sessionId;
    unit->info.LUN = LUN;
    pthread_mutex_init(&unit->unalignedLock,NULL);
    pthread_mutex_init(&unit->flushLock,NULL);
    pthread_cond_init(&unit->flushCond,NULL);

    // Decode the logical unit number (peripheral or flat addressing)
    UInt8 first = (UInt8)(LUN >> 56), second = (UInt8)(LUN >> 48);
    unit->info.number = ((first >> 6) == 0 && (first & 0x3f) == 0) ? second
                                                                  : (((UInt32)(first & 0x3f) << 8) | second);

    CopyInquiryString(unit->info.vendor,sizeof(unit->info.vendor),data + 8,8);
    CopyInquiryString(unit->info.product,sizeof(unit->info.product),data + 16,16);
    CopyInquiryString(unit->info.revision,sizeof(unit->info.revision),data + 32,4);

    // Unit serial number (vital product data page 0x80), if available
    memset(cdb,0,sizeof(cdb));
    memset(data,0,sizeof(data));
    cdb[0] = kSCSIInquiry;
    cdb[1] = 0x01;
    cdb[2] = 0x80;
    cdb[4] = 255;

    if(ExecuteCommand(interface,sessionId,LUN,cdb,6,kiSCSIHBADataRead,data,255,&transferred,NULL) == 0 &&
       transferred >= 4 && data[1] == 0x80) {
        size_t length = data[3];

        if(length > transferred - 4)
            length = transferred - 4;

        CopyInquiryString(unit->info.serialNumber,sizeof(unit->info.serialNumber),data + 4,length);
    }

    // Wait for the unit to become ready (this also consumes the unit
    // attention condition that follows a login)
    memset(cdb,0,sizeof(cdb));
    cdb[0] = kSCSITestUnitReady;
    ExecuteCommand(interface,sessionId,LUN,cdb,6,kiSCSIHBADataNone,NULL,0,NULL,NULL);

    // Capacity: the 16-byte variant is tried first as it handles large units
    memset(cdb,0,sizeof(cdb));
    memset(data,0,sizeof(data));
    cdb[0] = kSCSIServiceActionIn16;
    cdb[1] = 0x10;
    Put32(cdb + 10,32);

    int error = ExecuteCommand(interface,sessionId,LUN,cdb,16,kiSCSIHBADataRead,data,32,&transferred,NULL);

    if(error == 0 && transferred >= 12) {
        unit->info.blockCount = Get64(data) + 1;
        unit->info.blockSize = Get32(data + 8);
    }
    else {
        memset(cdb,0,sizeof(cdb));
        memset(data,0,sizeof(data));
        cdb[0] = kSCSIReadCapacity10;

        error = ExecuteCommand(interface,sessionId,LUN,cdb,10,kiSCSIHBADataRead,data,8,&transferred,NULL);

        if(error == 0 && transferred >= 8) {
            unit->info.blockCount = (UInt64)Get32(data) + 1;
            unit->info.blockSize = Get32(data + 4);
        }
    }

    if(unit->info.blockSize < 512 || (unit->info.blockSize & (unit->info.blockSize - 1)) != 0 ||
       unit->info.blockSize > 65536 || unit->info.blockCount == 0) {
        iSCSILogWarning("skipping LUN %u: unable to determine its capacity (sid %u)",unit->info.number,sessionId);
        iSCSILogicalUnitRelease(unit);
        return NULL;
    }

    // Mode parameters: write protection, force unit access, write cache.
    // If they cannot be read the cache is assumed to be volatile.
    unit->info.writeCache = true;

    memset(cdb,0,sizeof(cdb));
    memset(data,0,sizeof(data));
    cdb[0] = kSCSIModeSense6;
    cdb[2] = 0x08;
    cdb[4] = 192;

    if(ExecuteCommand(interface,sessionId,LUN,cdb,6,kiSCSIHBADataRead,data,192,&transferred,NULL) == 0 &&
       transferred >= 4) {
        unit->info.readOnly = (data[2] & 0x80) != 0;
        unit->info.forceUnitAccess = (data[2] & 0x10) != 0;

        UInt32 pageOffset = 4 + data[3];

        if(pageOffset + 3 <= transferred && (data[pageOffset] & 0x3f) == 0x08)
            unit->info.writeCache = (data[pageOffset + 2] & 0x04) != 0;
    }

    // Block limits (vital product data page 0xb0), if available
    unit->maxTransferBlocks = kMaxTransferBytes / unit->info.blockSize;

    memset(cdb,0,sizeof(cdb));
    memset(data,0,sizeof(data));
    cdb[0] = kSCSIInquiry;
    cdb[1] = 0x01;
    cdb[2] = 0xb0;
    cdb[4] = 64;

    if(ExecuteCommand(interface,sessionId,LUN,cdb,6,kiSCSIHBADataRead,data,64,&transferred,NULL) == 0 &&
       transferred >= 12 && data[1] == 0xb0) {
        UInt32 limit = Get32(data + 8);

        if(limit > 0 && limit < unit->maxTransferBlocks)
            unit->maxTransferBlocks = limit;
    }

    if(unit->maxTransferBlocks == 0)
        unit->maxTransferBlocks = 1;

    return unit;
}

errno_t iSCSILogicalUnitScan(iSCSIHBAInterfaceRef interface,
                             SessionIdentifier sessionId,
                             iSCSILogicalUnitRef * * units,
                             UInt32 * count)
{
    if(!interface || !units || !count)
        return EINVAL;

    *units = NULL;
    *count = 0;

    // Ask the target for its inventory of logical units
    const UInt32 maxLUNs = 256;
    const UInt32 listLength = 8 + maxLUNs * 8;
    UInt8 * list = calloc(1,listLength);
    UInt8 cdb[16];
    UInt32 transferred = 0;
    UInt64 defaultLUN = 0;
    UInt32 lunCount = 0;

    memset(cdb,0,sizeof(cdb));
    cdb[0] = kSCSIReportLUNs;
    Put32(cdb + 6,listLength);

    int error = ExecuteCommand(interface,sessionId,0,cdb,12,kiSCSIHBADataRead,list,listLength,&transferred,NULL);

    if(error == 0 && transferred >= 8) {
        lunCount = Get32(list) / 8;

        if(lunCount > (transferred - 8) / 8)
            lunCount = (transferred - 8) / 8;
    }
    // Fall back to LUN 0 if the target does not report its logical units
    else if(error == EINVAL || error == 0) {
        memcpy(list + 8,&defaultLUN,8);
        lunCount = 1;
    }
    else {
        free(list);
        return (error == kiSCSIBlockExportErrorTryLater) ? EAGAIN : error;
    }

    iSCSILogicalUnitRef * found = calloc(lunCount ? lunCount : 1,sizeof(iSCSILogicalUnitRef));

    for(UInt32 index = 0; index < lunCount; index++) {
        iSCSILogicalUnitRef unit = LogicalUnitCreate(interface,sessionId,Get64(list + 8 + index * 8));

        if(unit)
            found[(*count)++] = unit;
    }

    free(list);
    *units = found;
    return 0;
}

void iSCSILogicalUnitRelease(iSCSILogicalUnitRef unit)
{
    if(!unit)
        return;

    pthread_mutex_destroy(&unit->unalignedLock);
    pthread_mutex_destroy(&unit->flushLock);
    pthread_cond_destroy(&unit->flushCond);
    free(unit);
}

const iSCSILogicalUnitInfo * iSCSILogicalUnitGetInfo(iSCSILogicalUnitRef unit)
{
    return &unit->info;
}

#pragma mark - Block I/O

/*! Reads or writes whole blocks, splitting the transfer as required. */
static int LogicalUnitTransfer(iSCSILogicalUnitRef unit,
                               bool write,
                               UInt64 block,
                               UInt32 blockCount,
                               void * buffer,
                               bool forceUnitAccess)
{
    UInt8 * cursor = buffer;

    while(blockCount > 0) {
        UInt32 chunk = (blockCount < unit->maxTransferBlocks) ? blockCount : unit->maxTransferBlocks;
        UInt32 length = chunk * unit->info.blockSize;
        UInt8 cdb[16];
        UInt8 cdbLength;
        UInt32 transferred = 0;

        memset(cdb,0,sizeof(cdb));

        if(block + chunk - 1 <= 0xffffffffULL && chunk <= 0xffff) {
            cdb[0] = write ? kSCSIWrite10 : kSCSIRead10;
            Put32(cdb + 2,(UInt32)block);
            Put16(cdb + 7,(UInt16)chunk);
            cdbLength = 10;
        }
        else {
            cdb[0] = write ? kSCSIWrite16 : kSCSIRead16;
            Put64(cdb + 2,block);
            Put32(cdb + 10,chunk);
            cdbLength = 16;
        }

        if(write && forceUnitAccess)
            cdb[1] |= 0x08;

        int error = ExecuteCommand(unit->interface,unit->sessionId,unit->info.LUN,cdb,cdbLength,
                                   write ? kiSCSIHBADataWrite : kiSCSIHBADataRead,
                                   cursor,length,&transferred,NULL);
        if(error)
            return error;

        if(transferred != length) {
            iSCSILogError("short %s of LUN %u: %u of %u bytes (sid %u)",write ? "write" : "read",
                          unit->info.number,(unsigned)transferred,(unsigned)length,unit->sessionId);
            return EIO;
        }

        cursor += length;
        block += chunk;
        blockCount -= chunk;
    }
    return 0;
}

static bool LogicalUnitRangeValid(iSCSILogicalUnitRef unit,UInt64 offset,UInt32 length)
{
    UInt64 size = unit->info.blockCount * unit->info.blockSize;
    return offset <= size && length <= size - offset;
}

/*! Makes sure that what was written so far is on stable storage, sharing
 *  the flush of the cache with other threads that ask for the same. */
static int LogicalUnitFlushShared(iSCSILogicalUnitRef unit)
{
    int error = 0;

    pthread_mutex_lock(&unit->flushLock);
    UInt64 ticket = ++unit->flushTicket;

    while(unit->flushedTicket < ticket) {
        if(unit->flushInProgress) {
            pthread_cond_wait(&unit->flushCond,&unit->flushLock);
            continue;
        }

        // This thread flushes on behalf of all tickets taken so far
        UInt64 covered = unit->flushTicket;
        unit->flushInProgress = true;
        pthread_mutex_unlock(&unit->flushLock);

        error = iSCSILogicalUnitFlush(unit);

        pthread_mutex_lock(&unit->flushLock);
        unit->flushInProgress = false;

        if(!error)
            unit->flushedTicket = covered;

        pthread_cond_broadcast(&unit->flushCond);

        if(error)
            break;
    }

    pthread_mutex_unlock(&unit->flushLock);
    return error;
}

int iSCSILogicalUnitRead(iSCSILogicalUnitRef unit,UInt64 offset,UInt32 length,void * buffer)
{
    if(!unit || !buffer || !LogicalUnitRangeValid(unit,offset,length))
        return EINVAL;

    if(length == 0)
        return 0;

    UInt32 blockSize = unit->info.blockSize;

    if(offset % blockSize == 0 && length % blockSize == 0)
        return LogicalUnitTransfer(unit,false,offset / blockSize,length / blockSize,buffer,false);

    // Read the blocks that enclose the range and copy the range out
    UInt64 firstBlock = offset / blockSize;
    UInt64 lastBlock = (offset + length - 1) / blockSize;
    UInt32 blockCount = (UInt32)(lastBlock - firstBlock + 1);
    UInt8 * bounce = malloc((size_t)blockCount * blockSize);

    if(!bounce)
        return ENOMEM;

    int error = LogicalUnitTransfer(unit,false,firstBlock,blockCount,bounce,false);

    if(!error)
        memcpy(buffer,bounce + (offset - firstBlock * blockSize),length);

    free(bounce);
    return error;
}

int iSCSILogicalUnitWrite(iSCSILogicalUnitRef unit,UInt64 offset,UInt32 length,const void * buffer,bool sync)
{
    if(!unit || !buffer || !LogicalUnitRangeValid(unit,offset,length))
        return EINVAL;

    if(unit->info.readOnly)
        return EROFS;

    if(length == 0)
        return 0;

    UInt32 blockSize = unit->info.blockSize;

    // Synchronous writes bypass the write cache where the unit allows it;
    // otherwise the cache is flushed after the write
    bool forceUnitAccess = sync && unit->info.writeCache && unit->info.forceUnitAccess;
    bool flushAfter = sync && unit->info.writeCache && !unit->info.forceUnitAccess;
    int error;

    if(offset % blockSize == 0 && length % blockSize == 0)
        error = LogicalUnitTransfer(unit,true,offset / blockSize,length / blockSize,(void *)buffer,forceUnitAccess);
    else {
        // Read the blocks at the edges of the range, merge in the new data
        // and write whole blocks back
        UInt64 firstBlock = offset / blockSize;
        UInt64 lastBlock = (offset + length - 1) / blockSize;
        UInt32 blockCount = (UInt32)(lastBlock - firstBlock + 1);
        UInt8 * bounce = malloc((size_t)blockCount * blockSize);

        if(!bounce)
            return ENOMEM;

        pthread_mutex_lock(&unit->unalignedLock);

        error = LogicalUnitTransfer(unit,false,firstBlock,1,bounce,false);

        if(!error && blockCount > 1)
            error = LogicalUnitTransfer(unit,false,lastBlock,1,bounce + (size_t)(blockCount - 1) * blockSize,false);

        if(!error) {
            memcpy(bounce + (offset - firstBlock * blockSize),buffer,length);
            error = LogicalUnitTransfer(unit,true,firstBlock,blockCount,bounce,forceUnitAccess);
        }

        pthread_mutex_unlock(&unit->unalignedLock);
        free(bounce);
    }

    if(!error && flushAfter)
        error = LogicalUnitFlushShared(unit);

    return error;
}

int iSCSILogicalUnitFlush(iSCSILogicalUnitRef unit)
{
    if(!unit)
        return EINVAL;

    if(unit->info.readOnly || !unit->info.writeCache || unit->flushUnsupported)
        return 0;

    // A block count of zero covers everything up to the end of the unit
    UInt8 cdb[16];
    UInt8 senseKey = 0;
    memset(cdb,0,sizeof(cdb));
    cdb[0] = kSCSISynchronizeCache10;

    int error = ExecuteCommand(unit->interface,unit->sessionId,unit->info.LUN,cdb,10,
                               kiSCSIHBADataNone,NULL,0,NULL,&senseKey);

    // Units without a cache may not implement the command at all
    if(error == EINVAL && senseKey == kSenseIllegalRequest) {
        unit->flushUnsupported = true;
        return 0;
    }
    return error;
}
