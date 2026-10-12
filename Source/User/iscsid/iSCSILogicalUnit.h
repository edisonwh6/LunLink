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

#ifndef __ISCSI_LOGICAL_UNIT_H__
#define __ISCSI_LOGICAL_UNIT_H__

#include "iSCSIHBAInterface.h"

/*! A SCSI logical unit of the direct-access (disk) type that is reached
 *  through a session of the HBA.  The logical unit layer issues the SCSI
 *  commands that turn a logical unit into a byte-addressed block device. */
typedef struct __iSCSILogicalUnit * iSCSILogicalUnitRef;

typedef struct __iSCSILogicalUnitInfo {

    /*! The 8-byte SAM logical unit number, in host byte order. */
    UInt64 LUN;

    /*! The logical unit number as it is commonly displayed. */
    UInt32 number;

    char vendor[9];
    char product[17];
    char revision[5];
    char serialNumber[65];

    /*! Size of a logical block, in bytes. */
    UInt32 blockSize;

    /*! Number of logical blocks. */
    UInt64 blockCount;

    /*! The logical unit is write-protected. */
    bool readOnly;

    /*! The logical unit has a volatile write cache. */
    bool writeCache;

    /*! The logical unit can be told to bypass its write cache for a
     *  particular write (force unit access). */
    bool forceUnitAccess;

} iSCSILogicalUnitInfo;

/*! Discovers the direct-access logical units of a session.
 *  @param interface the HBA.
 *  @param sessionId the session to scan.
 *  @param units an array of logical units (returned; release each unit and
 *  free the array when done).
 *  @param count the number of logical units (returned).
 *  @return an error code indicating the result of the operation. */
errno_t iSCSILogicalUnitScan(iSCSIHBAInterfaceRef interface,
                             SessionIdentifier sessionId,
                             iSCSILogicalUnitRef * * units,
                             UInt32 * count);

void iSCSILogicalUnitRelease(iSCSILogicalUnitRef unit);

/*! Chooses when data that is written to a unit with a write cache reaches
 *  stable storage.  By default every write is on stable storage when it
 *  returns.  With deferred flushing a write returns as soon as the unit has
 *  the data in its cache, which is flushed a moment later: much faster, at
 *  the price that the last moments' writes are lost if the unit loses power
 *  just then (the initiator crashing does no harm).
 *  @param unit the logical unit.
 *  @param enable true to defer flushing. */
void iSCSILogicalUnitSetDeferredFlush(iSCSILogicalUnitRef unit,bool enable);

const iSCSILogicalUnitInfo * iSCSILogicalUnitGetInfo(iSCSILogicalUnitRef unit);

/*! Reads from a logical unit.  Offset and length are in bytes and need not
 *  be aligned to the block size.
 *  @return 0, an errno value, or kiSCSIBlockExportErrorTryLater if the
 *  session is being recovered. */
int iSCSILogicalUnitRead(iSCSILogicalUnitRef unit,UInt64 offset,UInt32 length,void * buffer);

/*! Writes to a logical unit.  If sync is true the data is on stable storage
 *  when the function returns.
 *  @return 0, an errno value, or kiSCSIBlockExportErrorTryLater. */
int iSCSILogicalUnitWrite(iSCSILogicalUnitRef unit,UInt64 offset,UInt32 length,const void * buffer,bool sync);

/*! Flushes the write cache of a logical unit to stable storage.
 *  @return 0, an errno value, or kiSCSIBlockExportErrorTryLater. */
int iSCSILogicalUnitFlush(iSCSILogicalUnitRef unit);

#endif /* defined(__ISCSI_LOGICAL_UNIT_H__) */
