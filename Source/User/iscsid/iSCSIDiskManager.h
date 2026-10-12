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

#ifndef __ISCSI_DISK_MANAGER_H__
#define __ISCSI_DISK_MANAGER_H__

#include <CoreFoundation/CoreFoundation.h>

#include "iSCSIHBAInterface.h"
#include "iSCSITypes.h"

/*! The disk manager turns the logical units of iSCSI sessions into disks
 *  of the system (/dev/disk nodes), without any kernel code of its own:
 *
 *    1. each logical unit is published as a file by a block export, which
 *       is a small NFS server that listens on a local socket;
 *    2. the export is mounted using the NFS client built into macOS;
 *    3. the files are attached as raw disk images.
 *
 *  From there on the system treats a logical unit like any other disk: it
 *  can be partitioned, formatted and its volumes are mounted. */
typedef struct __iSCSIDiskManager * iSCSIDiskManagerRef;

/*! Creates a disk manager.  Disks that were left behind by a previous
 *  instance that did not shut down cleanly are detached.
 *  @param interface the HBA through which logical units are reached.
 *  @return a disk manager or NULL if one could not be created. */
iSCSIDiskManagerRef iSCSIDiskManagerCreate(iSCSIHBAInterfaceRef interface);

/*! Forcibly detaches all disks and releases the disk manager. */
void iSCSIDiskManagerRelease(iSCSIDiskManagerRef manager);

/*! Scans a session for logical units and attaches them as disks. Volumes
 *  on the disks are mounted in the background.
 *  @param manager the disk manager.
 *  @param sessionId the session identifier.
 *  @param targetIQN the name of the target (used to name the disks).
 *  @param readOnly attach the disks read-only, even if the logical units
 *  can be written to.
 *  @return an error code indicating the result of the operation. */
errno_t iSCSIDiskManagerAttachSession(iSCSIDiskManagerRef manager,
                                      SessionIdentifier sessionId,
                                      CFStringRef targetIQN,
                                      bool readOnly);

/*! Unmounts the volumes of the disks of a session and detaches the disks.
 *  @param manager the disk manager.
 *  @param sessionId the session identifier.
 *  @param force detach even if volumes are in use (data may be lost).
 *  @return 0, or EBUSY if a volume is in use (in which case all disks of
 *  the session remain attached). */
errno_t iSCSIDiskManagerDetachSession(iSCSIDiskManagerRef manager,
                                      SessionIdentifier sessionId,
                                      bool force);

/*! Creates an array of dictionaries that describe the disks of a session.
 *  @param manager the disk manager.
 *  @param sessionId the session identifier.
 *  @return an array of dictionaries (see the kiSCSIDisk keys of iSCSITypes.h). */
CFArrayRef iSCSIDiskManagerCopyDisksForSession(iSCSIDiskManagerRef manager,
                                               SessionIdentifier sessionId);

/*! Flushes the write caches of all attached logical units. */
void iSCSIDiskManagerFlushAll(iSCSIDiskManagerRef manager);

#endif /* defined(__ISCSI_DISK_MANAGER_H__) */
