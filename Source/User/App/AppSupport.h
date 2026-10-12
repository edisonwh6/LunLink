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

#ifndef __ISCSI_APP_SUPPORT_H__
#define __ISCSI_APP_SUPPORT_H__

#include <CoreFoundation/CoreFoundation.h>
#include <stdbool.h>

#include "iSCSI.h"

// A property-list oriented facade of the iSCSI client library for the
// graphical application: state comes out as dictionaries and arrays, and
// changes go in the same way.  This keeps the memory management of Core
// Foundation objects in C and out of the Swift code.

CF_IMPLICIT_BRIDGING_ENABLED

/*! Creates a snapshot of the configuration and state of the initiator:
 *
 *    Daemon      { Running, Version, ProcessID }
 *    Initiator   { Name, Alias, CHAP, CHAPName, HasSecret }
 *    Discovery   { Enabled, Interval, Portals [ { Address, Port, Interface } ] }
 *    Targets   [ { IQN, Alias, Dynamic, DiscoveryPortal, AutoLogin, Persistent,
 *                  ReadOnly, HeaderDigest, DataDigest, InitiatorAuth ("Default",
 *                  "None" or "CHAP"), InitiatorCHAPName, HasInitiatorSecret,
 *                  MutualCHAP, TargetCHAPName, HasTargetSecret,
 *                  Portals [ { Address, Port, Interface, Active } ],
 *                  Session { ... } (if logged in), Disks [ { ... } ] } ]
 *
 *  @param handle a handle to a daemon connection (negative if the daemon
 *  is not running, in which case the snapshot holds the configuration only).
 *  @return the snapshot. */
CFDictionaryRef iSCSIAppCopySnapshot(iSCSIDaemonHandle handle);

/*! Queries a portal for the targets that it offers.
 *  @param error an error code (returned).
 *  @param statusCode the iSCSI login status (returned).
 *  @return an array of { IQN, Portals [ { Address, Port } ] } or NULL. */
CFArrayRef iSCSIAppCopyDiscoveredTargets(iSCSIDaemonHandle handle,
                                         CFStringRef portal,
                                         int * error,
                                         int * statusCode);

/*! Copies the path of the socket on which the daemon accepts requests. */
CFStringRef iSCSIAppCopyDaemonSocketPath(void);

/*! Copies the path of the log file of the daemon. */
CFStringRef iSCSIAppCopyDaemonLogPath(void);

/*! Copies a description of an iSCSI login status code. */
CFStringRef iSCSIAppCopyLoginStatusDescription(int statusCode);

CF_IMPLICIT_BRIDGING_DISABLED

/*! Logs in to a target.
 *  @param statusCode the iSCSI login status (returned).
 *  @return an error code indicating the result of the operation. */
int iSCSIAppLogin(iSCSIDaemonHandle handle,CFStringRef targetIQN,int * statusCode);

/*! Logs out of a target.
 *  @param force logout even if volumes of the target are in use. */
int iSCSIAppLogout(iSCSIDaemonHandle handle,CFStringRef targetIQN,bool force);

/*! Adds a target, or a portal to an existing target.
 *  @param portal the portal ("<address>[:<port>]"). */
int iSCSIAppAddTarget(iSCSIDaemonHandle handle,CFStringRef targetIQN,CFStringRef portal);

/*! Removes a target along with its settings and secrets. */
int iSCSIAppRemoveTarget(iSCSIDaemonHandle handle,CFStringRef targetIQN);

/*! Changes settings of a target.  The dictionary holds the settings to
 *  change, using the keys of the snapshot; in addition, the keys
 *  InitiatorSecret and TargetSecret set the respective CHAP secrets. */
int iSCSIAppUpdateTarget(iSCSIDaemonHandle handle,CFStringRef targetIQN,CFDictionaryRef settings);

/*! Changes settings of the initiator (keys: Name, Alias, CHAP, CHAPName,
 *  Secret). */
int iSCSIAppUpdateInitiator(iSCSIDaemonHandle handle,CFDictionaryRef settings);

/*! Changes settings of discovery (keys: Enabled, Interval). */
int iSCSIAppUpdateDiscovery(iSCSIDaemonHandle handle,CFDictionaryRef settings);

/*! Adds a discovery portal ("<address>[:<port>]"). */
int iSCSIAppAddDiscoveryPortal(iSCSIDaemonHandle handle,CFStringRef portal);

/*! Removes a discovery portal along with the targets that it contributed
 *  (none of which may be logged in). */
int iSCSIAppRemoveDiscoveryPortal(iSCSIDaemonHandle handle,CFStringRef address);

#endif /* defined(__ISCSI_APP_SUPPORT_H__) */
