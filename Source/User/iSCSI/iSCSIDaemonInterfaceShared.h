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

#ifndef __ISCSI_DAEMON_INTERFACE_SHARED_H__
#define __ISCSI_DAEMON_INTERFACE_SHARED_H__

#include <CoreFoundation/CoreFoundation.h>

#include "iSCSITypes.h"
#include "iSCSITypesShared.h"

// The daemon and its clients exchange messages over a local stream socket.
// A message is a dictionary, encoded as a binary property list and preceded
// by its length (a 32-bit integer in network byte order).  A request names
// the function to carry out along with its arguments; the response carries
// an error code along with the results.

/*! Largest message that is accepted. */
#define kiSCSIDMaxMessageLength (16 * 1024 * 1024)

// Keys of requests
#define kiSCSIDKeyFunction      CFSTR("Function")
#define kiSCSIDKeyTarget        CFSTR("Target")         // dictionary (iSCSITarget)
#define kiSCSIDKeyPortal        CFSTR("Portal")         // dictionary (iSCSIPortal)
#define kiSCSIDKeyTargetIQN     CFSTR("Target IQN")     // string
#define kiSCSIDKeyNode          CFSTR("Node")           // string
#define kiSCSIDKeySecret        CFSTR("Secret")         // string
#define kiSCSIDKeyPreferences   CFSTR("Preferences")    // data
#define kiSCSIDKeyForce         CFSTR("Force")          // boolean

// Keys of responses
#define kiSCSIDKeyError         CFSTR("Error")          // number (errno)
#define kiSCSIDKeyStatusCode    CFSTR("Status Code")    // number
#define kiSCSIDKeyActive        CFSTR("Active")         // boolean
#define kiSCSIDKeyAuthMethod    CFSTR("Auth Method")    // number
#define kiSCSIDKeyResult        CFSTR("Result")         // array or dictionary

// Functions
#define kiSCSIDFunctionLogin                    CFSTR("Login")
#define kiSCSIDFunctionLogout                   CFSTR("Logout")
#define kiSCSIDFunctionActiveTargets            CFSTR("ActiveTargets")
#define kiSCSIDFunctionActivePortals            CFSTR("ActivePortals")
#define kiSCSIDFunctionIsTargetActive           CFSTR("IsTargetActive")
#define kiSCSIDFunctionIsPortalActive           CFSTR("IsPortalActive")
#define kiSCSIDFunctionSessionProperties        CFSTR("SessionProperties")
#define kiSCSIDFunctionConnectionProperties     CFSTR("ConnectionProperties")
#define kiSCSIDFunctionDisks                    CFSTR("Disks")
#define kiSCSIDFunctionQueryAuthMethod          CFSTR("QueryAuthMethod")
#define kiSCSIDFunctionQueryPortalForTargets    CFSTR("QueryPortalForTargets")
#define kiSCSIDFunctionUpdateDiscovery          CFSTR("UpdateDiscovery")
#define kiSCSIDFunctionPreferencesLock          CFSTR("PreferencesLock")
#define kiSCSIDFunctionPreferencesUnlock        CFSTR("PreferencesUnlock")
#define kiSCSIDFunctionSetSharedSecret          CFSTR("SetSharedSecret")
#define kiSCSIDFunctionRemoveSharedSecret       CFSTR("RemoveSharedSecret")
#define kiSCSIDFunctionStatus                   CFSTR("Status")
#define kiSCSIDFunctionShutdown                 CFSTR("Shutdown")

// Keys of the dictionary returned by the status function
#define kiSCSIDStatusVersion    CFSTR("Version")        // string
#define kiSCSIDStatusProcessId  CFSTR("Process ID")     // number

/*! Sends a message.
 *  @param fd the socket.
 *  @param message the message.
 *  @return an error code indicating the result of the operation. */
errno_t iSCSIDaemonSendMessage(int fd,CFDictionaryRef message);

/*! Receives a message.
 *  @param fd the socket.
 *  @param message the message (returned; release it when done).
 *  @return an error code indicating the result of the operation; ECONNRESET
 *  if the peer closed the connection. */
errno_t iSCSIDaemonReceiveMessage(int fd,CFDictionaryRef * message);

#endif /* defined(__ISCSI_DAEMON_INTERFACE_SHARED_H__) */
