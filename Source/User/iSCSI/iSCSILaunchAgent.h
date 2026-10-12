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

#ifndef __ISCSI_LAUNCH_AGENT_H__
#define __ISCSI_LAUNCH_AGENT_H__

#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>

// The iSCSI daemon can be registered with launchd as an agent of the user.
// It is then started when the user logs in (which is when targets that are
// configured for automatic login get connected) and whenever a client
// connects to its socket.

CF_IMPLICIT_BRIDGING_ENABLED

/*! Copies the path of the daemon executable that the launch agent starts.
 *  @return the path, or NULL if the launch agent is not installed. */
CFStringRef iSCSILaunchAgentCopyDaemonPath(void);

CF_IMPLICIT_BRIDGING_DISABLED

/*! Has launchd start the daemon, for as long as the user stays logged in
 *  (the launch agent, in contrast, is there again the next time).
 *
 *  A process is part of whatever started it as far as the system goes: a
 *  daemon that an application starts keeps the application in the Dock once
 *  the application has quit, and is put to an end along with it if the user
 *  then quits it for good.  A job of launchd stands on its own.
 *  @param daemonPath the path to the executable of the daemon.
 *  @return an error code indicating the result of the operation. */
errno_t iSCSILaunchAgentStartDaemon(const char * daemonPath);

/*! Has launchd let go of the job by which it ran the daemon, once the
 *  daemon was told to shut down (or else the daemon is put to an end). */
void iSCSILaunchAgentRetireDaemon(void);

/*! Installs the launch agent and has launchd start the daemon.  No daemon
 *  must be running at the time, since launchd takes over its socket.
 *  Variables of the environment that configure the initiator (those whose
 *  names start with ISCSI_) are passed on to the daemon.
 *  @param daemonPath the path of the daemon executable.
 *  @return an error code indicating the result of the operation. */
errno_t iSCSILaunchAgentInstall(const char * daemonPath);

/*! Removes the launch agent, which stops the daemon that it started.
 *  @return an error code indicating the result of the operation. */
errno_t iSCSILaunchAgentRemove(void);

#endif /* defined(__ISCSI_LAUNCH_AGENT_H__) */
