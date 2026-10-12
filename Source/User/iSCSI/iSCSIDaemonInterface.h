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

#ifndef __ISCSI_DAEMON_INTERFACE__
#define __ISCSI_DAEMON_INTERFACE__

#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <stdbool.h>
#include <MacTypes.h>

#include "iSCSITypes.h"
#include "iSCSIPreferences.h"

/*! A handle to a connection to the iSCSI daemon (a negative value is
 *  not a valid handle). */
typedef int iSCSIDaemonHandle;

/*! Connects to the iSCSI daemon.
 *  @return a handle that can be used to communicate with the daemon, or a
 *  negative value if the daemon is not running. */
iSCSIDaemonHandle iSCSIDaemonConnect(void);

/*! Connects to the iSCSI daemon, starting it first if it is not running.
 *  @param daemonPath the path of the daemon executable; if NULL, the daemon
 *  is expected next to the executable of the calling process.
 *  @return a handle that can be used to communicate with the daemon, or a
 *  negative value if the daemon could not be started. */
iSCSIDaemonHandle iSCSIDaemonConnectOrLaunch(const char * daemonPath);

/*! Disconnects from the iSCSI daemon.  The handle is freed.
 *  @param handle the handle of the connection to free. */
void iSCSIDaemonDisconnect(iSCSIDaemonHandle handle);

/*! Logs into a target using a specific portal or the portals in the database.
 *  If an argument is supplied for portal, login occurs over the specified
 *  portal.  Otherwise, the daemon tries the portals defined for the target
 *  until one of them works.  The logical units of the target are attached
 *  as disks before the function returns.
 *  @param handle a handle to a daemon connection.
 *  @param target specifies the target to log in to.
 *  @param portal specifies the portal to use (use NULL for any portal).
 *  @param statusCode iSCSI response code indicating operation status.
 *  @return an error code indicating whether the operation was successful. */
errno_t iSCSIDaemonLogin(iSCSIDaemonHandle handle,
                         iSCSITargetRef target,
                         iSCSIPortalRef portal,
                         enum iSCSILoginStatusCode * statusCode);

/*! Detaches the disks of a target and closes its session.
 *  @param handle a handle to a daemon connection.
 *  @param target the target to logout.
 *  @param force logout even if volumes of the target are in use, in which
 *  case data that was not yet written is lost.
 *  @param statusCode iSCSI response code indicating operation status.
 *  @return an error code indicating whether the operation was successful
 *  (EBUSY if a volume of the target is in use). */
errno_t iSCSIDaemonLogout(iSCSIDaemonHandle handle,
                          iSCSITargetRef target,
                          bool force,
                          enum iSCSILogoutStatusCode * statusCode);

/*! Creates an array of active target objects.
 *  @param handle a handle to a daemon connection.
 *  @return an array of active target objects or NULL if the daemon could
 *  not be reached. */
CFArrayRef iSCSIDaemonCreateArrayOfActiveTargets(iSCSIDaemonHandle handle);

/*! Creates an array of active portal objects.
 *  @param handle a handle to a daemon connection.
 *  @param target the target to retrieve active portals.
 *  @return an array of active portal objects or NULL if the daemon could
 *  not be reached. */
CFArrayRef iSCSIDaemonCreateArrayOfActivePortalsForTarget(iSCSIDaemonHandle handle,
                                                          iSCSITargetRef target);

/*! Gets whether a target has an active session.
 *  @param target the target to test for an active session.
 *  @return true if the is an active session for the target; false otherwise. */
Boolean iSCSIDaemonIsTargetActive(iSCSIDaemonHandle handle,
                                  iSCSITargetRef target);

/*! Gets whether a portal has an active session.
 *  @param target the target to test for an active session.
 *  @param portal the portal to test for an active connection.
 *  @return true if the is an active connection for the portal; false otherwise. */
Boolean iSCSIDaemonIsPortalActive(iSCSIDaemonHandle handle,
                                  iSCSITargetRef target,
                                  iSCSIPortalRef portal);

/*! Determines the authentication method that a target asks for.
 *  @param handle a handle to a daemon connection.
 *  @param portal the iSCSI portal to query.
 *  @param targetIQN the name of the target.
 *  @param authMethod the preferred authentication method.
 *  @param statusCode iSCSI response code indicating operation status.
 *  @return an error code indicating whether the operation was successful. */
errno_t iSCSIDaemonQueryTargetForAuthMethod(iSCSIDaemonHandle handle,
                                            iSCSIPortalRef portal,
                                            CFStringRef targetIQN,
                                            enum iSCSIAuthMethods * authMethod,
                                            enum iSCSILoginStatusCode * statusCode);

/*! Queries a portal for the targets that it offers (SendTargets discovery).
 *  The result is not recorded in the database.
 *  @param handle a handle to a daemon connection.
 *  @param portal the iSCSI portal to query.
 *  @param discoveryRec the targets and their portals (returned; release it).
 *  @param statusCode iSCSI response code indicating operation status.
 *  @return an error code indicating whether the operation was successful. */
errno_t iSCSIDaemonQueryPortalForTargets(iSCSIDaemonHandle handle,
                                         iSCSIPortalRef portal,
                                         iSCSIDiscoveryRecRef * discoveryRec,
                                         enum iSCSILoginStatusCode * statusCode);

/*! Creates a dictionary of session parameters for the session associated with
 *  the specified target, if one exists.
 *  @param handle a handle to a daemon connection.
 *  @param target the target to check for associated sessions to generate
 *  a dictionary of session parameters.
 *  @return a dictionary of session properties. */
CFDictionaryRef iSCSIDaemonCreateCFPropertiesForSession(iSCSIDaemonHandle handle,
                                                        iSCSITargetRef target);

/*! Creates a dictionary of connection parameters for the connection associated
 *  with the specified target and portal, if one exists.
 *  @param handle a handle to a daemon connection.
 *  @param target the target associated with the the specified portal.
 *  @param portal the portal to check for active connections to generate
 *  a dictionary of connection parameters.
 *  @return a dictionary of connection properties. */
CFDictionaryRef iSCSIDaemonCreateCFPropertiesForConnection(iSCSIDaemonHandle handle,
                                                           iSCSITargetRef target,
                                                           iSCSIPortalRef portal);

/*! Creates an array of dictionaries that describe the disks (logical units)
 *  of an active target.  See the kiSCSIDisk keys of iSCSITypes.h.
 *  @param handle a handle to a daemon connection.
 *  @param target the target.
 *  @return an array of dictionaries or NULL if the daemon could not be reached. */
CFArrayRef iSCSIDaemonCreateArrayOfDisksForTarget(iSCSIDaemonHandle handle,
                                                  iSCSITargetRef target);

/*! Forces daemon to update discovery parameters from property list and to
 *  run discovery (if enabled) right away.
 *  @param handle a handle to a daemon connection.
 *  @return an error code indicating whether the operationg was successful. */
errno_t iSCSIDaemonUpdateDiscovery(iSCSIDaemonHandle handle);

/*! Semaphore that allows a client exclusive accesss to the property list
 *  that contains iSCSI configuraiton parameters and targets. Forces the provided
 *  preferences object to synchronize with property list on the disk.
 *  @param handle a handle to a daemon connection.
 *  @param preferences the preferences to be synchronized
 *  @return an error code indicating whether the operating was successful. */
errno_t iSCSIDaemonPreferencesIOLockAndSync(iSCSIDaemonHandle handle,
                                            iSCSIPreferencesRef preferences);

/*! Synchronizes cached preference changes to disk and releases the locked
 *  semaphore, allowing other clients to make changes. If the prefereneces
 *  parameter is NULL, then no changes are made to disk and the semaphore is
 *  unlocked.
 *  @param handle a handle to a daemon connection.
 *  @param preferences the preferences to be synchronized
 *  @return an error code indicating whether the operating was successful. */
errno_t iSCSIDaemonPreferencesIOUnlockAndSync(iSCSIDaemonHandle handle,
                                              iSCSIPreferencesRef preferences);

/*! Sets or updates a shared secret.
 *  @param handle a handle to a daemon connection.
 *  @param nodeIQN the node iSCSI qualified name.
 *  @param sharedSecret the secret to set.
 *  @return an error code indicating whether the operating was successful. */
errno_t iSCSIDaemonSetSharedSecret(iSCSIDaemonHandle handle,
                                   CFStringRef nodeIQN,
                                   CFStringRef sharedSecret);

/*! Removes a shared secret.
 *  @param handle a handle to a daemon connection.
 *  @param nodeIQN the node iSCSI qualified name.
 *  @return an error code indicating whether the operating was successful. */
errno_t iSCSIDaemonRemoveSharedSecret(iSCSIDaemonHandle handle,
                                      CFStringRef nodeIQN);

/*! Gets information about the daemon (see the kiSCSIDStatus keys of
 *  iSCSIDaemonInterfaceShared.h).
 *  @param handle a handle to a daemon connection.
 *  @return a dictionary or NULL if the daemon could not be reached. */
CFDictionaryRef iSCSIDaemonCreateStatus(iSCSIDaemonHandle handle);

/*! Asks the daemon to log out of all targets and to exit.  Disks whose
 *  volumes are in use are detached nevertheless.
 *  @param handle a handle to a daemon connection.
 *  @return an error code indicating whether the operating was successful. */
errno_t iSCSIDaemonShutdown(iSCSIDaemonHandle handle);

#endif /* defined(__ISCSI_DAEMON_INTERFACE__) */
