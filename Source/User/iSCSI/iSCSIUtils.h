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

#ifndef __ISCSI_UTILS_H__
#define __ISCSI_UTILS_H__

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/scsi/SCSICmds_INQUIRY_Definitions.h>
#include <stdbool.h>

#include <netdb.h>
#include <regex.h>

#include "iSCSITypes.h"

struct sockaddr_storage;

/*! Verifies whether specified iSCSI qualified name (IQN) is valid per RFC3720.
 *  This function also validates 64-bit EUI names expressed as strings that
 *  start with the "eui" prefix.
 *  @param IQN the iSCSI qualified name.
 *  @return true if the name is valid, false otherwise. */
Boolean iSCSIUtilsValidateIQN(CFStringRef IQN);

/*! Validates the TCP port.
 *  @param port the TCP port to validate.
 *  @return true if the specified port is valid, false otherwise. */
Boolean iSCSIUtilsValidatePort(CFStringRef port);

/*! Validates and parses an expression of the form <host>:<port> into its
 *  hostname (or IPv4/IPv6 address) and port.  This function will return
 *  NULL if the specified expression is malformed, or an array containing
 *  either one or two elements (one if the portal is absent, two if it was
 *  specified).
 *  @param portal a string of the form <host>:<port>
 *  @return an array containing one or both portal parts, or NULL if the 
 *  specified portal was malformed. */
CFArrayRef iSCSIUtilsCreateArrayByParsingPortalParts(CFStringRef portal);

/*! Gets the SCSI peripheral description from a peripheral device type code.
 *  @param peripheralDeviceType the single byte peripheral device descriptor
 *  as outlined in the SPC-4 r36d.
 *  @return a string describing the device (guaranteed to be a valid string). */
CFStringRef iSCSIUtilsGetSCSIPeripheralDeviceDescription(UInt8 peripheralDeviceType);

/*! Gets a string describing the iSCSI login status.
 *  @param statusCode the login status code.
 *  @return a string describing the login status (guaranteed to be a valid string). */
CFStringRef iSCSIUtilsGetStringForLoginStatus(enum iSCSILoginStatusCode statusCode);

/*! Gets a string describing the iSCSI logout status.
 *  @param statusCode the logout status code.
 *  @return a string describing the login status (guaranteed to be a valid string). */
CFStringRef iSCSIUtilsGetStringForLogoutStatus(enum iSCSILogoutStatusCode statusCode);

/*! Creates address structures for an iSCSI target and the host (initiator)
 *  given an iSCSI portal reference. This function may be helpful when
 *  interfacing to low-level C networking APIs or other foundation libraries.
 *  @param portal an iSCSI portal.
 *  @param the target address structure (returned by this function).
 *  @param the host address structure (returned by this function). */
errno_t iSCSIUtilsGetAddressForPortal(iSCSIPortalRef portal,
                                      struct sockaddr_storage * remoteAddress,
                                      struct sockaddr_storage * localAddress);

/*! Gets the directory that holds the run-time files of the initiator: the
 *  socket of the daemon and the mount point of the disk export.  The
 *  directory is private to the user and is created if it does not exist. It
 *  can be overridden using the environment variable ISCSI_RUNTIME_DIR.
 *  @param path buffer for the path.
 *  @param size size of the buffer.
 *  @return true if the directory is available. */
bool iSCSIUtilsGetRuntimeDirectory(char * path,size_t size);

/*! Gets the path of a local socket with the specified name.  The socket is
 *  located in the run-time directory unless the resulting path would be
 *  too long for a socket address, in which case it is placed in the
 *  temporary directory of the user.
 *  @param name the file name of the socket.
 *  @param path buffer for the path.
 *  @param size size of the buffer.
 *  @return true if the path was determined. */
bool iSCSIUtilsGetSocketPath(const char * name,char * path,size_t size);

/*! Creates a portal from a string of the form "<address>[:<port>]", where
 *  the address is a host name, an IPv4 address or an IPv6 address (which
 *  must be enclosed in brackets if a port is specified).
 *  @param string the string to parse.
 *  @param hostInterface the host interface to use (NULL for the default).
 *  @return a portal or NULL if the string is not a valid portal. */
iSCSIMutablePortalRef iSCSIUtilsCreatePortalWithString(CFStringRef string,CFStringRef hostInterface);

/*! Gets the path of the log file of the daemon (when it is not started by
 *  launchd, which has its own idea of where output goes).  The directory
 *  of the file is created if it does not exist.
 *  @param path buffer for the path.
 *  @param size size of the buffer.
 *  @return true if the path was determined. */
bool iSCSIUtilsGetLogPath(char * path,size_t size);

/*! File name of the socket on which the daemon accepts requests. */
#define kiSCSIDaemonSocketName "iscsid.sock"

#endif /* defined(__ISCSI_UTILS_H__) */
