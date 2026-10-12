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

#ifndef __ISCSI_KEYCHAIN_H__
#define __ISCSI_KEYCHAIN_H__

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// CHAP shared secrets are kept in the login keychain of the user, as
// generic passwords of the service "LunLink".  Each secret belongs
// to a node, which is named by:
//
//  - the name of a target, for the secret by which that target proves its
//    identity to the initiator (mutual CHAP);
//  - the name of the initiator, for the secret by which the initiator
//    proves its identity to targets in general;
//  - the name returned by iSCSIKeychainCreateNodeForInitiatorOfTarget(),
//    for the secret by which the initiator proves its identity to one
//    particular target.
//
// If the environment variable ISCSI_SECRETS_FILE is set, secrets are kept
// in the property list file that it names instead of the keychain (for use
// where no keychain is available, e.g., in automated tests).

/*! Creates the name of the node whose secret the initiator uses to prove
 *  its identity to a particular target.
 *  @param targetIQN the iSCSI qualified name of the target.
 *  @return the name of the node (release it when done). */
CFStringRef iSCSIKeychainCreateNodeForInitiatorOfTarget(CFStringRef targetIQN);

/*! Copies a shared secret associated with a particular iSCSI node.
 *  @param nodeIQN the name of the node.
 *  @return the shared secret for the specified node, or NULL. */
CFStringRef iSCSIKeychainCopyCHAPSecretForNode(CFStringRef nodeIQN);

/*! Updates the shared secret associated with a particular iSCSI node.
 *  An entry for the node is created if it does not exist.
 *  @param nodeIQN the name of the node.
 *  @param sharedSecret the shared secret to store.
 *  @return error code indicating the result of the operation. */
OSStatus iSCSIKeychainSetCHAPSecretForNode(CFStringRef nodeIQN,
                                           CFStringRef sharedSecret);

/*! Removes the shared secret associated with a particular iSCSI node.
 *  @param nodeIQN the name of the node.
 *  @return error code indicating the result of the operation. */
OSStatus iSCSIKeychainDeleteCHAPSecretForNode(CFStringRef nodeIQN);

/*! Gets whether a CHAP secret exists for the specified node.
 *  @param nodeIQN the node to test.
 *  @return true if a CHAP secret exists for the specified node. */
Boolean iSCSIKeychainContainsCHAPSecretForNode(CFStringRef nodeIQN);

#endif /* defined(__ISCSI_KEYCHAIN_H__) */
