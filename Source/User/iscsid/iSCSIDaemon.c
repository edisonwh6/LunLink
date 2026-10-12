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

/* The iSCSI daemon.
 *
 * The daemon runs with the privileges of the user.  It owns the iSCSI
 * sessions (through the user-space HBA), turns the logical units of targets
 * into disks (through the disk manager) and serves requests of its clients:
 * the command-line tool and the graphical application.
 *
 * Threads:
 *  - the main thread runs a run loop that delivers notifications of the HBA
 *    and of the system (sleep and wake);
 *  - a listener thread accepts clients, each of which is served by a thread
 *    of its own;
 *  - a housekeeping thread recovers sessions that lost their connection,
 *    retries logins that are pending and runs discovery.
 *
 * Operations that change the state of the daemon are serialized by the
 * operation lock.  Queries about sessions and disks do not take it, so that
 * clients are answered while a lengthy operation is underway. */

// BSD includes
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <launch.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// Foundation includes
#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>

// I/O Kit includes
#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPMLib.h>

// iSCSI includes
#include "iSCSISession.h"
#include "iSCSIDaemonInterface.h"
#include "iSCSIDaemonInterfaceShared.h"
#include "iSCSIPreferences.h"
#include "iSCSIDiscovery.h"
#include "iSCSIDiskManager.h"
#include "iSCSIKeychain.h"
#include "iSCSIUtils.h"
#include "iSCSILog.h"

#ifndef ISCSI_VERSION
#define ISCSI_VERSION "unknown"
#endif

/*! Time for which the daemon tries to re-establish a session that lost its
 *  connection.  I/O to the disks of the session is suspended meanwhile;
 *  thereafter the disks are detached. */
static int recoveryTimeoutSec = 120;

/*! Interval between attempts to re-establish a session. */
static const int kRecoveryIntervalSec = 3;

/*! Intervals between attempts of a pending login. */
static const int kPendingLoginIntervalMinSec = 5;
static const int kPendingLoginIntervalMaxSec = 60;

/*! Time a client may hold on to the preferences lock. */
static const int kPreferencesLockTimeoutSec = 30;

/*! Used to manage iSCSI sessions. */
static iSCSISessionManagerRef sessionManager = NULL;

/*! Used to attach the logical units of sessions as disks. */
static iSCSIDiskManagerRef diskManager = NULL;

/*! Serializes operations that change the state of the daemon and protects
 *  the preferences object below. */
static pthread_mutex_t operationLock = PTHREAD_MUTEX_INITIALIZER;

/*! Preferences object used to syncrhonize iSCSI preferences. */
static iSCSIPreferencesRef preferences = NULL;

/*! A client that modifies the preferences holds this (logical) lock, which
 *  keeps the daemon and other clients from writing to the property list. */
static pthread_mutex_t preferencesLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t preferencesCond = PTHREAD_COND_INITIALIZER;
static int preferencesOwner = -1;
static time_t preferencesLockTime = 0;

/*! A session that lost its connection and is being re-established. */
struct Recovery {
    struct Recovery * next;
    SessionIdentifier sessionId;
    iSCSIPortalRef portal;
    time_t startTime;
    time_t nextAttempt;
};

/*! A target to log in to as soon as it can be reached. */
struct PendingLogin {
    struct PendingLogin * next;
    CFStringRef targetIQN;
    time_t nextAttempt;
    int interval;
};

/*! Protects the state of the housekeeping thread. */
static pthread_mutex_t housekeepingLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t housekeepingCond = PTHREAD_COND_INITIALIZER;
static struct Recovery * recoveries = NULL;
static struct PendingLogin * pendingLogins = NULL;
static time_t nextDiscoveryTime = 0;
static bool discoveryRequested = false;
static bool shuttingDown = false;

/*! Used to notify daemon of power state changes. */
static io_connect_t powerPlaneRoot;
static io_object_t powerNotifier;
static IONotificationPortRef powerNotifyPortRef;

/*! Held (shared) while a request of a client is processed, and taken
 *  (exclusively) by the main thread before it tears down the daemon. */
static pthread_rwlock_t requestLock = PTHREAD_RWLOCK_INITIALIZER;
static bool terminated = false;

/*! The socket on which clients connect, and its path if the daemon created
 *  the socket itself (as opposed to launchd). */
static int listenFd = -1;
static char listenPath[sizeof(((struct sockaddr_un *)0)->sun_path)] = "";
static ino_t listenInode = 0;

#pragma mark - Helpers

/*! Writes a message that involves Core Foundation objects to the log. */
static void iSCSIDLog(enum iSCSILogLevel level,CFStringRef format,...)
{
    va_list arguments;
    va_start(arguments,format);
    CFStringRef message = CFStringCreateWithFormatAndArguments(kCFAllocatorDefault,NULL,format,arguments);
    va_end(arguments);

    CFIndex length = CFStringGetMaximumSizeForEncoding(CFStringGetLength(message),kCFStringEncodingUTF8) + 1;
    char buffer[length];

    if(CFStringGetCString(message,buffer,length,kCFStringEncodingUTF8))
        iSCSILog(level,"%s",buffer);

    CFRelease(message);
}

static void iSCSIDWakeHousekeeping(void)
{
    pthread_mutex_lock(&housekeepingLock);
    pthread_cond_broadcast(&housekeepingCond);
    pthread_mutex_unlock(&housekeepingLock);
}

/*! Helper function. Updates the preferences object using application values.
 *  The operation lock must be held. */
static void iSCSIDUpdatePreferencesFromAppValues(void)
{
    if(preferences != NULL)
        iSCSIPreferencesRelease(preferences);

    preferences = iSCSIPreferencesCreateFromAppValues();
}

/*! Acquires the preferences lock on behalf of the daemon itself.
 *  @param waitSec time to wait for a client to release the lock.
 *  @return true if the lock was acquired. */
static bool iSCSIDPreferencesLockForDaemon(int waitSec)
{
    time_t deadline = time(NULL) + waitSec;
    bool acquired = false;

    pthread_mutex_lock(&preferencesLock);

    for(;;) {
        // A client that sits on the lock for too long loses it
        if(preferencesOwner >= 0 && time(NULL) - preferencesLockTime >= kPreferencesLockTimeoutSec)
            preferencesOwner = -1;

        if(preferencesOwner < 0) {
            preferencesOwner = INT32_MAX;
            preferencesLockTime = time(NULL);
            acquired = true;
            break;
        }

        if(time(NULL) >= deadline)
            break;

        struct timespec interval = { 0, 200 * 1000000L };
        pthread_cond_timedwait_relative_np(&preferencesCond,&preferencesLock,&interval);
    }
    pthread_mutex_unlock(&preferencesLock);
    return acquired;
}

static void iSCSIDPreferencesUnlock(int owner)
{
    pthread_mutex_lock(&preferencesLock);

    if(preferencesOwner == owner) {
        preferencesOwner = -1;
        pthread_cond_broadcast(&preferencesCond);
    }
    pthread_mutex_unlock(&preferencesLock);
}

/*! Applies the initiator name and alias of the preferences to new sessions.
 *  The operation lock must be held. */
static void iSCSIDUpdateInitiatorIdentity(void)
{
    CFStringRef initiatorIQN = iSCSIPreferencesCopyInitiatorIQN(preferences);

    if(initiatorIQN) {
        iSCSISessionManagerSetInitiatorName(sessionManager,initiatorIQN);
        CFRelease(initiatorIQN);
    }

    CFStringRef initiatorAlias = iSCSIPreferencesCopyInitiatorAlias(preferences);

    if(initiatorAlias) {
        iSCSISessionManagerSetInitiatorAlias(sessionManager,initiatorAlias);
        CFRelease(initiatorAlias);
    }
}

#pragma mark - Session configuration

static iSCSISessionConfigRef iSCSIDCreateSessionConfig(CFStringRef targetIQN)
{
    iSCSIMutableSessionConfigRef config = iSCSISessionConfigCreateMutable();

    iSCSISessionConfigSetErrorRecoveryLevel(config,iSCSIPreferencesGetErrorRecoveryLevelForTarget(preferences,targetIQN));
    iSCSISessionConfigSetMaxConnections(config,iSCSIPreferencesGetMaxConnectionsForTarget(preferences,targetIQN));

    return config;
}

static iSCSIConnectionConfigRef iSCSIDCreateConnectionConfig(CFStringRef targetIQN)
{
    iSCSIMutableConnectionConfigRef config = iSCSIConnectionConfigCreateMutable();

    enum iSCSIDigestTypes digestType;

    digestType = iSCSIPreferencesGetDataDigestForTarget(preferences,targetIQN);

    if(digestType == kiSCSIDigestInvalid)
        digestType = kiSCSIDigestNone;

    iSCSIConnectionConfigSetDataDigest(config,digestType);

    digestType = iSCSIPreferencesGetHeaderDigestForTarget(preferences,targetIQN);

    if(digestType == kiSCSIDigestInvalid)
        digestType = kiSCSIDigestNone;

    iSCSIConnectionConfigSetHeaderDigest(config,digestType);

    return config;
}

/*! Creates the authentication by which the target proves its identity to
 *  the initiator (mutual CHAP), per the configuration of the target. */
static iSCSIAuthRef iSCSIDCreateAuthenticationForTarget(CFStringRef targetIQN)
{
    iSCSIAuthRef auth = NULL;

    if(iSCSIPreferencesGetTargetAuthenticationMethod(preferences,targetIQN) == kiSCSIAuthMethodCHAP)
    {
        CFStringRef name = iSCSIPreferencesCopyTargetCHAPName(preferences,targetIQN);
        CFStringRef sharedSecret = iSCSIKeychainCopyCHAPSecretForNode(targetIQN);

        if(!name || CFStringGetLength(name) == 0)
            iSCSIDLog(kiSCSILogWarning,CFSTR("CHAP name of target %@ has not been set, the target will not be authenticated"),targetIQN);
        else if(!sharedSecret)
            iSCSIDLog(kiSCSILogWarning,CFSTR("CHAP secret of target %@ is not available, the target will not be authenticated"),targetIQN);
        else
            auth = iSCSIAuthCreateCHAP(name,sharedSecret);

        if(name)
            CFRelease(name);
        if(sharedSecret)
            CFRelease(sharedSecret);
    }

    return auth ? auth : iSCSIAuthCreateNone();
}

/*! Creates the authentication by which the initiator proves its identity
 *  to a target.  Credentials that were set for the target in particular
 *  take precedence over those of the initiator in general.
 *  @param targetIQN the target (NULL for the general credentials). */
static iSCSIAuthRef iSCSIDCreateAuthenticationForInitiator(CFStringRef targetIQN)
{
    iSCSIAuthRef auth = NULL;
    CFStringRef name = NULL, node = NULL;

    enum iSCSIAuthMethods authMethod = targetIQN ?
        iSCSIPreferencesGetInitiatorAuthenticationMethodForTarget(preferences,targetIQN) : kiSCSIAuthMethodInvalid;

    if(authMethod == kiSCSIAuthMethodNone)
        return iSCSIAuthCreateNone();

    if(authMethod == kiSCSIAuthMethodCHAP) {
        name = iSCSIPreferencesCopyInitiatorCHAPNameForTarget(preferences,targetIQN);
        node = iSCSIKeychainCreateNodeForInitiatorOfTarget(targetIQN);
    }
    else if(iSCSIPreferencesGetInitiatorAuthenticationMethod(preferences) == kiSCSIAuthMethodCHAP) {
        name = iSCSIPreferencesCopyInitiatorCHAPName(preferences);
        node = iSCSIPreferencesCopyInitiatorIQN(preferences);
    }

    if(node) {
        CFStringRef sharedSecret = iSCSIKeychainCopyCHAPSecretForNode(node);

        if(!name || CFStringGetLength(name) == 0)
            iSCSILogWarning("the CHAP name of the initiator has not been set, reverting to no authentication");
        else if(!sharedSecret)
            iSCSILogWarning("the CHAP secret of the initiator is not available, reverting to no authentication");
        else
            auth = iSCSIAuthCreateCHAP(name,sharedSecret);

        if(sharedSecret)
            CFRelease(sharedSecret);

        CFRelease(node);
    }

    if(name)
        CFRelease(name);

    return auth ? auth : iSCSIAuthCreateNone();
}

/*! Creates an array of the portals of a target, as defined in preferences.
 *  @param first a portal to place at the front of the array (may be NULL). */
static CFArrayRef iSCSIDCreateArrayOfPortalsForTarget(CFStringRef targetIQN,iSCSIPortalRef first)
{
    CFMutableArrayRef portals = CFArrayCreateMutable(kCFAllocatorDefault,0,&kCFTypeArrayCallBacks);

    if(first)
        CFArrayAppendValue(portals,first);

    CFArrayRef addresses = iSCSIPreferencesCreateArrayOfPortalsForTarget(preferences,targetIQN);

    for(CFIndex idx = 0; addresses && idx < CFArrayGetCount(addresses); idx++) {
        CFStringRef address = CFArrayGetValueAtIndex(addresses,idx);

        if(first && CFStringCompare(address,iSCSIPortalGetAddress(first),kCFCompareCaseInsensitive) == kCFCompareEqualTo)
            continue;

        iSCSIPortalRef portal = iSCSIPreferencesCopyPortalForTarget(preferences,targetIQN,address);

        if(portal) {
            CFArrayAppendValue(portals,portal);
            iSCSIPortalRelease(portal);
        }
    }

    if(addresses)
        CFRelease(addresses);

    return portals;
}

#pragma mark - Pending logins and recovery

/*! Arranges for a target to be logged in to as soon as it can be reached. */
static void iSCSIDQueueLogin(CFStringRef targetIQN)
{
    pthread_mutex_lock(&housekeepingLock);

    struct PendingLogin * login = pendingLogins;

    while(login && CFStringCompare(login->targetIQN,targetIQN,0) != kCFCompareEqualTo)
        login = login->next;

    if(!login) {
        login = calloc(1,sizeof(struct PendingLogin));
        login->targetIQN = CFStringCreateCopy(kCFAllocatorDefault,targetIQN);
        login->interval = kPendingLoginIntervalMinSec;
        login->next = pendingLogins;
        pendingLogins = login;
    }

    pthread_cond_broadcast(&housekeepingCond);
    pthread_mutex_unlock(&housekeepingLock);
}

static void iSCSIDDequeueLogin(CFStringRef targetIQN)
{
    pthread_mutex_lock(&housekeepingLock);

    for(struct PendingLogin ** link = &pendingLogins; *link; link = &(*link)->next) {
        struct PendingLogin * login = *link;

        if(CFStringCompare(login->targetIQN,targetIQN,0) == kCFCompareEqualTo) {
            *link = login->next;
            CFRelease(login->targetIQN);
            free(login);
            break;
        }
    }
    pthread_mutex_unlock(&housekeepingLock);
}

/*! Stops the recovery of a session (e.g., because it is logged out). */
static void iSCSIDCancelRecovery(SessionIdentifier sessionId)
{
    pthread_mutex_lock(&housekeepingLock);

    for(struct Recovery ** link = &recoveries; *link; link = &(*link)->next) {
        struct Recovery * recovery = *link;

        if(recovery->sessionId == sessionId) {
            *link = recovery->next;
            iSCSIPortalRelease(recovery->portal);
            free(recovery);
            break;
        }
    }
    pthread_mutex_unlock(&housekeepingLock);
}

/*! Called by the session manager (on the main thread) when the connection
 *  of a session was lost. */
static void iSCSIDSessionTimeoutHandler(iSCSITargetRef target,iSCSIPortalRef portal)
{
    if(!target || !portal)
        return;

    SessionIdentifier sessionId = iSCSISessionGetSessionIdForTarget(sessionManager,iSCSITargetGetIQN(target));

    if(sessionId == kiSCSIInvalidSessionId)
        return;

    iSCSIDLog(kiSCSILogWarning,CFSTR("connection to %@ over portal %@ was lost; attempting to recover the session"),
              iSCSITargetGetIQN(target),iSCSIPortalGetAddress(portal));

    pthread_mutex_lock(&housekeepingLock);

    struct Recovery * recovery = recoveries;

    while(recovery && recovery->sessionId != sessionId)
        recovery = recovery->next;

    if(!recovery && !shuttingDown) {
        recovery = calloc(1,sizeof(struct Recovery));
        recovery->sessionId = sessionId;
        recovery->portal = portal;
        iSCSIPortalRetain(portal);
        recovery->startTime = time(NULL);
        recovery->next = recoveries;
        recoveries = recovery;
    }

    pthread_cond_broadcast(&housekeepingCond);
    pthread_mutex_unlock(&housekeepingLock);
}

#pragma mark - Login and logout

/*! Logs in to a target and attaches its logical units as disks. The
 *  operation lock must be held and preferences must be up to date.
 *  @param targetIQN the name of the target.
 *  @param portal the portal to use (NULL to try the portals of the target
 *  one after another).
 *  @param statusCode the iSCSI login status.
 *  @return an error code indicating the result of the operation. */
static errno_t iSCSIDLoginTarget(CFStringRef targetIQN,
                                 iSCSIPortalRef portal,
                                 enum iSCSILoginStatusCode * statusCode)
{
    *statusCode = kiSCSILoginInvalidStatusCode;

    // There can be one session per target only
    SessionIdentifier sessionId = iSCSISessionGetSessionIdForTarget(sessionManager,targetIQN);

    if(sessionId != kiSCSIInvalidSessionId) {
        iSCSIHBAInterfaceRef interface = iSCSISessionManagerGetHBAInterface(sessionManager);
        return (iSCSIHBAInterfaceGetSessionState(interface,sessionId) == kiSCSIHBASessionStateRecovering) ? EINPROGRESS : EEXIST;
    }

    CFArrayRef portals = portal ? CFArrayCreate(kCFAllocatorDefault,(const void **)&portal,1,&kCFTypeArrayCallBacks)
                                : iSCSIDCreateArrayOfPortalsForTarget(targetIQN,NULL);

    if(CFArrayGetCount(portals) == 0) {
        CFRelease(portals);
        return ENOENT;
    }

    iSCSIDUpdateInitiatorIdentity();

    iSCSISessionConfigRef sessCfg = iSCSIDCreateSessionConfig(targetIQN);
    iSCSIConnectionConfigRef connCfg = iSCSIDCreateConnectionConfig(targetIQN);
    iSCSIAuthRef targetAuth = iSCSIDCreateAuthenticationForTarget(targetIQN);
    iSCSIAuthRef initiatorAuth = iSCSIDCreateAuthenticationForInitiator(targetIQN);

    if(iSCSIAuthGetMethod(targetAuth) == kiSCSIAuthMethodCHAP && iSCSIAuthGetMethod(initiatorAuth) != kiSCSIAuthMethodCHAP)
        iSCSIDLog(kiSCSILogWarning,CFSTR("target %@ cannot be authenticated unless the initiator uses CHAP as well"),targetIQN);

    iSCSIMutableTargetRef target = iSCSITargetCreateMutable();
    iSCSITargetSetIQN(target,targetIQN);

    errno_t error = ENOENT;
    ConnectionIdentifier connectionId = kiSCSIInvalidConnectionId;
    sessionId = kiSCSIInvalidSessionId;

    // Try the portals one after another until one of them works
    for(CFIndex idx = 0; idx < CFArrayGetCount(portals); idx++) {
        iSCSIPortalRef candidate = CFArrayGetValueAtIndex(portals,idx);
        enum iSCSILoginStatusCode candidateStatus = kiSCSILoginInvalidStatusCode;

        error = iSCSISessionLogin(sessionManager,target,candidate,initiatorAuth,targetAuth,
                                  sessCfg,connCfg,&sessionId,&connectionId,&candidateStatus);

        // Report the response of a target in preference over the failure
        // to reach another portal
        if(candidateStatus != kiSCSILoginInvalidStatusCode || *statusCode == kiSCSILoginInvalidStatusCode)
            *statusCode = candidateStatus;

        if(!error && candidateStatus == kiSCSILoginSuccess) {
            iSCSIDLog(kiSCSILogInfo,CFSTR("logged in to %@ over portal %@:%@ (sid %u)"),targetIQN,
                      iSCSIPortalGetAddress(candidate),iSCSIPortalGetPort(candidate),(unsigned)sessionId);
            break;
        }

        if(error)
            iSCSIDLog(kiSCSILogError,CFSTR("login to %@ over portal %@:%@ failed: %s%s"),targetIQN,
                      iSCSIPortalGetAddress(candidate),iSCSIPortalGetPort(candidate),strerror(error),
                      error == EHOSTUNREACH ? " (if the portal is on the local network, see that LunLink "
                                              "is allowed under Privacy & Security > Local Network in System Settings)" : "");
        else {
            iSCSIDLog(kiSCSILogError,CFSTR("login to %@ over portal %@:%@ failed: %@ (status %#06x)"),targetIQN,
                      iSCSIPortalGetAddress(candidate),iSCSIPortalGetPort(candidate),
                      iSCSIUtilsGetStringForLoginStatus(candidateStatus),(unsigned)candidateStatus);
            error = EAUTH;

            // Rejection by the target is final for all of its portals
            break;
        }
        sessionId = kiSCSIInvalidSessionId;
    }

    if(!error && sessionId != kiSCSIInvalidSessionId) {
        iSCSIDDequeueLogin(targetIQN);

        // Remember the alias that the target supplied, if any (unless a
        // client is busy modifying the preferences)
        CFStringRef alias = iSCSITargetGetAlias(target);

        if(alias && CFStringGetLength(alias) > 0 && iSCSIPreferencesContainsTarget(preferences,targetIQN) &&
           iSCSIDPreferencesLockForDaemon(0)) {
            iSCSIPreferencesUpdateWithAppValues(preferences);

            if(iSCSIPreferencesContainsTarget(preferences,targetIQN)) {
                iSCSIPreferencesSetTargetAlias(preferences,targetIQN,alias);
                iSCSIPreferencesSynchronzeAppValues(preferences);
            }
            iSCSIDPreferencesUnlock(INT32_MAX);
        }

        // Attach the logical units of the target as disks
        errno_t attachError = iSCSIDiskManagerAttachSession(diskManager,sessionId,targetIQN,
                                                            iSCSIPreferencesGetReadOnlyForTarget(preferences,targetIQN),
                                                            iSCSIPreferencesGetSyncWritesForTarget(preferences,targetIQN));

        if(attachError)
            iSCSIDLog(kiSCSILogError,CFSTR("unable to attach the disks of %@: %s"),targetIQN,strerror(attachError));
    }

    iSCSITargetRelease(target);
    iSCSISessionConfigRelease(sessCfg);
    iSCSIConnectionConfigRelease(connCfg);
    iSCSIAuthRelease(targetAuth);
    iSCSIAuthRelease(initiatorAuth);
    CFRelease(portals);

    return error;
}

/*! Detaches the disks of a session and logs out. The operation lock must
 *  be held.
 *  @param force logout even if volumes are in use.
 *  @return an error code indicating the result of the operation. */
static errno_t iSCSIDLogoutSession(SessionIdentifier sessionId,
                                   bool force,
                                   enum iSCSILogoutStatusCode * statusCode)
{
    iSCSIHBAInterfaceRef interface = iSCSISessionManagerGetHBAInterface(sessionManager);
    bool recovering = (iSCSIHBAInterfaceGetSessionState(interface,sessionId) == kiSCSIHBASessionStateRecovering);

    *statusCode = kiSCSILogoutInvalidStatusCode;

    // Volumes cannot be unmounted cleanly while the session is down
    if(recovering && !force)
        return EBUSY;

    // Without a connection, pending I/O would hold up the detach
    if(recovering)
        iSCSIHBAInterfaceCloseSession(interface,sessionId);

    errno_t error = iSCSIDiskManagerDetachSession(diskManager,sessionId,force);

    if(error)
        return error;

    iSCSIDCancelRecovery(sessionId);
    return iSCSISessionLogout(sessionManager,sessionId,statusCode);
}

/*! Attempts to re-establish a session that lost its connection.
 *  @return true if the recovery has come to an end, be it because the
 *  session was recovered, was given up on or no longer exists. */
static bool iSCSIDRecoverSession(struct Recovery * recovery)
{
    iSCSIHBAInterfaceRef interface = iSCSISessionManagerGetHBAInterface(sessionManager);
    bool finished = true;

    pthread_mutex_lock(&operationLock);

    iSCSITargetRef target = iSCSISessionCopyTargetForId(sessionManager,recovery->sessionId);

    if(target && iSCSIHBAInterfaceGetSessionState(interface,recovery->sessionId) == kiSCSIHBASessionStateRecovering)
    {
        CFStringRef targetIQN = iSCSITargetGetIQN(target);

        iSCSIDUpdatePreferencesFromAppValues();
        iSCSIDUpdateInitiatorIdentity();

        iSCSISessionConfigRef sessCfg = iSCSIDCreateSessionConfig(targetIQN);
        iSCSIConnectionConfigRef connCfg = iSCSIDCreateConnectionConfig(targetIQN);
        iSCSIAuthRef targetAuth = iSCSIDCreateAuthenticationForTarget(targetIQN);
        iSCSIAuthRef initiatorAuth = iSCSIDCreateAuthenticationForInitiator(targetIQN);

        // The portal that was in use is tried first, then the others
        CFArrayRef portals = iSCSIDCreateArrayOfPortalsForTarget(targetIQN,recovery->portal);
        errno_t error = ENOENT;

        for(CFIndex idx = 0; idx < CFArrayGetCount(portals) && error; idx++) {
            enum iSCSILoginStatusCode statusCode = kiSCSILoginInvalidStatusCode;

            error = iSCSISessionRecover(sessionManager,recovery->sessionId,CFArrayGetValueAtIndex(portals,idx),
                                        initiatorAuth,targetAuth,sessCfg,connCfg,&statusCode);
        }

        if(!error)
            iSCSIDLog(kiSCSILogInfo,CFSTR("session with %@ was recovered"),targetIQN);
        else if(time(NULL) - recovery->startTime < recoveryTimeoutSec)
            finished = false;
        else {
            // Give up: the disks are detached, pending I/O fails
            iSCSIDLog(kiSCSILogError,CFSTR("unable to recover the session with %@ (%s); detaching its disks"),
                      targetIQN,strerror(error));

            enum iSCSILogoutStatusCode statusCode;
            iSCSIHBAInterfaceCloseSession(interface,recovery->sessionId);
            iSCSIDiskManagerDetachSession(diskManager,recovery->sessionId,true);
            iSCSISessionLogout(sessionManager,recovery->sessionId,&statusCode);

            // Targets that are to be kept connected are logged in to again
            // once they can be reached
            if(iSCSIPreferencesContainsTarget(preferences,targetIQN) &&
               (iSCSIPreferencesGetPersistenceForTarget(preferences,targetIQN) ||
                iSCSIPreferencesGetAutoLoginForTarget(preferences,targetIQN)))
                iSCSIDQueueLogin(targetIQN);
        }

        CFRelease(portals);
        iSCSISessionConfigRelease(sessCfg);
        iSCSIConnectionConfigRelease(connCfg);
        iSCSIAuthRelease(targetAuth);
        iSCSIAuthRelease(initiatorAuth);
    }

    if(target)
        iSCSITargetRelease(target);

    pthread_mutex_unlock(&operationLock);
    return finished;
}

/*! Queues logins for the targets that are configured for automatic login. */
static void iSCSIDAutoLogin(void)
{
    pthread_mutex_lock(&operationLock);
    iSCSIDUpdatePreferencesFromAppValues();

    CFArrayRef targets = iSCSIPreferencesCreateArrayOfTargets(preferences);

    for(CFIndex idx = 0; targets && idx < CFArrayGetCount(targets); idx++) {
        CFStringRef targetIQN = CFArrayGetValueAtIndex(targets,idx);

        if(iSCSIPreferencesGetAutoLoginForTarget(preferences,targetIQN))
            iSCSIDQueueLogin(targetIQN);
    }

    if(targets)
        CFRelease(targets);

    pthread_mutex_unlock(&operationLock);
}

#pragma mark - Discovery

/*! Queries the discovery portals for targets and records the result in
 *  preferences. */
static void iSCSIDRunDiscovery(void)
{
    // The portals are queried without holding up other operations, based
    // on a private copy of the preferences
    pthread_mutex_lock(&operationLock);
    iSCSIDUpdatePreferencesFromAppValues();
    iSCSIDUpdateInitiatorIdentity();
    iSCSIAuthRef auth = iSCSIDCreateAuthenticationForInitiator(NULL);
    pthread_mutex_unlock(&operationLock);

    iSCSIPreferencesRef snapshot = iSCSIPreferencesCreateFromAppValues();
    CFDictionaryRef records = iSCSIDiscoveryCreateRecordsWithSendTargets(sessionManager,snapshot,auth);

    iSCSIPreferencesRelease(snapshot);
    iSCSIAuthRelease(auth);

    if(!records)
        return;

    CFIndex count = CFDictionaryGetCount(records);

    if(count > 0 && iSCSIDPreferencesLockForDaemon(kPreferencesLockTimeoutSec)) {
        pthread_mutex_lock(&operationLock);
        iSCSIDUpdatePreferencesFromAppValues();

        const void * keys[count];
        const void * values[count];
        CFDictionaryGetKeysAndValues(records,keys,values);

        for(CFIndex idx = 0; idx < count; idx++)
            iSCSIDiscoveryUpdatePreferencesWithDiscoveredTargets(sessionManager,preferences,keys[idx],values[idx]);

        iSCSIPreferencesSynchronzeAppValues(preferences);
        pthread_mutex_unlock(&operationLock);
        iSCSIDPreferencesUnlock(INT32_MAX);
    }
    CFRelease(records);
}

/*! Schedules discovery according to preferences.
 *  @param now run discovery right away (if it is enabled). */
static void iSCSIDScheduleDiscovery(bool now)
{
    pthread_mutex_lock(&operationLock);
    iSCSIDUpdatePreferencesFromAppValues();
    Boolean enabled = iSCSIPreferencesGetSendTargetsDiscoveryEnable(preferences);
    CFIndex interval = iSCSIPreferencesGetSendTargetsDiscoveryInterval(preferences);
    pthread_mutex_unlock(&operationLock);

    if(interval < kiSCSIInitiator_DiscoveryInterval_Min)
        interval = kiSCSIInitiator_DiscoveryInterval_Min;

    pthread_mutex_lock(&housekeepingLock);

    if(!enabled)
        nextDiscoveryTime = 0;
    else if(now)
        discoveryRequested = true;
    else
        nextDiscoveryTime = time(NULL) + interval;

    pthread_cond_broadcast(&housekeepingCond);
    pthread_mutex_unlock(&housekeepingLock);
}

#pragma mark - Housekeeping thread

static void * iSCSIDHousekeepingMain(void * context)
{
    pthread_setname_np("iscsid.housekeeping");
    pthread_mutex_lock(&housekeepingLock);

    while(!shuttingDown) {
        time_t now = time(NULL);

        // Sessions that lost their connection
        struct Recovery * recovery = recoveries;

        while(recovery && recovery->nextAttempt > now)
            recovery = recovery->next;

        if(recovery) {
            SessionIdentifier sessionId = recovery->sessionId;
            struct Recovery snapshot = *recovery;
            iSCSIPortalRetain(snapshot.portal);
            pthread_mutex_unlock(&housekeepingLock);

            bool finished = iSCSIDRecoverSession(&snapshot);
            iSCSIPortalRelease(snapshot.portal);

            // The entry may have been removed in the meantime
            pthread_mutex_lock(&housekeepingLock);

            for(struct Recovery ** link = &recoveries; *link; link = &(*link)->next) {
                struct Recovery * entry = *link;

                if(entry->sessionId != sessionId || entry->startTime != snapshot.startTime)
                    continue;

                if(finished) {
                    *link = entry->next;
                    iSCSIPortalRelease(entry->portal);
                    free(entry);
                }
                else
                    entry->nextAttempt = time(NULL) + kRecoveryIntervalSec;
                break;
            }
            continue;
        }

        // Logins that are waiting for their target to become reachable
        struct PendingLogin * login = pendingLogins;

        while(login && login->nextAttempt > now)
            login = login->next;

        if(login) {
            CFStringRef targetIQN = CFRetain(login->targetIQN);
            pthread_mutex_unlock(&housekeepingLock);

            pthread_mutex_lock(&operationLock);
            iSCSIDUpdatePreferencesFromAppValues();

            enum iSCSILoginStatusCode statusCode;
            errno_t error = EINVAL;
            bool drop = !iSCSIPreferencesContainsTarget(preferences,targetIQN);

            if(!drop) {
                error = iSCSIDLoginTarget(targetIQN,NULL,&statusCode);

                // No point in retrying if the target is logged in already,
                // turned us down or has no portals
                drop = (error == 0 || error == EEXIST || error == EINPROGRESS || error == EAUTH || error == ENOENT);
            }
            pthread_mutex_unlock(&operationLock);

            pthread_mutex_lock(&housekeepingLock);

            for(struct PendingLogin ** link = &pendingLogins; *link; link = &(*link)->next) {
                struct PendingLogin * entry = *link;

                if(CFStringCompare(entry->targetIQN,targetIQN,0) != kCFCompareEqualTo)
                    continue;

                if(drop) {
                    *link = entry->next;
                    CFRelease(entry->targetIQN);
                    free(entry);
                }
                else {
                    entry->nextAttempt = time(NULL) + entry->interval;
                    entry->interval *= 2;

                    if(entry->interval > kPendingLoginIntervalMaxSec)
                        entry->interval = kPendingLoginIntervalMaxSec;
                }
                break;
            }
            CFRelease(targetIQN);
            continue;
        }

        // Discovery
        if(discoveryRequested || (nextDiscoveryTime != 0 && nextDiscoveryTime <= now)) {
            discoveryRequested = false;
            nextDiscoveryTime = 0;
            pthread_mutex_unlock(&housekeepingLock);

            iSCSIDRunDiscovery();
            iSCSIDScheduleDiscovery(false);

            pthread_mutex_lock(&housekeepingLock);
            continue;
        }

        struct timespec interval = { 1, 0 };
        pthread_cond_timedwait_relative_np(&housekeepingCond,&housekeepingLock,&interval);
    }

    pthread_mutex_unlock(&housekeepingLock);
    return NULL;
}

#pragma mark - Requests

static void iSCSIDResponseSetError(CFMutableDictionaryRef response,errno_t error)
{
    int value = error;
    CFNumberRef number = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&value);
    CFDictionarySetValue(response,kiSCSIDKeyError,number);
    CFRelease(number);
}

static void iSCSIDResponseSetInt(CFMutableDictionaryRef response,CFStringRef key,int value)
{
    CFNumberRef number = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&value);
    CFDictionarySetValue(response,key,number);
    CFRelease(number);
}

/*! Creates the target that a request refers to, if any. */
static iSCSITargetRef iSCSIDRequestCopyTarget(CFDictionaryRef request)
{
    CFDictionaryRef dictionary = CFDictionaryGetValue(request,kiSCSIDKeyTarget);

    if(!dictionary || CFGetTypeID(dictionary) != CFDictionaryGetTypeID())
        return NULL;

    iSCSITargetRef target = iSCSITargetCreateWithDictionary(dictionary);

    if(target && (!iSCSITargetGetIQN(target) || CFGetTypeID(iSCSITargetGetIQN(target)) != CFStringGetTypeID())) {
        iSCSITargetRelease(target);
        target = NULL;
    }
    return target;
}

/*! Creates the portal that a request refers to, if any. */
static iSCSIPortalRef iSCSIDRequestCopyPortal(CFDictionaryRef request)
{
    CFDictionaryRef dictionary = CFDictionaryGetValue(request,kiSCSIDKeyPortal);

    if(!dictionary || CFGetTypeID(dictionary) != CFDictionaryGetTypeID())
        return NULL;

    iSCSIPortalRef portal = iSCSIPortalCreateWithDictionary(dictionary);
    CFStringRef address = portal ? iSCSIPortalGetAddress(portal) : NULL;
    CFStringRef port = portal ? iSCSIPortalGetPort(portal) : NULL;
    CFStringRef interface = portal ? iSCSIPortalGetHostInterface(portal) : NULL;

    if(portal && (!address || CFGetTypeID(address) != CFStringGetTypeID() ||
                  !port || CFGetTypeID(port) != CFStringGetTypeID() ||
                  !interface || CFGetTypeID(interface) != CFStringGetTypeID())) {
        iSCSIPortalRelease(portal);
        portal = NULL;
    }
    return portal;
}

static CFStringRef iSCSIDRequestGetString(CFDictionaryRef request,CFStringRef key)
{
    CFStringRef string = CFDictionaryGetValue(request,key);
    return (string && CFGetTypeID(string) == CFStringGetTypeID()) ? string : NULL;
}

/*! Gets the session of the target that a request refers to. */
static SessionIdentifier iSCSIDRequestGetSessionId(CFDictionaryRef request)
{
    iSCSITargetRef target = iSCSIDRequestCopyTarget(request);
    SessionIdentifier sessionId = kiSCSIInvalidSessionId;

    if(target) {
        sessionId = iSCSISessionGetSessionIdForTarget(sessionManager,iSCSITargetGetIQN(target));
        iSCSITargetRelease(target);
    }
    return sessionId;
}

static errno_t iSCSIDLogin(CFDictionaryRef request,CFMutableDictionaryRef response)
{
    iSCSITargetRef target = iSCSIDRequestCopyTarget(request);
    iSCSIPortalRef portal = iSCSIDRequestCopyPortal(request);
    enum iSCSILoginStatusCode statusCode = kiSCSILoginInvalidStatusCode;
    errno_t error = EINVAL;

    if(target) {
        pthread_mutex_lock(&operationLock);
        iSCSIDUpdatePreferencesFromAppValues();
        error = iSCSIDLoginTarget(iSCSITargetGetIQN(target),portal,&statusCode);
        pthread_mutex_unlock(&operationLock);

        // An explicit request supersedes a login that was pending
        iSCSIDDequeueLogin(iSCSITargetGetIQN(target));
        iSCSITargetRelease(target);
    }

    if(portal)
        iSCSIPortalRelease(portal);

    iSCSIDResponseSetInt(response,kiSCSIDKeyStatusCode,statusCode);
    return error;
}

static errno_t iSCSIDLogout(CFDictionaryRef request,CFMutableDictionaryRef response)
{
    iSCSITargetRef target = iSCSIDRequestCopyTarget(request);
    bool force = (CFDictionaryGetValue(request,kiSCSIDKeyForce) == kCFBooleanTrue);
    enum iSCSILogoutStatusCode statusCode = kiSCSILogoutInvalidStatusCode;
    errno_t error = EINVAL;

    if(target) {
        CFStringRef targetIQN = iSCSITargetGetIQN(target);

        // The user does not want the target any longer
        iSCSIDDequeueLogin(targetIQN);

        pthread_mutex_lock(&operationLock);
        SessionIdentifier sessionId = iSCSISessionGetSessionIdForTarget(sessionManager,targetIQN);

        if(sessionId == kiSCSIInvalidSessionId)
            error = ENOTCONN;
        else if(!(error = iSCSIDLogoutSession(sessionId,force,&statusCode)))
            iSCSIDLog(kiSCSILogInfo,CFSTR("logged out of %@"),targetIQN);
        else
            iSCSIDLog(kiSCSILogError,CFSTR("logout of %@ failed: %s"),targetIQN,strerror(error));

        pthread_mutex_unlock(&operationLock);
        iSCSITargetRelease(target);
    }

    iSCSIDResponseSetInt(response,kiSCSIDKeyStatusCode,statusCode);
    return error;
}

static errno_t iSCSIDActiveTargets(CFDictionaryRef request,CFMutableDictionaryRef response)
{
    CFMutableArrayRef activeTargets = CFArrayCreateMutable(kCFAllocatorDefault,0,&kCFTypeArrayCallBacks);
    CFArrayRef sessionIds = iSCSISessionCopyArrayOfSessionIds(sessionManager);

    for(CFIndex idx = 0; sessionIds && idx < CFArrayGetCount(sessionIds); idx++) {
        SessionIdentifier sessionId = (SessionIdentifier)(uintptr_t)CFArrayGetValueAtIndex(sessionIds,idx);
        iSCSITargetRef target = iSCSISessionCopyTargetForId(sessionManager,sessionId);

        if(!target)
            continue;

        CFDictionaryRef dictionary = iSCSITargetCreateDictionary(target);
        CFArrayAppendValue(activeTargets,dictionary);
        CFRelease(dictionary);
        iSCSITargetRelease(target);
    }

    if(sessionIds)
        CFRelease(sessionIds);

    CFDictionarySetValue(response,kiSCSIDKeyResult,activeTargets);
    CFRelease(activeTargets);
    return 0;
}

static errno_t iSCSIDActivePortals(CFDictionaryRef request,CFMutableDictionaryRef response)
{
    CFMutableArrayRef activePortals = CFArrayCreateMutable(kCFAllocatorDefault,0,&kCFTypeArrayCallBacks);
    SessionIdentifier sessionId = iSCSIDRequestGetSessionId(request);
    CFArrayRef connectionIds = iSCSISessionCopyArrayOfConnectionIds(sessionManager,sessionId);

    for(CFIndex idx = 0; connectionIds && idx < CFArrayGetCount(connectionIds); idx++) {
        ConnectionIdentifier connectionId = (ConnectionIdentifier)(uintptr_t)CFArrayGetValueAtIndex(connectionIds,idx);
        iSCSIPortalRef portal = iSCSISessionCopyPortalForConnectionId(sessionManager,sessionId,connectionId);

        if(!portal)
            continue;

        CFDictionaryRef dictionary = iSCSIPortalCreateDictionary(portal);
        CFArrayAppendValue(activePortals,dictionary);
        CFRelease(dictionary);
        iSCSIPortalRelease(portal);
    }

    if(connectionIds)
        CFRelease(connectionIds);

    CFDictionarySetValue(response,kiSCSIDKeyResult,activePortals);
    CFRelease(activePortals);
    return 0;
}

static errno_t iSCSIDIsTargetActive(CFDictionaryRef request,CFMutableDictionaryRef response)
{
    bool active = (iSCSIDRequestGetSessionId(request) != kiSCSIInvalidSessionId);
    CFDictionarySetValue(response,kiSCSIDKeyActive,active ? kCFBooleanTrue : kCFBooleanFalse);
    return 0;
}

static errno_t iSCSIDIsPortalActive(CFDictionaryRef request,CFMutableDictionaryRef response)
{
    SessionIdentifier sessionId = iSCSIDRequestGetSessionId(request);
    iSCSIPortalRef portal = iSCSIDRequestCopyPortal(request);
    bool active = false;

    if(portal && sessionId != kiSCSIInvalidSessionId)
        active = (iSCSISessionGetConnectionIdForPortal(sessionManager,sessionId,portal) != kiSCSIInvalidConnectionId);

    if(portal)
        iSCSIPortalRelease(portal);

    CFDictionarySetValue(response,kiSCSIDKeyActive,active ? kCFBooleanTrue : kCFBooleanFalse);
    return 0;
}

static errno_t iSCSIDSessionProperties(CFDictionaryRef request,CFMutableDictionaryRef response)
{
    iSCSITargetRef target = iSCSIDRequestCopyTarget(request);

    if(!target)
        return EINVAL;

    CFDictionaryRef properties = iSCSISessionCopyCFPropertiesForTarget(sessionManager,target);
    iSCSITargetRelease(target);

    if(properties) {
        CFDictionarySetValue(response,kiSCSIDKeyResult,properties);
        CFRelease(properties);
    }
    return 0;
}

static errno_t iSCSIDConnectionProperties(CFDictionaryRef request,CFMutableDictionaryRef response)
{
    iSCSITargetRef target = iSCSIDRequestCopyTarget(request);
    iSCSIPortalRef portal = iSCSIDRequestCopyPortal(request);
    errno_t error = EINVAL;

    if(target && portal) {
        CFDictionaryRef properties = iSCSISessionCopyCFPropertiesForPortal(sessionManager,target,portal);

        if(properties) {
            CFDictionarySetValue(response,kiSCSIDKeyResult,properties);
            CFRelease(properties);
        }
        error = 0;
    }

    if(target)
        iSCSITargetRelease(target);

    if(portal)
        iSCSIPortalRelease(portal);

    return error;
}

static errno_t iSCSIDDisks(CFDictionaryRef request,CFMutableDictionaryRef response)
{
    SessionIdentifier sessionId = iSCSIDRequestGetSessionId(request);
    CFArrayRef disks = (sessionId != kiSCSIInvalidSessionId)
                           ? iSCSIDiskManagerCopyDisksForSession(diskManager,sessionId)
                           : CFArrayCreate(kCFAllocatorDefault,NULL,0,&kCFTypeArrayCallBacks);

    CFDictionarySetValue(response,kiSCSIDKeyResult,disks);
    CFRelease(disks);
    return 0;
}

static errno_t iSCSIDQueryAuthMethod(CFDictionaryRef request,CFMutableDictionaryRef response)
{
    iSCSIPortalRef portal = iSCSIDRequestCopyPortal(request);
    CFStringRef targetIQN = iSCSIDRequestGetString(request,kiSCSIDKeyTargetIQN);
    enum iSCSIAuthMethods authMethod = kiSCSIAuthMethodInvalid;
    enum iSCSILoginStatusCode statusCode = kiSCSILoginInvalidStatusCode;
    errno_t error = EINVAL;

    if(portal && targetIQN) {
        pthread_mutex_lock(&operationLock);
        iSCSIDUpdatePreferencesFromAppValues();
        iSCSIDUpdateInitiatorIdentity();
        pthread_mutex_unlock(&operationLock);

        error = iSCSIQueryTargetForAuthMethod(sessionManager,portal,targetIQN,&authMethod,&statusCode);
    }

    if(portal)
        iSCSIPortalRelease(portal);

    iSCSIDResponseSetInt(response,kiSCSIDKeyAuthMethod,authMethod);
    iSCSIDResponseSetInt(response,kiSCSIDKeyStatusCode,statusCode);
    return error;
}

static errno_t iSCSIDQueryPortalForTargets(CFDictionaryRef request,CFMutableDictionaryRef response)
{
    iSCSIPortalRef portal = iSCSIDRequestCopyPortal(request);
    enum iSCSILoginStatusCode statusCode = kiSCSILoginInvalidStatusCode;
    iSCSIMutableDiscoveryRecRef discoveryRec = NULL;

    if(!portal)
        return EINVAL;

    pthread_mutex_lock(&operationLock);
    iSCSIDUpdatePreferencesFromAppValues();
    iSCSIDUpdateInitiatorIdentity();
    iSCSIAuthRef auth = iSCSIDCreateAuthenticationForInitiator(NULL);
    pthread_mutex_unlock(&operationLock);

    errno_t error = iSCSIQueryPortalForTargets(sessionManager,portal,auth,&discoveryRec,&statusCode);

    if(!error && statusCode != kiSCSILoginSuccess)
        error = EAUTH;

    if(discoveryRec) {
        CFDictionaryRef dictionary = iSCSIDiscoveryRecCreateDictionary(discoveryRec);

        if(!error && dictionary)
            CFDictionarySetValue(response,kiSCSIDKeyResult,dictionary);

        if(dictionary)
            CFRelease(dictionary);

        iSCSIDiscoveryRecRelease(discoveryRec);
    }

    iSCSIAuthRelease(auth);
    iSCSIPortalRelease(portal);

    iSCSIDResponseSetInt(response,kiSCSIDKeyStatusCode,statusCode);
    return error;
}

static errno_t iSCSIDUpdateDiscovery(CFDictionaryRef request,CFMutableDictionaryRef response)
{
    iSCSIDScheduleDiscovery(true);
    return 0;
}

static errno_t iSCSIDPreferencesLockForClient(int fd)
{
    time_t deadline = time(NULL) + kPreferencesLockTimeoutSec;
    errno_t error = 0;

    pthread_mutex_lock(&preferencesLock);

    while(preferencesOwner >= 0 && preferencesOwner != fd) {
        time_t now = time(NULL);

        // A client that sits on the lock for too long loses it
        if(now - preferencesLockTime >= kPreferencesLockTimeoutSec) {
            preferencesOwner = -1;
            break;
        }

        if(now >= deadline) {
            error = EBUSY;
            break;
        }

        struct timespec interval = { 0, 200 * 1000000L };
        pthread_cond_timedwait_relative_np(&preferencesCond,&preferencesLock,&interval);
    }

    if(!error) {
        preferencesOwner = fd;
        preferencesLockTime = time(NULL);
    }
    pthread_mutex_unlock(&preferencesLock);
    return error;
}

static errno_t iSCSIDPreferencesUnlockForClient(int fd,CFDictionaryRef request)
{
    CFDataRef data = CFDictionaryGetValue(request,kiSCSIDKeyPreferences);
    errno_t error = 0;

    pthread_mutex_lock(&preferencesLock);
    bool owner = (preferencesOwner == fd);
    pthread_mutex_unlock(&preferencesLock);

    // Changes are only accepted from the client that holds the lock
    if(data && CFGetTypeID(data) == CFDataGetTypeID()) {
        if(!owner)
            error = EPERM;
        else {
            iSCSIPreferencesRef preferencesToSync = iSCSIPreferencesCreateWithData(data);

            if(!preferencesToSync)
                error = EINVAL;
            else {
                pthread_mutex_lock(&operationLock);

                // The CHAP secret of the initiator is filed under the name
                // of the initiator and follows it if the name changes
                iSCSIDUpdatePreferencesFromAppValues();
                CFStringRef oldIQN = iSCSIPreferencesCopyInitiatorIQN(preferences);
                CFStringRef newIQN = iSCSIPreferencesCopyInitiatorIQN(preferencesToSync);

                if(oldIQN && newIQN && CFStringCompare(oldIQN,newIQN,0) != kCFCompareEqualTo) {
                    CFStringRef secret = iSCSIKeychainCopyCHAPSecretForNode(oldIQN);

                    if(secret) {
                        if(iSCSIKeychainSetCHAPSecretForNode(newIQN,secret) == errSecSuccess)
                            iSCSIKeychainDeleteCHAPSecretForNode(oldIQN);

                        CFRelease(secret);
                    }
                }

                if(oldIQN)
                    CFRelease(oldIQN);
                if(newIQN)
                    CFRelease(newIQN);

                iSCSIPreferencesSynchronzeAppValues(preferencesToSync);
                iSCSIDUpdatePreferencesFromAppValues();
                iSCSIDUpdateInitiatorIdentity();
                pthread_mutex_unlock(&operationLock);

                iSCSIPreferencesRelease(preferencesToSync);
            }
        }
    }

    iSCSIDPreferencesUnlock(fd);
    return error;
}

static errno_t iSCSIDSetSharedSecret(CFDictionaryRef request,CFMutableDictionaryRef response)
{
    CFStringRef node = iSCSIDRequestGetString(request,kiSCSIDKeyNode);
    CFStringRef secret = iSCSIDRequestGetString(request,kiSCSIDKeySecret);

    if(!node || !secret || CFStringGetLength(node) == 0)
        return EINVAL;

    OSStatus status = iSCSIKeychainSetCHAPSecretForNode(node,secret);

    if(status != errSecSuccess) {
        iSCSILogError("unable to store a CHAP secret (status %d)",(int)status);
        return EACCES;
    }
    return 0;
}

static errno_t iSCSIDRemoveSharedSecret(CFDictionaryRef request,CFMutableDictionaryRef response)
{
    CFStringRef node = iSCSIDRequestGetString(request,kiSCSIDKeyNode);

    if(!node)
        return EINVAL;

    OSStatus status = iSCSIKeychainDeleteCHAPSecretForNode(node);
    return (status == errSecSuccess || status == errSecItemNotFound) ? 0 : EACCES;
}

static errno_t iSCSIDStatus(CFDictionaryRef request,CFMutableDictionaryRef response)
{
    CFMutableDictionaryRef status = CFDictionaryCreateMutable(kCFAllocatorDefault,0,
                                                              &kCFTypeDictionaryKeyCallBacks,
                                                              &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(status,kiSCSIDStatusVersion,CFSTR(ISCSI_VERSION));
    iSCSIDResponseSetInt(status,kiSCSIDStatusProcessId,(int)getpid());

    CFDictionarySetValue(response,kiSCSIDKeyResult,status);
    CFRelease(status);
    return 0;
}

/*! Carries out the request of a client.
 *  @param fd identifies the client.
 *  @param shutdown set if the daemon is to exit after responding. */
static CFDictionaryRef iSCSIDProcessRequest(int fd,CFDictionaryRef request,bool * shutdown)
{
    CFMutableDictionaryRef response = CFDictionaryCreateMutable(kCFAllocatorDefault,0,
                                                                &kCFTypeDictionaryKeyCallBacks,
                                                                &kCFTypeDictionaryValueCallBacks);
    CFStringRef function = iSCSIDRequestGetString(request,kiSCSIDKeyFunction);
    errno_t error = ENOTSUP;

    static const struct {
        CFStringRef name;
        errno_t (*handler)(CFDictionaryRef,CFMutableDictionaryRef);
    } handlers[] = {
        { kiSCSIDFunctionLogin, iSCSIDLogin },
        { kiSCSIDFunctionLogout, iSCSIDLogout },
        { kiSCSIDFunctionActiveTargets, iSCSIDActiveTargets },
        { kiSCSIDFunctionActivePortals, iSCSIDActivePortals },
        { kiSCSIDFunctionIsTargetActive, iSCSIDIsTargetActive },
        { kiSCSIDFunctionIsPortalActive, iSCSIDIsPortalActive },
        { kiSCSIDFunctionSessionProperties, iSCSIDSessionProperties },
        { kiSCSIDFunctionConnectionProperties, iSCSIDConnectionProperties },
        { kiSCSIDFunctionDisks, iSCSIDDisks },
        { kiSCSIDFunctionQueryAuthMethod, iSCSIDQueryAuthMethod },
        { kiSCSIDFunctionQueryPortalForTargets, iSCSIDQueryPortalForTargets },
        { kiSCSIDFunctionUpdateDiscovery, iSCSIDUpdateDiscovery },
        { kiSCSIDFunctionSetSharedSecret, iSCSIDSetSharedSecret },
        { kiSCSIDFunctionRemoveSharedSecret, iSCSIDRemoveSharedSecret },
        { kiSCSIDFunctionStatus, iSCSIDStatus },
    };

    pthread_rwlock_rdlock(&requestLock);

    if(terminated)
        error = ESHUTDOWN;
    else if(!function)
        error = EINVAL;
    else if(CFEqual(function,kiSCSIDFunctionPreferencesLock))
        error = iSCSIDPreferencesLockForClient(fd);
    else if(CFEqual(function,kiSCSIDFunctionPreferencesUnlock))
        error = iSCSIDPreferencesUnlockForClient(fd,request);
    else if(CFEqual(function,kiSCSIDFunctionShutdown)) {
        *shutdown = true;
        error = 0;
    }
    else {
        for(size_t idx = 0; idx < sizeof(handlers) / sizeof(handlers[0]); idx++) {
            if(CFEqual(function,handlers[idx].name)) {
                error = handlers[idx].handler(request,response);
                break;
            }
        }
    }

    pthread_rwlock_unlock(&requestLock);

    iSCSIDResponseSetError(response,error);
    return response;
}

#pragma mark - Clients

static void iSCSIDStop(void);

static void * iSCSIDClientMain(void * context)
{
    int fd = (int)(intptr_t)context;
    pthread_setname_np("iscsid.client");

    for(;;) {
        CFDictionaryRef request = NULL;

        if(iSCSIDaemonReceiveMessage(fd,&request) != 0)
            break;

        bool shutdown = false;
        CFDictionaryRef response = iSCSIDProcessRequest(fd,request,&shutdown);
        errno_t error = iSCSIDaemonSendMessage(fd,response);

        CFRelease(response);
        CFRelease(request);

        if(shutdown)
            iSCSIDStop();

        if(error || shutdown)
            break;
    }

    // A client that goes away gives up the preferences lock
    iSCSIDPreferencesUnlock(fd);
    close(fd);
    return NULL;
}

static void * iSCSIDListenerMain(void * context)
{
    pthread_setname_np("iscsid.listener");

    for(;;) {
        int fd = accept(listenFd,NULL,NULL);

        if(fd < 0) {
            if(errno == EINTR || errno == ECONNABORTED)
                continue;
            return NULL;
        }

        int enable = 1;
        setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&enable,sizeof(enable));

        pthread_t thread;
        pthread_attr_t attributes;
        pthread_attr_init(&attributes);
        pthread_attr_setdetachstate(&attributes,PTHREAD_CREATE_DETACHED);

        if(pthread_create(&thread,&attributes,iSCSIDClientMain,(void *)(intptr_t)fd) != 0)
            close(fd);

        pthread_attr_destroy(&attributes);
    }
}

/*! Obtains the socket on which clients connect: from launchd if it started
 *  the daemon, otherwise the socket is created.
 *  @return true if the socket is ready. */
static bool iSCSIDOpenListener(void)
{
    int * fds = NULL;
    size_t count = 0;

    if(launch_activate_socket("Listeners",&fds,&count) == 0 && count > 0) {
        listenFd = fds[0];

        for(size_t idx = 1; idx < count; idx++)
            close(fds[idx]);

        free(fds);
        return true;
    }

    struct sockaddr_un address;
    memset(&address,0,sizeof(address));
    address.sun_family = AF_LOCAL;

    if(!iSCSIUtilsGetSocketPath(kiSCSIDaemonSocketName,address.sun_path,sizeof(address.sun_path))) {
        iSCSILogError("unable to determine the path of the daemon socket");
        return false;
    }

    // There can be one daemon only: check whether another one answers
    int probe = socket(PF_LOCAL,SOCK_STREAM,0);

    if(probe >= 0) {
        bool running = false;

        if(connect(probe,(const struct sockaddr *)&address,(socklen_t)SUN_LEN(&address)) == 0) {
            struct timeval timeout = { 3, 0 };
            setsockopt(probe,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
            setsockopt(probe,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));

            CFDictionaryRef status = iSCSIDaemonCreateStatus(probe);

            if(status) {
                running = true;
                CFRelease(status);
            }
        }
        close(probe);

        if(running) {
            iSCSILogError("another instance of the daemon is running");
            return false;
        }
    }

    unlink(address.sun_path);

    if((listenFd = socket(PF_LOCAL,SOCK_STREAM,0)) < 0)
        return false;

    // Only the user may talk to the daemon
    mode_t mask = umask(0177);
    bool bound = (bind(listenFd,(const struct sockaddr *)&address,(socklen_t)SUN_LEN(&address)) == 0 &&
                  listen(listenFd,16) == 0);
    umask(mask);

    if(!bound) {
        iSCSILogError("unable to listen on %s: %s",address.sun_path,strerror(errno));
        close(listenFd);
        listenFd = -1;
        return false;
    }

    struct stat socketStatus;

    if(stat(address.sun_path,&socketStatus) == 0)
        listenInode = socketStatus.st_ino;

    fcntl(listenFd,F_SETFD,FD_CLOEXEC);
    strlcpy(listenPath,address.sun_path,sizeof(listenPath));
    return true;
}

#pragma mark - Power management

/*! Handles power event messages received from the kernel.
 *  @param refCon always NULL (not used).
 *  @param service the service associated with the notification port.
 *  @param messageType the type of notification message.
 *  @param messageArgument argument associated with the notification message. */
static void iSCSIDHandlePowerEvent(void * refCon,
                                   io_service_t service,
                                   natural_t messageType,
                                   void * messageArgument)
{
    switch(messageType)
    {
        case kIOMessageCanSystemSleep:
            IOAllowPowerChange(powerPlaneRoot,(long)messageArgument);
            break;

        // The system will go to sleep (we have no control).  Sessions are
        // kept; they are recovered upon wake should the target have
        // dropped them in the meantime.  Make sure that what was written
        // so far is safe.
        case kIOMessageSystemWillSleep:
            iSCSILogInfo("system is going to sleep");
            sync();
            iSCSIDiskManagerFlushAll(diskManager);
            IOAllowPowerChange(powerPlaneRoot,(long)messageArgument);
            break;

        // Hasten whatever was waiting for the network
        case kIOMessageSystemHasPoweredOn:
            iSCSILogInfo("system woke up");
            pthread_mutex_lock(&housekeepingLock);

            for(struct Recovery * recovery = recoveries; recovery; recovery = recovery->next)
                recovery->nextAttempt = 0;

            for(struct PendingLogin * login = pendingLogins; login; login = login->next) {
                login->nextAttempt = 0;
                login->interval = kPendingLoginIntervalMinSec;
            }

            pthread_cond_broadcast(&housekeepingCond);
            pthread_mutex_unlock(&housekeepingLock);
            break;
    };
}

/*! Registers the daemon with the kernel to receive power events
 *  (e.g., sleep/wake notifications).
 *  @return true if the daemon was successfully registered. */
static bool iSCSIDRegisterForPowerEvents(void)
{
    powerPlaneRoot = IORegisterForSystemPower(NULL,
                                              &powerNotifyPortRef,
                                              iSCSIDHandlePowerEvent,
                                              &powerNotifier);
    if(powerPlaneRoot == 0)
        return false;

    CFRunLoopAddSource(CFRunLoopGetMain(),
                       IONotificationPortGetRunLoopSource(powerNotifyPortRef),
                       kCFRunLoopDefaultMode);
    return true;
}

/*! Deregisters the daemon with the kernel to no longer receive power events. */
static void iSCSIDDeregisterForPowerEvents(void)
{
    if(powerPlaneRoot == 0)
        return;

    CFRunLoopRemoveSource(CFRunLoopGetMain(),
                          IONotificationPortGetRunLoopSource(powerNotifyPortRef),
                          kCFRunLoopDefaultMode);

    IODeregisterForSystemPower(&powerNotifier);
    IOServiceClose(powerPlaneRoot);
    IONotificationPortDestroy(powerNotifyPortRef);
}

#pragma mark - Startup and shutdown

/*! Makes the main thread leave its run loop, upon which the daemon shuts
 *  down.  May be called from any thread. */
static void iSCSIDStop(void)
{
    CFRunLoopStop(CFRunLoopGetMain());
    CFRunLoopWakeUp(CFRunLoopGetMain());
}

/*! Logs out of all targets.  Volumes are unmounted if possible; disks are
 *  detached regardless. */
static void iSCSIDLogoutAll(void)
{
    pthread_mutex_lock(&operationLock);

    CFArrayRef sessionIds = iSCSISessionCopyArrayOfSessionIds(sessionManager);

    for(CFIndex idx = 0; sessionIds && idx < CFArrayGetCount(sessionIds); idx++) {
        SessionIdentifier sessionId = (SessionIdentifier)(uintptr_t)CFArrayGetValueAtIndex(sessionIds,idx);
        enum iSCSILogoutStatusCode statusCode;

        if(iSCSIDLogoutSession(sessionId,false,&statusCode) != 0)
            iSCSIDLogoutSession(sessionId,true,&statusCode);
    }

    if(sessionIds)
        CFRelease(sessionIds);

    pthread_mutex_unlock(&operationLock);
}

/*! iSCSI daemon entry point. */
int main(int argc,char * argv[])
{
    for(int idx = 1; idx < argc; idx++) {
        if(strcmp(argv[idx],"-d") == 0 || strcmp(argv[idx],"--debug") == 0)
            iSCSILogSetDebug(true);
        else if(strcmp(argv[idx],"-v") == 0 || strcmp(argv[idx],"--version") == 0) {
            printf("iscsid %s\n",ISCSI_VERSION);
            return 0;
        }
        else {
            fprintf(stderr,"usage: iscsid [-d] [-v]\n");
            return EINVAL;
        }
    }

    const char * timeout = getenv("ISCSI_RECOVERY_TIMEOUT");

    if(timeout && atoi(timeout) > 0)
        recoveryTimeoutSec = atoi(timeout);

    // A client that disappears must not take the daemon down with it
    signal(SIGPIPE,SIG_IGN);

    if(!iSCSIDOpenListener())
        return EADDRINUSE;

    // Start the iSCSI session manager (which creates the HBA)
    iSCSISessionManagerCallBacks callbacks;
    callbacks.timeoutCallback = iSCSIDSessionTimeoutHandler;
    sessionManager = iSCSISessionManagerCreate(kCFAllocatorDefault,callbacks);

    if(!sessionManager) {
        iSCSILogError("unable to create the session manager");
        return ENOMEM;
    }
    iSCSISessionManagerScheduleWithRunLoop(sessionManager,CFRunLoopGetMain(),kCFRunLoopDefaultMode);

    if(!(diskManager = iSCSIDiskManagerCreate(iSCSISessionManagerGetHBAInterface(sessionManager)))) {
        iSCSILogError("unable to create the disk manager");
        return EIO;
    }

    // Read configuration parameters from the iSCSI property list. The
    // identity of the initiator is recorded the first time around.
    pthread_mutex_lock(&operationLock);
    iSCSIDUpdatePreferencesFromAppValues();

    if(iSCSIPreferencesEstablishInitiator(preferences))
        iSCSIPreferencesSynchronzeAppValues(preferences);

    CFStringRef initiatorIQN = iSCSIPreferencesCopyInitiatorIQN(preferences);
    CFStringRef initiatorAlias = iSCSIPreferencesCopyInitiatorAlias(preferences);
    iSCSIDUpdateInitiatorIdentity();
    pthread_mutex_unlock(&operationLock);

    iSCSIDLog(kiSCSILogInfo,CFSTR("iscsid %s started; initiator name is %@"),ISCSI_VERSION,initiatorIQN);

    if(initiatorIQN)
        CFRelease(initiatorIQN);

    if(initiatorAlias)
        CFRelease(initiatorAlias);

    if(!iSCSIDRegisterForPowerEvents())
        iSCSILogWarning("could not register to receive system power events");

    // Termination signals are handled on the main thread
    dispatch_source_t signalSources[2];
    const int signals[2] = { SIGTERM, SIGINT };

    for(int idx = 0; idx < 2; idx++) {
        signal(signals[idx],SIG_IGN);
        signalSources[idx] = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,(uintptr_t)signals[idx],0,
                                                    dispatch_get_main_queue());
        dispatch_source_set_event_handler(signalSources[idx],^{ iSCSIDStop(); });
        dispatch_resume(signalSources[idx]);
    }

    pthread_t housekeepingThread, listenerThread;
    pthread_create(&housekeepingThread,NULL,iSCSIDHousekeepingMain,NULL);
    pthread_create(&listenerThread,NULL,iSCSIDListenerMain,NULL);
    pthread_detach(listenerThread);

    // Log in to the targets that are configured for it and start discovery
    iSCSIDAutoLogin();
    iSCSIDScheduleDiscovery(true);

    CFRunLoopRun();

    iSCSILogInfo("shutting down");

    // Requests that are underway are seen through; no more are accepted
    pthread_rwlock_wrlock(&requestLock);
    terminated = true;
    pthread_rwlock_unlock(&requestLock);

    // Stop housekeeping before the sessions are taken down
    pthread_mutex_lock(&housekeepingLock);
    shuttingDown = true;
    pthread_cond_broadcast(&housekeepingCond);
    pthread_mutex_unlock(&housekeepingLock);
    pthread_join(housekeepingThread,NULL);

    iSCSIDLogoutAll();
    iSCSIDDeregisterForPowerEvents();

    iSCSIDiskManagerRelease(diskManager);
    iSCSISessionManagerUnscheduleWithRunloop(sessionManager,CFRunLoopGetMain(),kCFRunLoopDefaultMode);
    iSCSISessionManagerRelease(sessionManager);

    // Remove the socket, unless another instance has put its own in place
    struct stat socketStatus;

    if(listenPath[0] != '\0' && stat(listenPath,&socketStatus) == 0 && socketStatus.st_ino == listenInode)
        unlink(listenPath);

    iSCSILogInfo("stopped");
    return 0;
}
