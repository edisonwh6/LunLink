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

#include "AppSupport.h"
#include "iSCSIDaemonInterfaceShared.h"

#include <string.h>

#pragma mark - Helpers

static CFMutableDictionaryRef CreateDictionary(void)
{
    return CFDictionaryCreateMutable(kCFAllocatorDefault,0,&kCFTypeDictionaryKeyCallBacks,
                                     &kCFTypeDictionaryValueCallBacks);
}

static void SetBool(CFMutableDictionaryRef dictionary,CFStringRef key,bool value)
{
    CFDictionarySetValue(dictionary,key,value ? kCFBooleanTrue : kCFBooleanFalse);
}

static void SetInt(CFMutableDictionaryRef dictionary,CFStringRef key,SInt64 value)
{
    CFNumberRef number = CFNumberCreate(kCFAllocatorDefault,kCFNumberSInt64Type,&value);
    CFDictionarySetValue(dictionary,key,number);
    CFRelease(number);
}

/*! Sets a string; the string is released if release is true. */
static void SetString(CFMutableDictionaryRef dictionary,CFStringRef key,CFStringRef value,bool release)
{
    if(!value)
        return;

    CFDictionarySetValue(dictionary,key,value);

    if(release)
        CFRelease(value);
}

static CFStringRef GetString(CFDictionaryRef dictionary,CFStringRef key)
{
    CFStringRef value = dictionary ? CFDictionaryGetValue(dictionary,key) : NULL;
    return (value && CFGetTypeID(value) == CFStringGetTypeID()) ? value : NULL;
}

/*! Gets a boolean setting; returns false if the setting is absent. */
static bool GetBool(CFDictionaryRef dictionary,CFStringRef key,bool * value)
{
    CFBooleanRef boolean = dictionary ? CFDictionaryGetValue(dictionary,key) : NULL;

    if(!boolean || CFGetTypeID(boolean) != CFBooleanGetTypeID())
        return false;

    *value = CFBooleanGetValue(boolean);
    return true;
}

static CFMutableDictionaryRef CreatePortalDictionary(iSCSIPortalRef portal)
{
    CFMutableDictionaryRef dictionary = CreateDictionary();
    SetString(dictionary,CFSTR("Address"),iSCSIPortalGetAddress(portal),false);
    SetString(dictionary,CFSTR("Port"),iSCSIPortalGetPort(portal),false);
    SetString(dictionary,CFSTR("Interface"),iSCSIPortalGetHostInterface(portal),false);
    return dictionary;
}

static iSCSIMutableTargetRef CreateTarget(CFStringRef targetIQN)
{
    iSCSIMutableTargetRef target = iSCSITargetCreateMutable();
    iSCSITargetSetIQN(target,targetIQN);
    return target;
}

/*! Modifies the preferences under the preferences lock of the daemon. */
static int ModifyPreferences(iSCSIDaemonHandle handle,int (^modify)(iSCSIPreferencesRef preferences))
{
    if(handle < 0)
        return ENOTCONN;

    iSCSIPreferencesRef preferences = iSCSIPreferencesCreateFromAppValues();
    int error = iSCSIDaemonPreferencesIOLockAndSync(handle,preferences);

    if(!error) {
        if(!(error = modify(preferences)))
            error = iSCSIDaemonPreferencesIOUnlockAndSync(handle,preferences);
        else
            iSCSIDaemonPreferencesIOUnlockAndSync(handle,NULL);
    }

    iSCSIPreferencesRelease(preferences);
    return error;
}

#pragma mark - Snapshot

static CFMutableDictionaryRef CreateTargetSnapshot(iSCSIDaemonHandle handle,
                                                   iSCSIPreferencesRef preferences,
                                                   CFStringRef targetIQN)
{
    CFMutableDictionaryRef snapshot = CreateDictionary();
    iSCSIMutableTargetRef target = CreateTarget(targetIQN);
    bool dynamic = (iSCSIPreferencesGetTargetConfigType(preferences,targetIQN) == kiSCSITargetConfigDynamicSendTargets);

    SetString(snapshot,CFSTR("IQN"),targetIQN,false);
    SetString(snapshot,CFSTR("Alias"),iSCSIPreferencesGetTargetAlias(preferences,targetIQN),false);
    SetBool(snapshot,CFSTR("Dynamic"),dynamic);

    if(dynamic)
        SetString(snapshot,CFSTR("DiscoveryPortal"),iSCSIPreferencesGetDiscoveryPortalForTarget(preferences,targetIQN),false);

    SetBool(snapshot,CFSTR("AutoLogin"),iSCSIPreferencesGetAutoLoginForTarget(preferences,targetIQN));
    SetBool(snapshot,CFSTR("Persistent"),iSCSIPreferencesGetPersistenceForTarget(preferences,targetIQN));
    SetBool(snapshot,CFSTR("ReadOnly"),iSCSIPreferencesGetReadOnlyForTarget(preferences,targetIQN));
    SetBool(snapshot,CFSTR("SyncWrites"),iSCSIPreferencesGetSyncWritesForTarget(preferences,targetIQN));
    SetBool(snapshot,CFSTR("HeaderDigest"),iSCSIPreferencesGetHeaderDigestForTarget(preferences,targetIQN) == kiSCSIDigestCRC32C);
    SetBool(snapshot,CFSTR("DataDigest"),iSCSIPreferencesGetDataDigestForTarget(preferences,targetIQN) == kiSCSIDigestCRC32C);

    // How the initiator authenticates itself to this target
    enum iSCSIAuthMethods method = iSCSIPreferencesGetInitiatorAuthenticationMethodForTarget(preferences,targetIQN);
    CFStringRef node = iSCSIKeychainCreateNodeForInitiatorOfTarget(targetIQN);

    SetString(snapshot,CFSTR("InitiatorAuth"),(method == kiSCSIAuthMethodCHAP) ? CFSTR("CHAP") :
                                              (method == kiSCSIAuthMethodNone) ? CFSTR("None") : CFSTR("Default"),false);
    SetString(snapshot,CFSTR("InitiatorCHAPName"),iSCSIPreferencesCopyInitiatorCHAPNameForTarget(preferences,targetIQN),true);
    SetBool(snapshot,CFSTR("HasInitiatorSecret"),iSCSIKeychainContainsCHAPSecretForNode(node));
    CFRelease(node);

    // How the target authenticates itself to the initiator
    SetBool(snapshot,CFSTR("MutualCHAP"),iSCSIPreferencesGetTargetAuthenticationMethod(preferences,targetIQN) == kiSCSIAuthMethodCHAP);
    SetString(snapshot,CFSTR("TargetCHAPName"),iSCSIPreferencesCopyTargetCHAPName(preferences,targetIQN),true);
    SetBool(snapshot,CFSTR("HasTargetSecret"),iSCSIKeychainContainsCHAPSecretForNode(targetIQN));

    // Portals
    CFMutableArrayRef portals = CFArrayCreateMutable(kCFAllocatorDefault,0,&kCFTypeArrayCallBacks);
    CFArrayRef addresses = iSCSIPreferencesCreateArrayOfPortalsForTarget(preferences,targetIQN);

    for(CFIndex idx = 0; addresses && idx < CFArrayGetCount(addresses); idx++) {
        iSCSIPortalRef portal = iSCSIPreferencesCopyPortalForTarget(preferences,targetIQN,CFArrayGetValueAtIndex(addresses,idx));

        if(!portal)
            continue;

        CFMutableDictionaryRef dictionary = CreatePortalDictionary(portal);
        SetBool(dictionary,CFSTR("Active"),handle >= 0 && iSCSIDaemonIsPortalActive(handle,target,portal));
        CFArrayAppendValue(portals,dictionary);
        CFRelease(dictionary);
        iSCSIPortalRelease(portal);
    }

    if(addresses)
        CFRelease(addresses);

    CFDictionarySetValue(snapshot,CFSTR("Portals"),portals);
    CFRelease(portals);

    // Session and disks
    if(handle >= 0) {
        CFDictionaryRef session = iSCSIDaemonCreateCFPropertiesForSession(handle,target);

        if(session) {
            CFDictionarySetValue(snapshot,CFSTR("Session"),session);
            CFRelease(session);

            CFArrayRef disks = iSCSIDaemonCreateArrayOfDisksForTarget(handle,target);

            if(disks) {
                CFDictionarySetValue(snapshot,CFSTR("Disks"),disks);
                CFRelease(disks);
            }
        }
    }

    iSCSITargetRelease(target);
    return snapshot;
}

CFDictionaryRef iSCSIAppCopySnapshot(iSCSIDaemonHandle handle)
{
    CFMutableDictionaryRef snapshot = CreateDictionary();
    iSCSIPreferencesRef preferences = iSCSIPreferencesCreateFromAppValues();

    // Daemon
    CFMutableDictionaryRef daemon = CreateDictionary();
    CFDictionaryRef status = (handle >= 0) ? iSCSIDaemonCreateStatus(handle) : NULL;

    SetBool(daemon,CFSTR("Running"),status != NULL);

    if(status) {
        SetString(daemon,CFSTR("Version"),GetString(status,kiSCSIDStatusVersion),false);

        CFNumberRef processId = CFDictionaryGetValue(status,kiSCSIDStatusProcessId);
        if(processId)
            CFDictionarySetValue(daemon,CFSTR("ProcessID"),processId);

        CFRelease(status);
    }
    else
        handle = -1;

    CFDictionarySetValue(snapshot,CFSTR("Daemon"),daemon);
    CFRelease(daemon);

    // Initiator
    CFMutableDictionaryRef initiator = CreateDictionary();
    CFStringRef initiatorIQN = iSCSIPreferencesCopyInitiatorIQN(preferences);

    SetBool(initiator,CFSTR("HasSecret"),initiatorIQN && iSCSIKeychainContainsCHAPSecretForNode(initiatorIQN));
    SetString(initiator,CFSTR("Name"),initiatorIQN,true);
    SetString(initiator,CFSTR("Alias"),iSCSIPreferencesCopyInitiatorAlias(preferences),true);
    SetBool(initiator,CFSTR("CHAP"),iSCSIPreferencesGetInitiatorAuthenticationMethod(preferences) == kiSCSIAuthMethodCHAP);
    SetString(initiator,CFSTR("CHAPName"),iSCSIPreferencesCopyInitiatorCHAPName(preferences),true);
    CFDictionarySetValue(snapshot,CFSTR("Initiator"),initiator);
    CFRelease(initiator);

    // Discovery
    CFMutableDictionaryRef discovery = CreateDictionary();
    CFMutableArrayRef discoveryPortals = CFArrayCreateMutable(kCFAllocatorDefault,0,&kCFTypeArrayCallBacks);
    CFArrayRef addresses = iSCSIPreferencesCreateArrayOfPortalsForSendTargetsDiscovery(preferences);

    for(CFIndex idx = 0; addresses && idx < CFArrayGetCount(addresses); idx++) {
        iSCSIPortalRef portal = iSCSIPreferencesCopySendTargetsDiscoveryPortal(preferences,CFArrayGetValueAtIndex(addresses,idx));

        if(!portal)
            continue;

        CFMutableDictionaryRef dictionary = CreatePortalDictionary(portal);
        CFArrayAppendValue(discoveryPortals,dictionary);
        CFRelease(dictionary);
        iSCSIPortalRelease(portal);
    }

    if(addresses)
        CFRelease(addresses);

    SetBool(discovery,CFSTR("Enabled"),iSCSIPreferencesGetSendTargetsDiscoveryEnable(preferences));
    SetInt(discovery,CFSTR("Interval"),iSCSIPreferencesGetSendTargetsDiscoveryInterval(preferences));
    CFDictionarySetValue(discovery,CFSTR("Portals"),discoveryPortals);
    CFRelease(discoveryPortals);
    CFDictionarySetValue(snapshot,CFSTR("Discovery"),discovery);
    CFRelease(discovery);

    // Targets
    CFMutableArrayRef targets = CFArrayCreateMutable(kCFAllocatorDefault,0,&kCFTypeArrayCallBacks);
    CFArrayRef targetIQNs = iSCSIPreferencesCreateArrayOfTargets(preferences);

    for(CFIndex idx = 0; targetIQNs && idx < CFArrayGetCount(targetIQNs); idx++) {
        CFMutableDictionaryRef target = CreateTargetSnapshot(handle,preferences,CFArrayGetValueAtIndex(targetIQNs,idx));
        CFArrayAppendValue(targets,target);
        CFRelease(target);
    }

    if(targetIQNs)
        CFRelease(targetIQNs);

    CFDictionarySetValue(snapshot,CFSTR("Targets"),targets);
    CFRelease(targets);

    iSCSIPreferencesRelease(preferences);
    return snapshot;
}

#pragma mark - Discovery

CFArrayRef iSCSIAppCopyDiscoveredTargets(iSCSIDaemonHandle handle,
                                         CFStringRef portalString,
                                         int * error,
                                         int * statusCode)
{
    *error = 0;
    *statusCode = kiSCSILoginInvalidStatusCode;

    iSCSIMutablePortalRef portal = iSCSIUtilsCreatePortalWithString(portalString,NULL);

    if(!portal) {
        *error = EINVAL;
        return NULL;
    }

    iSCSIDiscoveryRecRef discoveryRec = NULL;
    enum iSCSILoginStatusCode loginStatus = kiSCSILoginInvalidStatusCode;

    *error = (handle < 0) ? ENOTCONN : iSCSIDaemonQueryPortalForTargets(handle,portal,&discoveryRec,&loginStatus);
    *statusCode = loginStatus;
    iSCSIPortalRelease(portal);

    if(*error || !discoveryRec) {
        if(discoveryRec)
            iSCSIDiscoveryRecRelease(discoveryRec);

        if(!*error)
            *error = EIO;

        return NULL;
    }

    CFMutableArrayRef result = CFArrayCreateMutable(kCFAllocatorDefault,0,&kCFTypeArrayCallBacks);
    CFArrayRef targets = iSCSIDiscoveryRecCreateArrayOfTargets(discoveryRec);

    for(CFIndex idx = 0; targets && idx < CFArrayGetCount(targets); idx++) {
        CFStringRef targetIQN = CFArrayGetValueAtIndex(targets,idx);
        CFMutableDictionaryRef entry = CreateDictionary();
        CFMutableArrayRef portals = CFArrayCreateMutable(kCFAllocatorDefault,0,&kCFTypeArrayCallBacks);
        CFArrayRef groups = iSCSIDiscoveryRecCreateArrayOfPortalGroupTags(discoveryRec,targetIQN);

        for(CFIndex groupIdx = 0; groups && groupIdx < CFArrayGetCount(groups); groupIdx++) {
            CFArrayRef groupPortals = iSCSIDiscoveryRecGetPortals(discoveryRec,targetIQN,CFArrayGetValueAtIndex(groups,groupIdx));

            for(CFIndex portalIdx = 0; groupPortals && portalIdx < CFArrayGetCount(groupPortals); portalIdx++) {
                CFMutableDictionaryRef dictionary = CreatePortalDictionary(CFArrayGetValueAtIndex(groupPortals,portalIdx));
                CFArrayAppendValue(portals,dictionary);
                CFRelease(dictionary);
            }
        }

        if(groups)
            CFRelease(groups);

        SetString(entry,CFSTR("IQN"),targetIQN,false);
        CFDictionarySetValue(entry,CFSTR("Portals"),portals);
        CFRelease(portals);
        CFArrayAppendValue(result,entry);
        CFRelease(entry);
    }

    if(targets)
        CFRelease(targets);

    iSCSIDiscoveryRecRelease(discoveryRec);
    return result;
}

#pragma mark - Paths and descriptions

CFStringRef iSCSIAppCopyDaemonSocketPath(void)
{
    char path[1024];

    if(!iSCSIUtilsGetSocketPath(kiSCSIDaemonSocketName,path,sizeof(path)))
        return NULL;

    return CFStringCreateWithFileSystemRepresentation(kCFAllocatorDefault,path);
}

CFStringRef iSCSIAppCopyDaemonLogPath(void)
{
    char path[1024];

    if(!iSCSIUtilsGetLogPath(path,sizeof(path)))
        return NULL;

    return CFStringCreateWithFileSystemRepresentation(kCFAllocatorDefault,path);
}

CFStringRef iSCSIAppCopyLoginStatusDescription(int statusCode)
{
    return CFStringCreateCopy(kCFAllocatorDefault,iSCSIUtilsGetStringForLoginStatus((enum iSCSILoginStatusCode)statusCode));
}

#pragma mark - Sessions

int iSCSIAppLogin(iSCSIDaemonHandle handle,CFStringRef targetIQN,int * statusCode)
{
    *statusCode = kiSCSILoginInvalidStatusCode;

    if(handle < 0)
        return ENOTCONN;

    if(!targetIQN)
        return EINVAL;

    iSCSIMutableTargetRef target = CreateTarget(targetIQN);
    enum iSCSILoginStatusCode loginStatus = kiSCSILoginInvalidStatusCode;
    int error = iSCSIDaemonLogin(handle,target,NULL,&loginStatus);

    *statusCode = loginStatus;
    iSCSITargetRelease(target);
    return error;
}

int iSCSIAppLogout(iSCSIDaemonHandle handle,CFStringRef targetIQN,bool force)
{
    if(handle < 0)
        return ENOTCONN;

    if(!targetIQN)
        return EINVAL;

    iSCSIMutableTargetRef target = CreateTarget(targetIQN);
    enum iSCSILogoutStatusCode logoutStatus;
    int error = iSCSIDaemonLogout(handle,target,force,&logoutStatus);

    iSCSITargetRelease(target);
    return error;
}

#pragma mark - Targets

int iSCSIAppAddTarget(iSCSIDaemonHandle handle,CFStringRef targetIQN,CFStringRef portalString)
{
    if(!targetIQN || !iSCSIUtilsValidateIQN(targetIQN))
        return EINVAL;

    iSCSIMutablePortalRef portal = iSCSIUtilsCreatePortalWithString(portalString,NULL);

    if(!portal)
        return EDESTADDRREQ;

    int error = ModifyPreferences(handle,^int(iSCSIPreferencesRef preferences) {
        if(!iSCSIPreferencesContainsTarget(preferences,targetIQN))
            iSCSIPreferencesAddStaticTarget(preferences,targetIQN,portal);
        else if(!iSCSIPreferencesContainsPortalForTarget(preferences,targetIQN,iSCSIPortalGetAddress(portal)))
            iSCSIPreferencesSetPortalForTarget(preferences,targetIQN,portal);
        else
            return EEXIST;

        return 0;
    });

    iSCSIPortalRelease(portal);
    return error;
}

int iSCSIAppRemoveTarget(iSCSIDaemonHandle handle,CFStringRef targetIQN)
{
    if(handle < 0)
        return ENOTCONN;

    if(!targetIQN)
        return EINVAL;

    iSCSIMutableTargetRef target = CreateTarget(targetIQN);
    Boolean active = iSCSIDaemonIsTargetActive(handle,target);
    iSCSITargetRelease(target);

    if(active)
        return EBUSY;

    int error = ModifyPreferences(handle,^int(iSCSIPreferencesRef preferences) {
        if(!iSCSIPreferencesContainsTarget(preferences,targetIQN))
            return ENOENT;

        iSCSIPreferencesRemoveTarget(preferences,targetIQN);
        return 0;
    });

    // The secrets of a target go with it
    if(!error) {
        CFStringRef node = iSCSIKeychainCreateNodeForInitiatorOfTarget(targetIQN);
        iSCSIDaemonRemoveSharedSecret(handle,targetIQN);
        iSCSIDaemonRemoveSharedSecret(handle,node);
        CFRelease(node);
    }
    return error;
}

int iSCSIAppUpdateTarget(iSCSIDaemonHandle handle,CFStringRef targetIQN,CFDictionaryRef settings)
{
    if(!targetIQN || !settings)
        return EINVAL;

    int error = ModifyPreferences(handle,^int(iSCSIPreferencesRef preferences) {
        if(!iSCSIPreferencesContainsTarget(preferences,targetIQN))
            return ENOENT;

        bool value = false;
        CFStringRef string;

        if(GetBool(settings,CFSTR("AutoLogin"),&value))
            iSCSIPreferencesSetAutoLoginForTarget(preferences,targetIQN,value);

        if(GetBool(settings,CFSTR("Persistent"),&value))
            iSCSIPreferencesSetPersistenceForTarget(preferences,targetIQN,value);

        if(GetBool(settings,CFSTR("ReadOnly"),&value))
            iSCSIPreferencesSetReadOnlyForTarget(preferences,targetIQN,value);

        if(GetBool(settings,CFSTR("SyncWrites"),&value))
            iSCSIPreferencesSetSyncWritesForTarget(preferences,targetIQN,value);

        if(GetBool(settings,CFSTR("HeaderDigest"),&value))
            iSCSIPreferencesSetHeaderDigestForTarget(preferences,targetIQN,value ? kiSCSIDigestCRC32C : kiSCSIDigestNone);

        if(GetBool(settings,CFSTR("DataDigest"),&value))
            iSCSIPreferencesSetDataDigestForTarget(preferences,targetIQN,value ? kiSCSIDigestCRC32C : kiSCSIDigestNone);

        if((string = GetString(settings,CFSTR("InitiatorAuth")))) {
            enum iSCSIAuthMethods method = CFEqual(string,CFSTR("CHAP")) ? kiSCSIAuthMethodCHAP :
                                           CFEqual(string,CFSTR("None")) ? kiSCSIAuthMethodNone : kiSCSIAuthMethodInvalid;
            iSCSIPreferencesSetInitiatorAuthenticationMethodForTarget(preferences,targetIQN,method);
        }

        if((string = GetString(settings,CFSTR("InitiatorCHAPName"))))
            iSCSIPreferencesSetInitiatorCHAPNameForTarget(preferences,targetIQN,string);

        if(GetBool(settings,CFSTR("MutualCHAP"),&value))
            iSCSIPreferencesSetTargetAuthenticationMethod(preferences,targetIQN,value ? kiSCSIAuthMethodCHAP : kiSCSIAuthMethodNone);

        if((string = GetString(settings,CFSTR("TargetCHAPName"))))
            iSCSIPreferencesSetTargetCHAPName(preferences,targetIQN,string);

        return 0;
    });

    // Secrets are kept by the daemon, apart from the preferences
    CFStringRef secret;

    if(!error && (secret = GetString(settings,CFSTR("InitiatorSecret")))) {
        CFStringRef node = iSCSIKeychainCreateNodeForInitiatorOfTarget(targetIQN);
        error = iSCSIDaemonSetSharedSecret(handle,node,secret);
        CFRelease(node);
    }

    if(!error && (secret = GetString(settings,CFSTR("TargetSecret"))))
        error = iSCSIDaemonSetSharedSecret(handle,targetIQN,secret);

    return error;
}

#pragma mark - Initiator and discovery

int iSCSIAppUpdateInitiator(iSCSIDaemonHandle handle,CFDictionaryRef settings)
{
    if(!settings)
        return EINVAL;

    __block CFStringRef initiatorIQN = NULL;

    int error = ModifyPreferences(handle,^int(iSCSIPreferencesRef preferences) {
        bool value = false;
        CFStringRef string;

        if((string = GetString(settings,CFSTR("Name")))) {
            if(!iSCSIUtilsValidateIQN(string))
                return EINVAL;

            iSCSIPreferencesSetInitiatorIQN(preferences,string);
        }

        if((string = GetString(settings,CFSTR("Alias"))))
            iSCSIPreferencesSetInitiatorAlias(preferences,string);

        if(GetBool(settings,CFSTR("CHAP"),&value))
            iSCSIPreferencesSetInitiatorAuthenticationMethod(preferences,value ? kiSCSIAuthMethodCHAP : kiSCSIAuthMethodNone);

        if((string = GetString(settings,CFSTR("CHAPName"))))
            iSCSIPreferencesSetInitiatorCHAPName(preferences,string);

        initiatorIQN = iSCSIPreferencesCopyInitiatorIQN(preferences);
        return 0;
    });

    // The secret is filed under the name of the initiator
    CFStringRef secret = GetString(settings,CFSTR("Secret"));

    if(!error && secret && initiatorIQN)
        error = iSCSIDaemonSetSharedSecret(handle,initiatorIQN,secret);

    if(initiatorIQN)
        CFRelease(initiatorIQN);

    return error;
}

int iSCSIAppUpdateDiscovery(iSCSIDaemonHandle handle,CFDictionaryRef settings)
{
    if(!settings)
        return EINVAL;

    int error = ModifyPreferences(handle,^int(iSCSIPreferencesRef preferences) {
        bool value = false;
        CFNumberRef interval = CFDictionaryGetValue(settings,CFSTR("Interval"));

        if(GetBool(settings,CFSTR("Enabled"),&value))
            iSCSIPreferencesSetSendTargetsDiscoveryEnable(preferences,value);

        if(interval && CFGetTypeID(interval) == CFNumberGetTypeID()) {
            CFIndex seconds = 0;
            CFNumberGetValue(interval,kCFNumberCFIndexType,&seconds);

            if(seconds < (CFIndex)kiSCSIInitiator_DiscoveryInterval_Min || seconds > (CFIndex)kiSCSIInitiator_DiscoveryInterval_Max)
                return EINVAL;

            iSCSIPreferencesSetSendTargetsDiscoveryInterval(preferences,seconds);
        }
        return 0;
    });

    if(!error)
        iSCSIDaemonUpdateDiscovery(handle);

    return error;
}

int iSCSIAppAddDiscoveryPortal(iSCSIDaemonHandle handle,CFStringRef portalString)
{
    iSCSIMutablePortalRef portal = iSCSIUtilsCreatePortalWithString(portalString,NULL);

    if(!portal)
        return EDESTADDRREQ;

    int error = ModifyPreferences(handle,^int(iSCSIPreferencesRef preferences) {
        if(iSCSIPreferencesContainsPortalForSendTargetsDiscovery(preferences,iSCSIPortalGetAddress(portal)))
            return EEXIST;

        iSCSIPreferencesAddSendTargetsDiscoveryPortal(preferences,portal);

        // A discovery portal is of little use unless discovery is enabled
        iSCSIPreferencesSetSendTargetsDiscoveryEnable(preferences,true);
        return 0;
    });

    if(!error)
        iSCSIDaemonUpdateDiscovery(handle);

    iSCSIPortalRelease(portal);
    return error;
}

int iSCSIAppRemoveDiscoveryPortal(iSCSIDaemonHandle handle,CFStringRef address)
{
    if(handle < 0)
        return ENOTCONN;

    if(!address)
        return EINVAL;

    // Targets that were discovered through the portal are removed along
    // with it, hence none of them may be logged in
    CFArrayRef activeTargets = iSCSIDaemonCreateArrayOfActiveTargets(handle);

    int error = ModifyPreferences(handle,^int(iSCSIPreferencesRef preferences) {
        if(!iSCSIPreferencesContainsPortalForSendTargetsDiscovery(preferences,address))
            return ENOENT;

        CFArrayRef targets = iSCSIPreferencesCreateArrayOfDynamicTargetsForSendTargets(preferences,address);
        bool busy = false;

        for(CFIndex idx = 0; targets && idx < CFArrayGetCount(targets) && !busy; idx++) {
            for(CFIndex activeIdx = 0; activeTargets && activeIdx < CFArrayGetCount(activeTargets) && !busy; activeIdx++) {
                iSCSITargetRef active = iSCSITargetCreateWithDictionary(CFArrayGetValueAtIndex(activeTargets,activeIdx));

                if(active) {
                    busy = CFStringCompare(iSCSITargetGetIQN(active),CFArrayGetValueAtIndex(targets,idx),0) == kCFCompareEqualTo;
                    iSCSITargetRelease(active);
                }
            }
        }

        if(targets)
            CFRelease(targets);

        if(busy)
            return EBUSY;

        iSCSIPortalRef portal = iSCSIPreferencesCopySendTargetsDiscoveryPortal(preferences,address);

        if(portal) {
            iSCSIPreferencesRemoveSendTargetsDiscoveryPortal(preferences,portal);
            iSCSIPortalRelease(portal);
        }
        return 0;
    });

    if(activeTargets)
        CFRelease(activeTargets);

    return error;
}
