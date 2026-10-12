/*
 * Exercises the facade through which the graphical application talks to the
 * daemon (Source/User/App/AppSupport.c), in the order in which a user would:
 * discover a target, add it, set it up, connect, disconnect and remove it.
 *
 * usage: appsupport-test <target-iqn> <portal> <chap-name> <chap-secret>
 */

#include "AppSupport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) \
    do { \
        if(!(condition)) { \
            fprintf(stderr,"%s:%d: check failed: %s\n",__FILE__,__LINE__,#condition); \
            exit(1); \
        } \
    } while(0)

static CFStringRef String(const char * string)
{
    return CFStringCreateWithCString(kCFAllocatorDefault,string,kCFStringEncodingUTF8);
}

/*! Finds the entry of a target in a snapshot (NULL if there is none). */
static CFDictionaryRef FindTarget(CFDictionaryRef snapshot,CFStringRef targetIQN)
{
    CFArrayRef targets = CFDictionaryGetValue(snapshot,CFSTR("Targets"));

    for(CFIndex idx = 0; targets && idx < CFArrayGetCount(targets); idx++) {
        CFDictionaryRef target = CFArrayGetValueAtIndex(targets,idx);

        if(CFEqual(CFDictionaryGetValue(target,CFSTR("IQN")),targetIQN))
            return target;
    }
    return NULL;
}

int main(int argc,char * argv[])
{
    if(argc != 5) {
        fprintf(stderr,"usage: %s <target-iqn> <portal> <chap-name> <chap-secret>\n",argv[0]);
        return 2;
    }

    CFStringRef targetIQN = String(argv[1]);
    CFStringRef portal = String(argv[2]);
    CFStringRef chapName = String(argv[3]);
    CFStringRef chapSecret = String(argv[4]);

    iSCSIDaemonHandle handle = iSCSIDaemonConnect();
    CHECK(handle >= 0);

    // Discovery lists the target
    int error = 0, status = 0;
    CFArrayRef discovered = iSCSIAppCopyDiscoveredTargets(handle,portal,&error,&status);
    CHECK(error == 0 && discovered && CFArrayGetCount(discovered) == 1);
    CHECK(CFEqual(CFDictionaryGetValue(CFArrayGetValueAtIndex(discovered,0),CFSTR("IQN")),targetIQN));
    CFRelease(discovered);

    discovered = iSCSIAppCopyDiscoveredTargets(handle,CFSTR("not a portal"),&error,&status);
    CHECK(!discovered && error == EINVAL);

    // Adding the target, and what cannot be added
    CHECK(iSCSIAppAddTarget(handle,targetIQN,portal) == 0);
    CHECK(iSCSIAppAddTarget(handle,targetIQN,portal) == EEXIST);
    CHECK(iSCSIAppAddTarget(handle,CFSTR("bogus"),portal) == EINVAL);
    CHECK(iSCSIAppAddTarget(handle,targetIQN,CFSTR("")) == EDESTADDRREQ);

    // The target requires CHAP: without credentials the login fails
    CHECK(iSCSIAppLogin(handle,targetIQN,&status) != 0);

    const void * keys[] = { CFSTR("AutoLogin"), CFSTR("HeaderDigest"), CFSTR("InitiatorAuth"),
                            CFSTR("InitiatorCHAPName"), CFSTR("InitiatorSecret") };
    const void * values[] = { kCFBooleanTrue, kCFBooleanTrue, CFSTR("CHAP"), chapName, chapSecret };
    CFDictionaryRef settings = CFDictionaryCreate(kCFAllocatorDefault,keys,values,5,&kCFTypeDictionaryKeyCallBacks,
                                                  &kCFTypeDictionaryValueCallBacks);
    CHECK(iSCSIAppUpdateTarget(handle,targetIQN,settings) == 0);
    CFRelease(settings);

    CFDictionaryRef snapshot = iSCSIAppCopySnapshot(handle);
    CFDictionaryRef target = FindTarget(snapshot,targetIQN);
    CHECK(CFDictionaryGetValue(CFDictionaryGetValue(snapshot,CFSTR("Daemon")),CFSTR("Running")) == kCFBooleanTrue);
    CHECK(target != NULL);
    CHECK(CFDictionaryGetValue(target,CFSTR("AutoLogin")) == kCFBooleanTrue);
    CHECK(CFDictionaryGetValue(target,CFSTR("HeaderDigest")) == kCFBooleanTrue);
    CHECK(CFDictionaryGetValue(target,CFSTR("DataDigest")) == kCFBooleanFalse);
    CHECK(CFEqual(CFDictionaryGetValue(target,CFSTR("InitiatorAuth")),CFSTR("CHAP")));
    CHECK(CFEqual(CFDictionaryGetValue(target,CFSTR("InitiatorCHAPName")),chapName));
    CHECK(CFDictionaryGetValue(target,CFSTR("HasInitiatorSecret")) == kCFBooleanTrue);
    CHECK(CFArrayGetCount(CFDictionaryGetValue(target,CFSTR("Portals"))) == 1);
    CHECK(!CFDictionaryContainsKey(target,CFSTR("Session")));
    CFRelease(snapshot);

    // Connecting brings a session and a disk
    CHECK(iSCSIAppLogin(handle,targetIQN,&status) == 0);
    CHECK(iSCSIAppLogin(handle,targetIQN,&status) == EEXIST);

    snapshot = iSCSIAppCopySnapshot(handle);
    target = FindTarget(snapshot,targetIQN);
    CHECK(target && CFDictionaryContainsKey(target,CFSTR("Session")));

    CFArrayRef disks = CFDictionaryGetValue(target,CFSTR("Disks"));
    CHECK(disks && CFArrayGetCount(disks) == 1);
    CHECK(CFDictionaryContainsKey(CFArrayGetValueAtIndex(disks,0),kiSCSIDiskBSDName));

    CFArrayRef portals = CFDictionaryGetValue(target,CFSTR("Portals"));
    CHECK(CFDictionaryGetValue(CFArrayGetValueAtIndex(portals,0),CFSTR("Active")) == kCFBooleanTrue);
    CFRelease(snapshot);

    // A target that is connected cannot be removed
    CHECK(iSCSIAppRemoveTarget(handle,targetIQN) == EBUSY);
    CHECK(iSCSIAppLogout(handle,targetIQN,false) == 0);
    CHECK(iSCSIAppLogout(handle,targetIQN,false) == ENOTCONN);

    // Settings of the initiator
    snapshot = iSCSIAppCopySnapshot(handle);
    CFStringRef alias = CFRetain(CFDictionaryGetValue(CFDictionaryGetValue(snapshot,CFSTR("Initiator")),CFSTR("Alias")));
    CFRelease(snapshot);

    const void * aliasKey = CFSTR("Alias");
    const void * aliasValue = CFSTR("app-support-test");
    settings = CFDictionaryCreate(kCFAllocatorDefault,&aliasKey,&aliasValue,1,&kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks);
    CHECK(iSCSIAppUpdateInitiator(handle,settings) == 0);
    CFRelease(settings);

    snapshot = iSCSIAppCopySnapshot(handle);
    CHECK(CFEqual(CFDictionaryGetValue(CFDictionaryGetValue(snapshot,CFSTR("Initiator")),CFSTR("Alias")),aliasValue));
    CFRelease(snapshot);

    settings = CFDictionaryCreate(kCFAllocatorDefault,&aliasKey,(const void **)&alias,1,&kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks);
    CHECK(iSCSIAppUpdateInitiator(handle,settings) == 0);
    CFRelease(settings);
    CFRelease(alias);

    const void * nameKey = CFSTR("Name");
    const void * nameValue = CFSTR("not an iqn");
    settings = CFDictionaryCreate(kCFAllocatorDefault,&nameKey,&nameValue,1,&kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks);
    CHECK(iSCSIAppUpdateInitiator(handle,settings) == EINVAL);
    CFRelease(settings);

    // Removing the target takes its secret along
    CHECK(iSCSIAppRemoveTarget(handle,targetIQN) == 0);
    CHECK(iSCSIAppRemoveTarget(handle,targetIQN) == ENOENT);

    snapshot = iSCSIAppCopySnapshot(handle);
    CHECK(FindTarget(snapshot,targetIQN) == NULL);
    CFRelease(snapshot);

    CFStringRef node = iSCSIKeychainCreateNodeForInitiatorOfTarget(targetIQN);
    CHECK(!iSCSIKeychainContainsCHAPSecretForNode(node));
    CFRelease(node);

    // Discovery portals
    CHECK(iSCSIAppAddDiscoveryPortal(handle,portal) == 0);
    CHECK(iSCSIAppAddDiscoveryPortal(handle,portal) == EEXIST);

    snapshot = iSCSIAppCopySnapshot(handle);
    CFDictionaryRef discovery = CFDictionaryGetValue(snapshot,CFSTR("Discovery"));
    CFArrayRef discoveryPortals = CFDictionaryGetValue(discovery,CFSTR("Portals"));
    CHECK(CFDictionaryGetValue(discovery,CFSTR("Enabled")) == kCFBooleanTrue);
    CHECK(CFArrayGetCount(discoveryPortals) == 1);

    CFStringRef address = CFRetain(CFDictionaryGetValue(CFArrayGetValueAtIndex(discoveryPortals,0),CFSTR("Address")));
    CFRelease(snapshot);

    CHECK(iSCSIAppRemoveDiscoveryPortal(handle,address) == 0);
    CHECK(iSCSIAppRemoveDiscoveryPortal(handle,address) == ENOENT);
    CFRelease(address);

    const void * enabledKey = CFSTR("Enabled");
    const void * enabledValue = kCFBooleanFalse;
    settings = CFDictionaryCreate(kCFAllocatorDefault,&enabledKey,&enabledValue,1,&kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks);
    CHECK(iSCSIAppUpdateDiscovery(handle,settings) == 0);
    CFRelease(settings);

    iSCSIDaemonDisconnect(handle);
    printf("OK\n");
    return 0;
}
