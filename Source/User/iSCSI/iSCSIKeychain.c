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

#include "iSCSIKeychain.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

/*! Service name of the keychain items. */
static const CFStringRef kiSCSIKeychainService = CFSTR("LunLink");

/*! Description of the keychain items. */
static const CFStringRef kiSCSIKeychainDescription = CFSTR("iSCSI CHAP Shared Secret");

CFStringRef iSCSIKeychainCreateNodeForInitiatorOfTarget(CFStringRef targetIQN)
{
    return CFStringCreateWithFormat(kCFAllocatorDefault,NULL,CFSTR("initiator@%@"),targetIQN);
}

#pragma mark - File store

/*! Gets the path of the file that replaces the keychain, if any. */
static const char * iSCSIKeychainGetFilePath(void)
{
    const char * path = getenv("ISCSI_SECRETS_FILE");
    return (path && path[0] != '\0') ? path : NULL;
}

static CFMutableDictionaryRef iSCSIKeychainFileRead(const char * path)
{
    CFMutableDictionaryRef secrets = NULL;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,(const UInt8 *)path,
                                                           (CFIndex)strlen(path),false);
    CFReadStreamRef stream = CFReadStreamCreateWithFile(kCFAllocatorDefault,url);

    if(stream && CFReadStreamOpen(stream)) {
        CFPropertyListRef plist = CFPropertyListCreateWithStream(kCFAllocatorDefault,stream,0,
                                                                 kCFPropertyListMutableContainers,NULL,NULL);
        if(plist && CFGetTypeID(plist) == CFDictionaryGetTypeID())
            secrets = (CFMutableDictionaryRef)plist;
        else if(plist)
            CFRelease(plist);

        CFReadStreamClose(stream);
    }

    if(stream)
        CFRelease(stream);

    CFRelease(url);

    if(!secrets)
        secrets = CFDictionaryCreateMutable(kCFAllocatorDefault,0,&kCFTypeDictionaryKeyCallBacks,
                                            &kCFTypeDictionaryValueCallBacks);
    return secrets;
}

static OSStatus iSCSIKeychainFileWrite(const char * path,CFDictionaryRef secrets)
{
    CFDataRef data = CFPropertyListCreateData(kCFAllocatorDefault,secrets,kCFPropertyListXMLFormat_v1_0,0,NULL);

    if(!data)
        return errSecParam;

    // The file is readable by its owner only
    OSStatus status = errSecIO;
    int fd = open(path,O_WRONLY | O_CREAT | O_TRUNC,0600);

    if(fd >= 0) {
        fchmod(fd,0600);

        if(write(fd,CFDataGetBytePtr(data),(size_t)CFDataGetLength(data)) == CFDataGetLength(data))
            status = errSecSuccess;

        close(fd);
    }
    CFRelease(data);
    return status;
}

#pragma mark - Keychain

/*! Creates a query that matches the keychain item of a node. */
static CFMutableDictionaryRef iSCSIKeychainCreateQuery(CFStringRef nodeIQN)
{
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault,0,
                                                             &kCFTypeDictionaryKeyCallBacks,
                                                             &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query,kSecClass,kSecClassGenericPassword);
    CFDictionarySetValue(query,kSecAttrService,kiSCSIKeychainService);
    CFDictionarySetValue(query,kSecAttrAccount,nodeIQN);
    return query;
}

CFStringRef iSCSIKeychainCopyCHAPSecretForNode(CFStringRef nodeIQN)
{
    if(!nodeIQN)
        return NULL;

    const char * path = iSCSIKeychainGetFilePath();

    if(path) {
        CFMutableDictionaryRef secrets = iSCSIKeychainFileRead(path);
        CFStringRef secret = CFDictionaryGetValue(secrets,nodeIQN);

        if(secret && CFGetTypeID(secret) == CFStringGetTypeID())
            CFRetain(secret);
        else
            secret = NULL;

        CFRelease(secrets);
        return secret;
    }

    CFMutableDictionaryRef query = iSCSIKeychainCreateQuery(nodeIQN);
    CFDictionarySetValue(query,kSecReturnData,kCFBooleanTrue);
    CFDictionarySetValue(query,kSecMatchLimit,kSecMatchLimitOne);

    CFTypeRef data = NULL;
    CFStringRef secret = NULL;

    if(SecItemCopyMatching(query,&data) == errSecSuccess && data && CFGetTypeID(data) == CFDataGetTypeID())
        secret = CFStringCreateFromExternalRepresentation(kCFAllocatorDefault,data,kCFStringEncodingUTF8);

    if(data)
        CFRelease(data);

    CFRelease(query);
    return secret;
}

OSStatus iSCSIKeychainSetCHAPSecretForNode(CFStringRef nodeIQN,
                                           CFStringRef sharedSecret)
{
    if(!nodeIQN || !sharedSecret)
        return errSecParam;

    const char * path = iSCSIKeychainGetFilePath();

    if(path) {
        CFMutableDictionaryRef secrets = iSCSIKeychainFileRead(path);
        CFDictionarySetValue(secrets,nodeIQN,sharedSecret);
        OSStatus status = iSCSIKeychainFileWrite(path,secrets);
        CFRelease(secrets);
        return status;
    }

    CFDataRef data = CFStringCreateExternalRepresentation(kCFAllocatorDefault,sharedSecret,kCFStringEncodingUTF8,0);

    if(!data)
        return errSecParam;

    // Update the secret if it exists; else create a new entry
    CFMutableDictionaryRef query = iSCSIKeychainCreateQuery(nodeIQN);
    CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(kCFAllocatorDefault,0,
                                                                  &kCFTypeDictionaryKeyCallBacks,
                                                                  &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(attributes,kSecValueData,data);

    OSStatus status = SecItemUpdate(query,attributes);

    if(status == errSecItemNotFound) {
        CFStringRef label = CFStringCreateWithFormat(kCFAllocatorDefault,NULL,CFSTR("iSCSI: %@"),nodeIQN);

        CFDictionarySetValue(query,kSecValueData,data);
        CFDictionarySetValue(query,kSecAttrLabel,label);
        CFDictionarySetValue(query,kSecAttrDescription,kiSCSIKeychainDescription);
        status = SecItemAdd(query,NULL);
        CFRelease(label);
    }

    CFRelease(attributes);
    CFRelease(query);
    CFRelease(data);
    return status;
}

OSStatus iSCSIKeychainDeleteCHAPSecretForNode(CFStringRef nodeIQN)
{
    if(!nodeIQN)
        return errSecParam;

    const char * path = iSCSIKeychainGetFilePath();

    if(path) {
        CFMutableDictionaryRef secrets = iSCSIKeychainFileRead(path);
        OSStatus status = errSecItemNotFound;

        if(CFDictionaryContainsKey(secrets,nodeIQN)) {
            CFDictionaryRemoveValue(secrets,nodeIQN);
            status = iSCSIKeychainFileWrite(path,secrets);
        }
        CFRelease(secrets);
        return status;
    }

    CFMutableDictionaryRef query = iSCSIKeychainCreateQuery(nodeIQN);
    OSStatus status = SecItemDelete(query);
    CFRelease(query);
    return status;
}

Boolean iSCSIKeychainContainsCHAPSecretForNode(CFStringRef nodeIQN)
{
    if(!nodeIQN)
        return false;

    const char * path = iSCSIKeychainGetFilePath();

    if(path) {
        CFMutableDictionaryRef secrets = iSCSIKeychainFileRead(path);
        Boolean contains = CFDictionaryContainsKey(secrets,nodeIQN);
        CFRelease(secrets);
        return contains;
    }

    // Looking up an item without asking for its data does not require
    // access to the secret itself
    CFMutableDictionaryRef query = iSCSIKeychainCreateQuery(nodeIQN);
    CFDictionarySetValue(query,kSecMatchLimit,kSecMatchLimitOne);

    OSStatus status = SecItemCopyMatching(query,NULL);
    CFRelease(query);
    return status == errSecSuccess;
}
