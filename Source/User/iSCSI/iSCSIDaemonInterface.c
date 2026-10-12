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

#include "iSCSIDaemonInterface.h"
#include "iSCSIDaemonInterfaceShared.h"
#include "iSCSILaunchAgent.h"
#include "iSCSIUtils.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <spawn.h>
#include <unistd.h>

extern char ** environ;

/*! Time allowed for the daemon to respond.  Operations such as logging in
 *  involve the network and attaching disks, which takes a while. */
static const int kiSCSIDaemonTimeoutSec = 180;

#pragma mark - Messages

static errno_t iSCSIDaemonReadFully(int fd,void * buffer,size_t length)
{
    UInt8 * cursor = buffer;

    while(length > 0) {
        ssize_t count = recv(fd,cursor,length,0);

        if(count == 0)
            return ECONNRESET;

        if(count < 0) {
            if(errno == EINTR)
                continue;
            return (errno == EAGAIN) ? ETIMEDOUT : errno;
        }
        cursor += count;
        length -= (size_t)count;
    }
    return 0;
}

static errno_t iSCSIDaemonWriteFully(int fd,const void * buffer,size_t length)
{
    const UInt8 * cursor = buffer;

    while(length > 0) {
        ssize_t count = send(fd,cursor,length,0);

        if(count < 0) {
            if(errno == EINTR)
                continue;
            return (errno == EAGAIN) ? ETIMEDOUT : errno;
        }
        cursor += count;
        length -= (size_t)count;
    }
    return 0;
}

errno_t iSCSIDaemonSendMessage(int fd,CFDictionaryRef message)
{
    if(fd < 0 || !message)
        return EINVAL;

    CFDataRef data = CFPropertyListCreateData(kCFAllocatorDefault,message,
                                              kCFPropertyListBinaryFormat_v1_0,0,NULL);
    if(!data)
        return EINVAL;

    UInt32 length = htonl((UInt32)CFDataGetLength(data));
    errno_t error = iSCSIDaemonWriteFully(fd,&length,sizeof(length));

    if(!error)
        error = iSCSIDaemonWriteFully(fd,CFDataGetBytePtr(data),(size_t)CFDataGetLength(data));

    CFRelease(data);
    return error;
}

errno_t iSCSIDaemonReceiveMessage(int fd,CFDictionaryRef * message)
{
    if(fd < 0 || !message)
        return EINVAL;

    *message = NULL;

    UInt32 length = 0;
    errno_t error = iSCSIDaemonReadFully(fd,&length,sizeof(length));

    if(error)
        return error;

    length = ntohl(length);

    if(length == 0 || length > kiSCSIDMaxMessageLength)
        return EMSGSIZE;

    CFMutableDataRef data = CFDataCreateMutable(kCFAllocatorDefault,length);
    CFDataSetLength(data,length);

    if((error = iSCSIDaemonReadFully(fd,CFDataGetMutableBytePtr(data),length))) {
        CFRelease(data);
        return error;
    }

    CFPropertyListRef plist = CFPropertyListCreateWithData(kCFAllocatorDefault,data,
                                                           kCFPropertyListImmutable,NULL,NULL);
    CFRelease(data);

    if(!plist || CFGetTypeID(plist) != CFDictionaryGetTypeID()) {
        if(plist)
            CFRelease(plist);
        return EBADMSG;
    }

    *message = plist;
    return 0;
}

#pragma mark - Helpers

/*! Creates a request for the specified function. */
static CFMutableDictionaryRef iSCSIDaemonCreateRequest(CFStringRef function)
{
    CFMutableDictionaryRef request = CFDictionaryCreateMutable(kCFAllocatorDefault,0,
                                                               &kCFTypeDictionaryKeyCallBacks,
                                                               &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(request,kiSCSIDKeyFunction,function);
    return request;
}

static void iSCSIDaemonRequestSetTarget(CFMutableDictionaryRef request,iSCSITargetRef target)
{
    CFDictionaryRef dictionary = target ? iSCSITargetCreateDictionary(target) : NULL;

    if(dictionary) {
        CFDictionarySetValue(request,kiSCSIDKeyTarget,dictionary);
        CFRelease(dictionary);
    }
}

static void iSCSIDaemonRequestSetPortal(CFMutableDictionaryRef request,iSCSIPortalRef portal)
{
    CFDictionaryRef dictionary = portal ? iSCSIPortalCreateDictionary(portal) : NULL;

    if(dictionary) {
        CFDictionarySetValue(request,kiSCSIDKeyPortal,dictionary);
        CFRelease(dictionary);
    }
}

/*! Sends a request and receives the response.  The request is released.
 *  @param response the response (returned if the daemon reported no error
 *  and response is not NULL; release it).
 *  @return an error code: either that of the transport or the one that
 *  the daemon reported. */
static errno_t iSCSIDaemonTransact(iSCSIDaemonHandle handle,
                                   CFMutableDictionaryRef request,
                                   CFDictionaryRef * response)
{
    CFDictionaryRef message = NULL;
    errno_t error = iSCSIDaemonSendMessage(handle,request);
    CFRelease(request);

    if(response)
        *response = NULL;

    if(!error)
        error = iSCSIDaemonReceiveMessage(handle,&message);

    if(error)
        return error;

    CFNumberRef number = CFDictionaryGetValue(message,kiSCSIDKeyError);
    int daemonError = 0;

    if(number && CFGetTypeID(number) == CFNumberGetTypeID())
        CFNumberGetValue(number,kCFNumberIntType,&daemonError);

    // The response is handed out along with errors since it may carry
    // details (e.g., an iSCSI status code)
    if(response)
        *response = message;
    else
        CFRelease(message);

    return daemonError;
}

static int iSCSIDaemonGetInt(CFDictionaryRef dictionary,CFStringRef key,int defaultValue)
{
    CFNumberRef number = dictionary ? CFDictionaryGetValue(dictionary,key) : NULL;
    int value = defaultValue;

    if(number && CFGetTypeID(number) == CFNumberGetTypeID())
        CFNumberGetValue(number,kCFNumberIntType,&value);

    return value;
}

/*! Extracts a result of the expected type from a response. The response
 *  is released. */
static CFTypeRef iSCSIDaemonCopyResult(CFDictionaryRef response,CFTypeID typeID)
{
    CFTypeRef result = response ? CFDictionaryGetValue(response,kiSCSIDKeyResult) : NULL;

    if(result && CFGetTypeID(result) == typeID)
        CFRetain(result);
    else
        result = NULL;

    if(response)
        CFRelease(response);

    return result;
}

#pragma mark - Public interface

iSCSIDaemonHandle iSCSIDaemonConnect(void)
{
    struct sockaddr_un address;
    memset(&address,0,sizeof(address));
    address.sun_family = AF_LOCAL;

    if(!iSCSIUtilsGetSocketPath(kiSCSIDaemonSocketName,address.sun_path,sizeof(address.sun_path)))
        return -1;

    iSCSIDaemonHandle handle = socket(PF_LOCAL,SOCK_STREAM,0);

    if(handle < 0)
        return -1;

    if(connect(handle,(const struct sockaddr *)&address,(socklen_t)SUN_LEN(&address)) != 0) {
        close(handle);
        return -1;
    }

    int enable = 1;
    setsockopt(handle,SOL_SOCKET,SO_NOSIGPIPE,&enable,sizeof(enable));

    struct timeval timeout = { kiSCSIDaemonTimeoutSec, 0 };
    setsockopt(handle,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    setsockopt(handle,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));

    return handle;
}

/*! Has a process that is about to be spawned answer for itself.  macOS
 *  holds one process responsible for all that descend from it (an
 *  application for the tools that it runs), which decides, among other
 *  things, whether a process may reach the local network; a process whose
 *  responsible process has exited is cut off for good.  The daemon outlives
 *  whichever application or tool happened to start it, hence it must not
 *  depend on that process in this way. */
static void DisclaimResponsibility(posix_spawnattr_t * attributes)
{
    // The function is part of the system library, though not of its headers
    int (* disclaim)(posix_spawnattr_t *,int) =
        (int (*)(posix_spawnattr_t *,int))dlsym(RTLD_DEFAULT,"responsibility_spawnattrs_setdisclaim");

    if(disclaim)
        disclaim(attributes,1);
}

iSCSIDaemonHandle iSCSIDaemonConnectOrLaunch(const char * daemonPath)
{
    iSCSIDaemonHandle handle = iSCSIDaemonConnect();

    if(handle >= 0)
        return handle;

    // By default the daemon lives next to the executable of this process
    char path[PATH_MAX];

    if(daemonPath) {
        if(strlcpy(path,daemonPath,sizeof(path)) >= sizeof(path))
            return -1;
    }
    else {
        char executable[PATH_MAX], resolved[PATH_MAX], directory[PATH_MAX];
        uint32_t size = sizeof(executable);

        if(_NSGetExecutablePath(executable,&size) != 0 || !realpath(executable,resolved) ||
           !dirname_r(resolved,directory) ||
           (size_t)snprintf(path,sizeof(path),"%s/iscsid",directory) >= sizeof(path))
            return -1;
    }

    if(access(path,X_OK) != 0)
        return -1;

    // The daemon is best started by launchd, which keeps it apart from this
    // process.  (With the launch agent in place launchd runs the daemon
    // already, by way of the socket that just failed to answer.)
    CFStringRef agent = iSCSILaunchAgentCopyDaemonPath();
    bool started = false;

    if(agent)
        CFRelease(agent);
    else
        started = (iSCSILaunchAgentStartDaemon(path) == 0);

    // Failing that (there may be no session of the window server to take
    // the job), the daemon is started right here: in a session of its own,
    // with its output in a log file
    char logPath[PATH_MAX];
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;

    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions,STDIN_FILENO,"/dev/null",O_RDONLY,0);

    if(iSCSIUtilsGetLogPath(logPath,sizeof(logPath))) {
        posix_spawn_file_actions_addopen(&actions,STDOUT_FILENO,logPath,O_WRONLY | O_CREAT | O_APPEND,0600);
        posix_spawn_file_actions_adddup2(&actions,STDOUT_FILENO,STDERR_FILENO);
    }
    else {
        posix_spawn_file_actions_addopen(&actions,STDOUT_FILENO,"/dev/null",O_WRONLY,0);
        posix_spawn_file_actions_addopen(&actions,STDERR_FILENO,"/dev/null",O_WRONLY,0);
    }

    posix_spawnattr_init(&attributes);
    posix_spawnattr_setflags(&attributes,POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT);
    DisclaimResponsibility(&attributes);

    char * const arguments[] = { path, NULL };
    pid_t pid;
    int error = started ? 0 : posix_spawn(&pid,path,&actions,&attributes,arguments,environ);

    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);

    if(error)
        return -1;

    // Wait for the daemon to accept connections
    for(int attempt = 0; attempt < 100; attempt++) {
        usleep(100 * 1000);

        if((handle = iSCSIDaemonConnect()) >= 0)
            return handle;
    }
    return -1;
}

void iSCSIDaemonDisconnect(iSCSIDaemonHandle handle)
{
    if(handle >= 0)
        close(handle);
}

errno_t iSCSIDaemonLogin(iSCSIDaemonHandle handle,
                         iSCSITargetRef target,
                         iSCSIPortalRef portal,
                         enum iSCSILoginStatusCode * statusCode)
{
    if(handle < 0 || !target || !statusCode)
        return EINVAL;

    *statusCode = kiSCSILoginInvalidStatusCode;

    CFMutableDictionaryRef request = iSCSIDaemonCreateRequest(kiSCSIDFunctionLogin);
    iSCSIDaemonRequestSetTarget(request,target);
    iSCSIDaemonRequestSetPortal(request,portal);

    CFDictionaryRef response = NULL;
    errno_t error = iSCSIDaemonTransact(handle,request,&response);

    if(response) {
        *statusCode = (enum iSCSILoginStatusCode)iSCSIDaemonGetInt(response,kiSCSIDKeyStatusCode,
                                                                    kiSCSILoginInvalidStatusCode);
        CFRelease(response);
    }
    return error;
}

errno_t iSCSIDaemonLogout(iSCSIDaemonHandle handle,
                          iSCSITargetRef target,
                          bool force,
                          enum iSCSILogoutStatusCode * statusCode)
{
    if(handle < 0 || !target || !statusCode)
        return EINVAL;

    *statusCode = kiSCSILogoutInvalidStatusCode;

    CFMutableDictionaryRef request = iSCSIDaemonCreateRequest(kiSCSIDFunctionLogout);
    iSCSIDaemonRequestSetTarget(request,target);
    CFDictionarySetValue(request,kiSCSIDKeyForce,force ? kCFBooleanTrue : kCFBooleanFalse);

    CFDictionaryRef response = NULL;
    errno_t error = iSCSIDaemonTransact(handle,request,&response);

    if(response) {
        *statusCode = (enum iSCSILogoutStatusCode)iSCSIDaemonGetInt(response,kiSCSIDKeyStatusCode,
                                                                     kiSCSILogoutInvalidStatusCode);
        CFRelease(response);
    }
    return error;
}

CFArrayRef iSCSIDaemonCreateArrayOfActiveTargets(iSCSIDaemonHandle handle)
{
    if(handle < 0)
        return NULL;

    CFDictionaryRef response = NULL;
    iSCSIDaemonTransact(handle,iSCSIDaemonCreateRequest(kiSCSIDFunctionActiveTargets),&response);
    return iSCSIDaemonCopyResult(response,CFArrayGetTypeID());
}

CFArrayRef iSCSIDaemonCreateArrayOfActivePortalsForTarget(iSCSIDaemonHandle handle,
                                                          iSCSITargetRef target)
{
    if(handle < 0 || !target)
        return NULL;

    CFMutableDictionaryRef request = iSCSIDaemonCreateRequest(kiSCSIDFunctionActivePortals);
    iSCSIDaemonRequestSetTarget(request,target);

    CFDictionaryRef response = NULL;
    iSCSIDaemonTransact(handle,request,&response);
    return iSCSIDaemonCopyResult(response,CFArrayGetTypeID());
}

Boolean iSCSIDaemonIsTargetActive(iSCSIDaemonHandle handle,
                                  iSCSITargetRef target)
{
    if(handle < 0 || !target)
        return false;

    CFMutableDictionaryRef request = iSCSIDaemonCreateRequest(kiSCSIDFunctionIsTargetActive);
    iSCSIDaemonRequestSetTarget(request,target);

    CFDictionaryRef response = NULL;
    iSCSIDaemonTransact(handle,request,&response);

    Boolean active = response && CFDictionaryGetValue(response,kiSCSIDKeyActive) == kCFBooleanTrue;

    if(response)
        CFRelease(response);

    return active;
}

Boolean iSCSIDaemonIsPortalActive(iSCSIDaemonHandle handle,
                                  iSCSITargetRef target,
                                  iSCSIPortalRef portal)
{
    if(handle < 0 || !target || !portal)
        return false;

    CFMutableDictionaryRef request = iSCSIDaemonCreateRequest(kiSCSIDFunctionIsPortalActive);
    iSCSIDaemonRequestSetTarget(request,target);
    iSCSIDaemonRequestSetPortal(request,portal);

    CFDictionaryRef response = NULL;
    iSCSIDaemonTransact(handle,request,&response);

    Boolean active = response && CFDictionaryGetValue(response,kiSCSIDKeyActive) == kCFBooleanTrue;

    if(response)
        CFRelease(response);

    return active;
}

errno_t iSCSIDaemonQueryTargetForAuthMethod(iSCSIDaemonHandle handle,
                                            iSCSIPortalRef portal,
                                            CFStringRef targetIQN,
                                            enum iSCSIAuthMethods * authMethod,
                                            enum iSCSILoginStatusCode * statusCode)
{
    if(handle < 0 || !portal || !targetIQN || !authMethod || !statusCode)
        return EINVAL;

    *authMethod = kiSCSIAuthMethodInvalid;
    *statusCode = kiSCSILoginInvalidStatusCode;

    CFMutableDictionaryRef request = iSCSIDaemonCreateRequest(kiSCSIDFunctionQueryAuthMethod);
    iSCSIDaemonRequestSetPortal(request,portal);
    CFDictionarySetValue(request,kiSCSIDKeyTargetIQN,targetIQN);

    CFDictionaryRef response = NULL;
    errno_t error = iSCSIDaemonTransact(handle,request,&response);

    if(response) {
        *authMethod = (enum iSCSIAuthMethods)iSCSIDaemonGetInt(response,kiSCSIDKeyAuthMethod,kiSCSIAuthMethodInvalid);
        *statusCode = (enum iSCSILoginStatusCode)iSCSIDaemonGetInt(response,kiSCSIDKeyStatusCode,
                                                                    kiSCSILoginInvalidStatusCode);
        CFRelease(response);
    }
    return error;
}

errno_t iSCSIDaemonQueryPortalForTargets(iSCSIDaemonHandle handle,
                                         iSCSIPortalRef portal,
                                         iSCSIDiscoveryRecRef * discoveryRec,
                                         enum iSCSILoginStatusCode * statusCode)
{
    if(handle < 0 || !portal || !discoveryRec || !statusCode)
        return EINVAL;

    *discoveryRec = NULL;
    *statusCode = kiSCSILoginInvalidStatusCode;

    CFMutableDictionaryRef request = iSCSIDaemonCreateRequest(kiSCSIDFunctionQueryPortalForTargets);
    iSCSIDaemonRequestSetPortal(request,portal);

    CFDictionaryRef response = NULL;
    errno_t error = iSCSIDaemonTransact(handle,request,&response);

    if(response) {
        *statusCode = (enum iSCSILoginStatusCode)iSCSIDaemonGetInt(response,kiSCSIDKeyStatusCode,
                                                                    kiSCSILoginInvalidStatusCode);
        CFDictionaryRef result = CFDictionaryGetValue(response,kiSCSIDKeyResult);

        if(!error && result && CFGetTypeID(result) == CFDictionaryGetTypeID())
            *discoveryRec = iSCSIDiscoveryRecCreateWithDictionary(result);

        CFRelease(response);
    }
    return error;
}

CFDictionaryRef iSCSIDaemonCreateCFPropertiesForSession(iSCSIDaemonHandle handle,
                                                        iSCSITargetRef target)
{
    if(handle < 0 || !target)
        return NULL;

    CFMutableDictionaryRef request = iSCSIDaemonCreateRequest(kiSCSIDFunctionSessionProperties);
    iSCSIDaemonRequestSetTarget(request,target);

    CFDictionaryRef response = NULL;
    iSCSIDaemonTransact(handle,request,&response);
    return iSCSIDaemonCopyResult(response,CFDictionaryGetTypeID());
}

CFDictionaryRef iSCSIDaemonCreateCFPropertiesForConnection(iSCSIDaemonHandle handle,
                                                           iSCSITargetRef target,
                                                           iSCSIPortalRef portal)
{
    if(handle < 0 || !target || !portal)
        return NULL;

    CFMutableDictionaryRef request = iSCSIDaemonCreateRequest(kiSCSIDFunctionConnectionProperties);
    iSCSIDaemonRequestSetTarget(request,target);
    iSCSIDaemonRequestSetPortal(request,portal);

    CFDictionaryRef response = NULL;
    iSCSIDaemonTransact(handle,request,&response);
    return iSCSIDaemonCopyResult(response,CFDictionaryGetTypeID());
}

CFArrayRef iSCSIDaemonCreateArrayOfDisksForTarget(iSCSIDaemonHandle handle,
                                                  iSCSITargetRef target)
{
    if(handle < 0 || !target)
        return NULL;

    CFMutableDictionaryRef request = iSCSIDaemonCreateRequest(kiSCSIDFunctionDisks);
    iSCSIDaemonRequestSetTarget(request,target);

    CFDictionaryRef response = NULL;
    iSCSIDaemonTransact(handle,request,&response);
    return iSCSIDaemonCopyResult(response,CFArrayGetTypeID());
}

errno_t iSCSIDaemonUpdateDiscovery(iSCSIDaemonHandle handle)
{
    if(handle < 0)
        return EINVAL;

    return iSCSIDaemonTransact(handle,iSCSIDaemonCreateRequest(kiSCSIDFunctionUpdateDiscovery),NULL);
}

errno_t iSCSIDaemonPreferencesIOLockAndSync(iSCSIDaemonHandle handle,
                                            iSCSIPreferencesRef preferences)
{
    if(handle < 0 || !preferences)
        return EINVAL;

    errno_t error = iSCSIDaemonTransact(handle,iSCSIDaemonCreateRequest(kiSCSIDFunctionPreferencesLock),NULL);

    // The daemon will not write to the property list until the lock is
    // released; pick up the most recent version
    if(!error)
        iSCSIPreferencesUpdateWithAppValues(preferences);

    return error;
}

errno_t iSCSIDaemonPreferencesIOUnlockAndSync(iSCSIDaemonHandle handle,
                                              iSCSIPreferencesRef preferences)
{
    if(handle < 0)
        return EINVAL;

    CFMutableDictionaryRef request = iSCSIDaemonCreateRequest(kiSCSIDFunctionPreferencesUnlock);
    CFDataRef data = preferences ? iSCSIPreferencesCreateData(preferences) : NULL;

    if(data) {
        CFDictionarySetValue(request,kiSCSIDKeyPreferences,data);
        CFRelease(data);
    }
    return iSCSIDaemonTransact(handle,request,NULL);
}

errno_t iSCSIDaemonSetSharedSecret(iSCSIDaemonHandle handle,
                                   CFStringRef nodeIQN,
                                   CFStringRef sharedSecret)
{
    if(handle < 0 || !nodeIQN || !sharedSecret)
        return EINVAL;

    CFMutableDictionaryRef request = iSCSIDaemonCreateRequest(kiSCSIDFunctionSetSharedSecret);
    CFDictionarySetValue(request,kiSCSIDKeyNode,nodeIQN);
    CFDictionarySetValue(request,kiSCSIDKeySecret,sharedSecret);
    return iSCSIDaemonTransact(handle,request,NULL);
}

errno_t iSCSIDaemonRemoveSharedSecret(iSCSIDaemonHandle handle,
                                      CFStringRef nodeIQN)
{
    if(handle < 0 || !nodeIQN)
        return EINVAL;

    CFMutableDictionaryRef request = iSCSIDaemonCreateRequest(kiSCSIDFunctionRemoveSharedSecret);
    CFDictionarySetValue(request,kiSCSIDKeyNode,nodeIQN);
    return iSCSIDaemonTransact(handle,request,NULL);
}

CFDictionaryRef iSCSIDaemonCreateStatus(iSCSIDaemonHandle handle)
{
    if(handle < 0)
        return NULL;

    CFDictionaryRef response = NULL;
    iSCSIDaemonTransact(handle,iSCSIDaemonCreateRequest(kiSCSIDFunctionStatus),&response);
    return iSCSIDaemonCopyResult(response,CFDictionaryGetTypeID());
}

errno_t iSCSIDaemonShutdown(iSCSIDaemonHandle handle)
{
    if(handle < 0)
        return EINVAL;

    return iSCSIDaemonTransact(handle,iSCSIDaemonCreateRequest(kiSCSIDFunctionShutdown),NULL);
}
