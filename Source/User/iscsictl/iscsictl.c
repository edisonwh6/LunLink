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

/* iscsictl: the command-line tool for configuring the iSCSI initiator and
 * for managing its sessions.  All work is carried out by the iSCSI daemon,
 * which this tool starts if it is not running. */

#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/dyld.h>
#include <libgen.h>
#include <limits.h>
#include <readpassphrase.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "iSCSI.h"
#include "iSCSIDaemonInterfaceShared.h"

#ifndef ISCSI_VERSION
#define ISCSI_VERSION "unknown"
#endif

/*! Maximum number of attempts to enter a CHAP shared secret. */
#define kMaxSecretAttempts 3

/*! A switch of the command line ("-name [value]"). */
struct Option {
    const char * name;
    const char * value;
};

/*! The parsed command line. */
struct Arguments {
    const char * command;
    const char * subcommand;

    /*! The target and portal, either of which may be absent. */
    CFStringRef targetIQN;
    const char * portalString;

    struct Option options[32];
    int optionCount;
};

static const char * executableName = "iscsictl";

#pragma mark - Output

static void Print(CFStringRef format,...)
{
    va_list arguments;
    va_start(arguments,format);
    CFStringRef string = CFStringCreateWithFormatAndArguments(kCFAllocatorDefault,NULL,format,arguments);
    va_end(arguments);

    CFIndex length = CFStringGetMaximumSizeForEncoding(CFStringGetLength(string),kCFStringEncodingUTF8) + 1;
    char * buffer = malloc((size_t)length);

    if(CFStringGetCString(string,buffer,length,kCFStringEncodingUTF8))
        fputs(buffer,stdout);

    free(buffer);
    CFRelease(string);
}

static void PrintError(CFStringRef format,...)
{
    va_list arguments;
    va_start(arguments,format);
    CFStringRef string = CFStringCreateWithFormatAndArguments(kCFAllocatorDefault,NULL,format,arguments);
    va_end(arguments);

    CFIndex length = CFStringGetMaximumSizeForEncoding(CFStringGetLength(string),kCFStringEncodingUTF8) + 1;
    char * buffer = malloc((size_t)length);

    if(CFStringGetCString(string,buffer,length,kCFStringEncodingUTF8))
        fprintf(stderr,"%s: %s\n",executableName,buffer);

    free(buffer);
    CFRelease(string);
}

/*! What to look into when a server cannot be reached: macOS reports a host
 *  as unreachable if the user has not allowed access to the local network. */
static const char * LocalNetworkHint(errno_t error)
{
    return error == EHOSTUNREACH ? "; if the server is on your local network, make sure that LunLink "
                                   "is allowed under Privacy & Security > Local Network in System Settings" : "";
}

static void PrintUsage(void)
{
    fputs("Usage: iscsictl add target <target>,<portal> [-interface <interface>]\n"
          "       iscsictl remove target <target>[,<portal>]\n"
          "\n"
          "       iscsictl login  <target>[,<portal>]\n"
          "       iscsictl logout <target> [-force]\n"
          "\n"
          "       iscsictl modify initiator-config [...]\n"
          "       iscsictl modify target-config <target>[,<portal>] [...]\n"
          "       iscsictl modify discovery-config [...]\n"
          "\n"
          "       iscsictl list initiator-config\n"
          "       iscsictl list target-config <target>\n"
          "       iscsictl list discovery-config\n"
          "\n"
          "       iscsictl add discovery-portal <portal> [-interface <interface>]\n"
          "       iscsictl remove discovery-portal <portal>\n"
          "       iscsictl discover <portal>\n"
          "\n"
          "       iscsictl list targets\n"
          "       iscsictl list luns\n"
          "\n"
          "       iscsictl daemon status | start | stop | install | uninstall\n"
          "\n"
          "See iscsictl(8) for the options of the modify commands.\n",stderr);
}

#pragma mark - Helpers

static const char * GetOption(const struct Arguments * arguments,const char * name)
{
    for(int idx = 0; idx < arguments->optionCount; idx++)
        if(strcasecmp(arguments->options[idx].name,name) == 0)
            return arguments->options[idx].value ? arguments->options[idx].value : "";

    return NULL;
}

static bool HasOption(const struct Arguments * arguments,const char * name)
{
    return GetOption(arguments,name) != NULL;
}

static CFStringRef CreateString(const char * string)
{
    return CFStringCreateWithCString(kCFAllocatorDefault,string,kCFStringEncodingUTF8);
}

/*! Parses an option whose value is either "enable" or "disable".
 *  @return true if the option is present and valid. */
static bool GetEnableOption(const struct Arguments * arguments,const char * name,bool * enable,bool * invalid)
{
    const char * value = GetOption(arguments,name);

    if(!value)
        return false;

    if(strcasecmp(value,"enable") == 0)
        *enable = true;
    else if(strcasecmp(value,"disable") == 0)
        *enable = false;
    else {
        PrintError(CFSTR("invalid value for -%s (expected enable or disable)"),name);
        *invalid = true;
        return false;
    }
    return true;
}

/*! Connects to the daemon, starting it if need be. */
static iSCSIDaemonHandle ConnectToDaemon(void)
{
    iSCSIDaemonHandle handle = iSCSIDaemonConnectOrLaunch(NULL);

    if(handle < 0)
        PrintError(CFSTR("the iSCSI daemon is not running and could not be started"));

    return handle;
}

/*! Creates the portal named on the command line.
 *  @param required whether to complain if no portal was specified. */
static iSCSIMutablePortalRef CreatePortal(const struct Arguments * arguments,bool required)
{
    if(!arguments->portalString) {
        if(required)
            PrintError(CFSTR("a portal must be specified"));
        return NULL;
    }

    const char * interface = GetOption(arguments,"interface");
    CFStringRef portalString = CreateString(arguments->portalString);
    CFStringRef interfaceString = (interface && interface[0]) ? CreateString(interface) : NULL;

    iSCSIMutablePortalRef portal = iSCSIUtilsCreatePortalWithString(portalString,interfaceString);

    // A port may also be given as an option
    const char * port = GetOption(arguments,"port");

    if(portal && port && port[0]) {
        CFStringRef portString = CreateString(port);

        if(iSCSIUtilsValidatePort(portString))
            iSCSIPortalSetPort(portal,portString);
        else {
            iSCSIPortalRelease(portal);
            portal = NULL;
        }
        CFRelease(portString);
    }

    if(!portal)
        PrintError(CFSTR("the specified portal is invalid"));

    CFRelease(portalString);

    if(interfaceString)
        CFRelease(interfaceString);

    return portal;
}

static bool RequireTarget(const struct Arguments * arguments)
{
    if(!arguments->targetIQN) {
        PrintError(CFSTR("a target must be specified"));
        return false;
    }

    if(!iSCSIUtilsValidateIQN(arguments->targetIQN)) {
        PrintError(CFSTR("the specified target name is not a valid IQN or EUI-64 identifier"));
        return false;
    }
    return true;
}

static iSCSIMutableTargetRef CreateTarget(CFStringRef targetIQN)
{
    iSCSIMutableTargetRef target = iSCSITargetCreateMutable();
    iSCSITargetSetIQN(target,targetIQN);
    return target;
}

/*! Reads a shared secret: interactively (twice, to rule out typing errors)
 *  if the standard input is a terminal, else a line of the standard input. */
static CFStringRef CreateSecretFromInput(void)
{
    char buffer[256], verify[256];
    CFStringRef secret = NULL;

    if(!isatty(STDIN_FILENO)) {
        if(!fgets(buffer,sizeof(buffer),stdin))
            return NULL;

        buffer[strcspn(buffer,"\r\n")] = '\0';
        secret = CreateString(buffer);
        memset(buffer,0,sizeof(buffer));
        return secret;
    }

    for(int attempt = 0; attempt < kMaxSecretAttempts && !secret; attempt++) {
        if(attempt > 0)
            fputs("Shared secrets do not match. Try again.\n",stderr);

        if(!readpassphrase("Enter shared secret: ",buffer,sizeof(buffer),RPP_ECHO_OFF) ||
           !readpassphrase("Verify shared secret: ",verify,sizeof(verify),RPP_ECHO_OFF))
            break;

        if(strcmp(buffer,verify) == 0)
            secret = CreateString(buffer);
    }

    memset(buffer,0,sizeof(buffer));
    memset(verify,0,sizeof(verify));

    if(!secret)
        PrintError(CFSTR("no shared secret was entered"));

    return secret;
}

/*! Reads a shared secret and has the daemon store it. */
static errno_t SetSecret(iSCSIDaemonHandle handle,CFStringRef node)
{
    CFStringRef secret = CreateSecretFromInput();

    if(!secret)
        return EINVAL;

    errno_t error = iSCSIDaemonSetSharedSecret(handle,node,secret);
    CFRelease(secret);

    if(error)
        PrintError(CFSTR("unable to store the shared secret: %s"),strerror(error));

    return error;
}

/*! Parses an authentication method ("None" or "CHAP"). */
static bool ParseAuthMethod(const char * value,enum iSCSIAuthMethods * method)
{
    if(strcasecmp(value,"none") == 0)
        *method = kiSCSIAuthMethodNone;
    else if(strcasecmp(value,"chap") == 0)
        *method = kiSCSIAuthMethodCHAP;
    else
        return false;

    return true;
}

static bool ParseDigest(const char * value,enum iSCSIDigestTypes * digest)
{
    if(strcasecmp(value,"none") == 0)
        *digest = kiSCSIDigestNone;
    else if(strcasecmp(value,"crc32c") == 0)
        *digest = kiSCSIDigestCRC32C;
    else
        return false;

    return true;
}

/*! Modifies the preferences: acquires the preferences lock of the daemon,
 *  applies the modification and hands the result to the daemon to store.
 *  @param modify applies the modification; returns an error code, in which
 *  case the preferences are left as they were.
 *  @return an error code indicating the result of the operation. */
static errno_t ModifyPreferences(iSCSIDaemonHandle handle,errno_t (^modify)(iSCSIPreferencesRef preferences))
{
    iSCSIPreferencesRef preferences = iSCSIPreferencesCreateFromAppValues();
    errno_t error = iSCSIDaemonPreferencesIOLockAndSync(handle,preferences);

    if(error) {
        PrintError(CFSTR("unable to lock the preferences: %s"),strerror(error));
        iSCSIPreferencesRelease(preferences);
        return error;
    }

    if(!(error = modify(preferences)))
        error = iSCSIDaemonPreferencesIOUnlockAndSync(handle,preferences);
    else
        iSCSIDaemonPreferencesIOUnlockAndSync(handle,NULL);

    iSCSIPreferencesRelease(preferences);
    return error;
}

static int GetInt(CFDictionaryRef dictionary,CFStringRef key,int defaultValue)
{
    CFNumberRef number = dictionary ? CFDictionaryGetValue(dictionary,key) : NULL;
    int value = defaultValue;

    if(number && CFGetTypeID(number) == CFNumberGetTypeID())
        CFNumberGetValue(number,kCFNumberIntType,&value);

    return value;
}

static CFStringRef GetString(CFDictionaryRef dictionary,CFStringRef key,CFStringRef defaultValue)
{
    CFStringRef string = dictionary ? CFDictionaryGetValue(dictionary,key) : NULL;
    return (string && CFGetTypeID(string) == CFStringGetTypeID()) ? string : defaultValue;
}

/*! Formats a size in bytes for display (release the result). */
static CFStringRef CreateSizeString(UInt64 bytes)
{
    static const char * const units[] = { "bytes", "KB", "MB", "GB", "TB", "PB" };
    double value = (double)bytes;
    int unit = 0;

    while(value >= 1000.0 && unit < 5) {
        value /= 1000.0;
        unit++;
    }

    if(unit == 0)
        return CFStringCreateWithFormat(kCFAllocatorDefault,NULL,CFSTR("%llu bytes"),bytes);

    return CFStringCreateWithFormat(kCFAllocatorDefault,NULL,CFSTR("%.2f %s"),value,units[unit]);
}

#pragma mark - Login and logout

static errno_t CommandLogin(const struct Arguments * arguments)
{
    if(!RequireTarget(arguments))
        return EINVAL;

    iSCSIMutablePortalRef portal = CreatePortal(arguments,false);

    if(arguments->portalString && !portal)
        return EINVAL;

    iSCSIDaemonHandle handle = ConnectToDaemon();

    if(handle < 0) {
        if(portal)
            iSCSIPortalRelease(portal);
        return ENOTCONN;
    }

    iSCSIPreferencesRef preferences = iSCSIPreferencesCreateFromAppValues();
    iSCSIMutableTargetRef target = CreateTarget(arguments->targetIQN);
    enum iSCSILoginStatusCode statusCode = kiSCSILoginInvalidStatusCode;
    errno_t error = 0;

    if(!portal && !iSCSIPreferencesContainsTarget(preferences,arguments->targetIQN)) {
        PrintError(CFSTR("the specified target does not exist; add it first or specify a portal"));
        error = ENOENT;
    }
    else
        error = iSCSIDaemonLogin(handle,target,portal,&statusCode);

    if(error == EEXIST)
        PrintError(CFSTR("the specified target has an active session"));
    else if(error == EINPROGRESS)
        PrintError(CFSTR("the session of the specified target is being recovered"));
    else if(error && statusCode != kiSCSILoginInvalidStatusCode && statusCode != kiSCSILoginSuccess)
        PrintError(CFSTR("%@"),iSCSIUtilsGetStringForLoginStatus(statusCode));
    else if(error == ECONNRESET)
        PrintError(CFSTR("the target closed the connection during login; it may require CHAP authentication "
                         "or may not permit this initiator to access it"));
    else if(error && error != ENOENT)
        PrintError(CFSTR("login failed: %s%s"),strerror(error),LocalNetworkHint(error));
    else if(!error) {
        // Show the disks that the target provides
        CFArrayRef disks = iSCSIDaemonCreateArrayOfDisksForTarget(handle,target);
        CFIndex count = disks ? CFArrayGetCount(disks) : 0;

        Print(CFSTR("Logged in to %@ (%ld logical %s)\n"),arguments->targetIQN,(long)count,count == 1 ? "unit" : "units");

        for(CFIndex idx = 0; idx < count; idx++) {
            CFDictionaryRef disk = CFArrayGetValueAtIndex(disks,idx);
            CFStringRef bsdName = GetString(disk,kiSCSIDiskBSDName,NULL);

            if(bsdName)
                Print(CFSTR("\tLUN %d attached as %@\n"),GetInt(disk,kiSCSIDiskLUN,0),bsdName);
            else
                Print(CFSTR("\tLUN %d not attached: %@\n"),GetInt(disk,kiSCSIDiskLUN,0),
                      GetString(disk,kiSCSIDiskError,CFSTR("unknown error")));
        }

        if(disks)
            CFRelease(disks);
    }

    iSCSITargetRelease(target);
    iSCSIPreferencesRelease(preferences);

    if(portal)
        iSCSIPortalRelease(portal);

    iSCSIDaemonDisconnect(handle);
    return error;
}

static errno_t CommandLogout(const struct Arguments * arguments)
{
    if(!RequireTarget(arguments))
        return EINVAL;

    iSCSIDaemonHandle handle = ConnectToDaemon();

    if(handle < 0)
        return ENOTCONN;

    iSCSIMutableTargetRef target = CreateTarget(arguments->targetIQN);
    enum iSCSILogoutStatusCode statusCode = kiSCSILogoutInvalidStatusCode;
    errno_t error = iSCSIDaemonLogout(handle,target,HasOption(arguments,"force"),&statusCode);

    if(error == ENOTCONN)
        PrintError(CFSTR("the specified target has no active session"));
    else if(error == EBUSY)
        PrintError(CFSTR("a volume of the target is in use; close the files on it and try again, "
                         "or specify -force to logout regardless (at the risk of losing data)"));
    else if(error)
        PrintError(CFSTR("logout failed: %s"),strerror(error));
    else
        Print(CFSTR("Logged out of %@\n"),arguments->targetIQN);

    iSCSITargetRelease(target);
    iSCSIDaemonDisconnect(handle);
    return error;
}

#pragma mark - Targets

static errno_t CommandAddTarget(const struct Arguments * arguments)
{
    if(!RequireTarget(arguments))
        return EINVAL;

    iSCSIMutablePortalRef portal = CreatePortal(arguments,true);

    if(!portal)
        return EINVAL;

    iSCSIDaemonHandle handle = ConnectToDaemon();

    if(handle < 0) {
        iSCSIPortalRelease(portal);
        return ENOTCONN;
    }

    CFStringRef targetIQN = arguments->targetIQN;

    errno_t error = ModifyPreferences(handle,^errno_t(iSCSIPreferencesRef preferences) {
        if(!iSCSIPreferencesContainsTarget(preferences,targetIQN))
            iSCSIPreferencesAddStaticTarget(preferences,targetIQN,portal);
        else if(!iSCSIPreferencesContainsPortalForTarget(preferences,targetIQN,iSCSIPortalGetAddress(portal)))
            iSCSIPreferencesSetPortalForTarget(preferences,targetIQN,portal);
        else {
            PrintError(CFSTR("the specified target and portal already exist"));
            return EEXIST;
        }
        return 0;
    });

    iSCSIPortalRelease(portal);
    iSCSIDaemonDisconnect(handle);
    return error;
}

static errno_t CommandRemoveTarget(const struct Arguments * arguments)
{
    if(!RequireTarget(arguments))
        return EINVAL;

    iSCSIMutablePortalRef portal = CreatePortal(arguments,false);

    if(arguments->portalString && !portal)
        return EINVAL;

    iSCSIDaemonHandle handle = ConnectToDaemon();

    if(handle < 0) {
        if(portal)
            iSCSIPortalRelease(portal);
        return ENOTCONN;
    }

    CFStringRef targetIQN = arguments->targetIQN;
    iSCSIMutableTargetRef target = CreateTarget(targetIQN);
    Boolean targetActive = iSCSIDaemonIsTargetActive(handle,target);
    Boolean portalActive = portal && iSCSIDaemonIsPortalActive(handle,target,portal);

    errno_t error = ModifyPreferences(handle,^errno_t(iSCSIPreferencesRef preferences) {
        if(!iSCSIPreferencesContainsTarget(preferences,targetIQN)) {
            PrintError(CFSTR("the specified target does not exist"));
            return ENOENT;
        }

        if(!portal) {
            if(targetActive) {
                PrintError(CFSTR("the specified target has an active session and cannot be removed"));
                return EBUSY;
            }
            iSCSIPreferencesRemoveTarget(preferences,targetIQN);
            return 0;
        }

        if(!iSCSIPreferencesContainsPortalForTarget(preferences,targetIQN,iSCSIPortalGetAddress(portal))) {
            PrintError(CFSTR("the specified portal does not exist"));
            return ENOENT;
        }

        if(portalActive) {
            PrintError(CFSTR("the specified portal is in use by the active session and cannot be removed"));
            return EBUSY;
        }

        // A target without portals is of no use (and its settings would be
        // lost along with its last portal)
        CFArrayRef portals = iSCSIPreferencesCreateArrayOfPortalsForTarget(preferences,targetIQN);
        CFIndex portalCount = portals ? CFArrayGetCount(portals) : 0;

        if(portals)
            CFRelease(portals);

        if(portalCount <= 1) {
            PrintError(CFSTR("the specified portal is the only portal of the target; remove the target instead"));
            return EBUSY;
        }

        iSCSIPreferencesRemovePortalForTarget(preferences,targetIQN,iSCSIPortalGetAddress(portal));
        return 0;
    });

    // The secrets of a target go with it
    if(!error && !portal) {
        CFStringRef node = iSCSIKeychainCreateNodeForInitiatorOfTarget(targetIQN);
        iSCSIDaemonRemoveSharedSecret(handle,targetIQN);
        iSCSIDaemonRemoveSharedSecret(handle,node);
        CFRelease(node);
    }

    iSCSITargetRelease(target);

    if(portal)
        iSCSIPortalRelease(portal);

    iSCSIDaemonDisconnect(handle);
    return error;
}

static errno_t CommandModifyTarget(const struct Arguments * arguments)
{
    if(!RequireTarget(arguments))
        return EINVAL;

    iSCSIMutablePortalRef portal = CreatePortal(arguments,false);

    if(arguments->portalString && !portal)
        return EINVAL;

    iSCSIDaemonHandle handle = ConnectToDaemon();

    if(handle < 0) {
        if(portal)
            iSCSIPortalRelease(portal);
        return ENOTCONN;
    }

    CFStringRef targetIQN = arguments->targetIQN;

    errno_t error = ModifyPreferences(handle,^errno_t(iSCSIPreferencesRef preferences) {
        if(!iSCSIPreferencesContainsTarget(preferences,targetIQN)) {
            PrintError(CFSTR("the specified target does not exist"));
            return ENOENT;
        }

        bool enable = false, invalid = false;
        const char * value;

        if(GetEnableOption(arguments,"auto-login",&enable,&invalid))
            iSCSIPreferencesSetAutoLoginForTarget(preferences,targetIQN,enable);

        if(GetEnableOption(arguments,"persistent",&enable,&invalid))
            iSCSIPreferencesSetPersistenceForTarget(preferences,targetIQN,enable);

        if(GetEnableOption(arguments,"read-only",&enable,&invalid))
            iSCSIPreferencesSetReadOnlyForTarget(preferences,targetIQN,enable);

        if(GetEnableOption(arguments,"sync-writes",&enable,&invalid))
            iSCSIPreferencesSetSyncWritesForTarget(preferences,targetIQN,enable);

        if(invalid)
            return EINVAL;

        // The user-space HBA supports a single connection per session and
        // session-level error recovery
        if((value = GetOption(arguments,"MaxConnections")) && atoi(value) != 1) {
            PrintError(CFSTR("only a single connection per session is supported"));
            return ENOTSUP;
        }

        if((value = GetOption(arguments,"ErrorRecoveryLevel")) && (atoi(value) != 0 || value[0] != '0')) {
            PrintError(CFSTR("only error recovery level 0 is supported"));
            return ENOTSUP;
        }

        enum iSCSIDigestTypes digest;

        if((value = GetOption(arguments,"HeaderDigest"))) {
            if(!ParseDigest(value,&digest)) {
                PrintError(CFSTR("invalid value for -HeaderDigest (expected None or CRC32C)"));
                return EINVAL;
            }
            iSCSIPreferencesSetHeaderDigestForTarget(preferences,targetIQN,digest);
        }

        if((value = GetOption(arguments,"DataDigest"))) {
            if(!ParseDigest(value,&digest)) {
                PrintError(CFSTR("invalid value for -DataDigest (expected None or CRC32C)"));
                return EINVAL;
            }
            iSCSIPreferencesSetDataDigestForTarget(preferences,targetIQN,digest);
        }

        // How the target proves its identity to the initiator (mutual CHAP)
        enum iSCSIAuthMethods method;

        if((value = GetOption(arguments,"authentication"))) {
            if(!ParseAuthMethod(value,&method)) {
                PrintError(CFSTR("invalid value for -authentication (expected None or CHAP)"));
                return EINVAL;
            }
            iSCSIPreferencesSetTargetAuthenticationMethod(preferences,targetIQN,method);
        }

        if((value = GetOption(arguments,"CHAP-name"))) {
            CFStringRef name = CreateString(value);
            iSCSIPreferencesSetTargetCHAPName(preferences,targetIQN,name);
            CFRelease(name);
        }

        // How the initiator proves its identity to this particular target
        if((value = GetOption(arguments,"initiator-authentication"))) {
            if(strcasecmp(value,"default") == 0)
                method = kiSCSIAuthMethodInvalid;
            else if(!ParseAuthMethod(value,&method)) {
                PrintError(CFSTR("invalid value for -initiator-authentication (expected None, CHAP or default)"));
                return EINVAL;
            }
            iSCSIPreferencesSetInitiatorAuthenticationMethodForTarget(preferences,targetIQN,method);
        }

        if((value = GetOption(arguments,"initiator-CHAP-name"))) {
            CFStringRef name = CreateString(value);
            iSCSIPreferencesSetInitiatorCHAPNameForTarget(preferences,targetIQN,name);
            CFRelease(name);
        }

        // Changes to a portal (its port and interface)
        if(portal) {
            CFStringRef address = iSCSIPortalGetAddress(portal);

            if(!iSCSIPreferencesContainsPortalForTarget(preferences,targetIQN,address)) {
                PrintError(CFSTR("the specified portal does not exist"));
                return ENOENT;
            }

            iSCSIPortalRef existing = iSCSIPreferencesCopyPortalForTarget(preferences,targetIQN,address);
            iSCSIMutablePortalRef updated = iSCSIPortalCreateMutable();
            iSCSIPortalSetAddress(updated,address);
            iSCSIPortalSetPort(updated,(HasOption(arguments,"port") || strchr(arguments->portalString,':'))
                                           ? iSCSIPortalGetPort(portal) : iSCSIPortalGetPort(existing));
            iSCSIPortalSetHostInterface(updated,HasOption(arguments,"interface") ? iSCSIPortalGetHostInterface(portal)
                                                                                 : iSCSIPortalGetHostInterface(existing));
            iSCSIPreferencesSetPortalForTarget(preferences,targetIQN,updated);
            iSCSIPortalRelease(updated);
            iSCSIPortalRelease(existing);
        }
        return 0;
    });

    // Secrets are kept by the daemon, apart from the preferences
    if(!error && HasOption(arguments,"CHAP-secret"))
        error = SetSecret(handle,targetIQN);

    if(!error && HasOption(arguments,"initiator-CHAP-secret")) {
        CFStringRef node = iSCSIKeychainCreateNodeForInitiatorOfTarget(targetIQN);
        error = SetSecret(handle,node);
        CFRelease(node);
    }

    if(portal)
        iSCSIPortalRelease(portal);

    iSCSIDaemonDisconnect(handle);
    return error;
}

static const char * AuthMethodName(enum iSCSIAuthMethods method)
{
    return (method == kiSCSIAuthMethodCHAP) ? "CHAP" : "None";
}

static const char * DigestName(enum iSCSIDigestTypes digest)
{
    return (digest == kiSCSIDigestCRC32C) ? "CRC32C" : "None";
}

/*! Prints the properties of the session of a target, if there is one. */
static void PrintSessionProperties(iSCSIDaemonHandle handle,iSCSITargetRef target,const char * indent)
{
    CFDictionaryRef properties = iSCSIDaemonCreateCFPropertiesForSession(handle,target);

    if(!properties)
        return;

    Print(CFSTR("%sSession:\n"),indent);
    Print(CFSTR("%s\tState: %@\n"),indent,GetString(properties,kiSCSISessionStateKey,kiSCSISessionStateActive));
    Print(CFSTR("%s\tSession Identifier: %d\n"),indent,GetInt(properties,kRFC3720_Key_SessionId,0));
    Print(CFSTR("%s\tTSIH: %#x\n"),indent,GetInt(properties,kRFC3720_Key_TargetSessionId,0) & 0xffff);
    Print(CFSTR("%s\tTarget Portal Group Tag: %d\n"),indent,GetInt(properties,kRFC3720_Key_TargetPortalGroupTag,0));
    Print(CFSTR("%s\tInitialR2T: %@\n"),indent,GetString(properties,kRFC3720_Key_InitialR2T,CFSTR("")));
    Print(CFSTR("%s\tImmediateData: %@\n"),indent,GetString(properties,kRFC3720_Key_ImmediateData,CFSTR("")));
    Print(CFSTR("%s\tMaxBurstLength: %d\n"),indent,GetInt(properties,kRFC3720_Key_MaxBurstLength,0));
    Print(CFSTR("%s\tFirstBurstLength: %d\n"),indent,GetInt(properties,kRFC3720_Key_FirstBurstLength,0));
    Print(CFSTR("%s\tMaxOutstandingR2T: %d\n"),indent,GetInt(properties,kRFC3720_Key_MaxOutstandingR2T,0));
    Print(CFSTR("%s\tDefaultTime2Wait: %d\n"),indent,GetInt(properties,kRFC3720_Key_DefaultTime2Wait,0));
    Print(CFSTR("%s\tDefaultTime2Retain: %d\n"),indent,GetInt(properties,kRFC3720_Key_DefaultTime2Retain,0));
    Print(CFSTR("%s\tErrorRecoveryLevel: %d\n"),indent,GetInt(properties,kRFC3720_Key_ErrorRecoveryLevel,0));
    CFRelease(properties);

    CFArrayRef portals = iSCSIDaemonCreateArrayOfActivePortalsForTarget(handle,target);

    for(CFIndex idx = 0; portals && idx < CFArrayGetCount(portals); idx++) {
        iSCSIPortalRef portal = iSCSIPortalCreateWithDictionary(CFArrayGetValueAtIndex(portals,idx));
        CFDictionaryRef connection = portal ? iSCSIDaemonCreateCFPropertiesForConnection(handle,target,portal) : NULL;

        if(connection) {
            Print(CFSTR("%s\tConnection to %@:%@\n"),indent,iSCSIPortalGetAddress(portal),iSCSIPortalGetPort(portal));
            Print(CFSTR("%s\t\tHeaderDigest: %s\n"),indent,DigestName(GetInt(connection,kRFC3720_Key_HeaderDigest,0)));
            Print(CFSTR("%s\t\tDataDigest: %s\n"),indent,DigestName(GetInt(connection,kRFC3720_Key_DataDigest,0)));
            Print(CFSTR("%s\t\tMaxRecvDataSegmentLength: %d\n"),indent,
                  GetInt(connection,kRFC3720_Key_MaxRecvDataSegmentLength,0));
            CFRelease(connection);
        }

        if(portal)
            iSCSIPortalRelease(portal);
    }

    if(portals)
        CFRelease(portals);
}

static errno_t CommandListTargetConfig(const struct Arguments * arguments)
{
    if(!RequireTarget(arguments))
        return EINVAL;

    CFStringRef targetIQN = arguments->targetIQN;
    iSCSIPreferencesRef preferences = iSCSIPreferencesCreateFromAppValues();

    if(!iSCSIPreferencesContainsTarget(preferences,targetIQN)) {
        PrintError(CFSTR("the specified target does not exist"));
        iSCSIPreferencesRelease(preferences);
        return ENOENT;
    }

    CFStringRef alias = iSCSIPreferencesGetTargetAlias(preferences,targetIQN);

    Print(CFSTR("%@\n"),targetIQN);

    if(alias && CFStringGetLength(alias) > 0)
        Print(CFSTR("\tAlias: %@\n"),alias);

    bool dynamic = (iSCSIPreferencesGetTargetConfigType(preferences,targetIQN) == kiSCSITargetConfigDynamicSendTargets);

    Print(CFSTR("\tConfiguration:\n"));
    Print(CFSTR("\t\tType: %s\n"),dynamic ? "dynamic (SendTargets)" : "static");

    if(dynamic)
        Print(CFSTR("\t\tDiscovery portal: %@\n"),iSCSIPreferencesGetDiscoveryPortalForTarget(preferences,targetIQN));

    Print(CFSTR("\t\tAuto-login: %s\n"),iSCSIPreferencesGetAutoLoginForTarget(preferences,targetIQN) ? "enabled" : "disabled");
    Print(CFSTR("\t\tPersistent: %s\n"),iSCSIPreferencesGetPersistenceForTarget(preferences,targetIQN) ? "enabled" : "disabled");
    Print(CFSTR("\t\tRead-only: %s\n"),iSCSIPreferencesGetReadOnlyForTarget(preferences,targetIQN) ? "enabled" : "disabled");
    Print(CFSTR("\t\tFlush after every write: %s\n"),iSCSIPreferencesGetSyncWritesForTarget(preferences,targetIQN) ? "enabled" : "disabled");
    Print(CFSTR("\t\tHeaderDigest: %s\n"),DigestName(iSCSIPreferencesGetHeaderDigestForTarget(preferences,targetIQN)));
    Print(CFSTR("\t\tDataDigest: %s\n"),DigestName(iSCSIPreferencesGetDataDigestForTarget(preferences,targetIQN)));

    // Authentication of the initiator towards this target
    enum iSCSIAuthMethods method = iSCSIPreferencesGetInitiatorAuthenticationMethodForTarget(preferences,targetIQN);

    Print(CFSTR("\tInitiator authentication:\n"));

    if(method == kiSCSIAuthMethodInvalid)
        Print(CFSTR("\t\tMethod: default (see initiator-config)\n"));
    else {
        Print(CFSTR("\t\tMethod: %s\n"),AuthMethodName(method));

        if(method == kiSCSIAuthMethodCHAP) {
            CFStringRef name = iSCSIPreferencesCopyInitiatorCHAPNameForTarget(preferences,targetIQN);
            CFStringRef node = iSCSIKeychainCreateNodeForInitiatorOfTarget(targetIQN);
            Print(CFSTR("\t\tCHAP name: %@\n"),name ? name : CFSTR("<unspecified>"));
            Print(CFSTR("\t\tCHAP secret: %s\n"),iSCSIKeychainContainsCHAPSecretForNode(node) ? "<specified>" : "<unspecified>");
            CFRelease(node);

            if(name)
                CFRelease(name);
        }
    }

    // Authentication of the target towards the initiator
    method = iSCSIPreferencesGetTargetAuthenticationMethod(preferences,targetIQN);

    Print(CFSTR("\tTarget authentication:\n"));
    Print(CFSTR("\t\tMethod: %s\n"),AuthMethodName(method));

    if(method == kiSCSIAuthMethodCHAP) {
        CFStringRef name = iSCSIPreferencesCopyTargetCHAPName(preferences,targetIQN);
        Print(CFSTR("\t\tCHAP name: %@\n"),(name && CFStringGetLength(name) > 0) ? name : CFSTR("<unspecified>"));
        Print(CFSTR("\t\tCHAP secret: %s\n"),iSCSIKeychainContainsCHAPSecretForNode(targetIQN) ? "<specified>" : "<unspecified>");

        if(name)
            CFRelease(name);
    }

    CFArrayRef portals = iSCSIPreferencesCreateArrayOfPortalsForTarget(preferences,targetIQN);

    Print(CFSTR("\tPortals:\n"));

    for(CFIndex idx = 0; portals && idx < CFArrayGetCount(portals); idx++) {
        iSCSIPortalRef portal = iSCSIPreferencesCopyPortalForTarget(preferences,targetIQN,CFArrayGetValueAtIndex(portals,idx));

        if(!portal)
            continue;

        Print(CFSTR("\t\t%@ <port %@, interface %@>\n"),iSCSIPortalGetAddress(portal),iSCSIPortalGetPort(portal),
              iSCSIPortalGetHostInterface(portal));
        iSCSIPortalRelease(portal);
    }

    if(portals)
        CFRelease(portals);

    // Properties of the session, if the target is logged in
    iSCSIDaemonHandle handle = iSCSIDaemonConnect();

    if(handle >= 0) {
        iSCSIMutableTargetRef target = CreateTarget(targetIQN);
        PrintSessionProperties(handle,target,"\t");
        iSCSITargetRelease(target);
        iSCSIDaemonDisconnect(handle);
    }

    iSCSIPreferencesRelease(preferences);
    return 0;
}

static errno_t CommandListTargets(const struct Arguments * arguments)
{
    iSCSIPreferencesRef preferences = iSCSIPreferencesCreateFromAppValues();
    CFArrayRef targets = iSCSIPreferencesCreateArrayOfTargets(preferences);
    iSCSIDaemonHandle handle = iSCSIDaemonConnect();
    CFIndex count = targets ? CFArrayGetCount(targets) : 0;

    if(count == 0)
        Print(CFSTR("No targets are defined\n"));

    for(CFIndex idx = 0; idx < count; idx++) {
        CFStringRef targetIQN = CFArrayGetValueAtIndex(targets,idx);
        iSCSIMutableTargetRef target = CreateTarget(targetIQN);
        CFDictionaryRef properties = (handle >= 0) ? iSCSIDaemonCreateCFPropertiesForSession(handle,target) : NULL;

        bool dynamic = (iSCSIPreferencesGetTargetConfigType(preferences,targetIQN) == kiSCSITargetConfigDynamicSendTargets);
        const char * type = dynamic ? "dynamic" : "static";

        if(properties) {
            bool recovering = CFEqual(GetString(properties,kiSCSISessionStateKey,kiSCSISessionStateActive),
                                      kiSCSISessionStateRecovering);

            Print(CFSTR("%@ <%s, %s, sid %d, tpgt %d, tsid %#x>\n"),targetIQN,recovering ? "recovering" : "active",type,
                  GetInt(properties,kRFC3720_Key_SessionId,0),GetInt(properties,kRFC3720_Key_TargetPortalGroupTag,0),
                  GetInt(properties,kRFC3720_Key_TargetSessionId,0) & 0xffff);
        }
        else
            Print(CFSTR("%@ <inactive, %s>\n"),targetIQN,type);

        CFArrayRef portals = iSCSIPreferencesCreateArrayOfPortalsForTarget(preferences,targetIQN);

        for(CFIndex portalIdx = 0; portals && portalIdx < CFArrayGetCount(portals); portalIdx++) {
            iSCSIPortalRef portal = iSCSIPreferencesCopyPortalForTarget(preferences,targetIQN,
                                                                        CFArrayGetValueAtIndex(portals,portalIdx));
            if(!portal)
                continue;

            bool active = (handle >= 0) && iSCSIDaemonIsPortalActive(handle,target,portal);

            Print(CFSTR("\t%@ <%s, port %@, interface %@>\n"),iSCSIPortalGetAddress(portal),active ? "active" : "inactive",
                  iSCSIPortalGetPort(portal),iSCSIPortalGetHostInterface(portal));
            iSCSIPortalRelease(portal);
        }

        if(portals)
            CFRelease(portals);

        if(properties)
            CFRelease(properties);

        iSCSITargetRelease(target);
    }

    if(targets)
        CFRelease(targets);

    iSCSIDaemonDisconnect(handle);
    iSCSIPreferencesRelease(preferences);
    return 0;
}

static errno_t CommandListLUNs(const struct Arguments * arguments)
{
    iSCSIDaemonHandle handle = iSCSIDaemonConnect();
    CFArrayRef targets = (handle >= 0) ? iSCSIDaemonCreateArrayOfActiveTargets(handle) : NULL;
    CFIndex count = targets ? CFArrayGetCount(targets) : 0;

    if(count == 0)
        Print(CFSTR("No active targets with LUNs exist\n"));

    for(CFIndex idx = 0; idx < count; idx++) {
        iSCSITargetRef target = iSCSITargetCreateWithDictionary(CFArrayGetValueAtIndex(targets,idx));

        if(!target)
            continue;

        Print(CFSTR("%@\n"),iSCSITargetGetIQN(target));

        CFArrayRef disks = iSCSIDaemonCreateArrayOfDisksForTarget(handle,target);

        for(CFIndex diskIdx = 0; disks && diskIdx < CFArrayGetCount(disks); diskIdx++) {
            CFDictionaryRef disk = CFArrayGetValueAtIndex(disks,diskIdx);
            CFNumberRef blockCountNumber = CFDictionaryGetValue(disk,kiSCSIDiskBlockCount);
            SInt64 blockCount = 0;
            int blockSize = GetInt(disk,kiSCSIDiskBlockSize,0);

            if(blockCountNumber)
                CFNumberGetValue(blockCountNumber,kCFNumberSInt64Type,&blockCount);

            CFStringRef size = CreateSizeString((UInt64)blockCount * (UInt64)blockSize);
            CFStringRef bsdName = GetString(disk,kiSCSIDiskBSDName,NULL);

            Print(CFSTR("\tLUN %d: %@ %@ <%@, %lld blocks of %d bytes%s>\n"),GetInt(disk,kiSCSIDiskLUN,0),
                  GetString(disk,kiSCSIDiskVendor,CFSTR("")),GetString(disk,kiSCSIDiskProduct,CFSTR("")),
                  size,(long long)blockCount,blockSize,
                  (CFDictionaryGetValue(disk,kiSCSIDiskReadOnly) == kCFBooleanTrue) ? ", read-only" : "");

            if(bsdName)
                Print(CFSTR("\t\t/dev/%@\n"),bsdName);
            else
                Print(CFSTR("\t\tnot attached: %@\n"),GetString(disk,kiSCSIDiskError,CFSTR("unknown error")));

            CFRelease(size);
        }

        if(disks)
            CFRelease(disks);

        iSCSITargetRelease(target);
    }

    if(targets)
        CFRelease(targets);

    iSCSIDaemonDisconnect(handle);
    return 0;
}

#pragma mark - Initiator

static errno_t CommandModifyInitiator(const struct Arguments * arguments)
{
    iSCSIDaemonHandle handle = ConnectToDaemon();

    if(handle < 0)
        return ENOTCONN;

    __block CFStringRef initiatorIQN = NULL;

    errno_t error = ModifyPreferences(handle,^errno_t(iSCSIPreferencesRef preferences) {
        const char * value;

        if((value = GetOption(arguments,"node-name"))) {
            CFStringRef name = CreateString(value);
            Boolean valid = iSCSIUtilsValidateIQN(name);

            if(valid)
                iSCSIPreferencesSetInitiatorIQN(preferences,name);

            CFRelease(name);

            if(!valid) {
                PrintError(CFSTR("the specified name is not a valid IQN or EUI-64 identifier"));
                return EINVAL;
            }
        }

        if((value = GetOption(arguments,"node-alias"))) {
            CFStringRef alias = CreateString(value);
            iSCSIPreferencesSetInitiatorAlias(preferences,alias);
            CFRelease(alias);
        }

        if((value = GetOption(arguments,"authentication"))) {
            enum iSCSIAuthMethods method;

            if(!ParseAuthMethod(value,&method)) {
                PrintError(CFSTR("invalid value for -authentication (expected None or CHAP)"));
                return EINVAL;
            }
            iSCSIPreferencesSetInitiatorAuthenticationMethod(preferences,method);
        }

        if((value = GetOption(arguments,"CHAP-name"))) {
            CFStringRef name = CreateString(value);
            iSCSIPreferencesSetInitiatorCHAPName(preferences,name);
            CFRelease(name);
        }

        initiatorIQN = iSCSIPreferencesCopyInitiatorIQN(preferences);
        return 0;
    });

    // The secret is filed under the name of the initiator
    if(!error && HasOption(arguments,"CHAP-secret") && initiatorIQN)
        error = SetSecret(handle,initiatorIQN);

    if(initiatorIQN)
        CFRelease(initiatorIQN);

    iSCSIDaemonDisconnect(handle);
    return error;
}

static errno_t CommandListInitiator(const struct Arguments * arguments)
{
    // The daemon establishes the identity of the initiator when it starts
    iSCSIDaemonHandle handle = iSCSIDaemonConnectOrLaunch(NULL);
    iSCSIDaemonDisconnect(handle);

    iSCSIPreferencesRef preferences = iSCSIPreferencesCreateFromAppValues();
    CFStringRef initiatorIQN = iSCSIPreferencesCopyInitiatorIQN(preferences);
    CFStringRef alias = iSCSIPreferencesCopyInitiatorAlias(preferences);
    CFStringRef name = iSCSIPreferencesCopyInitiatorCHAPName(preferences);
    enum iSCSIAuthMethods method = iSCSIPreferencesGetInitiatorAuthenticationMethod(preferences);

    Print(CFSTR("%@\n"),initiatorIQN);
    Print(CFSTR("\tAlias: %@\n"),alias);
    Print(CFSTR("\tAuthentication: %s\n"),AuthMethodName(method));

    if(method == kiSCSIAuthMethodCHAP) {
        Print(CFSTR("\t\tCHAP name: %@\n"),(name && CFStringGetLength(name) > 0) ? name : CFSTR("<unspecified>"));
        Print(CFSTR("\t\tCHAP secret: %s\n"),iSCSIKeychainContainsCHAPSecretForNode(initiatorIQN) ? "<specified>" : "<unspecified>");
    }

    if(initiatorIQN)
        CFRelease(initiatorIQN);
    if(alias)
        CFRelease(alias);
    if(name)
        CFRelease(name);

    iSCSIPreferencesRelease(preferences);
    return 0;
}

#pragma mark - Discovery

static errno_t CommandAddDiscoveryPortal(const struct Arguments * arguments)
{
    iSCSIMutablePortalRef portal = CreatePortal(arguments,true);

    if(!portal)
        return EINVAL;

    iSCSIDaemonHandle handle = ConnectToDaemon();

    if(handle < 0) {
        iSCSIPortalRelease(portal);
        return ENOTCONN;
    }

    errno_t error = ModifyPreferences(handle,^errno_t(iSCSIPreferencesRef preferences) {
        if(iSCSIPreferencesContainsPortalForSendTargetsDiscovery(preferences,iSCSIPortalGetAddress(portal))) {
            PrintError(CFSTR("the specified discovery portal already exists"));
            return EEXIST;
        }

        iSCSIPreferencesAddSendTargetsDiscoveryPortal(preferences,portal);
        return 0;
    });

    if(!error)
        iSCSIDaemonUpdateDiscovery(handle);

    iSCSIPortalRelease(portal);
    iSCSIDaemonDisconnect(handle);
    return error;
}

static errno_t CommandRemoveDiscoveryPortal(const struct Arguments * arguments)
{
    iSCSIMutablePortalRef portal = CreatePortal(arguments,true);

    if(!portal)
        return EINVAL;

    iSCSIDaemonHandle handle = ConnectToDaemon();

    if(handle < 0) {
        iSCSIPortalRelease(portal);
        return ENOTCONN;
    }

    // Targets that were discovered through the portal are removed along
    // with it, hence none of them may be in use
    CFArrayRef activeTargets = iSCSIDaemonCreateArrayOfActiveTargets(handle);

    errno_t error = ModifyPreferences(handle,^errno_t(iSCSIPreferencesRef preferences) {
        CFStringRef address = iSCSIPortalGetAddress(portal);

        if(!iSCSIPreferencesContainsPortalForSendTargetsDiscovery(preferences,address)) {
            PrintError(CFSTR("the specified discovery portal does not exist"));
            return ENOENT;
        }

        CFArrayRef targets = iSCSIPreferencesCreateArrayOfDynamicTargetsForSendTargets(preferences,address);

        for(CFIndex idx = 0; targets && idx < CFArrayGetCount(targets); idx++) {
            CFStringRef targetIQN = CFArrayGetValueAtIndex(targets,idx);

            for(CFIndex activeIdx = 0; activeTargets && activeIdx < CFArrayGetCount(activeTargets); activeIdx++) {
                CFStringRef activeIQN = GetString(CFArrayGetValueAtIndex(activeTargets,activeIdx),CFSTR("Target Name"),NULL);
                iSCSITargetRef active = iSCSITargetCreateWithDictionary(CFArrayGetValueAtIndex(activeTargets,activeIdx));

                if(active)
                    activeIQN = iSCSITargetGetIQN(active);

                bool match = activeIQN && CFStringCompare(activeIQN,targetIQN,0) == kCFCompareEqualTo;

                if(active)
                    iSCSITargetRelease(active);

                if(match) {
                    PrintError(CFSTR("target %@ of the discovery portal has an active session; logout first"),targetIQN);
                    CFRelease(targets);
                    return EBUSY;
                }
            }
        }

        if(targets)
            CFRelease(targets);

        iSCSIPreferencesRemoveSendTargetsDiscoveryPortal(preferences,portal);
        return 0;
    });

    if(activeTargets)
        CFRelease(activeTargets);

    iSCSIPortalRelease(portal);
    iSCSIDaemonDisconnect(handle);
    return error;
}

static errno_t CommandModifyDiscovery(const struct Arguments * arguments)
{
    iSCSIDaemonHandle handle = ConnectToDaemon();

    if(handle < 0)
        return ENOTCONN;

    errno_t error = ModifyPreferences(handle,^errno_t(iSCSIPreferencesRef preferences) {
        bool enable = false, invalid = false;
        const char * value;

        if(GetEnableOption(arguments,"SendTargets",&enable,&invalid))
            iSCSIPreferencesSetSendTargetsDiscoveryEnable(preferences,enable);

        if(invalid)
            return EINVAL;

        if((value = GetOption(arguments,"interval"))) {
            int interval = atoi(value);

            if(interval < (int)kiSCSIInitiator_DiscoveryInterval_Min || interval > (int)kiSCSIInitiator_DiscoveryInterval_Max) {
                PrintError(CFSTR("the discovery interval must be between %u and %u seconds"),
                           kiSCSIInitiator_DiscoveryInterval_Min,kiSCSIInitiator_DiscoveryInterval_Max);
                return EINVAL;
            }
            iSCSIPreferencesSetSendTargetsDiscoveryInterval(preferences,interval);
        }
        return 0;
    });

    if(!error)
        iSCSIDaemonUpdateDiscovery(handle);

    iSCSIDaemonDisconnect(handle);
    return error;
}

static errno_t CommandListDiscovery(const struct Arguments * arguments)
{
    iSCSIPreferencesRef preferences = iSCSIPreferencesCreateFromAppValues();
    Boolean enabled = iSCSIPreferencesGetSendTargetsDiscoveryEnable(preferences);
    CFArrayRef portals = iSCSIPreferencesCreateArrayOfPortalsForSendTargetsDiscovery(preferences);

    Print(CFSTR("\tSendTargets: %s\n"),enabled ? "enabled" : "disabled");
    Print(CFSTR("\tDiscovery interval: %ld seconds\n"),(long)iSCSIPreferencesGetSendTargetsDiscoveryInterval(preferences));
    Print(CFSTR("\tDiscovery portals:\n"));

    for(CFIndex idx = 0; portals && idx < CFArrayGetCount(portals); idx++) {
        iSCSIPortalRef portal = iSCSIPreferencesCopySendTargetsDiscoveryPortal(preferences,CFArrayGetValueAtIndex(portals,idx));

        if(!portal)
            continue;

        Print(CFSTR("\t\t%@ <port %@, interface %@>\n"),iSCSIPortalGetAddress(portal),iSCSIPortalGetPort(portal),
              iSCSIPortalGetHostInterface(portal));
        iSCSIPortalRelease(portal);
    }

    if(portals)
        CFRelease(portals);

    iSCSIPreferencesRelease(preferences);
    return 0;
}

/*! Queries a portal for its targets, without recording anything. */
static errno_t CommandDiscover(const struct Arguments * arguments)
{
    iSCSIMutablePortalRef portal = CreatePortal(arguments,true);

    if(!portal)
        return EINVAL;

    iSCSIDaemonHandle handle = ConnectToDaemon();

    if(handle < 0) {
        iSCSIPortalRelease(portal);
        return ENOTCONN;
    }

    iSCSIDiscoveryRecRef discoveryRec = NULL;
    enum iSCSILoginStatusCode statusCode = kiSCSILoginInvalidStatusCode;
    errno_t error = iSCSIDaemonQueryPortalForTargets(handle,portal,&discoveryRec,&statusCode);

    if(error && statusCode != kiSCSILoginInvalidStatusCode && statusCode != kiSCSILoginSuccess)
        PrintError(CFSTR("%@"),iSCSIUtilsGetStringForLoginStatus(statusCode));
    else if(error || !discoveryRec)
        PrintError(CFSTR("discovery failed: %s%s"),strerror(error ? error : EIO),LocalNetworkHint(error));
    else {
        CFArrayRef targets = iSCSIDiscoveryRecCreateArrayOfTargets(discoveryRec);
        CFIndex count = targets ? CFArrayGetCount(targets) : 0;

        if(count == 0)
            Print(CFSTR("The portal offers no targets\n"));

        for(CFIndex idx = 0; idx < count; idx++) {
            CFStringRef targetIQN = CFArrayGetValueAtIndex(targets,idx);
            CFArrayRef groups = iSCSIDiscoveryRecCreateArrayOfPortalGroupTags(discoveryRec,targetIQN);

            Print(CFSTR("%@\n"),targetIQN);

            for(CFIndex groupIdx = 0; groups && groupIdx < CFArrayGetCount(groups); groupIdx++) {
                CFStringRef tag = CFArrayGetValueAtIndex(groups,groupIdx);
                CFArrayRef portals = iSCSIDiscoveryRecGetPortals(discoveryRec,targetIQN,tag);

                for(CFIndex portalIdx = 0; portals && portalIdx < CFArrayGetCount(portals); portalIdx++) {
                    iSCSIPortalRef entry = CFArrayGetValueAtIndex(portals,portalIdx);
                    Print(CFSTR("\t%@ <port %@, tpgt %@>\n"),iSCSIPortalGetAddress(entry),iSCSIPortalGetPort(entry),tag);
                }
            }

            if(groups)
                CFRelease(groups);
        }

        if(targets)
            CFRelease(targets);
    }

    if(discoveryRec)
        iSCSIDiscoveryRecRelease(discoveryRec);

    iSCSIPortalRelease(portal);
    iSCSIDaemonDisconnect(handle);
    return error;
}

#pragma mark - Daemon

/*! Waits for the daemon to answer (or to stop answering). */
static bool WaitForDaemon(bool running)
{
    for(int attempt = 0; attempt < 100; attempt++) {
        iSCSIDaemonHandle handle = iSCSIDaemonConnect();
        CFDictionaryRef status = (handle >= 0) ? iSCSIDaemonCreateStatus(handle) : NULL;
        bool answers = (status != NULL);

        if(status)
            CFRelease(status);

        iSCSIDaemonDisconnect(handle);

        if(answers == running)
            return true;

        usleep(100 * 1000);
    }
    return false;
}

/*! Stops the daemon so that it can be handed over to (or taken back from)
 *  launchd. Refuses if targets are logged in, as these would be cut off. */
static errno_t StopDaemonForReconfiguration(void)
{
    iSCSIDaemonHandle handle = iSCSIDaemonConnect();

    if(handle < 0)
        return 0;

    CFArrayRef activeTargets = iSCSIDaemonCreateArrayOfActiveTargets(handle);
    CFIndex activeCount = activeTargets ? CFArrayGetCount(activeTargets) : 0;

    if(activeTargets)
        CFRelease(activeTargets);

    if(activeCount > 0) {
        iSCSIDaemonDisconnect(handle);
        PrintError(CFSTR("logout of all targets first: the daemon has to be restarted"));
        return EBUSY;
    }

    // A daemon that launchd manages is stopped by launchd when the launch
    // agent is replaced or removed (and would be started again on demand
    // if it was merely asked to exit)
    CFStringRef agent = iSCSILaunchAgentCopyDaemonPath();

    if(agent)
        CFRelease(agent);
    else {
        iSCSIDaemonShutdown(handle);
        iSCSIDaemonDisconnect(handle);
        WaitForDaemon(false);
        return 0;
    }

    iSCSIDaemonDisconnect(handle);
    return 0;
}

static errno_t CommandDaemon(const struct Arguments * arguments)
{
    const char * action = arguments->subcommand ? arguments->subcommand : "status";
    errno_t error = 0;

    if(strcmp(action,"status") == 0) {
        iSCSIDaemonHandle handle = iSCSIDaemonConnect();
        CFDictionaryRef status = (handle >= 0) ? iSCSIDaemonCreateStatus(handle) : NULL;
        CFStringRef agent = iSCSILaunchAgentCopyDaemonPath();

        if(status) {
            Print(CFSTR("iscsid %@ is running (pid %d)\n"),GetString(status,kiSCSIDStatusVersion,CFSTR("")),
                  GetInt(status,kiSCSIDStatusProcessId,0));
            CFRelease(status);
        }
        else
            Print(CFSTR("iscsid is not running\n"));

        if(agent) {
            Print(CFSTR("iscsid starts at login (%@)\n"),agent);
            CFRelease(agent);
        }
        else
            Print(CFSTR("iscsid does not start at login\n"));

        iSCSIDaemonDisconnect(handle);
    }
    else if(strcmp(action,"start") == 0) {
        iSCSIDaemonHandle handle = ConnectToDaemon();
        error = (handle < 0) ? ENOTCONN : 0;
        iSCSIDaemonDisconnect(handle);
    }
    else if(strcmp(action,"stop") == 0) {
        iSCSIDaemonHandle handle = iSCSIDaemonConnect();

        CFStringRef agent = iSCSILaunchAgentCopyDaemonPath();

        if(handle < 0)
            Print(CFSTR("iscsid is not running\n"));
        else if((error = iSCSIDaemonShutdown(handle)))
            PrintError(CFSTR("unable to stop the daemon: %s"),strerror(error));
        else if(agent)
            Print(CFSTR("iscsid was stopped; launchd starts it again when it is needed\n"));
        else {
            WaitForDaemon(false);
            iSCSILaunchAgentRetireDaemon();
        }

        if(agent)
            CFRelease(agent);

        iSCSIDaemonDisconnect(handle);
    }
    // Have launchd start the daemon at login
    else if(strcmp(action,"install") == 0) {
        char executable[PATH_MAX], resolved[PATH_MAX], directory[PATH_MAX], daemonPath[PATH_MAX];
        uint32_t size = sizeof(executable);

        // The daemon lives next to this tool
        if(_NSGetExecutablePath(executable,&size) != 0 || !realpath(executable,resolved) ||
           !dirname_r(resolved,directory) ||
           (size_t)snprintf(daemonPath,sizeof(daemonPath),"%s/iscsid",directory) >= sizeof(daemonPath) ||
           access(daemonPath,X_OK) != 0) {
            PrintError(CFSTR("unable to locate the daemon executable"));
            return ENOENT;
        }

        if((error = StopDaemonForReconfiguration()))
            return error;

        if((error = iSCSILaunchAgentInstall(daemonPath)))
            PrintError(CFSTR("unable to install the launch agent: %s"),strerror(error));
        else if(!WaitForDaemon(true)) {
            PrintError(CFSTR("the launch agent was installed but the daemon did not start"));
            error = EIO;
        }
        else
            Print(CFSTR("iscsid will start at login\n"));
    }
    else if(strcmp(action,"uninstall") == 0) {
        if((error = StopDaemonForReconfiguration()))
            return error;

        if((error = iSCSILaunchAgentRemove()))
            PrintError(CFSTR("unable to remove the launch agent: %s"),strerror(error));
        else
            Print(CFSTR("iscsid will no longer start at login\n"));
    }
    else {
        PrintUsage();
        error = EINVAL;
    }
    return error;
}

#pragma mark - Command line

/*! Options that are not followed by a value. */
static bool OptionIsFlag(const char * name)
{
    return strcasecmp(name,"CHAP-secret") == 0 || strcasecmp(name,"initiator-CHAP-secret") == 0 ||
           strcasecmp(name,"force") == 0;
}

/*! Parses "<target>", "<portal>" or "<target>,<portal>". */
static void ParseTargetAndPortal(struct Arguments * arguments,char * argument)
{
    char * comma = strchr(argument,',');

    if(comma) {
        *comma = '\0';
        arguments->targetIQN = CreateString(argument);
        arguments->portalString = comma + 1;
    }
    else if(strncasecmp(argument,"iqn.",4) == 0 || strncasecmp(argument,"eui.",4) == 0)
        arguments->targetIQN = CreateString(argument);
    else
        arguments->portalString = argument;
}

int main(int argc,char * argv[])
{
    static const char * const subcommands[] = {
        "initiator-config", "target", "target-config", "targets", "discovery-portal", "discovery-config", "luns",
        "status", "start", "stop", "install", "uninstall"
    };

    struct Arguments arguments;
    memset(&arguments,0,sizeof(arguments));

    if(argc < 2) {
        PrintUsage();
        return EINVAL;
    }

    if(strcmp(argv[1],"-v") == 0 || strcmp(argv[1],"--version") == 0) {
        printf("iscsictl %s\n",ISCSI_VERSION);
        return 0;
    }

    arguments.command = argv[1];

    bool sawPositional = false;

    for(int idx = 2; idx < argc; idx++) {
        char * argument = argv[idx];

        if(argument[0] == '-' && argument[1] != '\0') {
            if(arguments.optionCount == (int)(sizeof(arguments.options) / sizeof(arguments.options[0])))
                break;

            struct Option * option = &arguments.options[arguments.optionCount++];
            option->name = argument + 1;

            if(!OptionIsFlag(option->name) && idx + 1 < argc)
                option->value = argv[++idx];

            continue;
        }

        // The first word after the command may be a sub-command
        bool isSubcommand = false;

        if(!sawPositional && !arguments.subcommand) {
            for(size_t sub = 0; sub < sizeof(subcommands) / sizeof(subcommands[0]); sub++)
                isSubcommand = isSubcommand || strcmp(argument,subcommands[sub]) == 0;
        }

        if(isSubcommand)
            arguments.subcommand = argument;
        else if(!sawPositional) {
            ParseTargetAndPortal(&arguments,argument);
            sawPositional = true;
        }
        else {
            PrintUsage();
            return EINVAL;
        }
    }

    const char * command = arguments.command;
    const char * subcommand = arguments.subcommand ? arguments.subcommand : "";
    errno_t error = EINVAL;

    if(strcmp(command,"login") == 0)
        error = CommandLogin(&arguments);
    else if(strcmp(command,"logout") == 0)
        error = CommandLogout(&arguments);
    else if(strcmp(command,"discover") == 0)
        error = CommandDiscover(&arguments);
    else if(strcmp(command,"daemon") == 0)
        error = CommandDaemon(&arguments);
    else if(strcmp(command,"add") == 0 && strcmp(subcommand,"target") == 0)
        error = CommandAddTarget(&arguments);
    else if(strcmp(command,"add") == 0 && strcmp(subcommand,"discovery-portal") == 0)
        error = CommandAddDiscoveryPortal(&arguments);
    else if(strcmp(command,"remove") == 0 && strcmp(subcommand,"target") == 0)
        error = CommandRemoveTarget(&arguments);
    else if(strcmp(command,"remove") == 0 && strcmp(subcommand,"discovery-portal") == 0)
        error = CommandRemoveDiscoveryPortal(&arguments);
    else if(strcmp(command,"modify") == 0 && strcmp(subcommand,"initiator-config") == 0)
        error = CommandModifyInitiator(&arguments);
    else if(strcmp(command,"modify") == 0 && strcmp(subcommand,"target-config") == 0)
        error = CommandModifyTarget(&arguments);
    else if(strcmp(command,"modify") == 0 && strcmp(subcommand,"discovery-config") == 0)
        error = CommandModifyDiscovery(&arguments);
    else if(strcmp(command,"list") == 0 && strcmp(subcommand,"initiator-config") == 0)
        error = CommandListInitiator(&arguments);
    else if(strcmp(command,"list") == 0 && strcmp(subcommand,"target-config") == 0)
        error = CommandListTargetConfig(&arguments);
    else if(strcmp(command,"list") == 0 && strcmp(subcommand,"discovery-config") == 0)
        error = CommandListDiscovery(&arguments);
    else if(strcmp(command,"list") == 0 && strcmp(subcommand,"targets") == 0)
        error = CommandListTargets(&arguments);
    else if(strcmp(command,"list") == 0 && strcmp(subcommand,"luns") == 0)
        error = CommandListLUNs(&arguments);
    else
        PrintUsage();

    if(arguments.targetIQN)
        CFRelease(arguments.targetIQN);

    return error;
}
