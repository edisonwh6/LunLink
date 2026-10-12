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

#include "iSCSILaunchAgent.h"
#include "iSCSIUtils.h"

#include <sys/stat.h>
#include <sys/wait.h>
#include <mach-o/dyld.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <pwd.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char ** environ;

/*! Label by which launchd knows the daemon. */
static const char kiSCSILaunchAgentLabelDefault[] = "io.github.edisonwh6.LunLink.iscsid";

/*! Gets the label of the launch agent (which can be overridden by means of
 *  the environment variable ISCSI_LAUNCH_AGENT_LABEL, so that a second
 *  instance can be set up, e.g., for testing). */
static const char * iSCSILaunchAgentGetLabel(void)
{
    const char * label = getenv("ISCSI_LAUNCH_AGENT_LABEL");
    return (label && label[0] != '\0') ? label : kiSCSILaunchAgentLabelDefault;
}

static bool iSCSILaunchAgentGetPlistPath(char * path,size_t size)
{
    struct passwd * user = getpwuid(getuid());

    if(!user || !user->pw_dir)
        return false;

    return (size_t)snprintf(path,size,"%s/Library/LaunchAgents/%s.plist",user->pw_dir,iSCSILaunchAgentGetLabel()) < size;
}

/*! Runs a tool and waits for it; returns its exit status. */
static int iSCSILaunchAgentRunTool(const char * const arguments[])
{
    posix_spawn_file_actions_t actions;
    pid_t pid;
    int status = 0;

    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions,STDIN_FILENO,"/dev/null",O_RDONLY,0);
    posix_spawn_file_actions_addopen(&actions,STDOUT_FILENO,"/dev/null",O_WRONLY,0);
    posix_spawn_file_actions_addopen(&actions,STDERR_FILENO,"/dev/null",O_WRONLY,0);

    int error = posix_spawn(&pid,arguments[0],&actions,NULL,(char * const *)arguments,environ);
    posix_spawn_file_actions_destroy(&actions);

    if(error)
        return -1;

    while(waitpid(pid,&status,0) < 0 && errno == EINTR);

    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/*! Locates the helper through which jobs are handed to launchd (see
 *  Launcher/launcher.c).  It is part of the application bundle, which this
 *  process may or may not be running from. */
static bool iSCSILaunchAgentGetLauncherPath(char * path,size_t size)
{
    char executable[PATH_MAX], resolved[PATH_MAX], directory[PATH_MAX];
    uint32_t length = sizeof(executable);

    return _NSGetExecutablePath(executable,&length) == 0 && realpath(executable,resolved) &&
           dirname_r(resolved,directory) &&
           (size_t)snprintf(path,size,"%s/../Helpers/Launcher.app",directory) < size &&
           access(path,F_OK) == 0;
}

/*! Runs launchctl by way of the launcher, so that a job is not put down to
 *  this process (and the application that it is part of).
 *  @return the exit status of launchctl, or -1 if it could not be run so. */
static int iSCSILaunchAgentRunLaunchctlThroughLauncher(const char * verb,const char * first,const char * second)
{
    char launcher[PATH_MAX], directory[PATH_MAX], statusPath[PATH_MAX];

    if(!iSCSILaunchAgentGetLauncherPath(launcher,sizeof(launcher)) ||
       !iSCSIUtilsGetRuntimeDirectory(directory,sizeof(directory)) ||
       (size_t)snprintf(statusPath,sizeof(statusPath),"%s/launchctl.%d.status",directory,(int)getpid()) >= sizeof(statusPath))
        return -1;

    unlink(statusPath);

    // The launcher is opened as an application of its own (a new instance
    // of it, in the background).  Whoever opens an application is not told
    // how it fares (nor, reliably, when it is done), which is why the
    // launcher leaves the exit status of launchctl in a file.
    const char * arguments[] = { "/usr/bin/open", "-n", "-g", "-j", launcher,
                                 "--args", statusPath, verb, first, second, NULL };
    int result = -1;

    if(iSCSILaunchAgentRunTool(arguments) == 0) {
        for(int attempt = 0; attempt < 500 && result < 0; attempt++) {
            FILE * file = fopen(statusPath,"r");

            if(!file) {
                usleep(20 * 1000);
                continue;
            }

            if(fscanf(file,"%d",&result) != 1)
                result = -1;

            fclose(file);
            break;
        }
    }
    unlink(statusPath);
    return result;
}

/*! Runs launchctl with the specified arguments; returns its exit status. */
static int iSCSILaunchAgentRunLaunchctl(const char * verb,const char * first,const char * second)
{
    int result = iSCSILaunchAgentRunLaunchctlThroughLauncher(verb,first,second);

    if(result >= 0)
        return result;

    const char * arguments[] = { "/bin/launchctl", verb, first, second, NULL };
    return iSCSILaunchAgentRunTool(arguments);
}

CFStringRef iSCSILaunchAgentCopyDaemonPath(void)
{
    char path[PATH_MAX];

    if(!iSCSILaunchAgentGetPlistPath(path,sizeof(path)))
        return NULL;

    CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,(const UInt8 *)path,
                                                           (CFIndex)strlen(path),false);
    CFReadStreamRef stream = CFReadStreamCreateWithFile(kCFAllocatorDefault,url);
    CFStringRef daemonPath = NULL;

    if(stream && CFReadStreamOpen(stream)) {
        CFPropertyListRef plist = CFPropertyListCreateWithStream(kCFAllocatorDefault,stream,0,
                                                                 kCFPropertyListImmutable,NULL,NULL);
        CFArrayRef arguments = NULL;

        if(plist && CFGetTypeID(plist) == CFDictionaryGetTypeID() &&
           (arguments = CFDictionaryGetValue(plist,CFSTR("ProgramArguments"))) &&
           CFGetTypeID(arguments) == CFArrayGetTypeID() && CFArrayGetCount(arguments) > 0) {
            CFStringRef first = CFArrayGetValueAtIndex(arguments,0);

            if(CFGetTypeID(first) == CFStringGetTypeID())
                daemonPath = CFStringCreateCopy(kCFAllocatorDefault,first);
        }

        if(plist)
            CFRelease(plist);

        CFReadStreamClose(stream);
    }

    if(stream)
        CFRelease(stream);

    CFRelease(url);
    return daemonPath;
}

/*! Describes the daemon to launchd as a job.
 *  @param label the label of the job.
 *  @param daemonPath the executable of the daemon.
 *  @param socketPath the socket on which launchd is to listen on behalf of
 *  the daemon, or NULL if the daemon is to see to its socket itself.
 *  @return the property list of the job in serialized form. */
static CFDataRef iSCSILaunchAgentCreateJob(const char * label,const char * daemonPath,const char * socketPath)
{
    char logPath[PATH_MAX];

    if(!iSCSIUtilsGetLogPath(logPath,sizeof(logPath)))
        return NULL;

    CFMutableDictionaryRef plist = CFDictionaryCreateMutable(kCFAllocatorDefault,0,&kCFTypeDictionaryKeyCallBacks,
                                                             &kCFTypeDictionaryValueCallBacks);
    CFStringRef labelString = CFStringCreateWithCString(kCFAllocatorDefault,label,kCFStringEncodingUTF8);
    CFStringRef program = CFStringCreateWithFileSystemRepresentation(kCFAllocatorDefault,daemonPath);
    CFStringRef log = CFStringCreateWithFileSystemRepresentation(kCFAllocatorDefault,logPath);
    CFArrayRef arguments = CFArrayCreate(kCFAllocatorDefault,(const void **)&program,1,&kCFTypeArrayCallBacks);

    // The daemon is given time to log out of its targets when it is told
    // to stop (when the user logs out, for one)
    int seconds = 60;
    CFNumberRef exitTimeout = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&seconds);

    CFDictionarySetValue(plist,CFSTR("Label"),labelString);
    CFDictionarySetValue(plist,CFSTR("ProgramArguments"),arguments);
    CFDictionarySetValue(plist,CFSTR("RunAtLoad"),kCFBooleanTrue);
    CFDictionarySetValue(plist,CFSTR("ProcessType"),CFSTR("Interactive"));
    CFDictionarySetValue(plist,CFSTR("ExitTimeOut"),exitTimeout);
    CFDictionarySetValue(plist,CFSTR("StandardOutPath"),log);
    CFDictionarySetValue(plist,CFSTR("StandardErrorPath"),log);

    if(socketPath) {
        CFStringRef socket = CFStringCreateWithFileSystemRepresentation(kCFAllocatorDefault,socketPath);
        int mode = 0600;
        CFNumberRef socketMode = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&mode);

        const void * listenerKeys[] = { CFSTR("SockPathName"), CFSTR("SockPathMode") };
        const void * listenerValues[] = { socket, socketMode };
        CFDictionaryRef listener = CFDictionaryCreate(kCFAllocatorDefault,listenerKeys,listenerValues,2,
                                                      &kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);

        const void * socketsKey = CFSTR("Listeners");
        CFDictionaryRef sockets = CFDictionaryCreate(kCFAllocatorDefault,&socketsKey,(const void **)&listener,1,
                                                     &kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);

        CFDictionarySetValue(plist,CFSTR("Sockets"),sockets);

        CFRelease(sockets);
        CFRelease(listener);
        CFRelease(socketMode);
        CFRelease(socket);
    }

    // Pass on the variables that configure the initiator
    CFMutableDictionaryRef variables = CFDictionaryCreateMutable(kCFAllocatorDefault,0,&kCFTypeDictionaryKeyCallBacks,
                                                                 &kCFTypeDictionaryValueCallBacks);

    for(char ** variable = environ; *variable; variable++) {
        const char * equals = strchr(*variable,'=');

        if(strncmp(*variable,"ISCSI_",6) != 0 || !equals)
            continue;

        CFStringRef name = CFStringCreateWithBytes(kCFAllocatorDefault,(const UInt8 *)*variable,equals - *variable,
                                                   kCFStringEncodingUTF8,false);
        CFStringRef value = CFStringCreateWithCString(kCFAllocatorDefault,equals + 1,kCFStringEncodingUTF8);

        if(name && value)
            CFDictionarySetValue(variables,name,value);

        if(name)
            CFRelease(name);
        if(value)
            CFRelease(value);
    }

    if(CFDictionaryGetCount(variables) > 0)
        CFDictionarySetValue(plist,CFSTR("EnvironmentVariables"),variables);

    CFDataRef data = CFPropertyListCreateData(kCFAllocatorDefault,plist,kCFPropertyListXMLFormat_v1_0,0,NULL);

    CFRelease(variables);
    CFRelease(exitTimeout);
    CFRelease(arguments);
    CFRelease(log);
    CFRelease(program);
    CFRelease(labelString);
    CFRelease(plist);

    return data;
}

/*! Writes the description of a job to a file and has launchd take the job
 *  on, in place of whatever job it may know by the same label. */
static errno_t iSCSILaunchAgentLoadJob(const char * label,const char * plistPath,CFDataRef data)
{
    errno_t error = 0;
    int fd = open(plistPath,O_WRONLY | O_CREAT | O_TRUNC,0644);

    if(fd < 0)
        return errno;

    if(write(fd,CFDataGetBytePtr(data),(size_t)CFDataGetLength(data)) != CFDataGetLength(data))
        error = EIO;

    close(fd);

    if(error)
        return error;

    char domain[64], service[192];
    snprintf(domain,sizeof(domain),"gui/%u",(unsigned)getuid());
    snprintf(service,sizeof(service),"%s/%s",domain,label);
    iSCSILaunchAgentRunLaunchctl("bootout",service,NULL);

    // Removing a job takes launchd a moment, during which it refuses to
    // take the job on anew
    for(int attempt = 0; attempt < 10; attempt++) {
        if(iSCSILaunchAgentRunLaunchctl("bootstrap",domain,plistPath) == 0)
            return 0;

        usleep(300 * 1000);
    }
    return EAGAIN;
}

/*! The job by which launchd runs the daemon for the time being (as opposed
 *  to the launch agent, which is there to stay). */
static bool iSCSILaunchAgentGetSessionJob(char * label,size_t labelSize,char * plistPath,size_t plistPathSize)
{
    char directory[PATH_MAX];

    return (size_t)snprintf(label,labelSize,"%s.session",iSCSILaunchAgentGetLabel()) < labelSize &&
           iSCSIUtilsGetRuntimeDirectory(directory,sizeof(directory)) &&
           (size_t)snprintf(plistPath,plistPathSize,"%s/iscsid.session.plist",directory) < plistPathSize;
}

errno_t iSCSILaunchAgentStartDaemon(const char * daemonPath)
{
    char label[128], plistPath[PATH_MAX];

    if(!daemonPath || access(daemonPath,X_OK) != 0)
        return ENOENT;

    if(!iSCSILaunchAgentGetSessionJob(label,sizeof(label),plistPath,sizeof(plistPath)))
        return EIO;

    CFDataRef data = iSCSILaunchAgentCreateJob(label,daemonPath,NULL);

    if(!data)
        return EIO;

    errno_t error = iSCSILaunchAgentLoadJob(label,plistPath,data);
    CFRelease(data);
    return error;
}

void iSCSILaunchAgentRetireDaemon(void)
{
    char label[128], plistPath[PATH_MAX], service[192];

    if(!iSCSILaunchAgentGetSessionJob(label,sizeof(label),plistPath,sizeof(plistPath)) || access(plistPath,F_OK) != 0)
        return;

    snprintf(service,sizeof(service),"gui/%u/%s",(unsigned)getuid(),label);
    iSCSILaunchAgentRunLaunchctl("bootout",service,NULL);
    unlink(plistPath);
}

errno_t iSCSILaunchAgentInstall(const char * daemonPath)
{
    char plistPath[PATH_MAX], directory[PATH_MAX], socketPath[PATH_MAX];

    if(!daemonPath || access(daemonPath,X_OK) != 0)
        return ENOENT;

    if(!iSCSILaunchAgentGetPlistPath(plistPath,sizeof(plistPath)) ||
       !iSCSIUtilsGetSocketPath(kiSCSIDaemonSocketName,socketPath,sizeof(socketPath)))
        return EIO;

    // Describe the daemon to launchd: it is to run when the user logs in,
    // and launchd listens on its socket in the meantime
    CFDataRef data = iSCSILaunchAgentCreateJob(iSCSILaunchAgentGetLabel(),daemonPath,socketPath);

    if(!data)
        return EIO;

    // The agent takes the place of the job that ran the daemon so far
    char sessionLabel[128], sessionPlistPath[PATH_MAX], service[192];

    if(iSCSILaunchAgentGetSessionJob(sessionLabel,sizeof(sessionLabel),sessionPlistPath,sizeof(sessionPlistPath))) {
        snprintf(service,sizeof(service),"gui/%u/%s",(unsigned)getuid(),sessionLabel);
        iSCSILaunchAgentRunLaunchctl("bootout",service,NULL);
        unlink(sessionPlistPath);
    }

    // The property list goes where launchd looks for the agents of the user
    strlcpy(directory,plistPath,sizeof(directory));
    *strrchr(directory,'/') = '\0';
    mkdir(directory,0755);

    // The socket of a daemon that did not shut down cleanly is in the way
    unlink(socketPath);

    errno_t error = iSCSILaunchAgentLoadJob(iSCSILaunchAgentGetLabel(),plistPath,data);
    CFRelease(data);
    return error;
}

errno_t iSCSILaunchAgentRemove(void)
{
    char plistPath[PATH_MAX], service[128];

    if(!iSCSILaunchAgentGetPlistPath(plistPath,sizeof(plistPath)))
        return EIO;

    snprintf(service,sizeof(service),"gui/%u/%s",(unsigned)getuid(),iSCSILaunchAgentGetLabel());
    iSCSILaunchAgentRunLaunchctl("bootout",service,NULL);

    if(unlink(plistPath) != 0 && errno != ENOENT)
        return errno;

    return 0;
}
