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

#include "iSCSIDiskManager.h"
#include "iSCSIBlockExport.h"
#include "iSCSILogicalUnit.h"
#include "iSCSILog.h"
#include "iSCSIUtils.h"

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitLib.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <time.h>
#include <unistd.h>

extern char ** environ;

static const char kToolHdiutil[] = "/usr/bin/hdiutil";
static const char kToolDiskutil[] = "/usr/sbin/diskutil";
static const char kToolMountNFS[] = "/sbin/mount_nfs";
static const char kToolUnmount[] = "/sbin/umount";

/*! File name of the socket of the block export. */
static const char kExportSocketName[] = "disks.sock";

/*! Name of the directory, within the run-time directory, where the block
 *  export is mounted. */
static const char kMountDirectoryName[] = "Disks";

/*! Time allowed for a system tool to complete. */
static const int kToolTimeoutSec = 60;

struct Disk {
    struct Disk * next;
    SessionIdentifier sessionId;
    iSCSILogicalUnitRef unit;

    /*! File name of the logical unit in the block export. */
    char exportName[256];

    /*! Name of the disk (e.g., "disk4"), empty if not attached. */
    char bsdName[32];

    /*! Describes why the unit could not be attached (empty otherwise). */
    char error[128];

    /*! The disk is attached read-only. */
    bool readOnly;

    /*! The disk was attached but has been ejected since. */
    bool ejected;

    /*! Used while the disks of a session are being detached. */
    bool detached;
};

struct __iSCSIDiskManager {
    iSCSIHBAInterfaceRef interface;
    iSCSIBlockExportRef exportRef;
    char socketPath[PATH_MAX];
    char mountPath[PATH_MAX];
    bool mounted;

    /*! Serializes attach and detach operations. */
    pthread_mutex_t operationLock;

    /*! Protects the list of disks. */
    pthread_mutex_t lock;
    struct Disk * disks;
};

#pragma mark - Running system tools

/*! Runs a tool and waits for it to finish.
 *  @param arguments the argument vector (NULL-terminated).
 *  @param output the standard output of the tool (may be NULL; release it).
 *  @return the exit status of the tool, or -1 if it could not be run, was
 *  terminated by a signal or timed out. */
static int RunTool(const char * const arguments[],CFDataRef * output)
{
    int pipeFds[2];

    if(output)
        *output = NULL;

    if(pipe(pipeFds) != 0)
        return -1;

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions,STDIN_FILENO,"/dev/null",O_RDONLY,0);
    posix_spawn_file_actions_adddup2(&actions,pipeFds[1],STDOUT_FILENO);
    posix_spawn_file_actions_addopen(&actions,STDERR_FILENO,"/dev/null",O_WRONLY,0);

    // Tools (and whatever helpers they in turn start, some of which stay
    // around) must not inherit the sockets of the daemon: they would keep
    // them open beyond the life of the daemon
    posix_spawnattr_t attributes;
    posix_spawnattr_init(&attributes);
    posix_spawnattr_setflags(&attributes,POSIX_SPAWN_CLOEXEC_DEFAULT);

    pid_t pid;
    int error = posix_spawn(&pid,arguments[0],&actions,&attributes,(char * const *)arguments,environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);
    close(pipeFds[1]);

    if(error) {
        close(pipeFds[0]);
        iSCSILogError("unable to run %s: %s",arguments[0],strerror(error));
        return -1;
    }

    // Collect the output until the tool closes its end of the pipe
    CFMutableDataRef data = CFDataCreateMutable(kCFAllocatorDefault,0);
    time_t deadline = time(NULL) + kToolTimeoutSec;
    bool timedOut = false;

    for(;;) {
        struct pollfd pollFd = { .fd = pipeFds[0], .events = POLLIN };
        time_t now = time(NULL);

        if(now >= deadline) {
            timedOut = true;
            break;
        }

        int ready = poll(&pollFd,1,(int)(deadline - now) * 1000);

        if(ready < 0 && errno == EINTR)
            continue;

        if(ready <= 0) {
            timedOut = (ready == 0);
            break;
        }

        UInt8 buffer[4096];
        ssize_t count = read(pipeFds[0],buffer,sizeof(buffer));

        if(count < 0 && errno == EINTR)
            continue;

        if(count <= 0)
            break;

        CFDataAppendBytes(data,buffer,count);
    }
    close(pipeFds[0]);

    if(timedOut) {
        iSCSILogError("%s timed out",arguments[0]);
        kill(pid,SIGKILL);
    }

    int status = 0;
    while(waitpid(pid,&status,0) < 0 && errno == EINTR);

    if(output)
        *output = data;
    else
        CFRelease(data);

    return (!timedOut && WIFEXITED(status)) ? WEXITSTATUS(status) : -1;
}

static bool ToolAvailable(const char * path)
{
    return access(path,X_OK) == 0;
}

#pragma mark - Disk images

/*! Attaches a file as a raw disk image without mounting its volumes.
 *  @param bsdName the name of the new disk (e.g., "disk4").
 *  @return true if the image was attached. */
static bool ImageAttach(const char * imagePath,bool readOnly,char * bsdName,size_t bsdNameSize)
{
    const char * arguments[12];
    int count = 0;

    if(ToolAvailable(kToolHdiutil)) {
        arguments[count++] = kToolHdiutil;
        arguments[count++] = "attach";
        arguments[count++] = "-imagekey";
        arguments[count++] = "diskimage-class=CRawDiskImage";
        arguments[count++] = "-nomount";
        arguments[count++] = "-plist";

        if(readOnly)
            arguments[count++] = "-readonly";
    }
    else {
        arguments[count++] = kToolDiskutil;
        arguments[count++] = "image";
        arguments[count++] = "attach";
        arguments[count++] = "--plist";
        arguments[count++] = "--noMount";

        if(readOnly)
            arguments[count++] = "--readOnly";
    }
    arguments[count++] = imagePath;
    arguments[count] = NULL;

    CFDataRef output = NULL;
    int status = RunTool(arguments,&output);
    bool attached = false;

    bsdName[0] = '\0';

    // Of the devices that came into being, the disk of the image is a whole
    // disk (as opposed to a partition), yet not a synthesized one (an APFS
    // container, which the system derives from a partition of the disk and
    // presents as a whole disk in its own right).  The disk that it derives
    // from exists first, hence has the lower number.
    long unit = -1;

    if(status == 0 && output) {
        CFPropertyListRef plist = CFPropertyListCreateWithData(kCFAllocatorDefault,output,
                                                               kCFPropertyListImmutable,NULL,NULL);

        if(plist && CFGetTypeID(plist) == CFDictionaryGetTypeID()) {
            CFArrayRef entities = CFDictionaryGetValue(plist,CFSTR("system-entities"));

            if(entities && CFGetTypeID(entities) == CFArrayGetTypeID()) {
                for(CFIndex index = 0; index < CFArrayGetCount(entities); index++) {
                    CFDictionaryRef entity = CFArrayGetValueAtIndex(entities,index);
                    CFStringRef device = NULL, hint = NULL;
                    char devicePath[64];

                    if(CFGetTypeID(entity) != CFDictionaryGetTypeID() ||
                       !(device = CFDictionaryGetValue(entity,CFSTR("dev-entry"))) ||
                       CFGetTypeID(device) != CFStringGetTypeID() ||
                       !CFStringGetCString(device,devicePath,sizeof(devicePath),kCFStringEncodingUTF8) ||
                       strncmp(devicePath,"/dev/disk",9) != 0)
                        continue;

                    // The content of an APFS container goes by this identifier
                    if((hint = CFDictionaryGetValue(entity,CFSTR("content-hint"))) &&
                       CFGetTypeID(hint) == CFStringGetTypeID() &&
                       CFStringCompare(hint,CFSTR("EF57347C-0000-11AA-AA11-00306543ECAC"),
                                       kCFCompareCaseInsensitive) == kCFCompareEqualTo)
                        continue;

                    char * end = NULL;
                    long number = strtol(devicePath + 9,&end,10);

                    if(end == devicePath + 9 || *end != '\0')
                        continue;

                    if(!attached || number < unit) {
                        strlcpy(bsdName,devicePath + 5,bsdNameSize);
                        unit = number;
                        attached = true;
                    }
                }
            }
        }

        if(plist)
            CFRelease(plist);
    }

    if(output)
        CFRelease(output);

    if(!attached)
        iSCSILogError("unable to attach %s as a disk (status %d)",imagePath,status);

    return attached;
}

/*! Determines whether a disk is (still) the one that was attached for an
 *  image.  A disk can be ejected by other means than this daemon, upon which
 *  the system is free to give its name to another disk - one that must not
 *  be mistaken for ours.
 *  @param bsdName the name of the disk (e.g., "disk4").
 *  @param imagePath the path of the image; NULL to accept any disk image
 *  that resides in the specified directory.
 *  @param directory the directory to match if no image path is specified. */
static bool DiskBelongsToImage(const char * bsdName,const char * imagePath,const char * directory)
{
    bool belongs = false;
    io_service_t media = IOServiceGetMatchingService(kIOMainPortDefault,IOBSDNameMatching(kIOMainPortDefault,0,bsdName));

    if(!media)
        return false;

    // The device that provides the disk records where its image lives
    CFDictionaryRef protocol = IORegistryEntrySearchCFProperty(media,kIOServicePlane,CFSTR("Protocol Characteristics"),
                                                               kCFAllocatorDefault,
                                                               kIORegistryIterateRecursively | kIORegistryIterateParents);

    if(protocol && CFGetTypeID(protocol) == CFDictionaryGetTypeID()) {
        CFTypeRef location = CFDictionaryGetValue(protocol,CFSTR("Virtual Interface Location Path"));
        char path[PATH_MAX] = "";

        if(location && CFGetTypeID(location) == CFDataGetTypeID()) {
            CFIndex length = CFDataGetLength(location);

            if(length >= (CFIndex)sizeof(path))
                length = sizeof(path) - 1;

            memcpy(path,CFDataGetBytePtr(location),(size_t)length);
            path[length] = '\0';
        }
        else if(location && CFGetTypeID(location) == CFStringGetTypeID())
            CFStringGetFileSystemRepresentation(location,path,sizeof(path));

        if(imagePath)
            belongs = (strcmp(path,imagePath) == 0);
        else if(directory) {
            size_t length = strlen(directory);
            belongs = (strncmp(path,directory,length) == 0 && path[length] == '/');
        }
    }

    if(protocol)
        CFRelease(protocol);

    IOObjectRelease(media);
    return belongs;
}

/*! Unmounts the volumes of a disk and detaches its image.
 *  @param imagePath the image that the disk was attached for; the disk is
 *  left alone if it turns out to belong to something else by now.
 *  @return true if the disk is gone. */
static bool ImageDetach(const char * bsdName,const char * imagePath,const char * directory,bool force)
{
    char devicePath[64];
    snprintf(devicePath,sizeof(devicePath),"/dev/%s",bsdName);

    // Nothing to do if the disk was ejected by other means
    struct stat status;

    if(stat(devicePath,&status) != 0 || !DiskBelongsToImage(bsdName,imagePath,directory))
        return true;

    const char * arguments[6];
    int count = 0;

    if(ToolAvailable(kToolHdiutil)) {
        arguments[count++] = kToolHdiutil;
        arguments[count++] = "detach";
        arguments[count++] = devicePath;

        if(force)
            arguments[count++] = "-force";
    }
    else {
        arguments[count++] = kToolDiskutil;
        arguments[count++] = "eject";

        if(force)
            arguments[count++] = "force";

        arguments[count++] = devicePath;
    }
    arguments[count] = NULL;

    // A disk is briefly busy while the system examines it (which it does
    // whenever the disk was written to directly), so a refusal is only
    // taken at face value if it persists
    for(int attempt = 0; attempt < 4; attempt++) {
        if(attempt > 0)
            usleep(500 * 1000);

        if(RunTool(arguments,NULL) == 0 || stat(devicePath,&status) != 0 ||
           !DiskBelongsToImage(bsdName,imagePath,directory))
            return true;
    }
    return false;
}

/*! Whether a partition is one of those that hold nothing for the user to
 *  see.  The system does not mount them when a disk is connected (the EFI
 *  system partition that comes with a GUID partition map, above all), and
 *  neither does the daemon. */
static bool PartitionIsHidden(CFStringRef content)
{
    static const char * const kinds[] = { "EFI", "Apple_Boot", "Apple_APFS_Recovery", "Apple_APFS_ISC",
                                          "Apple_partition_map", "Apple_Free", "Apple_KernelCoreDump",
                                          "Microsoft Reserved", "Linux Swap" };
    char name[64];

    if(!content || !CFStringGetCString(content,name,sizeof(name),kCFStringEncodingUTF8))
        return false;

    for(size_t index = 0; index < sizeof(kinds) / sizeof(kinds[0]); index++) {
        if(strcmp(name,kinds[index]) == 0)
            return true;
    }
    return false;
}

static CFTypeRef EntryValue(CFDictionaryRef entry,CFStringRef key,CFTypeID type)
{
    CFTypeRef value = CFDictionaryGetValue(entry,key);
    return (value && CFGetTypeID(value) == type) ? value : NULL;
}

/*! Mounts a volume unless it is mounted already. */
static void MountVolume(CFDictionaryRef volume)
{
    CFStringRef identifier = EntryValue(volume,CFSTR("DeviceIdentifier"),CFStringGetTypeID());
    CFBooleanRef internal = EntryValue(volume,CFSTR("OSInternal"),CFBooleanGetTypeID());
    char name[64];

    // Volumes that an operating system keeps to itself are left alone
    if(!identifier || CFDictionaryContainsKey(volume,CFSTR("MountPoint")) || (internal && CFBooleanGetValue(internal)) ||
       !CFStringGetCString(identifier,name,sizeof(name),kCFStringEncodingUTF8))
        return;

    const char * arguments[] = { kToolDiskutil, "mount", name, NULL };
    RunTool(arguments,NULL);
}

/*! Mounts the volumes of the APFS containers that reside on a partition.
 *  @return true if there is such a container. */
static bool MountContainerVolumes(CFArrayRef entries,CFStringRef store)
{
    bool found = false;

    for(CFIndex index = 0; index < CFArrayGetCount(entries); index++) {
        CFDictionaryRef entry = CFArrayGetValueAtIndex(entries,index);
        CFArrayRef stores = NULL, volumes = NULL;

        if(CFGetTypeID(entry) != CFDictionaryGetTypeID() ||
           !(stores = EntryValue(entry,CFSTR("APFSPhysicalStores"),CFArrayGetTypeID())))
            continue;

        for(CFIndex storeIndex = 0; storeIndex < CFArrayGetCount(stores); storeIndex++) {
            CFDictionaryRef candidate = CFArrayGetValueAtIndex(stores,storeIndex);
            CFStringRef identifier = NULL;

            if(CFGetTypeID(candidate) != CFDictionaryGetTypeID() ||
               !(identifier = EntryValue(candidate,CFSTR("DeviceIdentifier"),CFStringGetTypeID())) ||
               CFStringCompare(identifier,store,0) != kCFCompareEqualTo)
                continue;

            found = true;

            if((volumes = EntryValue(entry,CFSTR("APFSVolumes"),CFArrayGetTypeID()))) {
                for(CFIndex volumeIndex = 0; volumeIndex < CFArrayGetCount(volumes); volumeIndex++) {
                    CFDictionaryRef volume = CFArrayGetValueAtIndex(volumes,volumeIndex);

                    if(CFGetTypeID(volume) == CFDictionaryGetTypeID())
                        MountVolume(volume);
                }
            }
        }
    }
    return found;
}

/*! Mounts the volumes of a disk the way the system does for a disk that is
 *  connected: all but those on partitions that are not for the user.
 *  @return true unless an APFS container has yet to make its appearance. */
static bool MountVolumesOfDisk(const char * bsdName)
{
    const char * arguments[] = { kToolDiskutil, "list", "-plist", NULL };
    CFDataRef output = NULL;

    if(RunTool(arguments,&output) != 0 || !output) {
        if(output)
            CFRelease(output);
        return true;
    }

    CFPropertyListRef plist = CFPropertyListCreateWithData(kCFAllocatorDefault,output,kCFPropertyListImmutable,NULL,NULL);
    CFStringRef disk = CFStringCreateWithCString(kCFAllocatorDefault,bsdName,kCFStringEncodingUTF8);
    CFArrayRef entries = NULL;
    bool complete = true;

    CFRelease(output);

    if(plist && CFGetTypeID(plist) == CFDictionaryGetTypeID() &&
       (entries = EntryValue(plist,CFSTR("AllDisksAndPartitions"),CFArrayGetTypeID())))
    {
        for(CFIndex index = 0; index < CFArrayGetCount(entries); index++) {
            CFDictionaryRef entry = CFArrayGetValueAtIndex(entries,index);
            CFStringRef identifier = NULL;

            if(CFGetTypeID(entry) != CFDictionaryGetTypeID() ||
               !(identifier = EntryValue(entry,CFSTR("DeviceIdentifier"),CFStringGetTypeID())) ||
               CFStringCompare(identifier,disk,0) != kCFCompareEqualTo)
                continue;

            CFArrayRef partitions = EntryValue(entry,CFSTR("Partitions"),CFArrayGetTypeID());

            // A disk without a partition map may hold a file system itself.
            // (A disk that holds nothing at all is left in peace: an attempt
            // to mount it would only be in the way of whoever is about to
            // format it, or to eject it.)
            if(!partitions || CFArrayGetCount(partitions) == 0) {
                CFStringRef content = EntryValue(entry,CFSTR("Content"),CFStringGetTypeID());

                if(content && CFStringGetLength(content) > 0 && !MountContainerVolumes(entries,disk))
                    MountVolume(entry);
                break;
            }

            for(CFIndex partitionIndex = 0; partitionIndex < CFArrayGetCount(partitions); partitionIndex++) {
                CFDictionaryRef partition = CFArrayGetValueAtIndex(partitions,partitionIndex);
                CFStringRef content = NULL, store = NULL;

                if(CFGetTypeID(partition) != CFDictionaryGetTypeID() ||
                   !(store = EntryValue(partition,CFSTR("DeviceIdentifier"),CFStringGetTypeID())))
                    continue;

                content = EntryValue(partition,CFSTR("Content"),CFStringGetTypeID());

                if(PartitionIsHidden(content))
                    continue;

                if(content && CFStringCompare(content,CFSTR("Apple_APFS"),0) == kCFCompareEqualTo)
                    complete = MountContainerVolumes(entries,store) && complete;
                else
                    MountVolume(partition);
            }
            break;
        }
    }

    if(plist)
        CFRelease(plist);

    CFRelease(disk);
    return complete;
}

/*! Mounts the volumes of a disk. Runs on a thread of its own since checking
 *  a file system prior to mounting it may take a long time. */
static void * MountVolumesMain(void * context)
{
    char * bsdName = context;

    pthread_setname_np("iscsid.mount");

    // The volumes of an APFS container take a moment to show up
    for(int attempt = 0; attempt < 20 && !MountVolumesOfDisk(bsdName); attempt++)
        usleep(500 * 1000);

    free(bsdName);
    return NULL;
}

static void MountVolumes(const char * bsdName)
{
    pthread_t thread;
    pthread_attr_t attributes;
    char * name = strdup(bsdName);

    pthread_attr_init(&attributes);
    pthread_attr_setdetachstate(&attributes,PTHREAD_CREATE_DETACHED);

    if(pthread_create(&thread,&attributes,MountVolumesMain,name) != 0)
        free(name);

    pthread_attr_destroy(&attributes);
}

#pragma mark - Mounting the block export

/*! Checks the mount table (without touching the file system, which could
 *  block if its server is gone) for a mount at the specified path. */
static bool IsMountPoint(const char * path)
{
    struct statfs * mounts = NULL;
    int count = getmntinfo(&mounts,MNT_NOWAIT);

    for(int index = 0; index < count; index++)
        if(strcmp(mounts[index].f_mntonname,path) == 0)
            return true;

    return false;
}

static bool ExportMount(iSCSIDiskManagerRef manager)
{
    if(manager->mounted)
        return true;

    // The NFS client connects to the export through its local socket
    // ("ticotsord" is the stream transport over local sockets)
    char options[PATH_MAX + 256];
    char source[PATH_MAX + 64];

    // The size of read and write requests is the unit in which the client
    // caches the files, that is, the disks: a read of a few kilobytes
    // fetches a whole unit, and a request that is not aligned to units
    // (none is: partitions start where they please) fetches one more.  A
    // small unit wastes little, and the client asks for many at a time.
    snprintf(options,sizeof(options),
             "vers=3,proto=ticotsord,mountport=%s,locallocks,nobrowse,noquota,nonegnamecache,"
             "intr,rwsize=65536,retrycnt=0,deadtimeout=45",manager->socketPath);

    snprintf(source,sizeof(source),"<%s>:%s",manager->socketPath,
             iSCSIBlockExportGetExportPath(manager->exportRef));

    const char * arguments[] = { kToolMountNFS, "-o", options, source, manager->mountPath, NULL };
    int status = RunTool(arguments,NULL);

    if(status != 0 && !IsMountPoint(manager->mountPath)) {
        iSCSILogError("unable to mount the disk export at %s (status %d)",manager->mountPath,status);
        return false;
    }

    manager->mounted = true;
    return true;
}

static void ExportUnmount(iSCSIDiskManagerRef manager)
{
    if(!manager->mounted)
        return;

    const char * arguments[] = { kToolUnmount, manager->mountPath, NULL };

    if(RunTool(arguments,NULL) != 0 && IsMountPoint(manager->mountPath)) {
        const char * forceArguments[] = { kToolUnmount, "-f", manager->mountPath, NULL };
        RunTool(forceArguments,NULL);
    }
    manager->mounted = false;
}

/*! Removes what an earlier instance of the daemon may have left behind if
 *  it did not exit cleanly: disks whose images live in the mount point of
 *  the export, and the (now dead) mount itself. */
static void CleanUpStaleState(iSCSIDiskManagerRef manager)
{
    if(!IsMountPoint(manager->mountPath))
        return;

    iSCSILogWarning("cleaning up after an unclean shutdown");

    // Find the disks whose images live in the mount point of the export
    char staleDisks[32][64];
    int staleCount = 0;

    if(ToolAvailable(kToolHdiutil)) {
        const char * arguments[] = { kToolHdiutil, "info", "-plist", NULL };
        CFDataRef output = NULL;

        if(RunTool(arguments,&output) == 0 && output) {
            CFPropertyListRef plist = CFPropertyListCreateWithData(kCFAllocatorDefault,output,
                                                                   kCFPropertyListImmutable,NULL,NULL);
            CFArrayRef images = NULL;

            if(plist && CFGetTypeID(plist) == CFDictionaryGetTypeID())
                images = CFDictionaryGetValue(plist,CFSTR("images"));

            for(CFIndex index = 0; images && CFGetTypeID(images) == CFArrayGetTypeID() &&
                                   index < CFArrayGetCount(images) && staleCount < 32; index++) {
                CFDictionaryRef image = CFArrayGetValueAtIndex(images,index);
                CFStringRef imagePath = NULL;
                CFArrayRef entities = NULL;
                char path[PATH_MAX];

                if(CFGetTypeID(image) != CFDictionaryGetTypeID() ||
                   !(imagePath = CFDictionaryGetValue(image,CFSTR("image-path"))) ||
                   CFGetTypeID(imagePath) != CFStringGetTypeID() ||
                   !CFStringGetFileSystemRepresentation(imagePath,path,sizeof(path)) ||
                   strncmp(path,manager->mountPath,strlen(manager->mountPath)) != 0 ||
                   path[strlen(manager->mountPath)] != '/')
                    continue;

                if(!(entities = CFDictionaryGetValue(image,CFSTR("system-entities"))) ||
                   CFGetTypeID(entities) != CFArrayGetTypeID())
                    continue;

                // Detaching the whole disk takes its partitions along
                char * bsdName = staleDisks[staleCount];
                bsdName[0] = '\0';

                for(CFIndex entityIndex = 0; entityIndex < CFArrayGetCount(entities); entityIndex++) {
                    CFDictionaryRef entity = CFArrayGetValueAtIndex(entities,entityIndex);
                    CFStringRef device = NULL;
                    char devicePath[64];

                    if(CFGetTypeID(entity) == CFDictionaryGetTypeID() &&
                       (device = CFDictionaryGetValue(entity,CFSTR("dev-entry"))) &&
                       CFGetTypeID(device) == CFStringGetTypeID() &&
                       CFStringGetCString(device,devicePath,sizeof(devicePath),kCFStringEncodingUTF8) &&
                       strncmp(devicePath,"/dev/",5) == 0 &&
                       (bsdName[0] == '\0' || strlen(devicePath + 5) < strlen(bsdName)))
                        strlcpy(bsdName,devicePath + 5,sizeof(staleDisks[0]));
                }

                if(bsdName[0] != '\0')
                    staleCount++;
            }

            if(plist)
                CFRelease(plist);
        }

        if(output)
            CFRelease(output);
    }

    // With the mount gone, I/O to the disks fails rather than waits for a
    // server that is not coming back; the disks then detach without delay
    const char * arguments[] = { kToolUnmount, "-f", manager->mountPath, NULL };
    RunTool(arguments,NULL);

    for(int index = 0; index < staleCount; index++) {
        iSCSILogWarning("detaching stale disk %s",staleDisks[index]);
        ImageDetach(staleDisks[index],NULL,manager->mountPath,true);
    }
}

/*! Composes the path of the image of a disk within the mounted export. */
static void DiskGetImagePath(iSCSIDiskManagerRef manager,const struct Disk * disk,char * path,size_t size)
{
    snprintf(path,size,"%s/%s",manager->mountPath,disk->exportName);
}

#pragma mark - Block export callbacks

static int DiskRead(void * info,uint64_t offset,uint32_t length,void * buffer)
{
    return iSCSILogicalUnitRead(info,offset,length,buffer);
}

static int DiskWrite(void * info,uint64_t offset,uint32_t length,const void * buffer,bool sync)
{
    return iSCSILogicalUnitWrite(info,offset,length,buffer,sync);
}

static int DiskFlush(void * info)
{
    return iSCSILogicalUnitFlush(info);
}

#pragma mark - Public interface

iSCSIDiskManagerRef iSCSIDiskManagerCreate(iSCSIHBAInterfaceRef interface)
{
    iSCSIDiskManagerRef manager = calloc(1,sizeof(struct __iSCSIDiskManager));
    char directory[PATH_MAX] = "";

    manager->interface = interface;
    pthread_mutex_init(&manager->operationLock,NULL);
    pthread_mutex_init(&manager->lock,NULL);

    char resolved[PATH_MAX];

    // Paths are compared with those that the system reports, which are
    // free of symbolic links
    if(iSCSIUtilsGetRuntimeDirectory(directory,sizeof(directory)) && realpath(directory,resolved))
        strlcpy(directory,resolved,sizeof(directory));

    if(directory[0] == '\0' ||
       !iSCSIUtilsGetSocketPath(kExportSocketName,manager->socketPath,sizeof(manager->socketPath)) ||
       (size_t)snprintf(manager->mountPath,sizeof(manager->mountPath),"%s/%s",
                        directory,kMountDirectoryName) >= sizeof(manager->mountPath)) {
        iSCSILogError("unable to set up the run-time directory");
        free(manager);
        return NULL;
    }

    CleanUpStaleState(manager);

    if(mkdir(manager->mountPath,0700) != 0 && errno != EEXIST) {
        iSCSILogError("unable to create %s: %s",manager->mountPath,strerror(errno));
        free(manager);
        return NULL;
    }

    if(!(manager->exportRef = iSCSIBlockExportCreate(manager->socketPath))) {
        iSCSILogError("unable to create the disk export at %s: %s",manager->socketPath,strerror(errno));
        free(manager);
        return NULL;
    }
    return manager;
}

void iSCSIDiskManagerRelease(iSCSIDiskManagerRef manager)
{
    if(!manager)
        return;

    for(SessionIdentifier sessionId = 0; sessionId < kiSCSIMaxSessions; sessionId++)
        iSCSIDiskManagerDetachSession(manager,sessionId,true);

    pthread_mutex_lock(&manager->operationLock);
    ExportUnmount(manager);
    pthread_mutex_unlock(&manager->operationLock);

    iSCSIBlockExportRelease(manager->exportRef);
    pthread_mutex_destroy(&manager->operationLock);
    pthread_mutex_destroy(&manager->lock);
    free(manager);
}

errno_t iSCSIDiskManagerAttachSession(iSCSIDiskManagerRef manager,
                                      SessionIdentifier sessionId,
                                      CFStringRef targetIQN,
                                      bool readOnly,
                                      bool syncWrites)
{
    if(!manager || !targetIQN)
        return EINVAL;

    iSCSILogicalUnitRef * units = NULL;
    UInt32 unitCount = 0;
    errno_t error = iSCSILogicalUnitScan(manager->interface,sessionId,&units,&unitCount);

    if(error) {
        iSCSILogError("unable to scan for logical units (sid %u): %s",sessionId,strerror(error));
        return error;
    }

    for(UInt32 index = 0; index < unitCount; index++)
        iSCSILogicalUnitSetDeferredFlush(units[index],!syncWrites && !readOnly);

    // Derive a file name for the disks of this target; only characters that
    // are unproblematic in file names are kept
    char targetName[160];

    if(!CFStringGetCString(targetIQN,targetName,sizeof(targetName),kCFStringEncodingASCII))
        strlcpy(targetName,"target",sizeof(targetName));

    for(char * cursor = targetName; *cursor; cursor++) {
        bool keep = (*cursor >= 'a' && *cursor <= 'z') || (*cursor >= 'A' && *cursor <= 'Z') ||
                    (*cursor >= '0' && *cursor <= '9') || *cursor == '.' || *cursor == '-';
        if(!keep)
            *cursor = '_';
    }

    pthread_mutex_lock(&manager->operationLock);

    for(UInt32 index = 0; index < unitCount; index++) {
        iSCSILogicalUnitRef unit = units[index];
        const iSCSILogicalUnitInfo * info = iSCSILogicalUnitGetInfo(unit);
        UInt64 size = info->blockCount * info->blockSize;

        struct Disk * disk = calloc(1,sizeof(struct Disk));
        disk->sessionId = sessionId;
        disk->unit = unit;
        disk->readOnly = readOnly || info->readOnly;
        snprintf(disk->exportName,sizeof(disk->exportName),"%s-lun%u.img",targetName,(unsigned)info->number);

        iSCSILogInfo("LUN %u: %s %s, %llu blocks of %u bytes%s%s (sid %u)",(unsigned)info->number,info->vendor,
                     info->product,(unsigned long long)info->blockCount,(unsigned)info->blockSize,
                     disk->readOnly ? ", read-only" : "",
                     !info->writeCache ? ", no write cache" :
                     info->forceUnitAccess ? ", write cache (bypassed by FUA)" : ", write cache (flushed after writes)",
                     sessionId);

        if(info->blockSize != 512)
            iSCSILogWarning("LUN %u has %u-byte blocks but is presented to the system with 512-byte blocks",
                            (unsigned)info->number,(unsigned)info->blockSize);

        iSCSIBlockExportCallbacks callbacks = {
            .info = unit,
            .read = DiskRead,
            .write = DiskWrite,
            .flush = DiskFlush
        };

        int exportError = iSCSIBlockExportAddDevice(manager->exportRef,disk->exportName,size,disk->readOnly,&callbacks);
        bool exported = (exportError == 0);

        if(!exported)
            snprintf(disk->error,sizeof(disk->error),"unable to export the logical unit: %s",strerror(exportError));
        else if(!ExportMount(manager))
            strlcpy(disk->error,"unable to mount the disk export",sizeof(disk->error));
        else {
            char imagePath[PATH_MAX + 256];
            DiskGetImagePath(manager,disk,imagePath,sizeof(imagePath));

            if(ImageAttach(imagePath,disk->readOnly,disk->bsdName,sizeof(disk->bsdName))) {
                iSCSILogInfo("LUN %u attached as %s (sid %u)",(unsigned)info->number,disk->bsdName,sessionId);
                MountVolumes(disk->bsdName);
            }
            else
                strlcpy(disk->error,"unable to attach the logical unit as a disk",sizeof(disk->error));
        }

        // A unit that could not be attached is kept so that the failure
        // can be reported, but it is not left in the export
        if(exported && disk->bsdName[0] == '\0')
            iSCSIBlockExportRemoveDevice(manager->exportRef,disk->exportName);

        pthread_mutex_lock(&manager->lock);
        struct Disk ** link = &manager->disks;

        while(*link)
            link = &(*link)->next;

        *link = disk;
        pthread_mutex_unlock(&manager->lock);
    }

    pthread_mutex_unlock(&manager->operationLock);
    free(units);
    return 0;
}

errno_t iSCSIDiskManagerDetachSession(iSCSIDiskManagerRef manager,
                                      SessionIdentifier sessionId,
                                      bool force)
{
    if(!manager)
        return EINVAL;

    errno_t error = 0;
    pthread_mutex_lock(&manager->operationLock);

    // Take the disks of the session off the list.  The list lock is not
    // held while disks are detached because that takes a while.
    struct Disk * disks = NULL, ** tail = &disks;

    pthread_mutex_lock(&manager->lock);
    struct Disk ** link = &manager->disks;

    while(*link) {
        struct Disk * disk = *link;

        if(disk->sessionId == sessionId) {
            *link = disk->next;
            disk->next = NULL;
            *tail = disk;
            tail = &disk->next;
        }
        else
            link = &disk->next;
    }
    pthread_mutex_unlock(&manager->lock);

    // Detach the disks, which unmounts their volumes first.  This fails
    // for a disk with a volume that is in use (unless forced).
    struct Disk * busy = NULL;

    for(struct Disk * disk = disks; disk && !busy; disk = disk->next) {
        if(disk->bsdName[0] == '\0')
            continue;

        char imagePath[PATH_MAX + 256];
        DiskGetImagePath(manager,disk,imagePath,sizeof(imagePath));

        if(ImageDetach(disk->bsdName,imagePath,NULL,force) || force) {
            iSCSILogInfo("%s detached (sid %u)",disk->bsdName,sessionId);
            disk->detached = true;
        }
        else
            busy = disk;
    }

    if(busy) {
        iSCSILogWarning("%s is in use and was not detached (sid %u)",busy->bsdName,sessionId);
        error = EBUSY;

        // The session stays as it was: bring back the disks that were
        // detached before the busy one was encountered
        for(struct Disk * disk = disks; disk; disk = disk->next) {
            if(!disk->detached)
                continue;

            char imagePath[PATH_MAX + 256];
            DiskGetImagePath(manager,disk,imagePath,sizeof(imagePath));
            disk->detached = false;

            if(ImageAttach(imagePath,disk->readOnly,disk->bsdName,sizeof(disk->bsdName)))
                MountVolumes(disk->bsdName);
            else {
                strlcpy(disk->error,"unable to attach the logical unit as a disk",sizeof(disk->error));
                iSCSIBlockExportRemoveDevice(manager->exportRef,disk->exportName);
            }
        }

        pthread_mutex_lock(&manager->lock);
        for(link = &manager->disks; *link; link = &(*link)->next);
        *link = disks;
        pthread_mutex_unlock(&manager->lock);
    }
    else {
        while(disks) {
            struct Disk * disk = disks;
            disks = disk->next;

            // Waits for I/O that is still in flight to complete
            if(disk->bsdName[0] != '\0' || disk->ejected)
                iSCSIBlockExportRemoveDevice(manager->exportRef,disk->exportName);

            iSCSILogicalUnitRelease(disk->unit);
            free(disk);
        }
    }

    pthread_mutex_lock(&manager->lock);
    bool empty = (manager->disks == NULL);
    pthread_mutex_unlock(&manager->lock);

    if(empty)
        ExportUnmount(manager);

    pthread_mutex_unlock(&manager->operationLock);
    return error;
}

static void DictionarySetCString(CFMutableDictionaryRef dictionary,CFStringRef key,const char * value)
{
    CFStringRef string = CFStringCreateWithCString(kCFAllocatorDefault,value,kCFStringEncodingUTF8);

    if(string) {
        CFDictionarySetValue(dictionary,key,string);
        CFRelease(string);
    }
}

static void DictionarySetNumber(CFMutableDictionaryRef dictionary,CFStringRef key,SInt64 value)
{
    CFNumberRef number = CFNumberCreate(kCFAllocatorDefault,kCFNumberSInt64Type,&value);
    CFDictionarySetValue(dictionary,key,number);
    CFRelease(number);
}

CFArrayRef iSCSIDiskManagerCopyDisksForSession(iSCSIDiskManagerRef manager,
                                               SessionIdentifier sessionId)
{
    CFMutableArrayRef disks = CFArrayCreateMutable(kCFAllocatorDefault,0,&kCFTypeArrayCallBacks);

    if(!manager)
        return disks;

    pthread_mutex_lock(&manager->lock);

    for(struct Disk * disk = manager->disks; disk; disk = disk->next) {
        if(disk->sessionId != sessionId)
            continue;

        // A disk that was ejected by other means is no longer ours; its
        // name may well belong to another disk by now
        if(disk->bsdName[0] != '\0') {
            char imagePath[PATH_MAX + 256];
            DiskGetImagePath(manager,disk,imagePath,sizeof(imagePath));

            if(!DiskBelongsToImage(disk->bsdName,imagePath,NULL)) {
                iSCSILogWarning("%s was ejected (sid %u)",disk->bsdName,sessionId);
                disk->bsdName[0] = '\0';
                disk->ejected = true;
                strlcpy(disk->error,"the disk was ejected; log out and in again to attach it",sizeof(disk->error));
            }
        }

        const iSCSILogicalUnitInfo * info = iSCSILogicalUnitGetInfo(disk->unit);
        CFMutableDictionaryRef dictionary = CFDictionaryCreateMutable(kCFAllocatorDefault,0,
                                                                      &kCFTypeDictionaryKeyCallBacks,
                                                                      &kCFTypeDictionaryValueCallBacks);
        DictionarySetNumber(dictionary,kiSCSIDiskLUN,info->number);
        DictionarySetCString(dictionary,kiSCSIDiskVendor,info->vendor);
        DictionarySetCString(dictionary,kiSCSIDiskProduct,info->product);
        DictionarySetCString(dictionary,kiSCSIDiskRevision,info->revision);
        DictionarySetCString(dictionary,kiSCSIDiskSerialNumber,info->serialNumber);
        DictionarySetNumber(dictionary,kiSCSIDiskBlockSize,info->blockSize);
        DictionarySetNumber(dictionary,kiSCSIDiskBlockCount,(SInt64)info->blockCount);
        CFDictionarySetValue(dictionary,kiSCSIDiskReadOnly,disk->readOnly ? kCFBooleanTrue : kCFBooleanFalse);

        if(disk->bsdName[0] != '\0')
            DictionarySetCString(dictionary,kiSCSIDiskBSDName,disk->bsdName);
        else if(disk->error[0] != '\0')
            DictionarySetCString(dictionary,kiSCSIDiskError,disk->error);

        CFArrayAppendValue(disks,dictionary);
        CFRelease(dictionary);
    }

    pthread_mutex_unlock(&manager->lock);
    return disks;
}

void iSCSIDiskManagerFlushAll(iSCSIDiskManagerRef manager)
{
    if(!manager)
        return;

    // Flushing may block while a session is being recovered, hence the
    // units are flushed without the lock.  They cannot go away meanwhile
    // because detaching is serialized by the operation lock.
    pthread_mutex_lock(&manager->operationLock);
    pthread_mutex_lock(&manager->lock);

    UInt32 count = 0;
    for(struct Disk * disk = manager->disks; disk; disk = disk->next)
        count++;

    iSCSILogicalUnitRef * units = calloc(count ? count : 1,sizeof(iSCSILogicalUnitRef));
    count = 0;

    for(struct Disk * disk = manager->disks; disk; disk = disk->next)
        if(disk->bsdName[0] != '\0')
            units[count++] = disk->unit;

    pthread_mutex_unlock(&manager->lock);

    for(UInt32 index = 0; index < count; index++)
        iSCSILogicalUnitFlush(units[index]);

    free(units);
    pthread_mutex_unlock(&manager->operationLock);
}
