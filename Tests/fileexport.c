/*
 * Test tool: exports a regular file as a block device through
 * iSCSIBlockExport, which allows the NFS loopback and disk image attachment
 * to be exercised without an iSCSI target.
 *
 * usage: fileexport <socket-path> <backing-file> [device-name]
 */

#include "iSCSIBlockExport.h"

#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int backingFd = -1;
static volatile sig_atomic_t done = 0;

static int FileRead(void * info,uint64_t offset,uint32_t length,void * buffer)
{
    ssize_t count = pread(backingFd,buffer,length,(off_t)offset);
    return (count == (ssize_t)length) ? 0 : (count < 0 ? errno : EIO);
}

static int FileWrite(void * info,uint64_t offset,uint32_t length,const void * buffer,bool sync)
{
    ssize_t count = pwrite(backingFd,buffer,length,(off_t)offset);

    if(count != (ssize_t)length)
        return count < 0 ? errno : EIO;

    return (sync && fsync(backingFd) != 0) ? errno : 0;
}

static int FileFlush(void * info)
{
    return fsync(backingFd) != 0 ? errno : 0;
}

static void HandleSignal(int signal)
{
    done = 1;
}

int main(int argc,char * argv[])
{
    if(argc < 3) {
        fprintf(stderr,"usage: %s <socket-path> <backing-file> [device-name]\n",argv[0]);
        return 1;
    }

    struct stat status;

    if((backingFd = open(argv[2],O_RDWR)) < 0 || fstat(backingFd,&status) != 0) {
        perror(argv[2]);
        return 1;
    }

    iSCSIBlockExportRef exportRef = iSCSIBlockExportCreate(argv[1]);

    if(!exportRef) {
        perror(argv[1]);
        return 1;
    }

    iSCSIBlockExportCallbacks callbacks = {
        .read = FileRead,
        .write = FileWrite,
        .flush = FileFlush
    };

    int error = iSCSIBlockExportAddDevice(exportRef,(argc > 3) ? argv[3] : "disk.img",
                                          (uint64_t)status.st_size,false,&callbacks);
    if(error) {
        fprintf(stderr,"failed to add device: %s\n",strerror(error));
        return 1;
    }

    signal(SIGINT,HandleSignal);
    signal(SIGTERM,HandleSignal);

    printf("exporting %s (%lld bytes) at %s:%s\n",argv[2],(long long)status.st_size,
           iSCSIBlockExportGetSocketPath(exportRef),iSCSIBlockExportGetExportPath(exportRef));
    fflush(stdout);

    while(!done)
        pause();

    iSCSIBlockExportRelease(exportRef);
    return 0;
}
