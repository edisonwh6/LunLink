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

/*
 * A go-between that hands jobs to launchd.
 *
 * launchd puts a job down to whoever asked for it.  A job that the
 * application asked for is part of the application as far as the system
 * goes: the application stays in the Dock for as long as the job runs, even
 * once it has quit, and quitting it there puts an end to the job as well.
 * That is not what one wants of the iSCSI daemon, which carries the disks
 * of the user.
 *
 * Hence the application (as well as the command-line tool) has this helper
 * ask in its stead.  The helper is opened the way applications are, which
 * makes it one in its own right; it has no user interface and is gone again
 * in an instant.
 *
 *   usage: launcher <status file> <argument for launchctl>...
 *
 * The exit status of launchctl is written to the status file, since whoever
 * opens an application learns nothing about how it fared.
 */

#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern char ** environ;

int main(int argc,char * argv[])
{
    if(argc < 3)
        return 64;

    const char * statusPath = argv[1];
    posix_spawn_file_actions_t actions;
    pid_t pid;
    int status = 0, result = -1;

    // What follows the status file is for launchctl
    argv[1] = "/bin/launchctl";

    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions,STDIN_FILENO,"/dev/null",O_RDONLY,0);
    posix_spawn_file_actions_addopen(&actions,STDOUT_FILENO,"/dev/null",O_WRONLY,0);
    posix_spawn_file_actions_addopen(&actions,STDERR_FILENO,"/dev/null",O_WRONLY,0);

    if(posix_spawn(&pid,argv[1],&actions,NULL,argv + 1,environ) == 0) {
        while(waitpid(pid,&status,0) < 0 && errno == EINTR);

        if(WIFEXITED(status))
            result = WEXITSTATUS(status);
    }
    posix_spawn_file_actions_destroy(&actions);

    // The file appears in one piece, for whoever is waiting for it
    char temporaryPath[PATH_MAX];
    FILE * file = NULL;

    if((size_t)snprintf(temporaryPath,sizeof(temporaryPath),"%s.tmp",statusPath) < sizeof(temporaryPath) &&
       (file = fopen(temporaryPath,"w"))) {
        fprintf(file,"%d\n",result);
        fclose(file);
        rename(temporaryPath,statusPath);
    }
    return result == 0 ? 0 : 1;
}
