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

#include "iSCSILog.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

static bool debugEnabled = false;
static pthread_mutex_t logMutex = PTHREAD_MUTEX_INITIALIZER;

void iSCSILogSetDebug(bool enable)
{
    debugEnabled = enable;
}

void iSCSILog(enum iSCSILogLevel level,const char * format,...)
{
    static const char * const names[] = { "error", "warning", "info", "debug" };

    if(level == kiSCSILogDebug && !debugEnabled)
        return;

    struct timeval now;
    struct tm local;
    char stamp[32];

    gettimeofday(&now,NULL);
    localtime_r(&now.tv_sec,&local);
    strftime(stamp,sizeof(stamp),"%Y-%m-%d %H:%M:%S",&local);

    va_list arguments;
    va_start(arguments,format);

    pthread_mutex_lock(&logMutex);
    fprintf(stderr,"%s.%03d [%s] ",stamp,(int)(now.tv_usec / 1000),names[level]);
    vfprintf(stderr,format,arguments);
    fputc('\n',stderr);
    fflush(stderr);
    pthread_mutex_unlock(&logMutex);

    va_end(arguments);
}
