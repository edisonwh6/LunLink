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

#ifndef __ISCSI_LOG_H__
#define __ISCSI_LOG_H__

#include <stdbool.h>

enum iSCSILogLevel {
    kiSCSILogError,
    kiSCSILogWarning,
    kiSCSILogInfo,
    kiSCSILogDebug
};

/*! Writes a message to the log of the daemon (a time-stamped line on the
 *  standard error stream, which launchd redirects to the log file). */
void iSCSILog(enum iSCSILogLevel level,const char * format,...) __attribute__((format(printf,2,3)));

/*! Enables or disables debug messages. */
void iSCSILogSetDebug(bool enable);

#define iSCSILogError(...)   iSCSILog(kiSCSILogError,__VA_ARGS__)
#define iSCSILogWarning(...) iSCSILog(kiSCSILogWarning,__VA_ARGS__)
#define iSCSILogInfo(...)    iSCSILog(kiSCSILogInfo,__VA_ARGS__)
#define iSCSILogDebug(...)   iSCSILog(kiSCSILogDebug,__VA_ARGS__)

#endif /* defined(__ISCSI_LOG_H__) */
