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

#include "iSCSISession.h"
#include "iSCSISessionManager.h"
#include "iSCSIPDUUser.h"
#include "iSCSIHBAInterface.h"
#include "iSCSIAuth.h"
#include "iSCSIQueryTarget.h"

#include "iSCSI.h"
#include "iSCSILog.h"

/*! Maximum number of key-value pairs supported by a dictionary that is used
 *  to produce the data section of text and login PDUs. */
const unsigned int kiSCSISessionMaxTextKeyValuePairs = 100;

// The values this initiator proposes for operational parameters.  These
// favor throughput and match what other software initiators ask for; the
// user-space HBA copes with whatever the target settles on.

/*! Largest data segment the initiator accepts in a single PDU. */
static const unsigned int kiSCSIProposedMaxRecvDataSegmentLength = 262144;

/*! Largest amount of unsolicited data per command. */
static const unsigned int kiSCSIProposedFirstBurstLength = 262144;

/*! Largest sequence of Data-In or solicited Data-Out PDUs. */
static const unsigned int kiSCSIProposedMaxBurstLength = 16776192;

/*! Maximum number of PDUs that make up a response outside of the full
 *  feature phase. */
static const int kiSCSISessionMaxResponsePDUs = 256;

/*! Helper function used during session negotiation. Returns true if the
 *  target declined to negotiate a key (in which case the default applies). */
static Boolean iSCSILVDeclined(CFStringRef rspStr)
{
    return CFStringCompare(rspStr,CFSTR("Irrelevant"),kCFCompareCaseInsensitive) == kCFCompareEqualTo ||
           CFStringCompare(rspStr,CFSTR("NotUnderstood"),kCFCompareCaseInsensitive) == kCFCompareEqualTo ||
           CFStringCompare(rspStr,CFSTR("Reject"),kCFCompareCaseInsensitive) == kCFCompareEqualTo;
}

/*! Helper function used during session negotiation.  Returns true if BOTH
 *  the command and the response strings are "Yes" */
Boolean iSCSILVGetEqual(CFStringRef cmdStr,CFStringRef rspStr)
{
    if(CFStringCompare(cmdStr,rspStr,kCFCompareCaseInsensitive) == kCFCompareEqualTo)
        return true;

    return false;
}

/*! Helper function used during session negotiation.  Returns true if BOTH
 *  the command and the response strings are "Yes" */
Boolean iSCSILVGetAnd(CFStringRef cmdStr,CFStringRef rspStr)
{
    CFComparisonResult cmd, rsp;
    cmd = CFStringCompare(cmdStr,kRFC3720_Value_Yes,kCFCompareCaseInsensitive);
    rsp = CFStringCompare(rspStr,kRFC3720_Value_Yes,kCFCompareCaseInsensitive);
    
    if(cmd == kCFCompareEqualTo && rsp == kCFCompareEqualTo)
        return true;
    
    return false;
}

/*! Helper function used during session negotiation.  Returns true if either
 *  one of the command or response strings are "Yes" */
Boolean iSCSILVGetOr(CFStringRef cmdStr,CFStringRef rspStr)
{
    if(CFStringCompare(cmdStr,kRFC3720_Value_Yes,kCFCompareCaseInsensitive) == kCFCompareEqualTo)
        return true;
    
    if(CFStringCompare(rspStr,kRFC3720_Value_Yes,kCFCompareCaseInsensitive) == kCFCompareEqualTo)
        return true;
    
    return false;
}

/*! Helper function used during session negotiation.  Converts values in 
 *  the command and response strings to numbers and returns the minimum. */
UInt32 iSCSILVGetMin(CFStringRef cmdStr, CFStringRef rspStr)
{
    // Convert string to unsigned integers
    UInt32 cmdInt = (UInt32)CFStringGetIntValue(cmdStr);
    UInt32 rspInt = (UInt32)CFStringGetIntValue(rspStr);
    
    // Compare & return minimum
    if(cmdInt < rspInt)
        return cmdInt;
    return rspInt;
}

/*! Helper function used during session negotiation.  Converts values in
 *  the command and response strings to numbers and returns the minimum. */
UInt32 iSCSILVGetMax(CFStringRef cmdStr, CFStringRef rspStr)
{
    // Convert string to unsigned integers
    UInt32 cmdInt = (UInt32)CFStringGetIntValue(cmdStr);
    UInt32 rspInt = (UInt32)CFStringGetIntValue(rspStr);
    
    // Compare & return minimum
    if(cmdInt > rspInt)
        return cmdInt;
    return rspInt;
}

/*! Helper function used during session negotiation.  Checks range of
 *  a particular value associated with a given key. */
Boolean iSCSILVRangeInvalid(UInt32 value,UInt32 min, UInt32 max)
{
    return (value < min || value > max);
}

/*! Helper function used by iSCSINegotiateSession to build a dictionary
 *  of session options (key-value pairs) that will be sent to the target.
 *  @param sessCfg a session configuration object.
 *  @param sessCmd a dictionary of key-value pairs used to negotiate session
 *  parameters during the iSCSI operational login negotiation. */
void iSCSINegotiateBuildSWDictNormal(iSCSISessionConfigRef sessCfg,
                                     CFMutableDictionaryRef sessCmd)
{
    CFStringRef value;
    
    // The user-space HBA runs a single connection per session
    CFDictionaryAddValue(sessCmd,kRFC3720_Key_MaxConnections,CFSTR("1"));
    
    // Ask to be allowed to send data along with commands
    CFDictionaryAddValue(sessCmd,kRFC3720_Key_InitialR2T,kRFC3720_Value_No);
    CFDictionaryAddValue(sessCmd,kRFC3720_Key_ImmediateData,kRFC3720_Value_Yes);
    
    value = CFStringCreateWithFormat(kCFAllocatorDefault,NULL,CFSTR("%u"),kiSCSIProposedMaxBurstLength);
    CFDictionaryAddValue(sessCmd,kRFC3720_Key_MaxBurstLength,value);
    CFRelease(value);
    
    value = CFStringCreateWithFormat(kCFAllocatorDefault,NULL,CFSTR("%u"),kiSCSIProposedFirstBurstLength);
    CFDictionaryAddValue(sessCmd,kRFC3720_Key_FirstBurstLength,value);
    CFRelease(value);
    
    value = CFStringCreateWithFormat(kCFAllocatorDefault,NULL,CFSTR("%u"),kRFC3720_MaxOutstandingR2T);
    CFDictionaryAddValue(sessCmd,kRFC3720_Key_MaxOutstandingR2T,value);
    CFRelease(value);
    
    CFDictionaryAddValue(sessCmd,kRFC3720_Key_DataPDUInOrder,kRFC3720_Value_Yes);
    CFDictionaryAddValue(sessCmd,kRFC3720_Key_DataSequenceInOrder,kRFC3720_Value_Yes);
}

/*! Helper function used by iSCSINegotiateSession to build a dictionary
 *  of session options (key-value pairs) that will be sent to the target.
 *  @param sessCfg a session configuration object.
 *  @param sessCmd a dictionary of key-value pairs used to negotiate session
 *  parameters during the iSCSI operational login negotiation. */
void iSCSINegotiateBuildSWDictCommon(iSCSISessionConfigRef sessCfg,
                                     CFMutableDictionaryRef sessCmd)
{
    CFStringRef value;
    
    // Add key-value pair for time to retain and time to wait
    value = CFStringCreateWithFormat(kCFAllocatorDefault,NULL,CFSTR("%u"),kRFC3720_DefaultTime2Wait);
    CFDictionaryAddValue(sessCmd,kRFC3720_Key_DefaultTime2Wait,value);
    CFRelease(value);
    
    value = CFStringCreateWithFormat(kCFAllocatorDefault,NULL,CFSTR("%u"),kRFC3720_DefaultTime2Retain);
    CFDictionaryAddValue(sessCmd,kRFC3720_Key_DefaultTime2Retain,value);
    CFRelease(value);
    
    // Only session-level error recovery is implemented
    CFDictionaryAddValue(sessCmd,kRFC3720_Key_ErrorRecoveryLevel,kRFC3720_Value_ErrorRecoveryLevelSession);
}

errno_t iSCSINegotiateParseSWDictCommon(iSCSISessionManagerRef managerRef,
                                        SessionIdentifier sessionId,
                                        CFDictionaryRef sessCmd,
                                        CFDictionaryRef sessRsp)

{
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    
    // Holds target value & comparison result for keys that we'll process
    CFStringRef targetRsp;
    
    // The defaults apply to keys that the target chose not to negotiate
    // (which is common for discovery sessions)
    UInt32 defaultTime2Retain = kRFC3720_DefaultTime2Retain;
    UInt32 defaultTime2Wait = kRFC3720_DefaultTime2Wait;
    UInt8 errorRecoveryLevel = kRFC3720_ErrorRecoveryLevel;
    
    // Grab minimum of default time 2 retain
    if(CFDictionaryGetValueIfPresent(sessRsp,kRFC3720_Key_DefaultTime2Retain,(void*)&targetRsp) &&
       !iSCSILVDeclined(targetRsp))
    {
        CFStringRef initCmd = CFDictionaryGetValue(sessCmd,kRFC3720_Key_DefaultTime2Retain);
        defaultTime2Retain = CFStringGetIntValue(targetRsp);

        // Range-check value...
        if(iSCSILVRangeInvalid(defaultTime2Retain,kRFC3720_DefaultTime2Retain_Min,kRFC3720_DefaultTime2Retain_Max))
            return ENOTSUP;
        
        defaultTime2Retain = iSCSILVGetMin(initCmd,targetRsp);
    }
    
    // Grab maximum of default time 2 wait
    if(CFDictionaryGetValueIfPresent(sessRsp,kRFC3720_Key_DefaultTime2Wait,(void*)&targetRsp) &&
       !iSCSILVDeclined(targetRsp))
    {
        CFStringRef initCmd = CFDictionaryGetValue(sessCmd,kRFC3720_Key_DefaultTime2Wait);
        defaultTime2Wait = CFStringGetIntValue(targetRsp);
        
        // Range-check value...
        if(iSCSILVRangeInvalid(defaultTime2Wait,kRFC3720_DefaultTime2Wait_Min,kRFC3720_DefaultTime2Wait_Max))
            return ENOTSUP;
        
        defaultTime2Wait = iSCSILVGetMax(initCmd,targetRsp);
    }

    // Grab minimum value of error recovery level
    if(CFDictionaryGetValueIfPresent(sessRsp,kRFC3720_Key_ErrorRecoveryLevel,(void*)&targetRsp) &&
       !iSCSILVDeclined(targetRsp))
    {
        CFStringRef initCmd = CFDictionaryGetValue(sessCmd,kRFC3720_Key_ErrorRecoveryLevel);
        UInt32 level = CFStringGetIntValue(targetRsp);
        
        // Range-check value...
        if(iSCSILVRangeInvalid(level,kRFC3720_ErrorRecoveryLevel_Min,kRFC3720_ErrorRecoveryLevel_Max))
            return ENOTSUP;
        
        errorRecoveryLevel = (UInt8)iSCSILVGetMin(initCmd,targetRsp);
    }
    
    iSCSIHBAInterfaceSetSessionParameter(hbaInterface,sessionId,kiSCSIHBASODefaultTime2Retain,
                                         &defaultTime2Retain,sizeof(defaultTime2Retain));
    iSCSIHBAInterfaceSetSessionParameter(hbaInterface,sessionId,kiSCSIHBASODefaultTime2Wait,
                                         &defaultTime2Wait,sizeof(defaultTime2Wait));
    iSCSIHBAInterfaceSetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOErrorRecoveryLevel,
                                         &errorRecoveryLevel,sizeof(errorRecoveryLevel));
    
    // The user-space HBA implements session-level recovery only
    if(errorRecoveryLevel != 0)
        return ENOTSUP;
    
    // Success
    return 0;
}

errno_t iSCSINegotiateParseSWDictNormal(iSCSISessionManagerRef managerRef,
                                        SessionIdentifier sessionId,
                                        CFDictionaryRef sessCmd,
                                        CFDictionaryRef sessRsp)

{
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    
    // Holds target value & comparison result for keys that we'll process
    CFStringRef targetRsp;
    
    // The values of RFC3720 apply to keys that were not negotiated
    UInt32 maxConnections = kRFC3720_MaxConnections;
    Boolean initialR2T = kRFC3720_InitialR2T;
    Boolean immediateData = kRFC3720_ImmediateData;
    Boolean dataPDUInOrder = kRFC3720_DataPDUInOrder;
    Boolean dataSequenceInOrder = kRFC3720_DataSequenceInOrder;
    UInt32 maxBurstLength = kRFC3720_MaxBurstLength;
    UInt32 firstBurstLength = kRFC3720_FirstBurstLength;
    UInt32 maxOutStandingR2T = kRFC3720_MaxOutstandingR2T;
    
    if(CFDictionaryGetValueIfPresent(sessRsp,kRFC3720_Key_MaxConnections,(void*)&targetRsp) &&
       !iSCSILVDeclined(targetRsp))
    {
        CFStringRef initCmd = CFDictionaryGetValue(sessCmd,kRFC3720_Key_MaxConnections);
        maxConnections = CFStringGetIntValue(targetRsp);
        
        // Range-check value...
        if(iSCSILVRangeInvalid(maxConnections,kRFC3720_MaxConnections_Min,kRFC3720_MaxConnections_Max))
            return ENOTSUP;
        
        maxConnections = iSCSILVGetMin(initCmd,targetRsp);
    }

    // Grab the OR for initialR2T command and response
    if(CFDictionaryGetValueIfPresent(sessRsp,kRFC3720_Key_InitialR2T,(void*)&targetRsp) &&
       !iSCSILVDeclined(targetRsp))
        initialR2T = iSCSILVGetOr(CFDictionaryGetValue(sessCmd,kRFC3720_Key_InitialR2T),targetRsp);
    
    // Grab the AND for immediate data command and response
    if(CFDictionaryGetValueIfPresent(sessRsp,kRFC3720_Key_ImmediateData,(void*)&targetRsp) &&
       !iSCSILVDeclined(targetRsp))
        immediateData = iSCSILVGetAnd(CFDictionaryGetValue(sessCmd,kRFC3720_Key_ImmediateData),targetRsp);

    // Get the OR of data PDU in order
    if(CFDictionaryGetValueIfPresent(sessRsp,kRFC3720_Key_DataPDUInOrder,(void*)&targetRsp) &&
       !iSCSILVDeclined(targetRsp))
        dataPDUInOrder = iSCSILVGetOr(CFDictionaryGetValue(sessCmd,kRFC3720_Key_DataPDUInOrder),targetRsp);
    
    // Get the OR of data sequence in order
    if(CFDictionaryGetValueIfPresent(sessRsp,kRFC3720_Key_DataSequenceInOrder,(void*)&targetRsp) &&
       !iSCSILVDeclined(targetRsp))
        dataSequenceInOrder = iSCSILVGetOr(CFDictionaryGetValue(sessCmd,kRFC3720_Key_DataSequenceInOrder),targetRsp);

    // Grab minimum of max burst length
    if(CFDictionaryGetValueIfPresent(sessRsp,kRFC3720_Key_MaxBurstLength,(void*)&targetRsp) &&
       !iSCSILVDeclined(targetRsp))
    {
        maxBurstLength = CFStringGetIntValue(targetRsp);
        
        // Range-check value...
        if(iSCSILVRangeInvalid(maxBurstLength,kRFC3720_MaxBurstLength_Min,kRFC3720_MaxBurstLength_Max))
            return ENOTSUP;
        
        maxBurstLength = iSCSILVGetMin(CFDictionaryGetValue(sessCmd,kRFC3720_Key_MaxBurstLength),targetRsp);
    }

    // Grab minimum of first burst length (the target does not respond to
    // this key if no unsolicited data can be sent in the first place)
    if(CFDictionaryGetValueIfPresent(sessRsp,kRFC3720_Key_FirstBurstLength,(void*)&targetRsp) &&
       !iSCSILVDeclined(targetRsp))
    {
        firstBurstLength = CFStringGetIntValue(targetRsp);
    
        // Range-check value...
        if(iSCSILVRangeInvalid(firstBurstLength,kRFC3720_FirstBurstLength_Min,kRFC3720_FirstBurstLength_Max))
            return ENOTSUP;
    
        firstBurstLength = iSCSILVGetMin(CFDictionaryGetValue(sessCmd,kRFC3720_Key_FirstBurstLength),targetRsp);
    }
    
    // The first burst cannot exceed the maximum burst
    if(firstBurstLength > maxBurstLength)
        firstBurstLength = maxBurstLength;

    // Grab minimum of max outstanding R2T
    if(CFDictionaryGetValueIfPresent(sessRsp,kRFC3720_Key_MaxOutstandingR2T,(void*)&targetRsp) &&
       !iSCSILVDeclined(targetRsp))
    {
        maxOutStandingR2T = CFStringGetIntValue(targetRsp);
        
        // Range-check value...
        if(iSCSILVRangeInvalid(maxOutStandingR2T,kRFC3720_MaxOutstandingR2T_Min,kRFC3720_MaxOutstandingR2T_Max))
            return ENOTSUP;
        
        maxOutStandingR2T = iSCSILVGetMin(CFDictionaryGetValue(sessCmd,kRFC3720_Key_MaxOutstandingR2T),targetRsp);
    }
    
    iSCSIHBAInterfaceSetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOMaxConnections,
                                         &maxConnections,sizeof(maxConnections));
    iSCSIHBAInterfaceSetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOInitialR2T,
                                         &initialR2T,sizeof(initialR2T));
    iSCSIHBAInterfaceSetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOImmediateData,
                                         &immediateData,sizeof(immediateData));
    iSCSIHBAInterfaceSetSessionParameter(hbaInterface,sessionId,kiSCSIHBASODataPDUInOrder,
                                         &dataPDUInOrder,sizeof(dataPDUInOrder));
    iSCSIHBAInterfaceSetSessionParameter(hbaInterface,sessionId,kiSCSIHBASODataSequenceInOrder,
                                         &dataSequenceInOrder,sizeof(dataSequenceInOrder));
    iSCSIHBAInterfaceSetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOMaxBurstLength,
                                         &maxBurstLength,sizeof(maxBurstLength));
    iSCSIHBAInterfaceSetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOFirstBurstLength,
                                         &firstBurstLength,sizeof(firstBurstLength));
    iSCSIHBAInterfaceSetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOMaxOutstandingR2T,
                                         &maxOutStandingR2T,sizeof(maxOutStandingR2T));
    
    // The HBA reassembles data by offset but generates it in order only
    if(!dataPDUInOrder || !dataSequenceInOrder)
        return ENOTSUP;
    
    // Success
    return 0;
}

/*! Helper function used by iSCSISessionNegotiateCW to build a dictionary
 *  of connection options (key-value pairs) that will be sent to the target.
 *  @param connCfg a connection configuration object.
 *  @param connCmd  a dictionary that is populated with key-value pairs that
 *  will be used to negotiate connection parameters. */
void iSCSINegotiateBuildCWDict(iSCSIConnectionConfigRef connCfg,
                               CFMutableDictionaryRef connCmd)
{
    // Setup digest options. Where a digest is desired the target is free to
    // decline it; the digest is then not used.
    if(iSCSIConnectionConfigGetDataDigest(connCfg))
        CFDictionaryAddValue(connCmd,kRFC3720_Key_DataDigest,CFSTR("CRC32C,None"));
    else
        CFDictionaryAddValue(connCmd,kRFC3720_Key_DataDigest,kRFC3720_Value_DataDigestNone);
    
    if(iSCSIConnectionConfigGetHeaderDigest(connCfg))
        CFDictionaryAddValue(connCmd,kRFC3720_Key_HeaderDigest,CFSTR("CRC32C,None"));
    else
        CFDictionaryAddValue(connCmd,kRFC3720_Key_HeaderDigest,kRFC3720_Value_HeaderDigestNone);
    
    // Setup maximum received data length
    CFStringRef maxRecvLength = CFStringCreateWithFormat(
        kCFAllocatorDefault,NULL,CFSTR("%u"),kiSCSIProposedMaxRecvDataSegmentLength);
    
    CFDictionaryAddValue(connCmd,kRFC3720_Key_MaxRecvDataSegmentLength,maxRecvLength);
    
    CFRelease(maxRecvLength);
}

/*! Helper function used by iSCSISessionNegotiateCW to parse a dictionary
 *  of connection options received from the target.  This function stores
 *  those options with the HBA.
 *  @param sessionId the session qualifier.
 *  @param connectionId the connection identifier.
 *  @param connCmd a dictionary of connection commands (key-value pairs)
 *  that were sent to the target.
 *  @param connRsp a dictionary of connection respones (key-value pairs)
 *  there were received from the target. */
errno_t iSCSINegotiateParseCWDict(iSCSISessionManagerRef managerRef,
                                  SessionIdentifier sessionId,
                                  ConnectionIdentifier connectionId,
                                  CFDictionaryRef connCmd,
                                  CFDictionaryRef connRsp)

{
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    
    // Holds target value & comparison result for keys that we'll process
    CFStringRef targetRsp;
    
    // A digest is used if the target selected it and it was among the
    // values that we offered
    Boolean useDataDigest = false, useHeaderDigest = false;
    
    if(CFDictionaryGetValueIfPresent(connRsp,kRFC3720_Key_DataDigest,(void*)&targetRsp) &&
       iSCSILVGetEqual(targetRsp,kRFC3720_Value_DataDigestCRC32C))
    {
        CFStringRef offered = CFDictionaryGetValue(connCmd,kRFC3720_Key_DataDigest);
        
        if(CFStringFind(offered,kRFC3720_Value_DataDigestCRC32C,kCFCompareCaseInsensitive).location == kCFNotFound)
            return ENOTSUP;
        
        useDataDigest = true;
    }
    
    if(CFDictionaryGetValueIfPresent(connRsp,kRFC3720_Key_HeaderDigest,(void*)&targetRsp) &&
       iSCSILVGetEqual(targetRsp,kRFC3720_Value_HeaderDigestCRC32C))
    {
        CFStringRef offered = CFDictionaryGetValue(connCmd,kRFC3720_Key_HeaderDigest);
        
        if(CFStringFind(offered,kRFC3720_Value_HeaderDigestCRC32C,kCFCompareCaseInsensitive).location == kCFNotFound)
            return ENOTSUP;
        
        useHeaderDigest = true;
    }
    
    // Digests take effect with the first PDU of the full feature phase,
    // i.e., once the login has been concluded
    iSCSIHBAInterfaceSetConnectionParameter(hbaInterface,sessionId,connectionId,
                                            kiSCSIHBACOUseDataDigest,
                                            &useDataDigest,sizeof(useDataDigest));
    
    iSCSIHBAInterfaceSetConnectionParameter(hbaInterface,sessionId,connectionId,
                                            kiSCSIHBACOUseHeaderDigest,
                                            &useHeaderDigest,sizeof(useHeaderDigest));
    
    // This option is declarative; we sent our length, and the target
    // must accept our choice as it is within a valid range
    UInt32 maxRecvDataSegmentLength = kiSCSIProposedMaxRecvDataSegmentLength;
    
    iSCSIHBAInterfaceSetConnectionParameter(hbaInterface,sessionId,connectionId,
                                            kiSCSIHBACOMaxRecvDataSegmentLength,
                                            &maxRecvDataSegmentLength,sizeof(maxRecvDataSegmentLength));
    
    // This is the declaration made by the target as to the length it can
    // receive.  Accept the value if it is within the RFC3720 allowed range
    // otherwise, terminate the connection...
    UInt32 maxSendDataSegmentLength = kRFC3720_MaxRecvDataSegmentLength;
    
    if(CFDictionaryGetValueIfPresent(connRsp,kRFC3720_Key_MaxRecvDataSegmentLength,(void*)&targetRsp) &&
       !iSCSILVDeclined(targetRsp))
    {
        UInt32 maxSendDataSegmentLengthRsp = CFStringGetIntValue(targetRsp);
        
        // Range-check value...
        if(iSCSILVRangeInvalid(maxSendDataSegmentLengthRsp,kRFC3720_MaxRecvDataSegmentLength_Min,kRFC3720_MaxRecvDataSegmentLength_Max))
            return ENOTSUP;
        
        maxSendDataSegmentLength = maxSendDataSegmentLengthRsp;
    }
    
    // Store value
    iSCSIHBAInterfaceSetConnectionParameter(hbaInterface,sessionId,connectionId,
                                            kiSCSIHBACOMaxSendDataSegmentLength,
                                            &maxSendDataSegmentLength,sizeof(maxSendDataSegmentLength));
    return 0;
}

errno_t iSCSINegotiateSession(iSCSISessionManagerRef managerRef,
                              iSCSIMutableTargetRef target,
                              SessionIdentifier sessionId,
                              ConnectionIdentifier connectionId,
                              iSCSISessionConfigRef sessCfg,
                              iSCSIConnectionConfigRef connCfg,
                              enum iSCSILoginStatusCode * statusCode)
{
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    
    // Create a new dictionary for connection parameters we want to send
    CFMutableDictionaryRef sessCmd = CFDictionaryCreateMutable(
                                            kCFAllocatorDefault,
                                            kiSCSISessionMaxTextKeyValuePairs,
                                            &kCFTypeDictionaryKeyCallBacks,
                                            &kCFTypeDictionaryValueCallBacks);
    
    // Add session parameters common to all session types
    iSCSINegotiateBuildSWDictCommon(sessCfg,sessCmd);
    
    // If target name is specified, this is a normal session; add parameters
    Boolean discoverySession = CFStringCompare(iSCSITargetGetIQN(target),kiSCSIUnspecifiedTargetIQN,0) == kCFCompareEqualTo;
    if(!discoverySession)
        iSCSINegotiateBuildSWDictNormal(sessCfg,sessCmd);
    
    // Add connection parameters
    iSCSINegotiateBuildCWDict(connCfg,sessCmd);
    
    // Create a dictionary to store query response
    CFMutableDictionaryRef sessRsp = CFDictionaryCreateMutable(
                                            kCFAllocatorDefault,
                                            kiSCSISessionMaxTextKeyValuePairs,
                                            &kCFTypeDictionaryKeyCallBacks,
                                            &kCFTypeDictionaryValueCallBacks);
    
    struct iSCSILoginQueryContext context;
    context.interface    = hbaInterface;
    context.sessionId    = sessionId;
    context.connectionId = connectionId;
    context.currentStage = kiSCSIPDULoginOperationalNegotiation;
    context.nextStage    = kiSCSIPDUFullFeaturePhase;
    context.targetSessionId = 0;

    enum iSCSIPDURejectCode rejectCode;
    
    // Send session-wide options to target and retreive a response dictionary
    errno_t error = iSCSISessionLoginQuery(&context,
                                           statusCode,
                                           &rejectCode,
                                           sessCmd,sessRsp);
    
    // Parse dictionaries and store session parameters if no I/O error occured
    if(*statusCode == kiSCSILoginSuccess) {
        
        // The TSIH was recorded by iSCSISessionLoginQuery since we're
        // entering the full-feature phase (see iSCSISessionLoginQuery documentation)
        iSCSIHBAInterfaceSetSessionParameter(hbaInterface,sessionId,
                                             kiSCSIHBASOTargetSessionId,
                                             &context.targetSessionId,sizeof(context.targetSessionId));
        if(!error)
            error = iSCSINegotiateParseSWDictCommon(managerRef,sessionId,sessCmd,sessRsp);
    
        if(!error && !discoverySession)
            error = iSCSINegotiateParseSWDictNormal(managerRef,sessionId,sessCmd,sessRsp);
    
        if(!error)
            error = iSCSINegotiateParseCWDict(managerRef,sessionId,connectionId,sessCmd,sessRsp);
    }
    
    // If no error and the target returned an alias save it...
    CFStringRef targetAlias;
    if(!error && CFDictionaryGetValueIfPresent(sessRsp,kRFC3720_Key_TargetAlias,(const void **)&targetAlias)) {
        iSCSITargetSetAlias(target,targetAlias);
    }
    
    CFRelease(sessCmd);
    CFRelease(sessRsp);
    return error;
}

/*! Helper function used to log out of connections and sessions. */
errno_t iSCSISessionLogoutCommon(iSCSISessionManagerRef managerRef,
                                 SessionIdentifier sessionId,
                                 ConnectionIdentifier connectionId,
                                 enum iSCSIPDULogoutReasons logoutReason,
                                 enum iSCSILogoutStatusCode * statusCode)
{
    if(sessionId >= kiSCSIInvalidSessionId || connectionId >= kiSCSIInvalidConnectionId)
        return EINVAL;
    
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    errno_t error = 0;
    
    // Create a logout PDU and log out of the session
    iSCSIPDULogoutReqBHS cmd = iSCSIPDULogoutReqBHSInit;
    cmd.reasonCode = logoutReason | kISCSIPDULogoutReasonCodeFlag;
    cmd.initiatorTaskTag = CFSwapInt32HostToBig(0xFFFFFFFE);
    
    if(logoutReason != kiSCSIPDULogoutCloseSession)
        cmd.CID = CFSwapInt16HostToBig((UInt16)connectionId);
    
    if((error = iSCSIHBAInterfaceSend(hbaInterface,sessionId,connectionId,(iSCSIPDUInitiatorBHS *)&cmd,NULL,0)))
        return error;
    
    // Get response from iSCSI portal.  PDUs that belong to tasks that were
    // in progress when the connection was deactivated may precede it.
    for(int count = 0; count < kiSCSISessionMaxResponsePDUs; count++) {
        iSCSIPDULogoutRspBHS rsp;
        void * data = NULL;
        size_t length = 0;
        
        if((error = iSCSIHBAInterfaceReceive(hbaInterface,sessionId,connectionId,(iSCSIPDUTargetBHS *)&rsp,&data,&length)))
            return error;
        
        iSCSIPDUDataRelease(&data);
        
        if(rsp.opCode == kiSCSIPDUOpCodeLogoutRsp) {
            *statusCode = rsp.response;
            return 0;
        }
    }
    return EIO;
}

/*! Creates a normal iSCSI session and returns a handle to the session. Users
 *  must call iSCSISessionClose to close this session and free resources.
 *  @param target specifies the target and connection parameters to use.
 *  @param portal specifies the portal to use for the new session.
 *  @param initiatorAuth specifies the initiator authentication parameters.
 *  @param targetAuth specifies the target authentication parameters.
 *  @param sessCfg the session configuration parameters to use.
 *  @param connCfg the connection configuration parameters to use.
 *  @param sessionId the new session identifier.
 *  @param connectionId the new connection identifier.
 *  @param statusCode iSCSI response code indicating operation status.
 *  @return an error code indicating whether the operation was successful. */
errno_t iSCSISessionLogin(iSCSISessionManagerRef managerRef,
                          iSCSIMutableTargetRef target,
                          iSCSIPortalRef portal,
                          iSCSIAuthRef initiatorAuth,
                          iSCSIAuthRef targetAuth,
                          iSCSISessionConfigRef sessCfg,
                          iSCSIConnectionConfigRef connCfg,
                          SessionIdentifier * sessionId,
                          ConnectionIdentifier * connectionId,
                          enum iSCSILoginStatusCode * statusCode)
{
    if(!target || !portal || !sessCfg || !connCfg || !sessionId || !connectionId ||
       !statusCode || !initiatorAuth || !targetAuth)
        return EINVAL;
    
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    errno_t error = 0;
    
    // Resolve the target address
    struct sockaddr_storage ssTarget, ssHost;
    
    if((error = iSCSIUtilsGetAddressForPortal(portal,&ssTarget,&ssHost)))
        return error;

    // Create a new session in the kernel.  This allocates session and
    // connection identifiers
    error = iSCSIHBAInterfaceCreateSession(hbaInterface,
                                           iSCSITargetGetIQN(target),
                                           iSCSIPortalGetAddress(portal),
                                           iSCSIPortalGetPort(portal),
                                           iSCSIPortalGetHostInterface(portal),
                                           &ssTarget,&ssHost,sessionId,connectionId);
    
    // If the portal could not be reached or sessions are maxed out, quit
    if(error)
        return error;
    
    if(*sessionId == kiSCSIInvalidSessionId || *connectionId == kiSCSIInvalidConnectionId)
        return EAGAIN;

    // If no error, authenticate (negotiate security parameters)
    if(!error) {
        error = iSCSIAuthNegotiate(managerRef,target,initiatorAuth,targetAuth,
                                   *sessionId,*connectionId,statusCode);
    }

    // Negotiate session & connection parameters
    if(!error && *statusCode == kiSCSILoginSuccess)
        error = iSCSINegotiateSession(managerRef,target,*sessionId,*connectionId,sessCfg,connCfg,statusCode);

    // Only activate connections for use by the HBA if no errors have occurred
    // and the session is not a discovery session
    if(error || *statusCode != kiSCSILoginSuccess) {
        iSCSIHBAInterfaceReleaseSession(hbaInterface,*sessionId);
        *sessionId = kiSCSIInvalidSessionId;
        *connectionId = kiSCSIInvalidConnectionId;
    }
    else if(CFStringCompare(iSCSITargetGetIQN(target),kiSCSIUnspecifiedTargetIQN,0) != kCFCompareEqualTo)
        error = iSCSIHBAInterfaceActivateConnection(hbaInterface,*sessionId,*connectionId);
    
    return error;
}

/*! Closes the iSCSI session by deactivating and removing all connections. Any
 *  pending or current data transfers are aborted. This function may be called 
 *  on a session with one or more connections that are either inactive or 
 *  active. The session identifier is released and may be reused by other
 *  sessions the future.
 *  @param sessionId the session to release.
 *  @return an error code indicating whether the operation was successful. */
errno_t iSCSISessionLogout(iSCSISessionManagerRef managerRef,
                           SessionIdentifier sessionId,
                           enum iSCSILogoutStatusCode * statusCode)
{
    if(sessionId == kiSCSIInvalidSessionId)
        return  EINVAL;
    
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    errno_t error = 0;
    
    if(statusCode)
        *statusCode = kiSCSILogoutInvalidStatusCode;

    // First deactivate all of the connections
    if((error = iSCSIHBAInterfaceDeactivateAllConnections(hbaInterface,sessionId)))
        return error;
    
    // Grab a handle to any connection so we can logout of the session. A
    // session that lost its connection has no one to tell about the logout.
    ConnectionIdentifier connectionId = kiSCSIInvalidConnectionId;
    enum iSCSILogoutStatusCode logoutStatus = kiSCSILogoutInvalidStatusCode;
    
    if(!iSCSIHBAInterfaceGetConnection(hbaInterface,sessionId,&connectionId)) {
        errno_t logoutError = iSCSISessionLogoutCommon(managerRef,sessionId,connectionId,
                                                       kiSCSIPDULogoutCloseSession,&logoutStatus);
        if(logoutError)
            iSCSILogWarning("no response to logout request (sid %u): %s",sessionId,strerror(logoutError));
        else if(statusCode)
            *statusCode = logoutStatus;
    }

    // Release all of the connections by releasing the session
    iSCSIHBAInterfaceReleaseSession(hbaInterface,sessionId);
    
    return error;
}

/*! Re-establishes a session whose connection was lost: connects to the
 *  specified portal and logs in anew.  The identity of the session (and
 *  therefore its logical units) is retained, and so are the SCSI tasks that
 *  were held back when the connection was lost; the target on its part
 *  replaces whatever it may remember of the old session (reinstatement).
 *  @param managerRef an instance of an iSCSISessionManagerRef.
 *  @param sessionId the session to recover.
 *  @param portal specifies the portal to use.
 *  @param initiatorAuth specifies the initiator authentication parameters.
 *  @param targetAuth specifies the target authentication parameters.
 *  @param sessCfg the session configuration parameters to use.
 *  @param connCfg the connection configuration parameters to use.
 *  @param statusCode iSCSI response code indicating operation status.
 *  @return an error code indicating whether the operation was successful. */
errno_t iSCSISessionRecover(iSCSISessionManagerRef managerRef,
                            SessionIdentifier sessionId,
                            iSCSIPortalRef portal,
                            iSCSIAuthRef initiatorAuth,
                            iSCSIAuthRef targetAuth,
                            iSCSISessionConfigRef sessCfg,
                            iSCSIConnectionConfigRef connCfg,
                            enum iSCSILoginStatusCode * statusCode)
{
    if(!portal || !sessCfg || !connCfg || !statusCode || !initiatorAuth || !targetAuth ||
       sessionId == kiSCSIInvalidSessionId)
        return EINVAL;
    
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    *statusCode = kiSCSILoginInvalidStatusCode;
    
    iSCSITargetRef targetTemp = iSCSISessionCopyTargetForId(managerRef,sessionId);
    
    if(!targetTemp)
        return ENOENT;
    
    iSCSIMutableTargetRef target = iSCSITargetCreateMutableCopy(targetTemp);
    iSCSITargetRelease(targetTemp);
    
    // Do away with the remains of the connection(s) that failed
    ConnectionIdentifier connectionIds[kiSCSIMaxConnectionsPerSession];
    UInt32 connectionCount = 0;
    
    if(!iSCSIHBAInterfaceGetConnectionIds(hbaInterface,sessionId,connectionIds,&connectionCount))
        for(UInt32 idx = 0; idx < connectionCount; idx++)
            iSCSIHBAInterfaceReleaseConnection(hbaInterface,sessionId,connectionIds[idx]);
    
    // Resolve the target address
    struct sockaddr_storage ssTarget, ssHost;
    errno_t error = iSCSIUtilsGetAddressForPortal(portal,&ssTarget,&ssHost);
    
    ConnectionIdentifier connectionId = kiSCSIInvalidConnectionId;
    
    if(!error)
        error = iSCSIHBAInterfaceCreateConnection(hbaInterface,sessionId,
                                                  iSCSIPortalGetAddress(portal),
                                                  iSCSIPortalGetPort(portal),
                                                  iSCSIPortalGetHostInterface(portal),
                                                  &ssTarget,&ssHost,&connectionId);
    if(error) {
        iSCSITargetRelease(target);
        return error;
    }
    
    // This is a leading login: the target assigns a new session handle
    TargetSessionIdentifier targetSessionId = 0;
    iSCSIHBAInterfaceSetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOTargetSessionId,
                                         &targetSessionId,sizeof(targetSessionId));
    
    error = iSCSIAuthNegotiate(managerRef,target,initiatorAuth,targetAuth,sessionId,connectionId,statusCode);
    
    if(!error && *statusCode == kiSCSILoginSuccess)
        error = iSCSINegotiateSession(managerRef,target,sessionId,connectionId,sessCfg,connCfg,statusCode);
    
    // Tasks resume as soon as the connection is activated
    if(!error && *statusCode == kiSCSILoginSuccess)
        error = iSCSIHBAInterfaceActivateConnection(hbaInterface,sessionId,connectionId);
    else {
        iSCSIHBAInterfaceReleaseConnection(hbaInterface,sessionId,connectionId);
        
        if(!error)
            error = EAUTH;
    }
    
    iSCSITargetRelease(target);
    return error;
}

/*! Context used while parsing the response to a SendTargets request. */
struct iSCSISendTargetsParseContext {
    
    /*! The target that subsequent addresses belong to. */
    CFStringRef targetIQN;
};

/*! Callback function used by iSCSIQueryPortalForTargets to parse discovery
 *  data into an iSCSIDiscoveryRec object. */
void iSCSIPDUDataParseToDiscoveryRecCallback(void * keyContainer,CFStringRef key,
                                             void * valContainer,CFStringRef val)
{
    struct iSCSISendTargetsParseContext * context = keyContainer;
    iSCSIMutableDiscoveryRecRef discoveryRec = (iSCSIMutableDiscoveryRecRef)(valContainer);
    
    // If the discovery data has a "TargetName = xxx" field, we're starting
    // a record for a new target
    if(CFStringCompare(key,kRFC3720_Key_TargetName,0) == kCFCompareEqualTo)
    {
        if(context->targetIQN)
            CFRelease(context->targetIQN);
        
        context->targetIQN = CFStringCreateCopy(kCFAllocatorDefault,val);
        iSCSIDiscoveryRecAddTarget(discoveryRec,context->targetIQN);
    }
    // Otherwise we're dealing with a portal entry. Per RFC3720, this is
    // of the form "TargetAddress = <address>[:<port>][,<portalGroupTag>]";
    // a target may have any number of them
    else if(CFStringCompare(key,kRFC3720_Key_TargetAddress,0) == kCFCompareEqualTo && context->targetIQN)
    {
        // Split the value string to extract the portal group tag
        CFArrayRef targetAddress = CFStringCreateArrayBySeparatingStrings(kCFAllocatorDefault,val,CFSTR(","));
        CFStringRef addressAndPort = CFArrayGetValueAtIndex(targetAddress,0);
        CFStringRef portalGroupTag = (CFArrayGetCount(targetAddress) > 1) ? CFArrayGetValueAtIndex(targetAddress,1) : CFSTR("1");
        
        CFStringRef address = NULL, port = NULL;
        CFIndex length = CFStringGetLength(addressAndPort);
        
        // IPv6 addresses are enclosed in brackets since they contain colons
        CFRange closeBracket = CFStringFind(addressAndPort,CFSTR("]"),kCFCompareBackwards);
        
        if(CFStringHasPrefix(addressAndPort,CFSTR("[")) && closeBracket.location != kCFNotFound) {
            address = CFStringCreateWithSubstring(kCFAllocatorDefault,addressAndPort,CFRangeMake(1,closeBracket.location - 1));
            
            if(closeBracket.location + 2 < length)
                port = CFStringCreateWithSubstring(kCFAllocatorDefault,addressAndPort,
                                                   CFRangeMake(closeBracket.location + 2,length - (closeBracket.location + 2)));
        }
        else {
            CFRange sepRange = CFStringFind(addressAndPort,CFSTR(":"),kCFCompareBackwards);
            
            if(sepRange.location == kCFNotFound)
                address = CFStringCreateCopy(kCFAllocatorDefault,addressAndPort);
            else {
                address = CFStringCreateWithSubstring(kCFAllocatorDefault,addressAndPort,CFRangeMake(0,sepRange.location));
                port = CFStringCreateWithSubstring(kCFAllocatorDefault,addressAndPort,
                                                   CFRangeMake(sepRange.location + 1,length - (sepRange.location + 1)));
            }
        }
        
        if(address && CFStringGetLength(address) > 0) {
            iSCSIMutablePortalRef portal = iSCSIPortalCreateMutable();
            iSCSIPortalSetAddress(portal,address);
            iSCSIPortalSetPort(portal,(port && CFStringGetLength(port) > 0) ? port : kiSCSIDefaultPort);
            iSCSIPortalSetHostInterface(portal,kiSCSIDefaultHostInterface);
            
            iSCSIDiscoveryRecAddPortal(discoveryRec,context->targetIQN,portalGroupTag,portal);
            iSCSIPortalRelease(portal);
        }
        
        if(port)
            CFRelease(port);
        if(address)
            CFRelease(address);
        CFRelease(targetAddress);
    }
}

/*! Queries a portal for available targets (utilizes iSCSI SendTargets).
 *  @param portal the iSCSI portal to query.
 *  @param auth specifies the authentication parameters to use.
 *  @param discoveryRec a discovery record, containing the query results.
 *  @param statusCode iSCSI response code indicating operation status.
 *  @return an error code indicating whether the operation was successful. */
errno_t iSCSIQueryPortalForTargets(iSCSISessionManagerRef managerRef,
                                   iSCSIPortalRef portal,
                                   iSCSIAuthRef initiatorAuth,
                                   iSCSIMutableDiscoveryRecRef * discoveryRec,
                                   enum iSCSILoginStatusCode * statusCode)
{
    if(!portal || !discoveryRec || !statusCode)
        return EINVAL;
    
    *discoveryRec = NULL;
    *statusCode = kiSCSILoginInvalidStatusCode;
    
    // Create a discovery session to the portal (empty target name is assumed to
    // be a discovery session)
    iSCSIMutableTargetRef target = iSCSITargetCreateMutable();
    iSCSITargetSetIQN(target,kiSCSIUnspecifiedTargetIQN);
    
    SessionIdentifier sessionId = kiSCSIInvalidSessionId;
    ConnectionIdentifier connectionId = kiSCSIInvalidConnectionId;
    
    iSCSIMutableSessionConfigRef sessCfg = iSCSISessionConfigCreateMutable();
    iSCSIMutableConnectionConfigRef connCfg = iSCSIConnectionConfigCreateMutable();

    iSCSIAuthRef targetAuth = iSCSIAuthCreateNone();

    errno_t error = iSCSISessionLogin(managerRef,target,portal,initiatorAuth,targetAuth,
                                      sessCfg,connCfg,&sessionId,
                                      &connectionId,statusCode);

    iSCSIAuthRelease(targetAuth);
    iSCSITargetRelease(target);
    iSCSISessionConfigRelease(sessCfg);
    iSCSIConnectionConfigRelease(connCfg);
    
    if(error || *statusCode != kiSCSILoginSuccess)
        return error;
    
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    
    // The response may arrive in several PDUs, and a key-value pair may be
    // split between them.  Hence the text is collected first, parsed later.
    CFMutableDataRef text = CFDataCreateMutable(kCFAllocatorDefault,0);
    UInt32 targetTransferTag = kiSCSIPDUTargetTransferTagReserved;
    Boolean firstRequest = true, complete = false;
    
    for(int count = 0; count < kiSCSISessionMaxResponsePDUs && !error && !complete; count++)
    {
        // The request names the targets we're after ("All"); if the target
        // indicates that there is more to come, empty requests fetch the rest
        iSCSIPDUTextReqBHS cmd = iSCSIPDUTextReqBHSInit;
        cmd.textReqStageFlags = kiSCSIPDUTextReqFinalFlag;
        cmd.initiatorTaskTag = CFSwapInt32HostToBig(1);
        cmd.targetTransferTag = targetTransferTag;
        
        void * data = NULL;
        size_t length = 0;
        
        if(firstRequest) {
            CFMutableDictionaryRef textCmd = CFDictionaryCreateMutable(kCFAllocatorDefault,0,
                                                                       &kCFTypeDictionaryKeyCallBacks,
                                                                       &kCFTypeDictionaryValueCallBacks);
            CFDictionarySetValue(textCmd,kRFC3720_Key_SendTargets,kRFC3720_Value_SendTargetsAll);
            iSCSIPDUDataCreateFromDict(textCmd,&data,&length);
            CFRelease(textCmd);
            firstRequest = false;
        }
        
        error = iSCSIHBAInterfaceSend(hbaInterface,sessionId,connectionId,(iSCSIPDUInitiatorBHS *)&cmd,data,length);
        iSCSIPDUDataRelease(&data);
        
        if(error)
            break;
        
        iSCSIPDUTextRspBHS rsp;
        
        if((error = iSCSIHBAInterfaceReceive(hbaInterface,sessionId,connectionId,(iSCSIPDUTargetBHS *)&rsp,&data,&length)))
            break;
        
        if(rsp.opCode == kiSCSIPDUOpCodeTextRsp) {
            if(data && length > 0)
                CFDataAppendBytes(text,data,length);
            
            targetTransferTag = rsp.targetTransferTag;
            complete = !(rsp.textReqStageBits & kiSCSIPDUTextReqContinueFlag);
        }
        // For this case some other kind of PDU or invalid data was received
        else
            error = EINVAL;
        
        iSCSIPDUDataRelease(&data);
    }
    
    if(!error && !complete)
        error = EMSGSIZE;
    
    enum iSCSILogoutStatusCode logoutStatusCode;
    iSCSISessionLogout(managerRef,sessionId,&logoutStatusCode);
    
    if(error) {
        CFRelease(text);
        return error;
    }
    
    *discoveryRec = iSCSIDiscoveryRecCreateMutable();
    
    struct iSCSISendTargetsParseContext parseContext = { NULL };
    iSCSIPDUDataParseCommon((void *)CFDataGetBytePtr(text),CFDataGetLength(text),&parseContext,*discoveryRec,
                            &iSCSIPDUDataParseToDiscoveryRecCallback);
    
    if(parseContext.targetIQN)
        CFRelease(parseContext.targetIQN);
    
    CFRelease(text);

    // Per RFC3720, the "TargetAddress" key is optional in a SendTargets
    // discovery operation.  Therefore, certain targets may respond with
    // a "TargetName" only, implying that the portal used for discovery
    // can also be used for access to the target.  For these targets, we must
    // add the discovery portal to the discovery record.
    CFArrayRef targets;

    if(!(targets = iSCSIDiscoveryRecCreateArrayOfTargets(*discoveryRec)))
       return error;

    for(CFIndex idx = 0; idx < CFArrayGetCount(targets); idx++) {
        CFStringRef targetIQN;

        if(!(targetIQN = CFArrayGetValueAtIndex(targets,idx)))
            continue;

        CFArrayRef portalGroups = iSCSIDiscoveryRecCreateArrayOfPortalGroupTags(
            *discoveryRec,targetIQN);

        // If at least one portal group exists then we can skip this target...
        if(CFArrayGetCount(portalGroups) != 0) {
            CFRelease(portalGroups);
            continue;
        }

        // Otherwise we need to create a new portal group and add the discovery
        // portal for this target
        iSCSIDiscoveryRecAddPortal(*discoveryRec,targetIQN,CFSTR("0"),portal);
        CFRelease(portalGroups);
    }

    CFRelease(targets);
    return error;
}

/*! Retrieves a list of targets available from a give portal.
 *  @param portal the iSCSI portal to look for targets.
 *  @param initiatorAuth specifies the initiator authentication parameters.
 *  @param statusCode iSCSI response code indicating operation status.
 *  @return an error code indicating whether the operation was successful. */
errno_t iSCSIQueryTargetForAuthMethod(iSCSISessionManagerRef managerRef,
                                      iSCSIPortalRef portal,
                                      CFStringRef targetIQN,
                                      enum iSCSIAuthMethods * authMethod,
                                      enum iSCSILoginStatusCode * statusCode)
{
    if(!portal || !authMethod)
        return EINVAL;

    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    errno_t error = 0;
    
    // Resolve information about the target
    struct sockaddr_storage ssTarget, ssHost;
    
    if((error = iSCSIUtilsGetAddressForPortal(portal,&ssTarget,&ssHost)))
        return error;
    
    // Create a discovery session to the portal
    iSCSIMutableTargetRef target = iSCSITargetCreateMutable();
    iSCSITargetSetIQN(target,targetIQN);
    
    // Create session (incl. qualifier) and a new connection (incl. Id)
    // Reset qualifier and connection ID by default
    SessionIdentifier sessionId;
    ConnectionIdentifier connectionId;
    error = iSCSIHBAInterfaceCreateSession(hbaInterface,
                                           targetIQN,
                                     iSCSIPortalGetAddress(portal),
                                     iSCSIPortalGetPort(portal),
                                     iSCSIPortalGetHostInterface(portal),
                                     &ssTarget,
                                     &ssHost,
                                     &sessionId,
                                     &connectionId);
    
    // If no error, authenticate (negotiate security parameters)
    if(!error) {
        error = iSCSIAuthInterrogate(managerRef,
                                     target,
                                     sessionId,
                                     connectionId,
                                     authMethod,
                                     statusCode);

        iSCSIHBAInterfaceReleaseSession(hbaInterface,sessionId);
    }
    iSCSITargetRelease(target);
    
    return error;
}

/*! Gets the session identifier associated with the specified target.
 *  @param targetIQN the name of the target.
 *  @return the session identiifer. */
SessionIdentifier iSCSISessionGetSessionIdForTarget(iSCSISessionManagerRef managerRef,
                                             CFStringRef targetIQN)
{
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    return iSCSIHBAInterfaceGetSessionIdForTargetIQN(hbaInterface,targetIQN);
}

/*! Gets the connection identifier associated with the specified portal.
 *  @param sessionId the session identifier.
 *  @param portal the portal connected on the specified session.
 *  @return the associated connection identifier. */
ConnectionIdentifier iSCSISessionGetConnectionIdForPortal(iSCSISessionManagerRef managerRef,
                                                   SessionIdentifier sessionId,
                                                   iSCSIPortalRef portal)
{
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    return iSCSIHBAInterfaceGetConnectionIdForPortalAddress(hbaInterface,sessionId,iSCSIPortalGetAddress(portal));
}

/*! Gets an array of session identifiers for each session.
 *  @param sessionIds an array of session identifiers.
 *  @return an array of session identifiers. */
CFArrayRef iSCSISessionCopyArrayOfSessionIds(iSCSISessionManagerRef managerRef)
{
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    SessionIdentifier sessionIds[kiSCSIMaxSessions];
    UInt16 sessionCount;

    if(iSCSIHBAInterfaceGetSessionIds(hbaInterface,sessionIds,&sessionCount))
        return NULL;
    
    // The identifiers are stored in the array in place of pointers
    const void * values[kiSCSIMaxSessions];
    
    for(UInt16 idx = 0; idx < sessionCount; idx++)
        values[idx] = (const void *)(uintptr_t)sessionIds[idx];
    
    return CFArrayCreate(kCFAllocatorDefault,values,sessionCount,NULL);
}

/*! Gets an array of connection identifiers for each session.
 *  @param sessionId session identifier.
 *  @return an array of connection identifiers. */
CFArrayRef iSCSISessionCopyArrayOfConnectionIds(iSCSISessionManagerRef managerRef,
                                            SessionIdentifier sessionId)
{
    if(sessionId == kiSCSIInvalidSessionId)
        return NULL;
    
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    ConnectionIdentifier connectionIds[kiSCSIMaxConnectionsPerSession];
    UInt32 connectionCount;
    
    if(iSCSIHBAInterfaceGetConnectionIds(hbaInterface,sessionId,connectionIds,&connectionCount))
        return NULL;

    // The identifiers are stored in the array in place of pointers
    const void * values[kiSCSIMaxConnectionsPerSession];
    
    for(UInt32 idx = 0; idx < connectionCount; idx++)
        values[idx] = (const void *)(uintptr_t)connectionIds[idx];
    
    return CFArrayCreate(kCFAllocatorDefault,values,connectionCount,NULL);
}

/*! Creates a target object for the specified session.
 *  @param sessionId the session identifier.
 *  @return target the target object. */
iSCSITargetRef iSCSISessionCopyTargetForId(iSCSISessionManagerRef managerRef,SessionIdentifier sessionId)
{
    if(sessionId == kiSCSIInvalidSessionId)
        return NULL;
    
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    CFStringRef targetIQN = iSCSIHBAInterfaceCreateTargetIQNForSessionId(hbaInterface,sessionId);
    
    if(!targetIQN)
        return NULL;
    
    iSCSIMutableTargetRef target = iSCSITargetCreateMutable();
    iSCSITargetSetIQN(target,targetIQN);

    CFRelease(targetIQN);
    
    return target;
}

/*! Creates a connection object for the specified connection.
 *  @param sessionId the session identifier.
 *  @param connectionId the connection identifier.
 *  @return portal information about the portal. */
iSCSIPortalRef iSCSISessionCopyPortalForConnectionId(iSCSISessionManagerRef managerRef,
                                                SessionIdentifier sessionId,
                                                ConnectionIdentifier connectionId)
                                      
{
    if(sessionId == kiSCSIInvalidSessionId || connectionId == kiSCSIInvalidConnectionId)
        return NULL;
    
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    CFStringRef address,port,hostInterface;
    
    if(!(address = iSCSIHBAInterfaceCreatePortalAddressForConnectionId(hbaInterface,sessionId,connectionId)))
        return NULL;

    if(!(port = iSCSIHBAInterfaceCreatePortalPortForConnectionId(hbaInterface,sessionId,connectionId)))
    {
        CFRelease(address);
        return NULL;
    }
    
    if(!(hostInterface = iSCSIHBAInterfaceCreateHostInterfaceForConnectionId(hbaInterface,sessionId,connectionId)))
    {
        CFRelease(address);
        CFRelease(port);
        return NULL;
    }
    
    iSCSIMutablePortalRef portal = iSCSIPortalCreateMutable();
    iSCSIPortalSetAddress(portal,address);
    iSCSIPortalSetPort(portal,port);
    iSCSIPortalSetHostInterface(portal,hostInterface);
    CFRelease(address);
    CFRelease(port);
    CFRelease(hostInterface);
    
    return portal;
}

/*! Creates a dictionary of session parameters for the session associated with
 *  the specified target, if one exists.
 *  @param handle a handle to a daemon connection.
 *  @param target the target to check for associated sessions to generate
 *  a dictionary of session parameters.
 *  @return a dictionary of session properties. */
CFDictionaryRef iSCSISessionCopyCFPropertiesForTarget(iSCSISessionManagerRef managerRef,
                                                  iSCSITargetRef target)
{
    if(!target)
        return NULL;

    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    CFDictionaryRef dictionary = NULL;
    
    SessionIdentifier sessionId = iSCSISessionGetSessionIdForTarget(managerRef,iSCSITargetGetIQN(target));
    
    if(sessionId == kiSCSIInvalidSessionId)
        return NULL;
    
    // Get session options from kernel
    UInt32 paramVal32 = 0;
    
    iSCSIHBAInterfaceGetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOMaxConnections,&paramVal32,sizeof(paramVal32));
    CFNumberRef maxConnections = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&paramVal32);

    iSCSIHBAInterfaceGetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOMaxBurstLength,&paramVal32,sizeof(paramVal32));
    CFNumberRef maxBurstLength = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&paramVal32);

    iSCSIHBAInterfaceGetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOFirstBurstLength,&paramVal32,sizeof(paramVal32));
    CFNumberRef firstBurstLength = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&paramVal32);

    iSCSIHBAInterfaceGetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOMaxOutstandingR2T,&paramVal32,sizeof(paramVal32));
    CFNumberRef maxOutStandingR2T = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&paramVal32);

    iSCSIHBAInterfaceGetSessionParameter(hbaInterface,sessionId,kiSCSIHBASODefaultTime2Retain,&paramVal32,sizeof(paramVal32));
    CFNumberRef defaultTime2Retain = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&paramVal32);
    
    iSCSIHBAInterfaceGetSessionParameter(hbaInterface,sessionId,kiSCSIHBASODefaultTime2Wait,&paramVal32,sizeof(paramVal32));
    CFNumberRef defaultTime2Wait = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&paramVal32);
    

    TargetPortalGroupTag tpgt = 0;
    iSCSIHBAInterfaceGetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOTargetPortalGroupTag,&tpgt,sizeof(TargetPortalGroupTag));
    CFNumberRef targetPortalGroupTag = CFNumberCreate(kCFAllocatorDefault,kCFNumberSInt16Type,&tpgt);

    TargetSessionIdentifier tsih = 0;
    iSCSIHBAInterfaceGetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOTargetSessionId,&tsih,sizeof(TargetSessionIdentifier));
    CFNumberRef targetSessionId = CFNumberCreate(kCFAllocatorDefault,kCFNumberSInt16Type,&tsih);

    UInt8 paramVal8 = 0;
    iSCSIHBAInterfaceGetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOErrorRecoveryLevel,&paramVal8,sizeof(paramVal8));
    CFNumberRef errorRecoveryLevel = CFNumberCreate(kCFAllocatorDefault,kCFNumberSInt8Type,&paramVal8);

    CFNumberRef sessionIdentifier = CFNumberCreate(kCFAllocatorDefault,kCFNumberSInt16Type,&sessionId);
    
    CFStringRef initialR2T = kRFC3720_Value_No;
    CFStringRef immediateData = kRFC3720_Value_No;
    CFStringRef dataPDUInOrder = kRFC3720_Value_No;
    CFStringRef dataSequenceInOrder = kRFC3720_Value_No;

    Boolean paramValBool = false;
    
    iSCSIHBAInterfaceGetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOImmediateData,&paramValBool,sizeof(Boolean));
    if(paramValBool)
        immediateData = kRFC3720_Value_Yes;

    iSCSIHBAInterfaceGetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOInitialR2T,&paramValBool,sizeof(Boolean));
    if(paramValBool)
        initialR2T = kRFC3720_Value_Yes;

    iSCSIHBAInterfaceGetSessionParameter(hbaInterface,sessionId,kiSCSIHBASODataPDUInOrder,&paramValBool,sizeof(Boolean));
    if(paramValBool)
        dataPDUInOrder = kRFC3720_Value_Yes;

    iSCSIHBAInterfaceGetSessionParameter(hbaInterface,sessionId,kiSCSIHBASODataSequenceInOrder,&paramValBool,sizeof(Boolean));
    if(paramValBool)
        dataSequenceInOrder = kRFC3720_Value_Yes;

    // The state of the session as far as its users are concerned
    CFStringRef state = (iSCSIHBAInterfaceGetSessionState(hbaInterface,sessionId) == kiSCSIHBASessionStateRecovering)
                            ? kiSCSISessionStateRecovering : kiSCSISessionStateActive;

    const void * keys[] = {
        kiSCSISessionStateKey,
        kRFC3720_Key_InitialR2T,
        kRFC3720_Key_ImmediateData,
        kRFC3720_Key_DataPDUInOrder,
        kRFC3720_Key_DataSequenceInOrder,
        kRFC3720_Key_MaxConnections,
        kRFC3720_Key_MaxBurstLength,
        kRFC3720_Key_FirstBurstLength,
        kRFC3720_Key_MaxOutstandingR2T,
        kRFC3720_Key_DefaultTime2Retain,
        kRFC3720_Key_DefaultTime2Wait,
        kRFC3720_Key_TargetPortalGroupTag,
        kRFC3720_Key_TargetSessionId,
        kRFC3720_Key_ErrorRecoveryLevel,
        kRFC3720_Key_SessionId
    };

    const void * values[] = {
        state,
        initialR2T,
        immediateData,
        dataPDUInOrder,
        dataSequenceInOrder,
        maxConnections,
        maxBurstLength,
        firstBurstLength,
        maxOutStandingR2T,
        defaultTime2Retain,
        defaultTime2Wait,
        targetPortalGroupTag,
        targetSessionId,
        errorRecoveryLevel,
        sessionIdentifier
    };

    dictionary = CFDictionaryCreate(kCFAllocatorDefault,keys,values,
                                    sizeof(keys)/sizeof(void*),
                                    &kCFTypeDictionaryKeyCallBacks,
                                    &kCFTypeDictionaryValueCallBacks);

    CFRelease(maxConnections);
    CFRelease(maxBurstLength);
    CFRelease(firstBurstLength);
    CFRelease(maxOutStandingR2T);
    CFRelease(defaultTime2Retain);
    CFRelease(defaultTime2Wait);
    CFRelease(targetPortalGroupTag);
    CFRelease(targetSessionId);
    CFRelease(errorRecoveryLevel);
    CFRelease(sessionIdentifier);
    
    return dictionary;
}

/*! Creates a dictionary of connection parameters for the connection associated
 *  with the specified target and portal, if one exists.
 *  @param handle a handle to a daemon connection.
 *  @param target the target associated with the the specified portal.
 *  @param portal the portal to check for active connections to generate
 *  a dictionary of connection parameters.
 *  @return a dictionary of connection properties. */
CFDictionaryRef iSCSISessionCopyCFPropertiesForPortal(iSCSISessionManagerRef managerRef,
                                                     iSCSITargetRef target,
                                                     iSCSIPortalRef portal)
{
    if(!target || !portal)
        return NULL;

    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    CFDictionaryRef dictionary = NULL;

    SessionIdentifier sessionId = iSCSISessionGetSessionIdForTarget(managerRef,iSCSITargetGetIQN(target));
    ConnectionIdentifier connectionId = kiSCSIInvalidConnectionId;

    if(sessionId == kiSCSIInvalidSessionId)
        return NULL;

    // Validate connection identifier
    connectionId = iSCSISessionGetConnectionIdForPortal(managerRef,sessionId,portal);
    if(connectionId == kiSCSIInvalidConnectionId)
        return NULL;
    
    // Get connection options from kernel

    UInt32 paramVal32 = 0;
    iSCSIHBAInterfaceGetConnectionParameter(hbaInterface,sessionId,connectionId,kiSCSIHBACOMaxRecvDataSegmentLength,&paramVal32,sizeof(paramVal32));
    CFNumberRef maxRecvDataSegmentLength = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&paramVal32);
    
    CFNumberRef connectionIdentifier = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&connectionId);
    

    enum iSCSIDigestTypes dataDigestType = kiSCSIDigestNone;
    enum iSCSIDigestTypes headerDigestType = kiSCSIDigestNone;

    Boolean paramValBool = false;
    
    iSCSIHBAInterfaceGetConnectionParameter(hbaInterface,sessionId,connectionId,kiSCSIHBACOUseDataDigest,&paramValBool,sizeof(Boolean));
    if(paramValBool)
        dataDigestType = kiSCSIDigestCRC32C;

    paramValBool = false;
    iSCSIHBAInterfaceGetConnectionParameter(hbaInterface,sessionId,connectionId,kiSCSIHBACOUseHeaderDigest,&paramValBool,sizeof(Boolean));
    if(paramValBool)
        headerDigestType = kiSCSIDigestCRC32C;

    int digestValue = (int)dataDigestType;
    CFNumberRef dataDigest = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&digestValue);

    digestValue = (int)headerDigestType;
    CFNumberRef headerDigest = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&digestValue);
    const void * keys[] = {
        kRFC3720_Key_DataDigest,
        kRFC3720_Key_HeaderDigest,
        kRFC3720_Key_MaxRecvDataSegmentLength,
        kRFC3720_Key_ConnectionId
    };

    const void * values[] = {
        dataDigest,
        headerDigest,
        maxRecvDataSegmentLength,
        connectionIdentifier
    };

    dictionary = CFDictionaryCreate(kCFAllocatorDefault,keys,values,
                                    sizeof(keys)/sizeof(void*),
                                    &kCFTypeDictionaryKeyCallBacks,
                                    &kCFTypeDictionaryValueCallBacks);
    
    CFRelease(dataDigest);
    CFRelease(headerDigest);
    CFRelease(maxRecvDataSegmentLength);
    CFRelease(connectionIdentifier);
    
    return dictionary;
}


