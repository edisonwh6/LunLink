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

#include "iSCSIAuth.h"
#include "iSCSIPDUUser.h"
#include "iSCSISession.h"
#include "iSCSIHBAInterface.h"
#include "iSCSIQueryTarget.h"

#include <string.h>


/*! Defined by the session layer and used during authentication here. */
extern unsigned int kiSCSISessionMaxTextKeyValuePairs;


/*! Helper function.  Creates a byte array (CFDataRef object) that holds the
 *  binary value encoded by a string.  Per RFC3720 large binary values are
 *  either hexadecimal ("0x" prefix) or base64 ("0b" prefix) encoded. */
CFDataRef CFDataCreateWithEncodedString(CFStringRef encodedString)
{
    if(!encodedString)
        return NULL;

    CFIndex length = CFStringGetLength(encodedString);
    char buffer[length + 1];
    
    if(!CFStringGetCString(encodedString,buffer,length + 1,kCFStringEncodingASCII))
        return NULL;

    CFMutableDataRef data = CFDataCreateMutable(kCFAllocatorDefault,0);
    const char * cursor = buffer;

    // Base64 encoded value
    if(length >= 2 && cursor[0] == '0' && (cursor[1] == 'b' || cursor[1] == 'B')) {
        UInt32 accumulator = 0;
        int bits = 0;
        
        for(cursor += 2; *cursor && *cursor != '='; cursor++) {
            int value;
            
            if(*cursor >= 'A' && *cursor <= 'Z')      value = *cursor - 'A';
            else if(*cursor >= 'a' && *cursor <= 'z') value = *cursor - 'a' + 26;
            else if(*cursor >= '0' && *cursor <= '9') value = *cursor - '0' + 52;
            else if(*cursor == '+')                   value = 62;
            else if(*cursor == '/')                   value = 63;
            else continue;
            
            accumulator = (accumulator << 6) | (UInt32)value;
            bits += 6;
            
            if(bits >= 8) {
                bits -= 8;
                UInt8 byte = (UInt8)(accumulator >> bits);
                CFDataAppendBytes(data,&byte,1);
            }
        }
        return data;
    }
    
    // Hexadecimal value, with or without a prefix
    if(length >= 2 && cursor[0] == '0' && (cursor[1] == 'x' || cursor[1] == 'X'))
        cursor += 2;
    
    size_t digits = strlen(cursor);
    
    // An odd number of digits implies a leading zero
    int pending = (digits % 2 != 0) ? 0 : -1;
    
    for(; *cursor; cursor++) {
        int value;
        
        if(*cursor >= '0' && *cursor <= '9')      value = *cursor - '0';
        else if(*cursor >= 'a' && *cursor <= 'f') value = *cursor - 'a' + 10;
        else if(*cursor >= 'A' && *cursor <= 'F') value = *cursor - 'A' + 10;
        else continue;
        
        if(pending < 0)
            pending = value;
        else {
            UInt8 byte = (UInt8)((pending << 4) | value);
            CFDataAppendBytes(data,&byte,1);
            pending = -1;
        }
    }
    return data;
}

/*! Helper function.  Creates a CFString object that holds the hexidecimal
 *  representation of the values contained in the byte array.  Use CFRelease()
 *  to free the CFString object created by this function (this follows the
 *  Core Foundation "Create" rule). */
CFStringRef CreateHexStringWithBytes(const UInt8 * bytes, size_t length)
{
    // Pad string by 3 bytes to leave room for "0x" prefix and null terminator
    const long hexStrLength = length * 2 + 3;
    
    char hexStr[hexStrLength];
    hexStr[0] = '0';
    hexStr[1] = 'x';
    
    // Print byte array into a hex string
    for(unsigned int i = 0; i < length; i++)
        snprintf(&hexStr[i*2+2],3,"%02x",bytes[i]);
    
    // Null terminate
    hexStr[hexStrLength-1] = 0;
    
    // This copies our buffer into a CFString object
    return CFStringCreateWithCString(kCFAllocatorDefault,hexStr,kCFStringEncodingASCII);
}

/*! Helper function.  Creates a CHAP response from a given identifier, 
 *  secret and challenge (see RFC1994). Use CFRelease() to free the 
 *  returned CHAP response string. */
CFStringRef iSCSIAuthNegotiateCHAPCreateResponse(CFStringRef identifier,
                                                 CFStringRef secret,
                                                 CFStringRef challenge)
{
    CFDataRef challengeData = CFDataCreateWithEncodedString(challenge);
    CFDataRef secretData = CFStringCreateExternalRepresentation(kCFAllocatorDefault,secret,kCFStringEncodingUTF8,0);
    
    if(!challengeData || !secretData) {
        if(challengeData)
            CFRelease(challengeData);
        if(secretData)
            CFRelease(secretData);
        return NULL;
    }
    
    // Holds our md5hash
    UInt8 md5Hash[CC_MD5_DIGEST_LENGTH];

    // Initialize md5 object
    CC_MD5_CTX md5;
    CC_MD5_Init(&md5);

    // Hash in the identifier
    UInt8 id = (UInt8)CFStringGetIntValue(identifier);
    CC_MD5_Update(&md5,&id,(CC_LONG)sizeof(id));

    // Hash in the secret
    CC_MD5_Update(&md5,CFDataGetBytePtr(secretData),(CC_LONG)CFDataGetLength(secretData));

    // Hash in the challenge
    CC_MD5_Update(&md5,CFDataGetBytePtr(challengeData),(CC_LONG)CFDataGetLength(challengeData));

    // Finalize and get the hash string
    CC_MD5_Final(md5Hash,&md5);

    CFRelease(challengeData);
    CFRelease(secretData);
    
    return CreateHexStringWithBytes(md5Hash,CC_MD5_DIGEST_LENGTH);
}

CFStringRef iSCSIAuthNegotiateCHAPCreateChallenge()
{
    // A challenge of 16 random bytes (CHAP standard)
    UInt8 challenge[16];
    arc4random_buf(challenge,sizeof(challenge));
    
    return CreateHexStringWithBytes(challenge,sizeof(challenge));
}

CFStringRef iSCSIAuthNegotiateCHAPCreateId()
{
    return CFStringCreateWithFormat(kCFAllocatorDefault,NULL,CFSTR("%d"),(int)arc4random_uniform(256));
}

/*! Helper function for iSCSIConnectionSecurityNegotiate.  Once it has been
 *  determined that a CHAP session is to be used, this function will perform
 *  the CHAP authentication. */
errno_t iSCSIAuthNegotiateCHAP(iSCSISessionManagerRef managerRef,
                               iSCSIMutableTargetRef target,
                               iSCSIAuthRef initiatorAuth,
                               iSCSIAuthRef targetAuth,
                               SessionIdentifier sessionId,
                               ConnectionIdentifier connectionId,
                               TargetSessionIdentifier targetSessionId,
                               enum iSCSILoginStatusCode * statusCode)
{
    // Setup dictionary CHAP authentication information
    CFMutableDictionaryRef authCmd = CFDictionaryCreateMutable(
        kCFAllocatorDefault,kiSCSISessionMaxTextKeyValuePairs,
        &kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    
    if(!authCmd)
        return EINVAL;

    // Setup dictionary to receive authentication response
    CFMutableDictionaryRef authRsp = CFDictionaryCreateMutable(
        kCFAllocatorDefault,kiSCSISessionMaxTextKeyValuePairs,
        &kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    
    if(!authRsp) {
        CFRelease(authCmd);
        return EINVAL;
    }
    
    // Target must first offer the authentication method (5 = MD5)
    // This key starts authentication process - target authenticates us
    CFDictionaryAddValue(authCmd,kRFC3720_Key_AuthCHAPDigest,kRFC3720_Value_AuthCHAPDigestMD5);
    
    struct iSCSILoginQueryContext context;
    context.interface       = iSCSISessionManagerGetHBAInterface(managerRef);
    context.sessionId       = sessionId;
    context.connectionId    = connectionId;
    context.targetSessionId = targetSessionId;
    context.nextStage       = kiSCSIPDUSecurityNegotiation;
    context.currentStage    = kiSCSIPDUSecurityNegotiation;
    
    enum iSCSIPDURejectCode rejectCode;

    errno_t error = iSCSISessionLoginQuery(&context,
                                           statusCode,
                                           &rejectCode,
                                           authCmd,authRsp);
    
    // Quit if the query failed for whatever reason, release dictionaries
    if(error || *statusCode != kiSCSILoginSuccess) {
        CFRelease(authCmd);
        CFRelease(authRsp);
        return error;
    }

    CFDictionaryRemoveAllValues(authCmd);
    
    // Get CHAP parameters
    CFStringRef targetUser = NULL, targetSecret = NULL;
    CFStringRef initiatorUser = NULL, initiatorSecret = NULL;
    iSCSIAuthGetCHAPValues(initiatorAuth,&initiatorUser,&initiatorSecret);
    iSCSIAuthGetCHAPValues(targetAuth,&targetUser,&targetSecret);
    
    // The target must have selected the algorithm we offered and sent its
    // identifier and challenge; calculate the response
    CFStringRef identifier = NULL, challenge = NULL, response = NULL;
    
    if(initiatorUser && initiatorSecret &&
       CFDictionaryGetValueIfPresent(authRsp,kRFC3720_Key_AuthCHAPId,(void*)&identifier) &&
       CFDictionaryGetValueIfPresent(authRsp,kRFC3720_Key_AuthCHAPChallenge,(void*)&challenge))
        response = iSCSIAuthNegotiateCHAPCreateResponse(identifier,initiatorSecret,challenge);
    
    if(!response) {
        CFRelease(authCmd);
        CFRelease(authRsp);
        return EAUTH;
    }
    
    // Send back our name and response
    CFDictionaryAddValue(authCmd,kRFC3720_Key_AuthCHAPResponse,response);
    CFDictionaryAddValue(authCmd,kRFC3720_Key_AuthCHAPName,initiatorUser);
    CFRelease(response);

    // If we must authenticate the target, generate id, challenge & send
    CFStringRef targetIdentifier = NULL, targetChallenge = NULL;
    
    if(targetUser && targetSecret) {
        targetIdentifier = iSCSIAuthNegotiateCHAPCreateId();
        targetChallenge = iSCSIAuthNegotiateCHAPCreateChallenge();

        CFDictionaryAddValue(authCmd,kRFC3720_Key_AuthCHAPId,targetIdentifier);
        CFDictionaryAddValue(authCmd,kRFC3720_Key_AuthCHAPChallenge,targetChallenge);
    }

    context.nextStage = kiSCSIPDULoginOperationalNegotiation;
    CFDictionaryRemoveAllValues(authRsp);

    error = iSCSISessionLoginQuery(&context,
                                   statusCode,
                                   &rejectCode,
                                   authCmd,authRsp);
    
    // If target authenticated us successfully, perform target authentication (we authenticate target)
    if(!error && *statusCode == kiSCSILoginSuccess && targetIdentifier && targetChallenge)
    {
        // Calculate the response we expect to get
        CFStringRef expResponse = iSCSIAuthNegotiateCHAPCreateResponse(
                                        targetIdentifier,targetSecret,targetChallenge);
        CFStringRef actualResponse = NULL, targetName = NULL;
        CFDataRef expData = NULL, actualData = NULL;
        
        // Compare to the actual received response (by value, as targets are
        // free to choose the encoding of their response)
        if(CFDictionaryGetValueIfPresent(authRsp,kRFC3720_Key_AuthCHAPResponse,(void*)&actualResponse)) {
            expData = CFDataCreateWithEncodedString(expResponse);
            actualData = CFDataCreateWithEncodedString(actualResponse);
        }
        
        if(!expData || !actualData || !CFEqual(expData,actualData))
            error = EAUTH;
        
        // The target must also identify itself by the expected name
        if(!error && (!CFDictionaryGetValueIfPresent(authRsp,kRFC3720_Key_AuthCHAPName,(void*)&targetName) ||
                      CFStringCompare(targetName,targetUser,0) != kCFCompareEqualTo))
            error = EAUTH;
        
        if(expData)
            CFRelease(expData);
        if(actualData)
            CFRelease(actualData);
        if(expResponse)
            CFRelease(expResponse);
    }
    
    if(targetIdentifier)
        CFRelease(targetIdentifier);
    if(targetChallenge)
        CFRelease(targetChallenge);
    
    // If no error and the target returned an alias save it...
    CFStringRef targetAlias;
    if(!error && CFDictionaryGetValueIfPresent(authRsp,kRFC3720_Key_TargetAlias,(const void **)&targetAlias)) {
        iSCSITargetSetAlias(target,targetAlias);
    }
    
    CFRelease(authCmd);
    CFRelease(authRsp);

    return error;
}

void iSCSIAuthNegotiateBuildDict(iSCSISessionManagerRef managerRef,
                                 iSCSITargetRef target,
                                 iSCSIAuthRef initiatorAuth,
                                 iSCSIAuthRef targetAuth,
                                 CFMutableDictionaryRef authCmd)
{
    CFStringRef targetIQN = iSCSITargetGetIQN(target);
    
    if(CFStringCompare(targetIQN,kiSCSIUnspecifiedTargetIQN,0) == kCFCompareEqualTo)
        CFDictionaryAddValue(authCmd,kRFC3720_Key_SessionType,kRFC3720_Value_SessionTypeDiscovery);
    else {
        CFDictionaryAddValue(authCmd,kRFC3720_Key_SessionType,kRFC3720_Value_SessionTypeNormal);
        CFDictionaryAddValue(authCmd,kRFC3720_Key_TargetName,iSCSITargetGetIQN(target));
    }

    // Add the initiator name & alias to the dictionary
    CFStringRef initiatorName = iSCSISessionManagerCopyInitiatorName(managerRef);
    CFStringRef initiatorAlias = iSCSISessionManagerCopyInitiatorAlias(managerRef);
    CFDictionaryAddValue(authCmd,kRFC3720_Key_InitiatorName,initiatorName);
    CFDictionaryAddValue(authCmd,kRFC3720_Key_InitiatorAlias,initiatorAlias);
    CFRelease(initiatorName);
    CFRelease(initiatorAlias);

    // Determine authentication method used and add to dictionary
    enum iSCSIAuthMethods initiatorAuthMethod = iSCSIAuthGetMethod(initiatorAuth);
    enum iSCSIAuthMethods targetAuthMethod = iSCSIAuthGetMethod(targetAuth);
    
    // Add authentication key(s) to dictionary
    if(initiatorAuthMethod == kiSCSIAuthMethodCHAP) {

        // Unidirectional CHAP (target authenticates initiator)
        if(targetAuthMethod == kiSCSIAuthMethodNone) {
            // In case the target doesn't wish to authenticate us, we can
            // include an additional option of no authentication.
            const CFTypeRef values[] = {
                kRFC3720_Value_AuthMethodNone,
                kRFC3720_Value_AuthMethodCHAP
            };

            CFArrayRef methods = CFArrayCreate(kCFAllocatorDefault,
                                               (const void**)values,sizeof(values)/sizeof(CFTypeRef),
                                               &kCFTypeArrayCallBacks);

            CFStringRef methodStrings = CFStringCreateByCombiningStrings(
                kCFAllocatorDefault,methods,CFSTR(","));
            CFDictionaryAddValue(authCmd,kRFC3720_Key_AuthMethod,methodStrings);
            CFRelease(methodStrings);
            CFRelease(methods);
        }
        // Bidirectional CHAP
        else {
            // Here we insist that we authenticate the target and therefore
            // no authentication is not an option.
            CFDictionaryAddValue(authCmd,kRFC3720_Key_AuthMethod,kRFC3720_Value_AuthMethodCHAP);
        }
    }
    else
        CFDictionaryAddValue(authCmd,kRFC3720_Key_AuthMethod,kRFC3720_Value_AuthMethodNone);
}

/*! Helper function.  Called by session or connection creation functions to
 *  begin authentication between the initiator and a selected target.  If the
 *  target name is set to blank (e.g., by a call to iSCSITargetSetIQN()) or 
 *  never set at all, a discovery session is assumed for authentication. */
errno_t iSCSIAuthNegotiate(iSCSISessionManagerRef managerRef,
                           iSCSIMutableTargetRef target,
                           iSCSIAuthRef initiatorAuth,
                           iSCSIAuthRef targetAuth,
                           SessionIdentifier sessionId,
                           ConnectionIdentifier connectionId,
                           enum iSCSILoginStatusCode * statusCode)
{
    iSCSIHBAInterfaceRef hbaInterface = iSCSISessionManagerGetHBAInterface(managerRef);
    
    // Setup dictionary with target and initiator info for authentication
    CFMutableDictionaryRef authCmd = CFDictionaryCreateMutable(
        kCFAllocatorDefault,kiSCSISessionMaxTextKeyValuePairs,
        &kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    
    // Setup dictionary to receive authentication response
    CFMutableDictionaryRef authRsp = CFDictionaryCreateMutable(
        kCFAllocatorDefault,kiSCSISessionMaxTextKeyValuePairs,
        &kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    
    iSCSIAuthNegotiateBuildDict(managerRef,target,initiatorAuth,targetAuth,authCmd);
    
    struct iSCSILoginQueryContext context;
    context.interface    = hbaInterface;
    context.sessionId    = sessionId;
    context.connectionId = connectionId;
    context.currentStage = kiSCSIPDUSecurityNegotiation;
    context.nextStage    = kiSCSIPDUSecurityNegotiation;
    
    // Retrieve the TSIH from the kernel
    TargetSessionIdentifier targetSessionId = 0;
    iSCSIHBAInterfaceGetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOTargetSessionId,
                                         &targetSessionId,sizeof(TargetSessionIdentifier));
    context.targetSessionId = targetSessionId;
    
    enum iSCSIPDURejectCode rejectCode;
    
    // If no authentication is supported (only value we sent was "None"), move on to the next stage
    if(iSCSIAuthGetMethod(initiatorAuth) == kiSCSIAuthMethodNone)
        context.nextStage = kiSCSIPDULoginOperationalNegotiation;
    
    errno_t error = iSCSISessionLoginQuery(&context,
                                           statusCode,
                                           &rejectCode,
                                           authCmd,
                                           authRsp);
    
    // Quit if the query failed for whatever reason, release dictionaries
    if(error || *statusCode != kiSCSILoginSuccess)
        goto ERROR_GENERIC;
    
    // If this is not a discovery session (the target is not specified for discovery),
    // we expect to receive a target portal group tag (TPGT) and validate it
    if(CFStringCompare(iSCSITargetGetIQN(target),kiSCSIUnspecifiedTargetIQN,0) != kCFCompareEqualTo)
    {
        // Ensure that the target returned a portal group tag (TPGT)...
        if(!CFDictionaryContainsKey(authRsp,kRFC3720_Key_TargetPortalGroupTag)) {
            error = EAUTH;
            goto ERROR_TPGT_MISSING;
        }

        // Extract target portal group tag
        CFStringRef targetPortalGroupRsp = (CFStringRef)CFDictionaryGetValue(authRsp,kRFC3720_Key_TargetPortalGroupTag);
        
        // If this is leading login (TSIH = 0 for leading login), store TPGT,
        // else compare it to the TPGT that we have stored for this session...
        if(targetSessionId == 0) {
            TargetPortalGroupTag targetPortalGroupTag = CFStringGetIntValue(targetPortalGroupRsp);
            
            iSCSIHBAInterfaceSetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOTargetPortalGroupTag,
                                                 &targetPortalGroupTag,sizeof(TargetPortalGroupTag));
        }
        else {
            // Retrieve from kernel
            TargetPortalGroupTag targetPortalGroupTag = 0;
            iSCSIHBAInterfaceGetSessionParameter(hbaInterface,sessionId,kiSCSIHBASOTargetPortalGroupTag,
                                                 &targetPortalGroupTag,sizeof(TargetPortalGroupTag));

            // Validate existing group against TPGT for this connection
            if(targetPortalGroupTag != CFStringGetIntValue(targetPortalGroupRsp)) {
                error = EAUTH;
                goto ERROR_AUTHENTICATION;
            }
        }
    }
    
    // Determine if target supports desired authentication method. Desired method could
    // be a comma-separated list in authCmd, so we check the target's desired method
    // as specified in the response (authRsp) against our list.  A target that does
    // not respond with a method does not authenticate.
    CFStringRef authValue = CFDictionaryGetValue(authRsp,kRFC3720_Key_AuthMethod);
    
    if(!authValue)
        authValue = kRFC3720_Value_AuthMethodNone;
    
    CFRange result = CFStringFind(CFDictionaryGetValue(authCmd,kRFC3720_Key_AuthMethod),
                                  authValue,kCFCompareCaseInsensitive);
    
    // Check if target supported our desired authentication method
    if(result.location == kCFNotFound) {
        error = EAUTH;
        goto ERROR_AUTHENTICATION;
    }
    
    // Get authentication method from response string. We can't rely
    // on the value we specified to the target because for initiator CHAP
    // authenticaiton we always supply a no authentication option in addition
    // to CHAP (just because we offer authentication does not mean the target
    // is obliged to use it). This tests whether the target chose to use it.
    enum iSCSIAuthMethods authMethod = kiSCSIAuthMethodNone;
    
    // Target chose to go with CHAP; since we supply a list of options including None,
    // we need to confirm that we're okay with the target's selection to move on...
    if(CFStringCompare(authValue,kRFC3720_Value_AuthMethodCHAP,0) == kCFCompareEqualTo)
    {
        authMethod = kiSCSIAuthMethodCHAP;
    }
    // Target chose to go with None (no authentication)
    else if(CFStringCompare(authValue,kRFC3720_Value_AuthMethodNone,0) == kCFCompareEqualTo)
    {
        // If we originally offered an authentication method and target chose none,
        // we will have to send a PDU to transition to the next stage...
        if(iSCSIAuthGetMethod(initiatorAuth) != kiSCSIAuthMethodNone) {
            context.nextStage = kiSCSIPDULoginOperationalNegotiation;
            error = iSCSISessionLoginQuery(&context,statusCode,&rejectCode,NULL,NULL);
            
            if(error || *statusCode != kiSCSILoginSuccess)
                goto ERROR_GENERIC;
        }
    }

    if(authMethod == kiSCSIAuthMethodCHAP) {
        error = iSCSIAuthNegotiateCHAP(managerRef,
                                       target,
                                       initiatorAuth,
                                       targetAuth,
                                       sessionId,
                                       connectionId,
                                       targetSessionId,
                                       statusCode);
        if(error || *statusCode != kiSCSILoginSuccess)
            goto ERROR_AUTHENTICATE_CHAP;
    }
    
    // If no error and the target returned an alias save it...
    CFStringRef targetAlias;
    if(!error && CFDictionaryGetValueIfPresent(authRsp,kRFC3720_Key_TargetAlias,(const void**)&targetAlias)) {
        iSCSITargetSetAlias(target,targetAlias);
    }
    
    CFRelease(authCmd);
    CFRelease(authRsp);
    
    return 0;
    
ERROR_AUTHENTICATE_CHAP:
    
ERROR_TPGT_MISSING:
    
ERROR_AUTHENTICATION:
    
ERROR_GENERIC:
    
    CFRelease(authCmd);
    CFRelease(authRsp);

    return error;
}


/*! Helper function.  Called by session or connection creation functions to
 *  determine available authentication options for a given target. */
errno_t iSCSIAuthInterrogate(iSCSISessionManagerRef managerRef,
                             iSCSITargetRef target,
                             SessionIdentifier sessionId,
                             ConnectionIdentifier connectionId,
                             enum iSCSIAuthMethods * authMethod,
                             enum iSCSILoginStatusCode * statusCode)
{
    if(sessionId == kiSCSIInvalidSessionId || connectionId == kiSCSIInvalidConnectionId || !target || !authMethod)
        return EINVAL;
    
    *authMethod = kiSCSIAuthMethodInvalid;
    
    // Setup dictionary with target and initiator info for authentication
    CFMutableDictionaryRef authCmd = CFDictionaryCreateMutable(
        kCFAllocatorDefault,kiSCSISessionMaxTextKeyValuePairs,
        &kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    
    CFDictionaryAddValue(authCmd,kRFC3720_Key_SessionType,kRFC3720_Value_SessionTypeNormal);
    CFDictionaryAddValue(authCmd,kRFC3720_Key_TargetName,iSCSITargetGetIQN(target));
    
    CFStringRef initiatorName = iSCSISessionManagerCopyInitiatorName(managerRef);
    CFStringRef initiatorAlias = iSCSISessionManagerCopyInitiatorAlias(managerRef);
    CFDictionaryAddValue(authCmd,kRFC3720_Key_InitiatorName,initiatorName);
    CFDictionaryAddValue(authCmd,kRFC3720_Key_InitiatorAlias,initiatorAlias);
    CFDictionaryAddValue(authCmd,kRFC3720_Key_AuthMethod,kRFC3720_Value_AuthMethodAll);
    CFRelease(initiatorName);
    CFRelease(initiatorAlias);

    // Setup dictionary to receive authentication response
    CFMutableDictionaryRef authRsp = CFDictionaryCreateMutable(
        kCFAllocatorDefault,kiSCSISessionMaxTextKeyValuePairs,
        &kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    
    struct iSCSILoginQueryContext context;
    context.interface    = iSCSISessionManagerGetHBAInterface(managerRef);
    context.sessionId    = sessionId;
    context.connectionId = connectionId;
    context.currentStage = kiSCSIPDUSecurityNegotiation;
    context.nextStage    = kiSCSIPDUSecurityNegotiation;
    context.targetSessionId = 0;
    
    enum iSCSIPDURejectCode rejectCode;
    
    // Query target with all possible authentication options
    errno_t error = iSCSISessionLoginQuery(&context,
                                           statusCode,
                                           &rejectCode,
                                           authCmd,authRsp);
    
    // Quit if the query failed for whatever reason, release dictionaries
    if(!error && *statusCode == kiSCSILoginSuccess) {
        // Grab authentication method that the target chose, if available
        if(CFDictionaryContainsKey(authRsp, kRFC3720_Key_AuthMethod))
        {
            CFStringRef method = CFDictionaryGetValue(authRsp,kRFC3720_Key_AuthMethod);
            if(CFStringCompare(method,kRFC3720_Value_AuthMethodCHAP,0) == kCFCompareEqualTo)
                *authMethod = kiSCSIAuthMethodCHAP;
            else if(CFStringCompare(method,kRFC3720_Value_AuthMethodNone,0) == kCFCompareEqualTo)
                *authMethod = kiSCSIAuthMethodNone;
        }
        // Otherwise the target didn't return an "AuthMethod" key, this means
        // that it doesn't require authentication
        else
            *authMethod = kiSCSIAuthMethodNone;
    }
    
    CFRelease(authCmd);
    CFRelease(authRsp);
    
    return error;
}


