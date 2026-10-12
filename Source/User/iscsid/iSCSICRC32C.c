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

#include "iSCSICRC32C.h"

#include <string.h>

#if defined(__ARM_FEATURE_CRC32)

#include <arm_acle.h>

#define CRC32C_U8(crc,value)    __crc32cb((crc),(value))
#define CRC32C_U64(crc,value)   __crc32cd((crc),(value))
#define CRC32C_HARDWARE 1

#elif defined(__SSE4_2__)

#include <nmmintrin.h>

#define CRC32C_U8(crc,value)    _mm_crc32_u8((crc),(value))
#define CRC32C_U64(crc,value)   ((uint32_t)_mm_crc32_u64((crc),(value)))
#define CRC32C_HARDWARE 1

#endif

#if defined(CRC32C_HARDWARE)

uint32_t iSCSICRC32C(uint32_t crc,const void * buffer,size_t length)
{
    const uint8_t * cursor = buffer;
    crc = ~crc;

    while(length >= 8) {
        uint64_t value;
        memcpy(&value,cursor,8);
        crc = CRC32C_U64(crc,value);
        cursor += 8;
        length -= 8;
    }

    while(length-- > 0)
        crc = CRC32C_U8(crc,*cursor++);

    return ~crc;
}

#else

/*! Table for the reflected Castagnoli polynomial (0x82F63B78), built lazily. */
static uint32_t table[256];
static int tableReady = 0;

static void BuildTable(void)
{
    for(uint32_t index = 0; index < 256; index++) {
        uint32_t value = index;

        for(int bit = 0; bit < 8; bit++)
            value = (value & 1) ? (value >> 1) ^ 0x82F63B78u : value >> 1;

        table[index] = value;
    }
    tableReady = 1;
}

uint32_t iSCSICRC32C(uint32_t crc,const void * buffer,size_t length)
{
    const uint8_t * cursor = buffer;

    if(!tableReady)
        BuildTable();

    crc = ~crc;

    while(length-- > 0)
        crc = table[(crc ^ *cursor++) & 0xff] ^ (crc >> 8);

    return ~crc;
}

#endif
