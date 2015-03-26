//
//  armstub.cpp
//  ndkutil
//
//  Created by banxian on 1/29/14.
//  Copyright (c) 2014 banxian. All rights reserved.
//

#include "armstub.h"
#ifdef _WIN32
#include "targetver.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#endif

using namespace ELFIO;

bool fillbcblcblxarm(unsigned char* opptr, int delta, bool forceblx, bool* overflowed)
{
    unsigned w1 = *(unsigned*)opptr;
    unsigned absdist = delta;
    if (delta < 0) {
        absdist = 0 - delta;
    }
    if ((w1 & 0xFE000000u) == 0xFA000000u) {
        // BLX <label>
        //imm32 = SignExtend(imm24:H:'0', 32);
        if (overflowed) {
            *overflowed = absdist >= 0x04000000;
        }
        if (absdist >= 0x04000000) {
            printf("Distance %s%X is over 26bit in ARMv6 BLX fill\n", delta < 0?"-":"", absdist);
        }
        unsigned imm32 = delta;
        unsigned h = (imm32 & 2 == 2);
        unsigned imm24 = imm32 >> 2 & 0x00FFFFFF;
        w1 = w1 & 0xFE000000 | imm24 | h << 24;
        *(unsigned*)opptr = w1;
        if (absdist < 0x04000000) {
            return true;
        }
    } else if ((w1 & 0x0F000000) == 0x0B000000 || (w1 & 0x0F000000u) == 0x0A000000u) {
        if (forceblx) {
            printf("Need BLX but B<c> BL<c> found\n");
        }
        if (overflowed) {
            *overflowed = absdist >= 0x04000000;
        }
        if (absdist >= 0x04000000) {
            printf("Distance %s%X is over 26bit in ARMv6 BL fill\n", delta < 0?"-":"", absdist);
        }
        // 28, R_ARM_CALL
        //BL      _Z11mh4gexptestv      = BL<c> <label>
        // 29, R_ARM_JMP24
        //B       _ZN2nn2fs7UnmountEPKc = B<c> <label>
        //BLMI    _Z7hardlogPKcz        = BL<c> <label> 
        unsigned imm32 = delta;
        unsigned imm24 = imm32 >> 2 & 0x00FFFFFF;
        w1 = w1 & 0xFF000000 | imm24;
        *(unsigned*)opptr = w1;
        if (absdist < 0x04000000) {
            return true;
        }
    } 

    return false;
}

bool fillblblxthumb1(unsigned char* opptr, int distance, bool forceblx, bool* overflowed)
{
    unsigned short hw1 = *(unsigned short*)opptr, hw2 = *(unsigned short*)(opptr + 2);
    unsigned absdist = distance;
    if (distance < 0) {
        absdist = 0 - distance;
    }

    if (((hw1 & 0xF800) == 0xF000) && ((hw2 & 0xF800) == 0xF800)) {
        // BL to thumb
        if (forceblx) {
            printf("Need BLX but BL<c> found\n");
        }
        if (overflowed) {
            *overflowed = (absdist & 0xFFC00000u) != 0;
        }
        if ((absdist & 0xFFC00000u) != 0) {
            printf("Distance %s%X is over 22bit in ARMv6 BL fill\n", distance < 0?"-":"", absdist);
        }
        unsigned char s = distance < 0;

        hw1 = (hw1 & 0xF800) | s << 10 | (distance >> 12 & 0x3FF);
        hw2 = (hw2 & 0xF800) | (distance >> 1 & 0x7FF);

        *(unsigned short*)opptr = hw1;
        *(unsigned short*)(opptr + 2) = hw2;
        if ((absdist & 0xFFC00000u) == 0) {
            return true;
        }
    } else if (((hw1 & 0xF800) == 0xF000) && ((hw2 & 0xF801) == 0xE800)) {
        // BLX to ARM
        if (overflowed) {
            *overflowed = (absdist & 0xFFC00000u) != 0;
        }
        if ((absdist & 0xFFC00000u) != 0) {
            printf("Distance %s%X is over 22bit in ARMv6 BLX fill\n", distance < 0?"-":"", absdist);
        }

        unsigned char s = distance < 0;

        hw1 = (hw1 & 0xF800) | s << 10 | (distance >> 12 & 0x3FF);
        hw2 = (hw2 & 0xF800) | (distance >> 1 & 0x7FE);

        *(unsigned short*)opptr = hw1;
        *(unsigned short*)(opptr + 2) = hw2;
        if ((absdist & 0xFFC00000u) == 0) {
            return true;
        }
    }

    return false;
}

bool fillb11b8thumb1(unsigned char* opptr, int distance, bool* overflowed)
{
    unsigned short hw = *(unsigned short*)opptr;
    unsigned absdist = ((distance < 0)?0 - distance:distance);
    if ((hw & 0xF000) == 0xD000) {
        //B<c> imm8
        if (overflowed) {
            *overflowed = absdist >= 0x200;
        }
        if (absdist >= 0x200) {
            printf("Distance %s%X is over 9bit in ARMv6 B<c> fill\n", distance < 0?"-":"", absdist);
        }
        hw = (hw & 0xFF00) | (distance >> 1 & 0xFF);
        *(unsigned short*)opptr = hw;
        if (absdist < 0x200) {
            return true;
        }
    } else if ((hw & 0xF800) == 0xE000) {
        //B<itc> imm11
        if (overflowed) {
            *overflowed = absdist >= 0x1000;
        }
        if (absdist >= 0x1000) {
            printf("Distance %s%X is over 12bit in ARMv6 B<c> fill\n", distance < 0?"-":"", absdist);
        }
        hw = (hw & 0xF800) | (distance >> 1 & 0x7FF);
        *(unsigned short*)opptr = hw;
        if (absdist < 0x1000) {
            return true;
        }
    }
    return false;
}