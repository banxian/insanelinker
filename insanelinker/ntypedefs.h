#ifndef __NTYPEDEFS_H__
#define __NTYPEDEFS_H__

#include <stdint.h>

typedef unsigned char		u8;
typedef unsigned short		u16;
typedef unsigned int		u32;
typedef unsigned long long	u64;

typedef signed char			s8;
typedef signed short		s16;
typedef signed int			s32;
typedef signed long long	s64;

#pragma pack(push, 1)
struct exhdr_CodeSegmentInfo
{
    u32 address; // le u32
    u32 numMaxPages; // le u32
    u32 codeSize; // le u32
};

struct exhdr_CodeSetInfo
{
    u8 name[8];
    u8 padding0[5];
    u8 flag;
    u16 remasterVersion; // le u16
    exhdr_CodeSegmentInfo text;
    u32 stackSize; // le u32
    exhdr_CodeSegmentInfo rodata;
    u32 padding1;
    exhdr_CodeSegmentInfo data;
    u32 bssSize; // le u32
};
#pragma pack(pop)

#endif