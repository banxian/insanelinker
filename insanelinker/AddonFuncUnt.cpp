#include "AddonFuncUnt.h"
#include <io.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

unsigned char QuadBit2Hex(unsigned char num) {
    if (num < 10) {
        return num + '0';
    } else {
        return num + '7';
    }
}

unsigned char Hex2QuadBit(unsigned char chr) {
    if (chr < 'A') {
        return chr - '0';
    } else {
        return chr - '7';
    }
}

std::string DumpByteBuffer( ByteVector& buffer )
{
    std::string Result = "";
    for (ByteVector::size_type i = 0; i < buffer.size(); i++) {
        Result += char(QuadBit2Hex(((unsigned char)buffer[i]) >> 4));
        Result += char(QuadBit2Hex(((unsigned char)buffer[i]) & 0xF));
    }
    return Result;
}

std::string DumpBuffer( const char *buffer, int size )
{
    std::string Result = "";
    for (int i = 0; i < size; i++) {
        Result += char(QuadBit2Hex(((unsigned char)buffer[i]) >> 4));
        Result += char(QuadBit2Hex((unsigned char)buffer[i] & 0xF));
    }
    return Result;
}


std::string DumpBinary( const char *buffer, int bits, int group )
{
    std::string Result = "";
    int y = 0;
    for (int i = 0; i < (bits + 7) / 8; i++) {
        unsigned char b1 = (unsigned char)buffer[i];
        for (int bit = 0; bit < 8; bit++)
        {
            if (y % group == 0 && y > 0) {
                Result += ',';
            }
            Result += '0' + (b1%2);
            b1 = b1 >> 1;
            y++;
            if (y >= bits) {
                return Result;
            }
        }
    }
    return Result;
}


unsigned ReverseEndian(unsigned source)
{
    source = (source>>24) | 
        ((source<<8) & 0x00FF0000) |
        ((source>>8) & 0x0000FF00) |
        (source<<24);
    return source;
}

std::string Int2Hex( unsigned Value, int Digits )
{
    char Buf[9];
    char* Dest;

    Dest = &Buf[8];
    *Dest = 0;
    do {
        Dest--;
        *Dest = '0';
        if (Value != 0) {
            *Dest = QuadBit2Hex(Value & 0xF);
            Value = Value >> 4;
        }
        Digits--;
    } while (Value != 0 || Digits > 0);
    return Dest;
}

//Result := 0;
//I := 1;
//if Value = '' then Exit;
//if Value[ 1 ] = '$' then Inc( I );
//while I <= Length( Value ) do
//begin
//  if Value[ I ] in [ '0'..'9' ] then
//     Result := (Result shl 4) or (Ord(Value[I]) - Ord('0'))
//  else
//  if Value[ I ] in [ 'A'..'F' ] then
//     Result := (Result shl 4) or (Ord(Value[I]) - Ord('A') + 10)
//  else
//  if Value[ I ] in [ 'a'..'f' ] then
//     Result := (Result shl 4) or (Ord(Value[I]) - Ord('a') + 10)
//  else
//    break;
//  Inc( I );
//end;
unsigned Hex2Int( const std::string& Value )
{
    // TODO: remove 0x
    unsigned result = 0;
    size_t ilen = Value.length();
    for (size_t i = 0; i < ilen; i++)
    {
        char b1 = Value[i];
        if (b1 >= '0' && b1 <= '9') {
            result = (result << 4) | (b1 - '0');
        } else if (b1 >= 'A' && b1 <= 'F') {
            result = (result << 4) | (b1 - 'A' + 10);
        } else if (b1 >= 'a' && b1 <= 'f') {
            result = (result << 4) | (b1 - 'a' + 10);
        } else {
            break;
        }
    }

    return result;
}

/*
* The memmem() function finds the start of the first occurrence of the
* substring 'needle' of length 'nlen' in the memory area 'haystack' of
* length 'hlen'.
*
* The return value is a pointer to the beginning of the sub-string, or
* NULL if the substring is not found.
*/
void *memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen)
{
    int needle_first;
    const void *p = haystack;
    size_t plen = hlen;

    if (!nlen)
        return NULL;

    needle_first = *(unsigned char *)needle;

    while (plen >= nlen && (p = memchr(p, needle_first, plen - nlen + 1)))
    {
        if (!memcmp(p, needle, nlen))
            return (void *)p;

        p = (char*)p + 1;
        plen = hlen - ((char*)p - (char*)haystack);
    }

    return NULL;
}

// determinate 
bool beginwith(const wchar_t* left, const wchar_t* right)
{
    int substrlen = wcslen(right);
    return wcsnicmp(left, right, substrlen) == 0;
}


int readallcontent(const wchar_t* path, void** outptr)
{
    struct _stat64 st;
    if (_wstat64(path, &st) == -1 || st.st_size == 0) {
        return -1;
    }
    int fd = _wopen(path, O_RDONLY | O_BINARY); // O_BINARY not available in OSX
    if (fd == -1) {
        return -1;
    }
    void* newmem = malloc((size_t)st.st_size); // TODO: PAE
    int readed = _read(fd, newmem, (size_t)st.st_size);
    _close(fd);
    *outptr = newmem;
    return readed;
}

int readpartcontent(const wchar_t* path, void** outptr, unsigned long long offset, unsigned size)
{
    struct _stat64 st;
    if (_wstat64(path, &st) == -1 || st.st_size == 0) {
        return -1;
    }
    int fd = _wopen(path, O_RDONLY | O_BINARY); // O_BINARY not available in OSX
    if (fd == -1) {
        return -1;
    }
    void* newmem = malloc(size);
    if (offset) {
        _lseeki64(fd, offset, SEEK_SET);
    }
    int readed = _read(fd, newmem, size);
    _close(fd);
    *outptr = newmem;
    return readed;
}

int savetofile(const wchar_t* path, void* data, size_t len)
{
    int fd = _wopen(path, O_CREAT | O_RDWR | O_BINARY,  S_IREAD | S_IWRITE );
    if (fd == -1) {
        printf("errno: %d, msg: %s\n", errno, strerror(errno));
        return -1;
    }
    int writed = _write(fd, data, len);
    _close(fd);
    return writed;
}

unsigned alignby4( unsigned size )
{
    return (size + 3) & ~3;
}
