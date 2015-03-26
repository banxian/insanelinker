#ifndef _ADDON_FUNC_UNIT_H
#define _ADDON_FUNC_UNIT_H

#include <vector>
#include <string>

typedef std::vector<unsigned char> ByteVector;
std::string DumpByteBuffer( ByteVector& buffer );
std::string DumpBuffer( const char *buffer, int size );
std::string DumpBinary( const char *buffer, int bits, int group );
unsigned ReverseEndian(unsigned source);
std::string Int2Hex( unsigned Value, int Digits );
unsigned Hex2Int( const std::string& Value );
unsigned char QuadBit2Hex(unsigned char num);
unsigned char Hex2QuadBit(unsigned char chr);
void *memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen);
bool beginwith(const wchar_t* left, const wchar_t* right);
int readallcontent(const wchar_t* path, void** outptr);
int savetofile(const wchar_t* path, void* data, size_t len);
int readpartcontent(const wchar_t* path, void** outptr, unsigned long long offset, unsigned size);
unsigned alignby4(unsigned size);

#endif