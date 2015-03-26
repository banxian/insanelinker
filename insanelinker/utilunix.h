


////////////////////////////////////////////////////////////////////////////////////////////////////
// file: util_unix.h
// date: 2006/10/24
// font: consolas,9pt tabsize: 4
// 
// Grab from VCL sources and ported to C.
// remix by azsd oct,10 2006
////////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef _UTIL_UNIX_H
#define _UTIL_UNIX_H



////////////////////////////////////////////////////////////////////////////////////////////////////
#include <string>
//#include <wtypes.h>
//#include <ctime>

//static float UnixStartDate = 25569.0;


////////////////////////////////////////////////////////////////////////////////////////////////////
//
//function UnixToDateTime(Value: Longword; InUTC: Boolean): TDateTime;
//function UnixUTCToDateTime(Value: Longword): TDateTime;
//function UnixLocalToDateTime(Value: Longword): TDateTime;
//function DateTimeToUnix(Value: TDateTime; InUTC: Boolean): LongWord;
//function DateTimeToUnixLocal(Value: TDateTime): LongWord;
//function DateTimeToUnixUTC(Value: TDateTime): LongWord;
//
////////////////////////////////////////////////////////////////////////////////////////////////////
//DATE UnixToDateTime(long Value, const bool InUTC);
//DATE UnixUTCToDateTime(long Value);
//DATE UnixLocalToDateTime(long Value);
//long DateTimeToUnix(const DATE Value, const bool InUTC);
//long DateTimeToUnixLocal(DATE Value);
//long DateTimeToUnixUTC(DATE Value);
//std::wstring GetDateTimeStr(time_t time);
//DATE Now(const bool InUTC = false);
////////////////////////////////////////////////////////////////////////////////////////////////////
int random(int from, int to);
//std::wstring GetModuleDirectory(void);
//bool DirectoryExists(const std::wstring& Name);
//bool CreateDir(const std::wstring& Dir);
//bool SetConsoleColor(WORD foreColor=7, WORD backColor=0);
//#if WINVER < 0x0502
//LONGLONG __fastcall InterlockedIncrement64(LONGLONG *V, INT32 IncValue = 1);
//#endif
////////////////////////////////////////////////////////////////////////////////////////////////////
struct ltwstring
{
    bool operator()(const std::wstring& s1, const std::wstring& s2) const
    {
        return s1.compare(s2) < 0;
    }
};
std::wstring QuoteString(const std::wstring& Source);
std::wstring StringToWideString(const std::string& Source, unsigned Codepage = 0);
std::string WideStringToString(const std::wstring& Source, unsigned Codepage = 0);
////////////////////////////////////////////////////////////////////////////////////////////////////

#endif
