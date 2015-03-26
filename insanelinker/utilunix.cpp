


////////////////////////////////////////////////////////////////////////////////////////////////////
// file: util_unix.cpp
// date: 2006/10/24
// font: consolas,9pt
// 
// Grab from VCL sources and ported to C.
// remix by azsd oct,10 2006
////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////

#ifdef _WIN32
#include "targetver.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <time.h>
#endif
#include "utilunix.h"
#include <stdlib.h>
//#include <math.h>
//#include <ctime>


////////////////////////////////////////////////////////////////////////////////////////////////////
static bool randomized = false;
int random(int from, int to) {
    int result;
    if (!randomized) {
#ifdef _WIN32
        srand(GetTickCount());
#else
        srand(time(NULL));
#endif
        randomized = true;
    }
    //result = floor((double(rand())/ RAND_MAX) * (to - from)) + from;
    result = rand()%(to - from + 1) + from;
    return result;
}
////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////
// add slashes for single quote, percent mark
std::wstring stringReplace(const std::wstring& subject, const std::wstring& src, const std::wstring& dest);
std::wstring stringReplace(const std::wstring& subject, const std::wstring& src, const std::wstring& dest) {
    std::wstring strOut(subject);   
    std::wstring::size_type curPos = 0;   
    std::wstring::size_type pos;   
    while((pos = strOut.find(src, curPos)) != std::wstring::size_type(std::wstring::npos))
    {
        // Ò»´ÎÌæ»»
        (void)strOut.replace(pos, src.size(), dest);
        // ·ÀÖ¹Ñ­»·Ìæ»»!!
        curPos = pos + dest.size();
    }
    return   strOut;   
}
std::wstring QuoteString(const std::wstring& Source) {
    // for inject
    std::wstring result = stringReplace(Source, L"'", L"''");
    // for wild char escape seq in LIKE query
    result = stringReplace(result, L"[", L"[[]"); //1st
    result = stringReplace(result, L"%", L"[%]");	//percent vs model
    result = stringReplace(result, L"_", L"[_]");	//underscore vs prefix
    result = stringReplace(result, L"-", L"[-]");	//conn vs subtract
    result = stringReplace(result, L"^", L"[^]");
    return result;
}
////////////////////////////////////////////////////////////////////////////////////////////////////


