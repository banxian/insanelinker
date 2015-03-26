//
//  armstub.h
//  ndkutil
//
//  Created by banxian on 1/29/14.
//  Copyright (c) 2014 banxian. All rights reserved.
//

#ifndef ndkutil_armstub_h
#define ndkutil_armstub_h

#include "elfio/elfio.hpp"

bool fillbcblcblxarm(unsigned char* opptr, int delta, bool forceblx, bool* overflowed);
bool fillblblxthumb1(unsigned char* opptr, int distance, bool forceblx, bool* overflowed);
bool fillb11b8thumb1(unsigned char* opptr, int distance, bool* overflowed);

#endif
