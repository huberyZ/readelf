/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：utils.c
*   @Author: nathan
*   @Date: 2019年03月06日
================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

unsigned long elf_hash(const unsigned char *name);

unsigned long elf_hash(const unsigned char *name)
{
    unsigned long h = 0, g;
    while(*name)
    {
        h = (h<<4) + *name++;
        if(g = h & 0xf0000000)
            h ^= g >> 24;
        h &= -g;
    }

    return h;
}
