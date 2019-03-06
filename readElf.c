/*================================================================
*   Copyright (C) 2019 Sangfor Ltd. All rights reserved.
*   
*   @File name：readElf.c
*   @Author: nathan
*   @Date: 2019年03月06日
================================================================*/

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>

void show_help();

void show_help()
{
    printf("-h: elf header.\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("help: -help.\n");
        return -1;
    }
    
    if (argc == 2 && !strcmp(argv[1], "-help")) {
        show_help();
        return 0;
    }

    if (argv[2] == NULL) {
        printf("please input the file to analysis.\n");
        return -1;
    }

    char *comm = argv[1];
    const char *elfFile = argv[2];
    int i = 1;
    int result = -1;
    char cmd = '';
    FILE *fp = NULL;
    char *data = NULL;
    int size = 0;
    struct stat st;

    for (i = 1; i < strlen(comm); i++) {
        printf("cmd: %c.\n", comm[i]);
        cmd = comm[i];
        switch(cmd) {
            case 'h':
                show_eheader();
                break;
            case 'p':
                show_pheader();
                break;
            default:
                break;
        }
    }

    result = stat(elfFile, &st);
    if (result < 0) {
        perror("stat()");
        return -1;
    }
    size = st.st_size;
    data = (char *)malloc(size);
    if (data == NULL) {
        perror("malloc()");
        goto out;
    }

    fp = fopen(elfFile, "r");
    if (fp == NULL) {
        perror("fopen()");
        goto out;
    }

    result = 0;
out:
    if (data != NULL) {
        free(data);
    }

    if (fp != NULL) {
        fclose(fp);
    }

    return result;
}
