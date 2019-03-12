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

#include "elf.h"
#define Elf64_Ehdr Elf_Ehdr

void show_help();

void show_help()
{
    printf("-h: elf header.\n");
}

void show_elf_header(void *data)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)data;
    printf("Elf Header:\n");
    printf("Magic: ");
    int i;
    for (i = 0; i < EI_NIDENT; i++) {
        printf("%02x ", ehdr->e_ident[i]);
    }
    printf("\n");

    printf("entry:  0x%llx\n", ehdr->e_entry);
    printf("offset program header table:  0x%llx\n", ehdr->e_phoff);
    printf("offset of section header table:  0x%llx\n", ehdr->e_shoff);
    printf("size of elf header:  %d\n", ehdr->e_ehsize);
    printf("size of program header:  %d\n", ehdr->e_phentsize);
    printf("number of program header:  %d\n", ehdr->e_phnum);
    printf("size of section header:  %d\n", ehdr->e_shentsize);
    printf("number of section header:  %d\n", ehdr->e_shnum);
    printf("index of section header string table: %d\n", ehdr->e_shstrndx);
}

void show_elf_section(char *data)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)data;
    Elf_Shdr *shdr = (Elf_Shdr *)(data + ehdr->e_shoff);
    char *sh_name = data + (shdr + ehdr->e_shstrndx)->sh_offset;
    int s_num = ehdr->e_shnum;
    int i;
    
    printf("section tables:\n");
	printf("%5s %-20s%-20s%-10s%-10s%-10s%-10s%-5s%-5s%-10s%-10s\n","Num", "Name","Type","Flag", "Addr","Off","Size","Lk","Inf","Ali","Es");
    for (i = 0; i < s_num; ++i) {
        printf("%5d %-20s", i, sh_name + shdr->sh_name);
        switch(shdr->sh_type) {
            case SHT_NULL:
                printf("%-20s", "SHT_NULL");
                break;
            case SHT_PROGBITS:
                printf("%-20s", "SHT_PROGBITS");
                break;
            case SHT_SYMTAB:
                printf("%-20s", "SHT_SYMTAB");
                break;
            case SHT_STRTAB:
                printf("%-20s", "SHT_STRTAB");
                break;
            case SHT_RELA:
                printf("%-20s", "SHT_RELA");
                break;
            case SHT_HASH:
                printf("%-20s", "SHT_HASH");
                break;
            case SHT_DYNAMIC:
                printf("%-20s", "SHT_DYNAMIC");
                break;
            case SHT_NOTE:
                printf("%-20s", "SHT_NOTE");
                break;
            case SHT_NOBITS:
                printf("%-20s", "SHT_NOBITS");
                break;
            case SHT_REL:
                printf("%-20s", "SHT_REL");
                break;
            case SHT_SHLIB:
                printf("%-20s", "SHT_SHLIB");
                break;
            case SHT_DYNSYM:
                printf("%-20s", "SHT_DYNSYM");
                break;
            case SHT_NUM:
                printf("%-20s", "SHT_NUM");
                break;
            case SHT_LOPROC:
                printf("%-20s", "SHT_LOPROC");
                break;
            case SHT_HIPROC:
                printf("%-20s", "SHT_HIPROC");
                break;
            case SHT_LOUSER:
                printf("%-20s", "SHT_LOUSER");
                break;
            case SHT_HIUSER:
                printf("%-20s", "SHT_HIUSER");
                break;
            default:
                printf("%-20s", "unknow");
                break;
        }
        switch (shdr->sh_flags) {
			case SHF_WRITE:
				printf("%-10s"," W ");
				break;
			case SHF_ALLOC:
				printf("%-10s"," A ");
				break;
			case SHF_EXECINSTR:
				printf("%-10s"," E ");
				break;
			case SHF_MASKPROC:
				printf("%-10s"," M ");
				break;
			case SHF_WRITE | SHF_ALLOC:
				printf("%-10s"," WA " );
				break;
			case SHF_WRITE | SHF_EXECINSTR:
				printf("%-10s"," WE");
				break;
			case SHF_ALLOC | SHF_EXECINSTR:
				printf("%-10s"," AE");
				break;
			case SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR:
				printf("%-10s"," WAE");
				break;
			default:
				printf("%-10s"," U ");
				break;

        }
        printf("%-10llx", shdr->sh_addr);
        printf("%-10llx", shdr->sh_offset);
        printf("%-10llx", shdr->sh_size);
        printf("%-5x", shdr->sh_link);
        printf("%-5x", shdr->sh_info);
        printf("%-10llx", shdr->sh_addralign);
        printf("%-10llx", shdr->sh_entsize);
        printf("\n");
        shdr++;
    }
    
}

void show_elf_symbal(char *data)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)data;
    Elf_Shdr *shdr = (Elf_Shdr *)(data + ehdr->e_shoff);
    char *section_name = data + (shdr + ehdr->e_shstrndx)->sh_offset;
    Elf_Sym *sym = NULL;
    Elf_Xword sym_ssize = 0;
    Elf_Sym *dynsym = NULL;
    Elf_Xword dynsym_ssize = 0;
    char *strtab = NULL;
    char *dynstr = NULL;

    int i;
    for (i = 0; i < ehdr->e_shnum; i++) {
        if (shdr->sh_type == SHT_SYMTAB) {
            sym = (Elf_Sym *)(data + shdr->sh_offset);
            sym_ssize = shdr->sh_size;
        }
        if (shdr->sh_type == SHT_DYNSYM) {
            dynsym = (Elf_Sym *)(data + shdr->sh_offset);
            dynsym_ssize = shdr->sh_size;
        }
        if (shdr->sh_type == SHT_STRTAB && (!strcmp(section_name + shdr->sh_name, ".strtab"))) {
            strtab = data + shdr->sh_offset;
        }

        if (shdr->sh_type == SHT_STRTAB && (!strcmp(section_name + shdr->sh_name, ".dynstr"))) {
            dynstr = data + shdr->sh_offset;
        }

        shdr++;
    }

    if (sym == NULL) {
        printf("no section.\n");
        return;
    }
    if (strtab == NULL) {
        printf("no strtab.\n");
        return;
    }

    printf("symbal table '.dynsym'\n");
	printf("%5s %16s%10s%10s%10s%8s %-s\n","Num", "Value","Size", "Bind","Type","Shndx", "Name");
    if (dynsym != NULL) {
        int dynsym_num = dynsym_ssize / sizeof(Elf_Sym);
        for (i = 0; i < dynsym_num; i++) {
            printf("%5d %016llx%10llu", i, dynsym->st_value, dynsym->st_size);
            switch(ELF_ST_BIND(dynsym->st_info)) {
                case STB_LOCAL:
                    printf("%10s", "LOCAL");
                    break;
                case STB_GLOBAL:
                    printf("%10s", "GLOBAL");
                    break;
                case STB_WEAK:
                    printf("%10s", "WEAK");
                    break;
                default:
                    printf("%10s", "UNKNOW");
                    break;
            }
            switch(ELF_ST_TYPE(dynsym->st_info)) {
                case STT_NOTYPE:
                    printf("%10s", "NOTYPE");
                    break;
                case STT_OBJECT:
                    printf("%10s", "OBJECT");
                    break;
                case STT_FUNC:
                    printf("%10s", "FUNC");
                    break;
                case STT_SECTION:
                    printf("%10s", "SECTION");
                    break;
                case STT_FILE:
                    printf("%10s", "FILE");
                    break;
                case STT_COMMON:
                    printf("%10s", "COMMON");
                    break;
                default:
                    printf("%10s", "UNKNOW");
                    break;
            }

            printf("%8d", dynsym->st_shndx);
            printf(" %-s", dynstr + dynsym->st_name);
            printf("\n");
            dynsym++;
        }

    }

    printf("symbal table '.symbal'\n");
	printf("%5s %16s%10s%10s%10s%8s %-s\n","Num", "Value","Size", "Bind","Type","Shndx", "Name");
    int sym_num = sym_ssize / sizeof(Elf_Sym);
    for (i = 0; i < sym_num; i++) {
        printf("%5d %016llx%10llu", i, sym->st_value, sym->st_size);
        switch(ELF_ST_BIND(sym->st_info)) {
            case STB_LOCAL:
                printf("%10s", "LOCAL");
                break;
            case STB_GLOBAL:
                printf("%10s", "GLOBAL");
                break;
            case STB_WEAK:
                printf("%10s", "WEAK");
                break;
            default:
                printf("%10s", "UNKNOW");
                break;
        }
        switch(ELF_ST_TYPE(sym->st_info)) {
            case STT_NOTYPE:
                printf("%10s", "NOTYPE");
                break;
            case STT_OBJECT:
                printf("%10s", "OBJECT");
                break;
            case STT_FUNC:
                printf("%10s", "FUNC");
                break;
            case STT_SECTION:
                printf("%10s", "SECTION");
                break;
            case STT_FILE:
                printf("%10s", "FILE");
                break;
            case STT_COMMON:
                printf("%10s", "COMMON");
                break;
            default:
                printf("%10s", "UNKNOW");
                break;
        }

        printf("%8d", sym->st_shndx);
        printf(" %-s", strtab + sym->st_name);
        printf("\n");

        sym++;
    }

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
    char cmd = ' ';
    FILE *fp = NULL;
    char *data = NULL;
    int size = 0;
    struct stat st;

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

    result = fread(data, 1, size, fp);
    if (result < 0) {
        perror("fread()");
        goto out;
    }

    for (i = 1; i < strlen(comm); i++) {
        printf("cmd: %c.\n", comm[i]);
        cmd = comm[i];
        switch(cmd) {
            case 'h':
                show_elf_header(data);
                break;
            case 'S':
                show_elf_section(data);
                break;
            case 's':
                show_elf_symbal(data);
            default:
                break;
        }
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
