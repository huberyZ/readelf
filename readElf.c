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

void show_elf_program(char *data)
{
	Elf_Ehdr *ehdr = (Elf_Ehdr *)data;
	Elf_Phdr *phdr = (Elf_Phdr *)(data + ehdr->e_phoff);

	int i;
	printf("There are %d program headers, starting at offset %lld\n", ehdr->e_phnum, ehdr->e_phoff);
	printf("Program Headers:\n");
	printf("%-18s %-18s %-18s %-18s\n%-18s %-18s %-18s %-10s %-10s\n", "Type", "Offset", "VirtAddr", "PhysAddr", "", "FileSize", "MemSize", "Flags", "Align");
	for (i = 0; i < ehdr->e_phnum; i++) {
		switch(phdr->p_type) {
			case PT_NULL:
				printf("%-18s", "NULL");
				break;
			case PT_LOAD:
				printf("%-18s", "LOAD");
				break;
			case PT_DYNAMIC:
				printf("%-18s", "DYNAMIC");
				break;
			case PT_INTERP:
				printf("%-18s", "INTERP");
				break;
			case PT_NOTE:
				printf("%-18s", "NOTE");
				break;
			case PT_SHLIB:
				printf("%-18s", "SHLIB");
				break;
			case PT_PHDR:
				printf("%-18s", "PHDR");
				break;
			case PT_TLS:
				printf("%-18s", "TLS");
				break;
			case PT_LOOS:
				printf("%-18s", "LOOS");
				break;
			case PT_HIOS:
				printf("%-18s", "HIOS");
				break;
			case PT_LOPROC:
				printf("%-18s", "LOPROC");
				break;
			case PT_HIPROC:
				printf("%-18s", "HIPROC");
				break;
			case PT_GNU_EH_FRAME:
				printf("%-18s", "GNU_EH_FRAME");
				break;
			case PT_GNU_STACK:
				printf("%-18s", "GNU_STACK");
				break;
			default:
				printf("%-18s", "UNKNOW");
				break;
		}
		printf(" 0x%016llx 0x%016llx 0x%016llx\n", phdr->p_offset, phdr->p_vaddr, phdr->p_paddr);
		printf("%-18s 0x%016llx 0x%016llx ", "", phdr->p_filesz, phdr->p_memsz);
		
		switch(phdr->p_flags) {
			case PF_R:
				printf("%-10s", "R");
				break;
			case PF_W:
				printf("%-10s", "W");
				break;
			case PF_X:
				printf("%-10s", "X");
				break;
			case PF_R|PF_W:
				printf("%-10s", "RW");
				break;
			case PF_R|PF_X:
				printf("%-10s", "R X");
				break;
			case PF_W|PF_X:
				printf("%-10s", " WX");
				break;
		}
	
		printf(" 0x%-10llx\n", phdr->p_align);
		phdr++;
	}
	printf("\n\nSection to Segment mapping:\n");
	printf("Segment Sections...\n");
}

void show_elf_dynamic(char *data)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr*)data;
    Elf_Phdr *phdr = (Elf_Phdr*)(data + ehdr->e_phoff);
    Elf_Dyn *dyn = NULL;
    int dynNum = 0;

    int i;
    for (i = 0; i < ehdr->e_phnum; i++) {
        if (phdr->p_type == PT_DYNAMIC) {
            dyn = (Elf_Dyn*)(data + phdr->p_offset);
            printf("filesize: %d, memsz: %d\n", phdr->p_filesz, phdr->p_memsz);
            dynNum = phdr->p_filesz / sizeof(Elf_Dyn);
            break;
        }
        phdr++;
    }

    if (dyn == NULL) {
        printf("no dynamic.\n");
        return;
    }

    printf("Dynamic section at offset 0x%x contains %d entries:\n", phdr->p_offset, dynNum);
    printf("%-18s %-20s %s\n", "Tag", "Type", "Name/Value");
    
    char *strtab = NULL;
    Elf_Dyn *dyn_p = dyn;
    for (i = 0; i < dynNum; i++) {
        if (dyn_p->d_tag == DT_STRTAB) {
            printf("strtab offset: %d\n", dyn_p->d_un.d_ptr);
            strtab = data + dyn_p->d_un.d_ptr;
        }
        dyn_p++;
    }

    for (i = 0; i < dynNum; i++) {
        switch(dyn->d_tag) {
            case DT_NULL:
                printf("0x%-018x %-20s %d\n", dyn->d_tag, "NULL", dyn->d_un.d_val);
                break;

            case DT_NEEDED:
                printf("0x%-018x %-20s Shared library: [%s]\n", dyn->d_tag, "NEEDED", strtab + dyn->d_un.d_val);
                break;

            case DT_PLTRELSZ:
                printf("0x%-018x %-20s %d(bytes)\n", dyn->d_tag, "PLTRELSZ", dyn->d_un.d_val);
                break;

            case DT_PLTGOT:
                printf("0x%-018x %-20s 0x%x\n", dyn->d_tag, "PLTGOT", dyn->d_un.d_ptr);
                break;

            case DT_HASH:
                printf("0x%-018x %-20s 0x%x\n", dyn->d_tag, "HASH", dyn->d_un.d_ptr);
                break;

            case DT_STRTAB:
                printf("0x%-018x %-20s 0x%x\n", dyn->d_tag, "STRTAB", dyn->d_un.d_ptr);
                break;

            case DT_SYMTAB:
                printf("0x%-018x %-20s 0x%x\n", dyn->d_tag, "SYMTAB", dyn->d_un.d_ptr);
                break;

            case DT_RELA:
                printf("0x%-018x %-20s 0x%x\n", dyn->d_tag, "RELA", dyn->d_un.d_ptr);
                break;

            case DT_RELASZ:
                printf("0x%-018x %-20s 0x%x\n", dyn->d_tag, "RELASZ", dyn->d_un.d_val);
                break;

            case DT_RELAENT:
                printf("0x%-018x %-20s %d\n", dyn->d_tag, "RELAENT", dyn->d_un.d_val);
                break;

            case DT_STRSZ:
                printf("0x%-018x %-20s %d\n", dyn->d_tag, "STRSZ", dyn->d_un.d_val);
                break;

            case DT_SYMENT:
                printf("0x%-018x %-20s %d\n", dyn->d_tag, "SYMENT", dyn->d_un.d_val);
                break;

            case DT_INIT:
                printf("0x%-018x %-20s 0x%x\n", dyn->d_tag, "INIT", dyn->d_un.d_ptr);
                break;

            case DT_FINI:
                printf("0x%-018x %-20s 0x%x\n", dyn->d_tag, "FINI", dyn->d_un.d_ptr);
                break;

            case DT_SONAME:
                printf("0x%-018x %-20s so name: [%s]\n", dyn->d_tag, "SONAME", strtab + dyn->d_un.d_val);
                break;

            case DT_RPATH:
                printf("0x%-018x %-20s rpath: [%s]\n", dyn->d_tag, "RPATH", strtab + dyn->d_un.d_val);
                break;

            case DT_REL:
                printf("0x%-018x %-20s 0x%x\n", dyn->d_tag, "REL", dyn->d_un.d_ptr);
                break;

            case DT_RELSZ:
                printf("0x%-018x %-20s %d\n", dyn->d_tag, "RELSZ", dyn->d_un.d_val);
                break;

            case DT_RELENT:
                printf("0x%-018x %-20s %d\n", dyn->d_tag, "RELENT", dyn->d_un.d_val);
                break;

            case DT_PLTREL:
                printf("0x%-018x %-20s %d\n", dyn->d_tag, "PLTREL", dyn->d_un.d_val);
                break;

            case DT_DEBUG:
                printf("0x%-018x %-20s 0x%x\n", dyn->d_tag, "DEBUG", dyn->d_un.d_ptr);
                break;

            case DT_JMPREL:
                printf("0x%-018x %-20s 0x%x\n", dyn->d_tag, "JMPREL", dyn->d_un.d_ptr);
                break;
        }
        dyn++;
    }
}

void show_elf_relocation(char *data)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)data;
    Elf_Shdr *shdr = (Elf_Shdr *)(data + ehdr->e_shoff);
    Elf_Rel *rel = NULL;
    Elf_Rela *rela = NULL;
    int relNum = 0;
    int relaNum = 0;

    int i;
    for (i = 0; i < ehdr->e_shnum; i++) {
        if (shdr->sh_type == SHT_RELA) {
            rela = (Elf_Rela *)(data + shdr->sh_offset);
            relaNum = shdr->sh_size / sizeof(Elf_Rela);
        }
        if (shdr->sh_type == SHT_REL) {
            rel = (Elf_Rel *)(data + shdr->sh_offset);
            relNum = shdr->sh_size / sizeof(Elf_Rel);
        }
        if (rela != NULL && rel != NULL) {
            break;
        }
    }

    if (rela != NULL) {
    
    }

    if (rel != NULL) {
    
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
				break;
            case 'l':
                show_elf_program(data);
				break;
            case 'd':
                show_elf_dynamic(data);
				break;
            case 'r':
                show_elf_relocation(data);
				break;
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
