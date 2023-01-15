#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file 

Elf64_Addr find_symbol(char* symbol_name, char* exe_file_name, int* error_val);
pid_t run_target(const char *programname);
Elf64_Addr get_shared_func_addr(pid_t child_pid, Elf64_Addr addr);
void break_start_func(unsigned long data, unsigned long data_trap, Elf64_Addr func_addr, pid_t child_pid);
void run_breakpoint_debugger(pid_t child_pid, Elf64_Addr addr, bool is_shared_function);
void print_registers(pid_t child);

/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */

Elf64_Addr find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
    //this function will read an ELF file and find the address of a symbol in it.
    // if the symbol is not found, we will put -1 in error_val.
    // if the the symbol is local only, we will put -2 in error_val.
    // if the file is not an executable, we will put -3 in error_val.
    // if the symbol is global, but not defined in the executable, we will put -4 in error_val.

    // open the file
    FILE* fp = fopen(exe_file_name, "rb");
    if (fp == NULL) {
        *error_val = -1;
        return 0;
    }

    // read the ELF header
    Elf64_Ehdr elf_header;
    fread(&elf_header, sizeof(Elf64_Ehdr), 1, fp);

    // check if the file is an executable
    if (elf_header.e_type != ET_EXEC) {
        *error_val = -3;
        return 0;
    }
    int i=0;
    // read the section header table
    Elf64_Shdr* section_header_table = (Elf64_Shdr*)malloc(elf_header.e_shentsize * elf_header.e_shnum);

    fseek(fp, elf_header.e_shoff, SEEK_SET);
    fread(section_header_table, elf_header.e_shentsize, elf_header.e_shnum, fp);

    // read the string table
    char* string_table = (char*)malloc(section_header_table[elf_header.e_shstrndx].sh_size);
    fseek(fp, section_header_table[elf_header.e_shstrndx].sh_offset, SEEK_SET);
    fread(string_table, section_header_table[elf_header.e_shstrndx].sh_size, 1, fp);

    // read the symbol table
    Elf64_Sym* symbol_table = NULL;
    int symbol_table_size = 0;

    for (int i = 0; i < elf_header.e_shnum; i++) {
        if (strcmp(string_table + section_header_table[i].sh_name, ".symtab") == 0) {
            symbol_table_size = section_header_table[i].sh_size / section_header_table[i].sh_entsize;
            symbol_table = (Elf64_Sym*)malloc(section_header_table[i].sh_entsize * symbol_table_size);
            fseek(fp, section_header_table[i].sh_offset, SEEK_SET);
            fread(symbol_table, section_header_table[i].sh_entsize, symbol_table_size, fp);
            break;
        }
    }

    // read the string table of the symbol table
    char* symbol_string_table = NULL;
    int symbol_string_table_size = 0;

    for (int i = 0; i < elf_header.e_shnum; i++) {
        if (strcmp(string_table + section_header_table[i].sh_name, ".strtab") == 0) {
            symbol_string_table_size = section_header_table[i].sh_size;
            symbol_string_table = (char*)malloc(symbol_string_table_size);
            fseek(fp, section_header_table[i].sh_offset, SEEK_SET);
            fread(symbol_string_table, symbol_string_table_size, 1, fp);
            break;
        }
    }

    // search for the symbol
    Elf64_Addr symbol_address = 0;
    bool symbol_found = false;
    bool symbol_is_global = false;

    // check if the symbol is defined in the executable
    bool symbol_is_defined_in_executable = false;

    for ( i = 0; i < symbol_table_size; i++) {
        if (strcmp(symbol_string_table + symbol_table[i].st_name, symbol_name) == 0) {
            symbol_found = true;
            symbol_address = symbol_table[i].st_value;

            if (!symbol_table[i].st_shndx) {
                symbol_is_defined_in_executable = false;
            }
            else {
                symbol_is_defined_in_executable = true;
            }
            // check if the symbol is global
            if (ELF64_ST_BIND(symbol_table[i].st_info) == 1) {
                symbol_is_global = true;
                break;
            }
        }
    }

    // get address if undefined in executable

    char* dynamic_symbol_string_table = NULL;
    int dynamic_symbol_string_table_size = 0;

    Elf64_Sym* dynamic_symbol_table = NULL;
    int dynamic_symbol_table_size = 0;
    int symbol_index = 0;

    Elf64_Rela* relocation_table = NULL;
    int relocation_table_size = 0;

    if(!symbol_is_defined_in_executable){

        // read the string table of the dynamic symbol table
        for (int i = 0; i < elf_header.e_shnum; i++) {
            if (strcmp(string_table + section_header_table[i].sh_name, ".dynstr") == 0) {
                dynamic_symbol_string_table_size = section_header_table[i].sh_size;
                dynamic_symbol_string_table = (char*)malloc(dynamic_symbol_string_table_size);
                fseek(fp, section_header_table[i].sh_offset, SEEK_SET);
                fread(dynamic_symbol_string_table, dynamic_symbol_string_table_size, 1, fp);
                break;
            }
        }

        // read the symbol table
        for (int i = 0; i < elf_header.e_shnum; i++) {
            if (strcmp(string_table + section_header_table[i].sh_name, ".dynsym") == 0) {
                dynamic_symbol_table_size = section_header_table[i].sh_size / section_header_table[i].sh_entsize;
                dynamic_symbol_table = (Elf64_Sym*)malloc(section_header_table[i].sh_entsize * dynamic_symbol_table_size);
                fseek(fp, section_header_table[i].sh_offset, SEEK_SET);
                fread(dynamic_symbol_table, section_header_table[i].sh_entsize, dynamic_symbol_table_size, fp);
                break;
            }
        }

        // get index of the symbol table in the dynamic symbol table
        for ( i = 0; i < dynamic_symbol_table_size; i++) {
//            printf("%s\n", dynamic_symbol_string_table + dynamic_symbol_table[i].st_name);
            if (strcmp(dynamic_symbol_string_table + dynamic_symbol_table[i].st_name, symbol_name) == 0) {
                symbol_found = true;
                symbol_index = i;
//
//                if (!dynamic_symbol_table[i].st_shndx) {
//                    symbol_is_defined_in_executable = false;
//                }
//                else {
//                    symbol_is_defined_in_executable = true;
//                }
//                // check if the symbol is global
//                if (ELF64_ST_BIND(dynamic_symbol_table[i].st_info) == 1) {
//                    symbol_is_global = true;
//                    break;
//                }
            }
        }

        // read relocation_table
        for (int i = 0; i < elf_header.e_shnum; i++) {
            if (strcmp(string_table + section_header_table[i].sh_name, ".rela.plt") == 0) {
                relocation_table_size = section_header_table[i].sh_size / section_header_table[i].sh_entsize;
                relocation_table = (Elf64_Rela*)malloc(section_header_table[i].sh_entsize * relocation_table_size);
                fseek(fp, section_header_table[i].sh_offset, SEEK_SET);
                fread(relocation_table, section_header_table[i].sh_entsize, relocation_table_size, fp);
                break;
            }
        }

        // find relocated symbol
        for ( i = 0; i < relocation_table_size; i++) {
            if (ELF64_R_SYM(relocation_table[i].r_info) == symbol_index) {
                symbol_address = relocation_table[i].r_offset;
                break;
            }
        }
    }


    // check if the symbol was found
    if (!symbol_found) {
        *error_val = -1;
        if (section_header_table != NULL){
            free(section_header_table);
        }
        if (string_table != NULL){
            free(string_table);
        }
        if (symbol_table != NULL){
            free(symbol_table);
        }
        if (symbol_string_table != NULL){
            free(symbol_string_table);
        }

        if (relocation_table != NULL){
            free(relocation_table);
        }
        if (dynamic_symbol_string_table != NULL){
            free(dynamic_symbol_string_table);
        }
        if (dynamic_symbol_table != NULL){
            free(dynamic_symbol_table);
        }
        return 0;
    }


    // check if the symbol is global
    if (!symbol_is_global) {
        *error_val = -2;
        if (section_header_table != NULL){
            free(section_header_table);
        }
        if (string_table != NULL){
            free(string_table);
        }
        if (symbol_table != NULL){
            free(symbol_table);
        }
        if (symbol_string_table != NULL){
            free(symbol_string_table);
        }
        if (relocation_table != NULL){
            free(relocation_table);
        }
        if (dynamic_symbol_string_table != NULL){
            free(dynamic_symbol_string_table);
        }
        if (dynamic_symbol_table != NULL){
            free(dynamic_symbol_table);
        }
        return 0;
    }

    // free the allocated memory
    if (section_header_table != NULL){
        free(section_header_table);
    }
    if (string_table != NULL){
        free(string_table);
    }
    if (symbol_table != NULL){
        free(symbol_table);
    }
    if (symbol_string_table != NULL){
        free(symbol_string_table);
    }
    if (relocation_table != NULL){
        free(relocation_table);
    }
    if (dynamic_symbol_string_table != NULL){
        free(dynamic_symbol_string_table);
    }
    if (dynamic_symbol_table != NULL){
        free(dynamic_symbol_table);
    }

    // return the address of the symbol
    *error_val = 1;
    if (symbol_found && symbol_is_global && !symbol_is_defined_in_executable) {
        *error_val = -4;
    }
    return symbol_address;
}

pid_t run_target(const char* programname)
{
    pid_t pid;

    pid = fork();

    if (pid > 0) {
        return pid;

    } else if (pid == 0) {
        /* Allow tracing of this process */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        /* Replace this process's image with the given program */
        execl(programname, programname, NULL);

    } else {
        // fork error
        perror("fork");
        exit(1);
    }
}



Elf64_Addr get_shared_func_addr(pid_t child_pid, Elf64_Addr addr){
    int wait_status;
    struct user_regs_struct regs;
    Elf64_Addr got_addr_ptr_new;

    // plt address stored in got
    Elf64_Addr got_addr_ptr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
    //printf("DBG: got_addr_ptr at 0x%lx: 0x%lx\n", addr, got_addr_ptr);

    // machine code of plt
    Elf64_Addr data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)got_addr_ptr, NULL);
    //printf("DBG: Original data at 0x%lx: 0x%lx\n", got_addr_ptr, data);


    // breakpoint plt in order to examine changes in got
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)got_addr_ptr, (void*)data_trap);

    /* Let the child run to the breakpoint and wait for it to reach it */
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);
    if(WIFEXITED(wait_status)){
        exit(0);
    }

    /* See where the child is now */
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    //printf("DBG: Child stopped at RIP = 0x%llx\n", regs.rip);

    /* Remove plt's breakpoint by restoring the previous data */
    ptrace(PTRACE_POKETEXT, child_pid, (void*)got_addr_ptr, (void*)data);
    regs.rip -= 1;
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

    while (WIFSTOPPED(wait_status)) {
        got_addr_ptr_new = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
        //printf("DBG: got_addr_ptr_new at 0x%llx: 0x%llx\n", addr, got_addr_ptr_new);

        if(got_addr_ptr_new != got_addr_ptr){

            return got_addr_ptr_new;
        }

        /* Make the child execute another instruction */
        if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
            perror("ptrace");
            exit(0);
        }

        /* Wait for child to stop on its next instruction */
        wait(&wait_status);
        if(WIFEXITED(wait_status)){
            exit(0);
        }
    }
}
void break_start_func(unsigned long data, unsigned long data_trap, Elf64_Addr func_addr, pid_t child_pid){
    struct user_regs_struct regs;
    int wait_status;

    // breakpoint real function
    data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)func_addr, NULL);
    //printf("DBG: Original data at 0x%lx: 0x%lx\n", func_addr, data);
    data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)func_addr, (void*)data_trap);

    /* Let the child run to the breakpoint and wait for it to reach it */
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);
    if(WIFEXITED(wait_status)){
        exit(0);
    }

    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    ptrace(PTRACE_POKETEXT, child_pid, (void*)func_addr, (void*)data);
    regs.rip -= 1;
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
}

void run_breakpoint_debugger(pid_t child_pid, Elf64_Addr addr, bool is_shared_function)
{
    int wait_status;
    struct user_regs_struct regs;
    //unsigned long long func_addr;
    Elf64_Addr func_addr;
    unsigned long data, data_trap;
    int call_counter = 1;
    //int diff_func_from_ret = 0

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    if(WIFEXITED(wait_status)){
        exit(0);
    }

    // get actual func address
    func_addr = is_shared_function ? get_shared_func_addr(child_pid, addr) : addr;

    break_start_func(data, data_trap, func_addr, child_pid);
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

    //breakpoint end function
    Elf64_Addr return_address = ptrace(PTRACE_PEEKTEXT, child_pid, (regs.rsp), NULL); // (regs.rsp)
    unsigned long return_data = ptrace(PTRACE_PEEKTEXT, child_pid, return_address, NULL);
    unsigned long return_data_trap = (return_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, return_address, (void*)return_data_trap);
    //printf("DBG: ret addr : 0x%lx\n", return_address);
    //diff_func_from_ret++;

    while(true){
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
        if(WIFEXITED(wait_status)){
            exit(0);
        }

        /* See where the child is now */
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        //printf("DBG: Child stopped at RIP = 0x%llx\n", regs.rip);

        /* Remove the breakpoint by restoring the previous data */
        ptrace(PTRACE_POKETEXT, child_pid, (void*)return_address, (void*)return_data);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

        //DEBUG:: print_registers(child_pid);
        printf("PRF:: run %d returned with %d\n", call_counter++, (int)regs.rdx);

        break_start_func(data, data_trap, func_addr, child_pid);
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

        //breakpoint end function
        return_address = ptrace(PTRACE_PEEKTEXT, child_pid, (regs.rsp), NULL); // (regs.rsp)
        return_data = ptrace(PTRACE_PEEKTEXT, child_pid, return_address, NULL);
        return_data_trap = (return_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, return_address, (void*)return_data_trap);

//        /* The child can continue running now */
//        ptrace(PTRACE_CONT, child_pid, 0, 0);
//        wait(&wait_status);
//        if (WIFEXITED(wait_status)) {
//            printf("DBG: Child exited\n");
//        } else {
//            printf("DBG: Unexpected signal\n");
//        }
    }

}

void print_registers(pid_t child) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, NULL, &regs);
    printf("rax: %llu\n", regs.rax);
    printf("rbx: %llu\n", regs.rbx);
    printf("rcx: %llu\n", regs.rcx);
    printf("rdx: %llu\n", regs.rdx);
    printf("rsi: %llu\n", regs.rsi);
    printf("rdi: %llu\n", regs.rdi);
    printf("rbp: %llu\n", regs.rbp);
    printf("rsp: %llu\n", regs.rsp);
    printf("r8: %llu\n", regs.r8);
    printf("r9: %llu\n", regs.r9);
    printf("r10: %llu\n", regs.r10);
    printf("r11: %llu\n", regs.r11);
    printf("r12: %llu\n", regs.r12);
    printf("r13: %llu\n", regs.r13);
    printf("r14: %llu\n", regs.r14);
    printf("r15: %llu\n", regs.r15);
    printf("rip: %llu\n", regs.rip);
    printf("eflags: %llu\n", regs.eflags);
}

int main(int argc, char *const argv[]) {
    int err = 0;
    Elf64_Addr addr = find_symbol(argv[1] ,argv[2], &err);
    //Elf64_Addr addr = find_symbol("addSoVar", "main.out", &err);
    
    //printf("%s will be loaded to 0x%lx\n", argv[1], addr);
    if (err == -3){
        printf("PRF:: %s not an executable! :(\n", argv[2]);
        return 0;
    }
    if (err == -1){
        printf("PRF:: %s not found!\n", argv[1]);
        return 0;
    }
    if (err == -2){
        printf("PRF:: %s is not a global symbol! :(\n", argv[1]);
        return 0;
    }

    pid_t child_pid;
    child_pid = run_target(argv[2]);
    //child_pid = run_target("main.out");

    // shared object function
    if (err == -4) {
//        printf("PRF:: %s is a global symbol, but will come from a shared library\n", argv[1]);
        run_breakpoint_debugger(child_pid, addr, true);
    }

    // local function
    if(err > 0){
        // run specific "debugger"
        run_breakpoint_debugger(child_pid, addr, false);
    }

    return 0;
}