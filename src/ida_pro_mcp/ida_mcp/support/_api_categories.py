"""
Canonical API category mappings for reverse engineering analysis.
Centralized to eliminate duplication across tool files.
"""

# ============================================================================
# Canonical API Categories (used by classify, summarize, llm_helpers, search, annotation)
# ============================================================================

API_CATEGORIES = {
    "network": [
        "socket", "connect", "bind", "listen", "accept", "send", "recv",
        "sendto", "recvfrom", "select", "poll", "shutdown", "closesocket",
        "WSAStartup", "WSACleanup", "WSAGetLastError", "WSASocket",
        "WSASend", "WSARecv", "WSAConnect",
        "getaddrinfo", "gethostbyname", "inet_addr", "inet_ntoa",
        "htons", "htonl", "ntohs", "ntohl",
        "InternetOpen", "InternetConnect", "HttpOpenRequest",
        "HttpSendRequest", "InternetReadFile", "URLDownloadToFile",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
        "WinHttpSendRequest", "WinHttpReceiveResponse",
        "curl_easy_init", "curl_easy_perform", "curl_easy_setopt", "curl_easy_cleanup",
        "SSL_read", "SSL_write", "SSL_connect",
    ],
    "file_io": [
        "CreateFile", "CreateFileA", "CreateFileW",
        "ReadFile", "WriteFile", "CloseHandle", "DeleteFile",
        "CopyFile", "MoveFile", "GetFileSize", "SetFilePointer",
        "FindFirstFile", "FindNextFile", "FindClose",
        "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "fgets", "fputs",
        "open", "close", "read", "write", "lseek",
        "stat", "fstat", "lstat", "unlink", "rename",
        "mkdir", "rmdir", "opendir", "readdir",
    ],
    "crypto": [
        "CryptAcquireContext", "CryptCreateHash", "CryptHashData",
        "CryptDeriveKey", "CryptEncrypt", "CryptDecrypt",
        "CryptGenRandom", "CryptReleaseContext",
        "BCryptOpenAlgorithmProvider", "BCryptGenerateSymmetricKey",
        "BCryptEncrypt", "BCryptDecrypt",
        "CreateHash", "HashData",
        "EVP_EncryptInit", "EVP_DecryptInit", "EVP_DigestInit",
        "EVP_EncryptUpdate", "EVP_DecryptUpdate", "EVP_DigestUpdate",
        "EVP_EncryptFinal", "EVP_DecryptFinal", "EVP_DigestFinal",
        "AES_encrypt", "AES_decrypt", "AES_set_encrypt_key", "AES_set_decrypt_key",
        "RSA_public_encrypt", "RSA_private_decrypt",
        "SHA1", "SHA256", "SHA384", "SHA512",
        "SHA1_Init", "SHA1_Update", "SHA1_Final",
        "SHA256_Init", "SHA256_Update", "SHA256_Final",
        "MD5_Init", "MD5_Update", "MD5_Final", "MD5Init", "MD5Update", "MD5Final",
        "HMAC", "HMAC_Init", "HMAC_Update", "HMAC_Final",
        "RAND_bytes", "RAND_pseudo_bytes",
    ],
    "memory": [
        "malloc", "calloc", "realloc", "free",
        "VirtualAlloc", "VirtualFree", "VirtualProtect", "VirtualQuery",
        "HeapAlloc", "HeapFree", "HeapCreate", "HeapDestroy",
        "GlobalAlloc", "GlobalFree", "LocalAlloc", "LocalFree",
        "mmap", "munmap", "mprotect", "brk", "sbrk",
        "new", "delete", "operator new", "operator delete",
        "memcpy", "memmove", "memset", "memcmp",
    ],
    "process": [
        "CreateProcess", "CreateProcessA", "CreateProcessW",
        "OpenProcess", "TerminateProcess", "ExitProcess",
        "GetCurrentProcess", "GetCurrentProcessId", "GetProcessId",
        "CreateThread", "CreateRemoteThread", "ExitThread",
        "GetCurrentThread", "GetCurrentThreadId",
        "WaitForSingleObject", "WaitForMultipleObjects",
        "fork", "exec", "execl", "execv", "execve", "execvp",
        "system", "popen", "kill", "waitpid", "wait",
        "ShellExecute", "ShellExecuteEx",
        "posix_spawn", "clone", "pthread_create", "pthread_join",
    ],
    "registry": [
        "RegOpenKey", "RegOpenKeyEx", "RegOpenKeyExA", "RegOpenKeyExW",
        "RegCloseKey",
        "RegQueryValue", "RegQueryValueEx", "RegQueryValueExA", "RegQueryValueExW",
        "RegSetValue", "RegSetValueEx", "RegSetValueExA", "RegSetValueExW",
        "RegCreateKey", "RegCreateKeyEx",
        "RegDeleteKey", "RegDeleteValue",
        "RegEnumKey", "RegEnumKeyEx", "RegEnumValue",
    ],
    "string_ops": [
        "strcpy", "strncpy", "strcat", "strncat", "strlen", "strcmp",
        "strncmp", "strstr", "strchr", "strrchr", "strtok",
        "sprintf", "snprintf", "sscanf", "printf", "fprintf",
        "wcslen", "wcscpy", "wcscat", "wcscmp", "wcsstr",
        "lstrcpy", "lstrcmp", "lstrlen", "lstrcat",
        "MultiByteToWideChar", "WideCharToMultiByte",
        "strtol", "strtoul", "atoi", "atol", "atof",
    ],
    "math": [
        "sin", "cos", "tan", "asin", "acos", "atan", "atan2",
        "sqrt", "pow", "exp", "log", "log10", "log2",
        "floor", "ceil", "round", "fabs", "fmod",
        "abs", "labs", "llabs", "div", "ldiv",
    ],
    "ui": [
        "CreateWindow", "CreateWindowEx", "ShowWindow", "UpdateWindow",
        "MessageBox", "MessageBoxA", "MessageBoxW",
        "DialogBox", "DialogBoxParam", "EndDialog",
        "GetDlgItem", "SetDlgItemText", "GetDlgItemText",
        "SendMessage", "PostMessage", "DefWindowProc",
        "RegisterClass", "RegisterClassEx",
        "GetMessage", "TranslateMessage", "DispatchMessage",
        "BeginPaint", "EndPaint", "InvalidateRect",
        "DrawText", "TextOut", "SetWindowText", "GetWindowText",
    ],
    "authentication": [
        "LogonUser", "LogonUserA", "LogonUserW",
        "LookupAccountSid", "LookupAccountName",
        "OpenProcessToken", "AdjustTokenPrivileges",
        "GetTokenInformation", "SetTokenInformation",
        "ImpersonateLoggedOnUser", "RevertToSelf",
        "LsaOpenPolicy", "LsaEnumerateAccountRights",
        "getpwnam", "getpwuid", "getgrnam", "crypt",
    ],
    "logging": [
        "OutputDebugString", "OutputDebugStringA", "OutputDebugStringW",
        "ReportEvent", "RegisterEventSource",
        "syslog", "openlog", "closelog",
        "vfprintf", "vsprintf", "vsnprintf",
    ],
    "error_handling": [
        "GetLastError", "SetLastError", "FormatMessage",
        "RaiseException", "SetUnhandledExceptionFilter",
        "AddVectoredExceptionHandler",
        "signal", "raise", "abort",
        "perror", "strerror", "errno",
        "__cxa_throw", "__cxa_begin_catch", "__cxa_end_catch",
        "_CxxThrowException",
    ],
    "serialization": [
        "json_object_new", "json_object_get", "json_tokener_parse",
        "cJSON_Parse", "cJSON_Print", "cJSON_CreateObject",
        "xmlReadFile", "xmlReadMemory", "xmlParseFile",
        "xmlNewDoc", "xmlNewNode", "xmlSaveFile",
        "yaml_parser_initialize", "yaml_parser_parse",
        "protobuf_c_message_pack", "protobuf_c_message_unpack",
    ],
    "compression": [
        "compress", "compress2", "uncompress",
        "deflateInit", "deflate", "deflateEnd",
        "inflateInit", "inflate", "inflateEnd",
        "BZ2_bzCompress", "BZ2_bzDecompress",
        "LZ4_compress", "LZ4_decompress_safe",
        "ZSTD_compress", "ZSTD_decompress",
    ],
    "sync": [
        "InitializeCriticalSection", "EnterCriticalSection",
        "LeaveCriticalSection", "DeleteCriticalSection",
        "CreateMutex", "ReleaseMutex", "CreateEvent", "SetEvent",
        "CreateSemaphore", "ReleaseSemaphore",
        "pthread_mutex_init", "pthread_mutex_lock", "pthread_mutex_unlock",
    ],
}

# Build reverse lookup: api_name -> category
API_TO_CATEGORY = {}
for _cat, _apis in API_CATEGORIES.items():
    for _api in _apis:
        API_TO_CATEGORY[_api.lower()] = _cat


# ============================================================================
# Dangerous APIs (used by annotation, threat_hunt, search)
# ============================================================================

DANGEROUS_APIS = {
    # Buffer overflow
    "strcpy": "unbounded copy - use strncpy/strlcpy",
    "strcat": "unbounded concat - use strncat/strlcat",
    "sprintf": "unbounded format - use snprintf",
    "gets": "no bounds checking - use fgets",
    "scanf": "no bounds checking - use fgets+sscanf",
    "vsprintf": "unbounded format - use vsnprintf",
    "wcscpy": "unbounded wide copy - use wcsncpy",
    "wcscat": "unbounded wide concat - use wcsncat",
    "lstrcpy": "unbounded copy - use StringCchCopy",
    "lstrcpyA": "unbounded copy - use StringCchCopyA",
    "lstrcpyW": "unbounded copy - use StringCchCopyW",
    "lstrcat": "unbounded concat - use StringCchCat",
    "lstrcatA": "unbounded concat - use StringCchCatA",
    "lstrcatW": "unbounded concat - use StringCchCatW",
    "memcpy": "verify size parameter - potential overflow",
    "memmove": "verify size parameter - potential overflow",
    "RtlCopyMemory": "verify size parameter - potential overflow",
    # Injection / execution
    "VirtualAlloc": "check for RWX permissions (PAGE_EXECUTE_READWRITE)",
    "VirtualProtect": "check for RWX permissions - code injection indicator",
    "CreateRemoteThread": "remote thread creation - injection technique",
    "WriteProcessMemory": "remote memory write - injection technique",
    "NtWriteVirtualMemory": "remote memory write - injection technique",
    "ShellExecute": "command execution - check for user-controlled input",
    "ShellExecuteA": "command execution - check for user-controlled input",
    "ShellExecuteW": "command execution - check for user-controlled input",
    "WinExec": "command execution - check for user-controlled input",
    "system": "shell command execution - check for injection",
    "popen": "shell command execution - check for injection",
    "exec": "process execution - check for injection",
    "execl": "process execution - check for injection",
    "execv": "process execution - check for injection",
    "execve": "process execution - check for injection",
    # Evasion
    "LoadLibrary": "dynamic library loading - check source",
    "LoadLibraryA": "dynamic library loading - check source",
    "LoadLibraryW": "dynamic library loading - check source",
    "GetProcAddress": "dynamic API resolution - evasion technique",
    "URLDownloadToFile": "file download - check URL source",
    "URLDownloadToFileA": "file download - check URL source",
    "InternetReadFile": "network read - validate buffer size",
    # Persistence
    "RegSetValueEx": "registry modification - persistence indicator",
    "RegSetValueExA": "registry modification - persistence indicator",
    "RegSetValueExW": "registry modification - persistence indicator",
    "SetWindowsHookEx": "global hook - keylogger/injection indicator",
    "SetWindowsHookExA": "global hook - keylogger/injection indicator",
    "SetWindowsHookExW": "global hook - keylogger/injection indicator",
    "NtCreateThreadEx": "thread creation - injection technique",
    "RtlCreateUserThread": "thread creation - injection technique",
    # Privilege escalation
    "AdjustTokenPrivileges": "privilege escalation",
    "ImpersonateLoggedOnUser": "privilege escalation via impersonation",
}


# ============================================================================
# Tag Categories (used by annotation for function tagging)
# ============================================================================

TAG_CATEGORIES = {
    "crypto": ["CryptAcquireContext", "CryptCreateHash", "CryptEncrypt", "CryptDecrypt",
               "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt",
               "EVP_EncryptInit", "EVP_DecryptInit", "AES_encrypt", "AES_decrypt",
               "SHA256", "SHA1", "MD5_Init", "HMAC"],
    "network": ["socket", "connect", "send", "recv", "bind", "listen", "accept",
                "WSAStartup", "InternetOpen", "HttpOpenRequest", "HttpSendRequest",
                "WinHttpOpen", "curl_easy_init", "getaddrinfo", "gethostbyname"],
    "file_io": ["CreateFile", "ReadFile", "WriteFile", "DeleteFile", "CopyFile",
                "fopen", "fread", "fwrite", "open", "read", "write", "stat"],
    "process": ["CreateProcess", "OpenProcess", "CreateThread", "CreateRemoteThread",
                "fork", "exec", "system", "ShellExecute", "TerminateProcess"],
    "registry": ["RegOpenKey", "RegOpenKeyEx", "RegSetValueEx", "RegQueryValueEx",
                 "RegCreateKeyEx", "RegDeleteKey", "RegDeleteValue"],
    "memory": ["VirtualAlloc", "VirtualProtect", "HeapAlloc", "malloc", "calloc",
               "mmap", "mprotect", "VirtualFree", "HeapFree"],
    "string_ops": ["strcpy", "strcat", "strlen", "strcmp", "sprintf", "strstr",
                   "wcslen", "wcscpy", "MultiByteToWideChar", "WideCharToMultiByte"],
    "ui": ["CreateWindow", "MessageBox", "ShowWindow", "DialogBox", "SendMessage",
           "GetMessage", "DispatchMessage"],
    "anti_debug": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                   "NtQueryInformationProcess", "OutputDebugString"],
    "persistence": ["RegSetValueEx", "CreateService", "RegCreateKeyEx",
                    "SetWindowsHookEx", "schtasks"],
    "evasion": ["GetProcAddress", "LoadLibrary", "VirtualProtect",
                "NtUnmapViewOfSection", "NtWriteVirtualMemory"],
}

# Build reverse lookup for tags
API_TO_TAG = {}
for _tag, _apis in TAG_CATEGORIES.items():
    for _api in _apis:
        API_TO_TAG.setdefault(_api.lower(), []).append(_tag)


# ============================================================================
# Magic Constants (used by annotation)
# ============================================================================

MAGIC_CONSTANTS = {
    0x5A4D: "IMAGE_DOS_SIGNATURE ('MZ')",
    0x4550: "IMAGE_NT_SIGNATURE ('PE')",
    0x014C: "IMAGE_FILE_MACHINE_I386",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
    0xAA64: "IMAGE_FILE_MACHINE_ARM64",
    0xFEEDFACE: "MH_MAGIC (Mach-O 32-bit)",
    0xFEEDFACF: "MH_MAGIC_64 (Mach-O 64-bit)",
    0x464C457F: "ELF_MAGIC",
    0xDEADBEEF: "common debug marker",
    0xCAFEBABE: "Java class / universal binary magic",
    0xD00DFEED: "device tree blob magic",
    0x80000000: "GENERIC_READ / sign bit",
    0x40000000: "GENERIC_WRITE",
    0x20000000: "GENERIC_EXECUTE",
    0x10000000: "GENERIC_ALL",
    0xC0000000: "GENERIC_READ | GENERIC_WRITE",
    0x00000001: "FILE_SHARE_READ / TRUE",
    0x00000002: "FILE_SHARE_WRITE / WM_DESTROY",
    0x00000003: "OPEN_EXISTING",
    0x00000004: "OPEN_ALWAYS / FILE_SHARE_DELETE",
    0x00000005: "TRUNCATE_EXISTING",
    0x00000040: "PAGE_EXECUTE_READWRITE",
    0x00000080: "FILE_ATTRIBUTE_NORMAL",
    0x00001000: "MEM_COMMIT / PAGE_SIZE",
    0x00002000: "MEM_RESERVE",
    0x00004000: "MEM_DECOMMIT",
    0xFFFFFFFF: "INVALID_HANDLE_VALUE (-1)",
    0x0200: "WM_CHAR",
    0x0100: "WM_KEYDOWN",
    0x0101: "WM_KEYUP",
    0x000F: "WM_PAINT",
    0x0010: "WM_CLOSE",
    0x0012: "WM_QUIT",
    0x0111: "WM_COMMAND",
    0x0400: "WM_USER",
    0x8000: "MEM_RELEASE / INTERNET_FLAG_RELOAD",
    0x1F0FFF: "PROCESS_ALL_ACCESS",
    0x001F03FF: "THREAD_ALL_ACCESS",
}
