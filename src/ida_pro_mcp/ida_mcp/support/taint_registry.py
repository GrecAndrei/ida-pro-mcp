"""Canonical taint source and dangerous sink definitions.

Single source of truth for all taint-related name sets used across tools.
Imported by: taint.py, combinators.py, summarize.py, code.py, analysis.py
"""

# ── TAINT_SOURCES: Functions that receive external/user-controlled input ─────
# Union of all existing source sets. Firmware-aware (UART/DMA/SPI/I2C/USB).

TAINT_SOURCES: frozenset[str] = frozenset({
    # Network
    "recv", "recvfrom", "recvmsg", "WSARecv", "WSARecvFrom",
    "read", "fread", "fgets", "gets",
    # File / stdin
    "scanf", "sscanf", "fscanf",
    # Environment
    "getenv", "getenv_s",
    # Windows
    "ReadFile", "RegQueryValueEx", "GetEnvironmentVariable",
    "WinHttpReceiveResponse", "InternetReadFile",
    # Firmware: UART receive
    "UART_Receive", "UART_Read", "uart_read", "uart_receive", "uart_getc",
    "HAL_UART_Receive", "HAL_UART_Receive_IT", "HAL_UART_Receive_DMA",
    "USART_ReceiveData", "USART_GetFlagStatus",
    "Serial_Read", "serial_read", "serial_getchar",
    # Firmware: DMA receive buffers
    "DMA_Receive", "dma_read", "HAL_DMA_Start", "HAL_DMA_PollForTransfer",
    # Firmware: SPI/I2C/USB receive
    "SPI_Receive", "HAL_SPI_Receive", "HAL_I2C_Master_Receive",
    "HAL_I2C_Slave_Receive", "USB_ReadPacket", "USBD_LL_DataOutStage",
    "HAL_PCD_DataOutStageCallback",
    # Firmware: network stack (lwIP, FreeRTOS+TCP)
    "pbuf_alloc", "netconn_recv", "xNetworkInterfaceInput",
    "FreeRTOS_recv", "FreeRTOS_recvfrom",
    # Windows: additional
    "ioctl", "DeviceIoControl", "NtDeviceIoControlFile",
    "NtQueryInformationFile",
    "URLDownloadToFile", "URLDownloadToCacheFile",
    "WinHttpReadData",
    # Firmware: additional from combinators.py
    "sic_recv", "spi_receive", "i2c_read",
    "DMA_Callback", "vfs_read",
})

# ── DANGEROUS_SINKS: Functions dangerous when fed tainted data ───────────────
# Maps API name → vulnerability category string.
#
# Bounded variants (strncpy, strncat, snprintf) are intentionally NOT listed
# as sinks: they take explicit size limits and are credited as mitigations in
# MITIGATION_CHECKS["safe_functions"]. Listing them as both sink and
# mitigation would produce contradictory findings.

DANGEROUS_SINKS: dict[str, str] = {
    # Memory corruption
    "memcpy": "buffer_overflow",
    "memmove": "buffer_overflow",
    "strcpy": "buffer_overflow",
    "strcat": "buffer_overflow",
    "sprintf": "format_string",
    "vsprintf": "format_string",
    "gets": "buffer_overflow",
    "scanf": "buffer_overflow",
    "sscanf": "buffer_overflow",
    "fscanf": "buffer_overflow",
    "lstrcpy": "buffer_overflow",
    "lstrcat": "buffer_overflow",
    "RtlCopyMemory": "buffer_overflow",
    # Command execution
    "system": "command_injection",
    "exec": "command_injection",
    "execve": "command_injection",
    "execl": "command_injection",
    "popen": "command_injection",
    "ShellExecute": "command_injection",
    "WinExec": "command_injection",
    "CreateProcess": "command_injection",
    # Memory control
    "VirtualAlloc": "memory_control",
    "WriteProcessMemory": "process_injection",
    "mmap": "memory_control",
    "malloc": "memory_issue",
    "realloc": "memory_issue",
    "HeapAlloc": "memory_issue",
    # Format string
    "wsprintf": "format_string",
    "wvsprintf": "format_string",
    # DLL injection / dynamic resolution
    "LoadLibrary": "dll_injection",
    "LoadLibraryA": "dll_injection",
    "LoadLibraryW": "dll_injection",
    "LoadLibraryEx": "dll_injection",
    "GetProcAddress": "dynamic_resolution",
    # Firmware: unsafe transmit with attacker-controlled data
    "UART_Transmit": "firmware_output_injection",
    "HAL_UART_Transmit": "firmware_output_injection",
    "netconn_write": "firmware_output_injection",
    "FreeRTOS_send": "firmware_output_injection",
    # Firmware: flash write
    "HAL_FLASH_Program": "firmware_flash_write",
    "flash_write": "firmware_flash_write",
    "spi_flash_write": "firmware_flash_write",
}

# ── DANGEROUS_SINK_NAMES: Just the API names (for set lookups) ───────────────

DANGEROUS_SINK_NAMES: frozenset[str] = frozenset(DANGEROUS_SINKS.keys())

# ── VULN_TYPE_TO_CWE: Mapping from vulnerability category to CWE IDs ─────────

VULN_TYPE_TO_CWE: dict[str, list[str]] = {
    "buffer_overflow": ["CWE-120", "CWE-121", "CWE-122", "CWE-787"],
    "format_string": ["CWE-134"],
    "format_string_candidate": ["CWE-134"],
    "command_injection": ["CWE-78", "CWE-77"],
    "process_injection": ["CWE-94"],
    "memory_control": ["CWE-119"],
    "memory_issue": ["CWE-119"],
    "firmware_output_injection": ["CWE-78", "CWE-77"],
    "firmware_flash_write": ["CWE-1275"],
    "dll_injection": ["CWE-427"],
    "dynamic_resolution": ["CWE-912"],
}

# ── DANGEROUS_APIS_CATEGORIZED: Grouped by vulnerability category ────────────
# Derived from DANGEROUS_SINKS for summarize.py compatibility.

DANGEROUS_APIS_CATEGORIZED: dict[str, list[str]] = {
    "buffer_overflow": sorted(k for k, v in DANGEROUS_SINKS.items()
                              if "buffer" in v or "overflow" in v),
    "format_string": sorted(k for k, v in DANGEROUS_SINKS.items()
                             if "format" in v),
    "command_injection": sorted(k for k, v in DANGEROUS_SINKS.items()
                                 if v == "command_injection"),
    "memory_unsafe": sorted(k for k, v in DANGEROUS_SINKS.items()
                             if "memory" in v),
    "deprecated_crypto": ["MD5Init", "MD5Update", "SHA1Init",
                          "DES_ecb_encrypt", "RC4"],
}

# ── MITIGATION_CHECKS: Functions that indicate security mitigations ──────────

MITIGATION_CHECKS: dict[str, list[str]] = {
    "stack_canary": ["__stack_chk_fail", "__stack_chk_guard", "__security_check_cookie"],
    "aslr_related": ["__security_init_cookie", "IsProcessorFeaturePresent"],
    "safe_functions": ["strcpy_s", "strcat_s", "sprintf_s", "snprintf", "strncat", "strncpy"],
    "cfi": ["__cfi_check", "__cfi_slowpath"],
}
