from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnPattern:
    id: str
    name: str
    description: str
    indicator_functions: list[str]
    indicator_strings: list[str]
    indicator_patterns: list[str]
    severity: str
    cwe_id: str
    remediation: str


VULN_PATTERNS: list[VulnPattern] = [
    VulnPattern("VP001", "strcpy_without_bounds", "Unbounded string copy into destination buffer.", ["strcpy", "strcat"], ["copy", "buffer"], ["strcpy(", "strcat("], "High", "CWE-120", "Use bounded copy APIs and validate destination capacity."),
    VulnPattern("VP002", "gets_usage", "Unsafe gets() allows unbounded input.", ["gets"], ["input"], ["gets("], "Critical", "CWE-242", "Replace gets() with fgets() and explicit size checks."),
    VulnPattern("VP003", "printf_non_literal", "User data reaches format string sinks.", ["printf", "sprintf", "syslog"], ["%n", "format"], ["printf(", "sprintf("], "High", "CWE-134", "Use constant format strings and sanitize user input."),
    VulnPattern("VP004", "malloc_without_null_check", "Allocated pointer used without null check.", ["malloc", "calloc", "realloc"], ["alloc"], ["malloc(", "calloc("], "Medium", "CWE-690", "Validate allocation result before dereference."),
    VulnPattern("VP005", "integer_overflow_alloc", "Integer arithmetic before allocation may overflow.", ["malloc", "new"], ["size", "count"], ["* sizeof", "count *"], "High", "CWE-190", "Use checked arithmetic and upper bounds."),
    VulnPattern("VP006", "pthread_mutex_misuse", "Potential race due to missing lock discipline.", ["pthread_mutex_lock", "pthread_mutex_unlock"], ["lock", "race"], ["pthread_mutex_"], "Medium", "CWE-362", "Enforce lock ordering and guard shared state."),
    VulnPattern("VP007", "memcpy_user_size", "Copy size may be user-controlled.", ["memcpy", "memmove"], ["length", "size"], ["memcpy(", "memmove("], "High", "CWE-119", "Validate copy length against both source and destination."),
    VulnPattern("VP008", "use_after_free", "Freed pointer may be reused.", ["free"], ["dangling", "uaf"], ["free(", "->"], "High", "CWE-416", "Null-out pointers after free and avoid post-free dereference."),
    VulnPattern("VP009", "command_injection_system", "Command execution from untrusted input.", ["system", "popen", "execve"], ["cmd", "shell"], ["system(", "popen("], "Critical", "CWE-78", "Use allow-listed commands and argumentized execution."),
    VulnPattern("VP010", "path_traversal", "User path input may escape intended directory.", ["fopen", "open", "CreateFile"], ["..", "/../"], ["../", "..\\"], "High", "CWE-22", "Canonicalize and constrain paths to trusted roots."),
    VulnPattern("VP011", "hardcoded_crypto_key", "Embedded secret key material detected.", ["AES_set_encrypt_key", "EVP_EncryptInit"], ["key=", "secret"], ["hardcoded", "key"], "High", "CWE-321", "Load keys from secure storage and rotate regularly."),
    VulnPattern("VP012", "weak_randomness", "Non-cryptographic RNG used for sensitive values.", ["rand", "srand"], ["token", "nonce"], ["rand(", "srand("], "High", "CWE-338", "Use cryptographically secure RNG."),
    VulnPattern("VP013", "unsafe_temp_file", "Predictable temp filename usage.", ["tmpnam", "mktemp"], ["/tmp", "temp"], ["tmpnam(", "mktemp("], "Medium", "CWE-377", "Use secure temp file creation APIs."),
    VulnPattern("VP014", "deserialization_untrusted", "Untrusted serialized data processing.", ["deserialize", "pickle", "protobuf"], ["payload"], ["deserialize", "unmarshal"], "High", "CWE-502", "Validate schema and authenticate serialized inputs."),
    VulnPattern("VP015", "sql_injection", "Unsanitized query construction.", ["sqlite3_exec", "mysql_query"], ["select", "where"], ["SELECT ", "INSERT "], "High", "CWE-89", "Use parameterized queries."),
    VulnPattern("VP016", "xml_external_entity", "XXE-capable parser configuration.", ["xmlReadMemory", "SAXParse"], ["DOCTYPE", "ENTITY"], ["<!DOCTYPE", "<!ENTITY"], "High", "CWE-611", "Disable external entities and DTD processing."),
    VulnPattern("VP017", "improper_auth_check", "Authentication checks missing or bypassable.", ["strcmp", "memcmp"], ["auth", "password"], ["auth", "login"], "Critical", "CWE-287", "Enforce centralized auth checks and fail-closed logic."),
    VulnPattern("VP018", "insecure_permissions", "File/object created with broad permissions.", ["chmod", "CreateFile"], ["0777", "Everyone"], ["0777", "FILE_ALL_ACCESS"], "Medium", "CWE-732", "Restrict ACLs to least privilege."),
    VulnPattern("VP019", "stack_overflow_recursion", "Unbounded recursion or deep stack use.", [], ["recursive"], ["while(1)", "recursion"], "Medium", "CWE-674", "Bound recursion depth and validate stack usage."),
    VulnPattern("VP020", "missing_input_validation", "Input parsing lacks boundary checks.", ["recv", "read", "fread"], ["len", "size"], ["if (len", "bounds"], "High", "CWE-20", "Validate all external input lengths and ranges."),
]

