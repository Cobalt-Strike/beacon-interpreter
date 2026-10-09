#include <windows.h>
#include <advapi.h>
#include <ntsecapi.h>
#include <beacon.h>

#define DACL_SECURITY_INFORMATION 0x00000004
#define ACCESS_ALLOWED_ACE_TYPE 0x00
#define ACCESS_DENIED_ACE_TYPE 0x01
#define CONTAINER_INHERIT_ACE 0x02
#define OBJECT_INHERIT_ACE 0x01
#define INHERIT_ONLY_ACE 0x08
#define ERROR_NONE_MAPPED 1332

#define FILE_READ_DATA 0x0001
#define FILE_WRITE_DATA 0x0002
#define FILE_APPEND_DATA 0x0004
#define FILE_READ_EA 0x0008
#define FILE_WRITE_EA 0x0010
#define FILE_EXECUTE 0x0020
#define FILE_DELETE_CHILD 0x0040
#define FILE_READ_ATTRIBUTES 0x0080
#define FILE_WRITE_ATTRIBUTES 0x0100
#define FILE_GENERIC_READ (READ_CONTROL | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE)
#define FILE_GENERIC_WRITE (READ_CONTROL | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE)
#define FILE_GENERIC_EXECUTE (READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE)
#define FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1ff)

typedef struct _ACCESS_ALLOWED_ACE {
    ACE_HEADER Header;
    DWORD Mask;
    DWORD SidStart;
} ACCESS_ALLOWED_ACE, *PACCESS_ALLOWED_ACE;

typedef struct _GENERIC_MAPPING {
    DWORD GenericRead;
    DWORD GenericWrite;
    DWORD GenericExecute;
    DWORD GenericAll;
} GENERIC_MAPPING, *PGENERIC_MAPPING;

ADVAPI32$ConvertSidToStringSidW: u32 (ptr, ptr);
ADVAPI32$LookupAccountSidW: u32 (ptr, ptr, ptr, ptr, ptr, ptr, ptr);

void init_rights() {
}

DWORD right_mask(int index) {
    if (index == 0) return FILE_WRITE_ATTRIBUTES;
    if (index == 1) return FILE_READ_ATTRIBUTES;
    if (index == 2) return FILE_DELETE_CHILD;
    if (index == 3) return FILE_EXECUTE;
    if (index == 4) return FILE_WRITE_EA;
    if (index == 5) return FILE_READ_EA;
    if (index == 6) return FILE_APPEND_DATA;
    if (index == 7) return FILE_WRITE_DATA;
    if (index == 8) return FILE_READ_DATA;
    if (index == 9) return FILE_GENERIC_EXECUTE;
    if (index == 10) return FILE_GENERIC_WRITE;
    if (index == 11) return FILE_GENERIC_READ;
    if (index == 12) return GENERIC_ALL;
    if (index == 13) return GENERIC_EXECUTE;
    if (index == 14) return GENERIC_WRITE;
    if (index == 15) return GENERIC_READ;
    if (index == 16) return MAXIMUM_ALLOWED;
    if (index == 17) return ACCESS_SYSTEM_SECURITY;
    if (index == 18) return SPECIFIC_RIGHTS_ALL;
    if (index == 19) return STANDARD_RIGHTS_REQUIRED;
    if (index == 20) return SYNCHRONIZE;
    if (index == 21) return WRITE_OWNER;
    if (index == 22) return WRITE_DAC;
    if (index == 23) return READ_CONTROL;
    if (index == 24) return DELETE;
    if (index == 25) return STANDARD_RIGHTS_ALL;
    return 0;
}

char *right_name(int index) {
    if (index == 0) return "FILE_WRITE_ATTRIBUTES";
    if (index == 1) return "FILE_READ_ATTRIBUTES";
    if (index == 2) return "FILE_DELETE_CHILD";
    if (index == 3) return "FILE_EXECUTE";
    if (index == 4) return "FILE_WRITE_EA";
    if (index == 5) return "FILE_READ_EA";
    if (index == 6) return "FILE_APPEND_DATA";
    if (index == 7) return "FILE_WRITE_DATA";
    if (index == 8) return "FILE_READ_DATA";
    if (index == 9) return "FILE_GENERIC_EXECUTE";
    if (index == 10) return "FILE_GENERIC_WRITE";
    if (index == 11) return "FILE_GENERIC_READ";
    if (index == 12) return "GENERIC_ALL";
    if (index == 13) return "GENERIC_EXECUTE";
    if (index == 14) return "GENERIC_WRITE";
    if (index == 15) return "GENERIC_READ";
    if (index == 16) return "MAXIMUM_ALLOWED";
    if (index == 17) return "ACCESS_SYSTEM_SECURITY";
    if (index == 18) return "SPECIFIC_RIGHTS_ALL";
    if (index == 19) return "STANDARD_RIGHTS_REQUIRED";
    if (index == 20) return "SYNCHRONIZE";
    if (index == 21) return "WRITE_OWNER";
    if (index == 22) return "WRITE_DAC";
    if (index == 23) return "READ_CONTROL";
    if (index == 24) return "DELETE";
    if (index == 25) return "STANDARD_RIGHTS_ALL";
    return "";
}

DWORD append_flags(formatp *out, BYTE flags) {
    DWORD indent;

    indent = 0;
    if (flags & CONTAINER_INHERIT_ACE) {
        BeaconFormatPrintf(out, "(CI)");
        indent += 4;
    }
    if (flags & OBJECT_INHERIT_ACE) {
        BeaconFormatPrintf(out, "(OI)");
        indent += 4;
    }
    if (flags & INHERIT_ONLY_ACE) {
        BeaconFormatPrintf(out, "(IO)");
        indent += 4;
    }
    return indent;
}

void append_prefix_spaces(formatp *out, DWORD count) {
    DWORD i;

    for (i = 0; i < count; i++) {
        BeaconFormatPrintf(out, " ");
    }
}

void append_special_rights(formatp *out, LPWSTR path, DWORD path_len, DWORD indent, DWORD mask) {
    int i;
    DWORD j;
    DWORD right;

    for (i = 25; i >= 0; i--) {
        right = right_mask(i);
        if (right != 0 && (mask & right) == right) {
            BeaconFormatPrintf(out, "\n");
            append_prefix_spaces(out, path_len + 1);
            for (j = 0; j < indent; j++) {
                BeaconFormatPrintf(out, " ");
            }
            BeaconFormatPrintf(out, "%s", right_name(i));
        }
    }
    BeaconFormatPrintf(out, "\n");
}

LPWSTR sid_display_name(PSID sid, DWORD *display_len, LPWSTR *allocated_name, LPWSTR *sid_string) {
    DWORD name_size;
    DWORD domain_size;
    DWORD use;
    LPWSTR name;
    LPWSTR domain;

    *allocated_name = NULL;
    *sid_string = NULL;
    *display_len = 0;
    name_size = 0;
    domain_size = 0;
    use = 0;

    ADVAPI32$LookupAccountSidW(NULL, sid, NULL, &name_size, NULL, &domain_size, &use);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && name_size != 0) {
        name = (LPWSTR)calloc(name_size + domain_size + 2, sizeof(WCHAR));
        if (name != NULL) {
            domain = name + name_size + 1;
            if (ADVAPI32$LookupAccountSidW(NULL, sid, name, &name_size, domain, &domain_size, &use)) {
                if (domain_size != 0 && domain[0] != 0) {
                    memmove(name + wcslen(name) + 1, domain, (SIZE_T)((wcslen(domain) + 1) * sizeof(WCHAR)));
                }
                *allocated_name = name;
                domain = name + wcslen(name) + 1;
                if (domain[0] != 0) {
                    *display_len = (DWORD)wcslen(domain) + (DWORD)wcslen(name);
                    return name;
                }
                *display_len = (DWORD)wcslen(name);
                return name;
            }
            free(name);
        }
    }

    if (ADVAPI32$ConvertSidToStringSidW(sid, sid_string)) {
        *display_len = (DWORD)wcslen(*sid_string);
        return *sid_string;
    }
    return L"";
}

void append_sid_name(formatp *out, LPWSTR display, LPWSTR allocated_name, DWORD *indent) {
    LPWSTR domain;

    if (allocated_name != NULL) {
        domain = allocated_name + wcslen(allocated_name) + 1;
        if (domain[0] != 0) {
            BeaconFormatPrintf(out, "%S\\%S:", domain, allocated_name);
            return;
        }
    }
    BeaconFormatPrintf(out, "%S:", display);
}

void append_ace(formatp *out, LPWSTR path, DWORD path_len, PACCESS_ALLOWED_ACE ace, DWORD ace_index) {
    GENERIC_MAPPING mapping;
    DWORD access_mask;
    DWORD indent;
    DWORD display_len;
    LPWSTR allocated_name;
    LPWSTR sid_string;
    LPWSTR display;

    memset(&mapping, 0, sizeof(mapping));
    access_mask = ace->Mask;
    display = sid_display_name((PSID)&ace->SidStart, &display_len, &allocated_name, &sid_string);

    if (ace_index == 0) {
        BeaconFormatPrintf(out, "%S ", path);
    } else {
        append_prefix_spaces(out, path_len + 1);
    }

    indent = display_len;
    append_sid_name(out, display, allocated_name, &indent);
    indent += append_flags(out, ace->Header.AceFlags);
    indent += 2;

    ADVAPI32$MapGenericMask(&access_mask, &mapping);
    if (ace->Header.AceType == ACCESS_DENIED_ACE_TYPE) {
        if (access_mask == FILE_ALL_ACCESS) {
            BeaconFormatPrintf(out, "N");
        } else {
            BeaconFormatPrintf(out, "(DENY)(special access:)");
            append_special_rights(out, path, path_len, indent, ace->Mask);
        }
    } else {
        if (access_mask == FILE_ALL_ACCESS) {
            BeaconFormatPrintf(out, "F");
        } else if (!(ace->Mask & (GENERIC_READ | GENERIC_EXECUTE)) && access_mask == (FILE_GENERIC_READ | FILE_EXECUTE)) {
            BeaconFormatPrintf(out, "R");
        } else if (access_mask == (FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_EXECUTE | DELETE)) {
            BeaconFormatPrintf(out, "C");
        } else if (access_mask == FILE_GENERIC_WRITE) {
            BeaconFormatPrintf(out, "W");
        } else {
            BeaconFormatPrintf(out, "(special access:)");
            append_special_rights(out, path, path_len, indent, ace->Mask);
        }
    }
    BeaconFormatPrintf(out, "\n");

    if (allocated_name != NULL) {
        free(allocated_name);
    }
    if (sid_string != NULL) {
        LocalFree(sid_string);
    }
}

datap parser;
LPWSTR path;
DWORD needed;
PSECURITY_DESCRIPTOR security_descriptor;
PACL dacl;
BOOL dacl_present;
BOOL dacl_defaulted;
DWORD i;
PACCESS_ALLOWED_ACE ace;
formatp out;
char *output;
int output_length;
DWORD path_len;

path = L"C:\\";
if (__argc > 0) {
    BeaconDataParse(&parser, __argv, __argc);
    path = (LPWSTR)BeaconDataExtract(&parser, NULL);
    if (path == NULL || path[0] == 0) {
        path = L"C:\\";
    }
}

init_rights();
needed = 0;
ADVAPI32$GetFileSecurityW(path, DACL_SECURITY_INFORMATION, NULL, 0, &needed);
if (needed == 0) {
    BeaconPrintf(CALLBACK_ERROR, "GetFileSecurityW sizing failed for %S: %lu", path, GetLastError());
} else {
    security_descriptor = (PSECURITY_DESCRIPTOR)calloc(1, needed);
    if (security_descriptor == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Allocation failed for security descriptor.");
    } else if (!ADVAPI32$GetFileSecurityW(path, DACL_SECURITY_INFORMATION, security_descriptor, needed, &needed)) {
        BeaconPrintf(CALLBACK_ERROR, "GetFileSecurityW failed for %S: %lu", path, GetLastError());
        free(security_descriptor);
    } else if (!ADVAPI32$GetSecurityDescriptorDacl(security_descriptor, &dacl_present, &dacl, &dacl_defaulted)) {
        BeaconPrintf(CALLBACK_ERROR, "GetSecurityDescriptorDacl failed: %lu", GetLastError());
        free(security_descriptor);
    } else if (!dacl_present || dacl == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "%S has no DACL.", path);
        free(security_descriptor);
    } else {
        path_len = (DWORD)wcslen(path);
        BeaconFormatAlloc(&out, 8192);
        for (i = 0; i < dacl->AceCount; i++) {
            ace = NULL;
            if (ADVAPI32$GetAce(dacl, i, &ace)) {
                append_ace(&out, path, path_len, ace, i);
            }
        }
        output = BeaconFormatToString(&out, &output_length);
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
        BeaconFormatFree(&out);
        free(security_descriptor);
    }
}
