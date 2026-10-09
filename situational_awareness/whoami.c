#include <windows.h>
#include <advapi.h>
#include <beacon.h>

#define NameSamCompatible 2
#define SE_PRIVILEGE_ENABLED 0x00000002
#define SE_GROUP_MANDATORY 0x00000001
#define SE_GROUP_ENABLED_BY_DEFAULT 0x00000002
#define SE_GROUP_ENABLED 0x00000004
#define SE_GROUP_OWNER 0x00000008
#define SE_GROUP_LOGON_ID 0xC0000000

typedef struct _TOKEN_GROUPS {
    DWORD GroupCount;
    SID_AND_ATTRIBUTES Groups[ANYSIZE_ARRAY];
} TOKEN_GROUPS, *PTOKEN_GROUPS;

SECUR32$GetUserNameExA: u32 (u32, ptr, ptr);
ADVAPI32$ConvertSidToStringSidA: u32 (ptr, ptr);
ADVAPI32$LookupAccountSidA: u32 (ptr, ptr, ptr, ptr, ptr, ptr, ptr);
ADVAPI32$LookupPrivilegeNameA: u32 (ptr, ptr, ptr, ptr);
ADVAPI32$LookupPrivilegeDisplayNameA: u32 (ptr, ptr, ptr, ptr, ptr);

void flush_output(formatp *buffer) {
    int output_length;
    char *output;

    output = BeaconFormatToString(buffer, &output_length);
    if (output != NULL && output_length > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatReset(buffer);
}

char *whoami_get_user(void) {
    char *user;
    ULONG user_size;

    user_size = MAX_PATH;
    user = (char *)calloc(1, MAX_PATH);
    if (user == NULL) {
        return NULL;
    }

    if (SECUR32$GetUserNameExA(NameSamCompatible, user, &user_size)) {
        return user;
    }

    free(user);
    return NULL;
}

void *whoami_get_token_info(TOKEN_INFORMATION_CLASS token_type, formatp *out) {
    HANDLE token;
    DWORD length;
    void *token_info;
    void *result;

    token = NULL;
    length = 0;
    token_info = NULL;
    result = NULL;

    if (ADVAPI32$OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &token)) {
        ADVAPI32$GetTokenInformation(token, token_type, NULL, length, &length);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            token_info = calloc(1, length);
            if (token_info == NULL) {
                BeaconFormatPrintf(out, "ERROR: not enough memory to allocate the token structure.\r\n");
                goto token_cleanup;
            }
        } else {
            goto token_cleanup;
        }

        if (!ADVAPI32$GetTokenInformation(token, token_type, token_info, length, &length)) {
            BeaconFormatPrintf(out, "ERROR 0x%x: could not get token information.\r\n", GetLastError());
            goto token_cleanup;
        }

        result = token_info;
        token_info = NULL;
    }

token_cleanup:
    if (token != NULL) {
        CloseHandle(token);
    }
    if (token_info != NULL) {
        free(token_info);
    }
    return result;
}

int whoami_user(formatp *out) {
    PTOKEN_USER user_info;
    char *user_name;
    char *sid_string;
    int retval;

    user_info = (PTOKEN_USER)whoami_get_token_info(TokenUser, out);
    user_name = NULL;
    sid_string = NULL;
    retval = 0;

    if (user_info == NULL) {
        retval = 1;
        goto user_cleanup;
    }

    user_name = whoami_get_user();
    if (user_name == NULL) {
        retval = 1;
        goto user_cleanup;
    }

    BeaconFormatPrintf(out, "\nUserName\t\tSID\n");
    BeaconFormatPrintf(out, "====================== ====================================\n");

    if (ADVAPI32$ConvertSidToStringSidA(user_info->User.Sid, &sid_string)) {
        BeaconFormatPrintf(out, "%s\t%s\n\n", user_name, sid_string);
        LocalFree(sid_string);
        sid_string = NULL;
    }

user_cleanup:
    if (sid_string != NULL) {
        LocalFree(sid_string);
    }
    if (user_info != NULL) {
        free(user_info);
    }
    if (user_name != NULL) {
        free(user_name);
    }
    return retval;
}

void append_group_type(formatp *out, SID_NAME_USE sid_type) {
    if (sid_type == SidTypeWellKnownGroup) {
        BeaconFormatPrintf(out, "%-25s", "Well-known group ");
    } else if (sid_type == SidTypeAlias) {
        BeaconFormatPrintf(out, "%-25s", "Alias ");
    } else if (sid_type == SidTypeLabel) {
        BeaconFormatPrintf(out, "%-25s", "Label ");
    } else if (sid_type == SidTypeGroup) {
        BeaconFormatPrintf(out, "%-25s", "Group ");
    }
}

void append_group_attributes(formatp *out, DWORD attributes) {
    if (attributes & SE_GROUP_MANDATORY) {
        BeaconFormatPrintf(out, "Mandatory group, ");
    }
    if (attributes & SE_GROUP_ENABLED_BY_DEFAULT) {
        BeaconFormatPrintf(out, "Enabled by default, ");
    }
    if (attributes & SE_GROUP_ENABLED) {
        BeaconFormatPrintf(out, "Enabled group, ");
    }
    if (attributes & SE_GROUP_OWNER) {
        BeaconFormatPrintf(out, "Group owner, ");
    }
    BeaconFormatPrintf(out, "\n");
}

int should_print_group(SID_NAME_USE sid_type, DWORD attributes) {
    if (attributes & SE_GROUP_LOGON_ID) {
        return 0;
    }
    if (sid_type == SidTypeWellKnownGroup) {
        return 1;
    }
    if (sid_type == SidTypeAlias) {
        return 1;
    }
    if (sid_type == SidTypeLabel) {
        return 1;
    }
    if (sid_type == SidTypeGroup) {
        return 1;
    }
    return 0;
}

int whoami_groups(formatp *out) {
    DWORD index;
    char *sid_string;
    char group_name[255];
    char domain_name[255];
    DWORD group_name_size;
    DWORD domain_name_size;
    SID_NAME_USE sid_type;
    PTOKEN_GROUPS group_info;
    PSID_AND_ATTRIBUTES group_attr;
    DWORD attributes;
    char display_name[1024];

    group_info = (PTOKEN_GROUPS)whoami_get_token_info(TokenGroups, out);
    if (group_info == NULL) {
        return 1;
    }

    BeaconFormatPrintf(out, "\n%-50s%-25s%-45s%-25s\n", "GROUP INFORMATION", "Type", "SID", "Attributes");
    BeaconFormatPrintf(out, "================================================= ===================== ============================================= ==================================================\n");

    group_attr = group_info->Groups;
    for (index = 0; index < group_info->GroupCount; index++) {
        if (out->length > 7600) {
            flush_output(out);
        }

        memset(group_name, 0, sizeof(group_name));
        memset(domain_name, 0, sizeof(domain_name));
        memset(display_name, 0, sizeof(display_name));
        group_name_size = 255;
        domain_name_size = 255;
        sid_type = 0;
        sid_string = NULL;

        if (!ADVAPI32$LookupAccountSidA(NULL, group_attr->Sid, group_name, &group_name_size, domain_name, &domain_name_size, &sid_type)) {
            group_attr++;
            continue;
        }

        attributes = group_attr->Attributes;
        if (!should_print_group(sid_type, attributes)) {
            group_attr++;
            continue;
        }

        if (attributes == 0x60) {
            attributes = 0x07;
        }

        sprintf(display_name, "%s%s%s", domain_name, domain_name_size ? "\\" : "", group_name);
        BeaconFormatPrintf(out, "%-50s", display_name);
        append_group_type(out, sid_type);

        if (ADVAPI32$ConvertSidToStringSidA(group_attr->Sid, &sid_string)) {
            BeaconFormatPrintf(out, "%-45s ", sid_string);
            LocalFree(sid_string);
            sid_string = NULL;
        }

        append_group_attributes(out, attributes);
        group_attr++;
    }

    free(group_info);
    return 0;
}

int whoami_priv(formatp *out) {
    PTOKEN_PRIVILEGES privilege_info;
    DWORD language_id;
    DWORD index;
    DWORD privilege_name_size;
    DWORD display_name_size;
    char *privilege_name;
    char *display_name;
    PLUID_AND_ATTRIBUTES privilege_attr;
    BOOL display_ok;

    privilege_info = (PTOKEN_PRIVILEGES)whoami_get_token_info(TokenPrivileges, out);
    if (privilege_info == NULL) {
        return 1;
    }

    BeaconFormatPrintf(out, "\n\n%-30s%-50s%-30s\n", "Privilege Name", "Description", "State");
    BeaconFormatPrintf(out, "============================= ================================================= ===========================\n");

    privilege_attr = privilege_info->Privileges;
    for (index = 0; index < privilege_info->PrivilegeCount; index++) {
        if (out->length > 7600) {
            flush_output(out);
        }

        privilege_name = NULL;
        display_name = NULL;
        privilege_name_size = 0;
        display_name_size = 0;
        language_id = 0;
        display_ok = FALSE;

        ADVAPI32$LookupPrivilegeNameA(NULL, &privilege_attr->Luid, NULL, &privilege_name_size);
        privilege_name_size++;
        privilege_name = (char *)calloc(1, privilege_name_size);
        if (privilege_name == NULL) {
            privilege_attr++;
            continue;
        }

        if (!ADVAPI32$LookupPrivilegeNameA(NULL, &privilege_attr->Luid, privilege_name, &privilege_name_size)) {
            free(privilege_name);
            privilege_attr++;
            continue;
        }

        BeaconFormatPrintf(out, "%-30s", privilege_name);

        ADVAPI32$LookupPrivilegeDisplayNameA(NULL, privilege_name, NULL, &display_name_size, &language_id);
        display_name_size++;
        display_name = (char *)calloc(1, display_name_size);
        if (display_name != NULL) {
            display_ok = ADVAPI32$LookupPrivilegeDisplayNameA(NULL, privilege_name, display_name, &display_name_size, &language_id);
        }

        if (display_ok && display_name != NULL) {
            BeaconFormatPrintf(out, "%-50s", display_name);
        } else {
            BeaconFormatPrintf(out, "%-50s", "???");
        }

        if (display_name != NULL) {
            free(display_name);
        }
        free(privilege_name);

        if (privilege_attr->Attributes & SE_PRIVILEGE_ENABLED) {
            BeaconFormatPrintf(out, "%-30s\n", "Enabled");
        } else {
            BeaconFormatPrintf(out, "%-30s\n", "Disabled");
        }
        privilege_attr++;
    }

    free(privilege_info);
    return 0;
}

formatp out;

BeaconFormatAlloc(&out, 8192);
whoami_user(&out);
whoami_groups(&out);
whoami_priv(&out);
flush_output(&out);
BeaconFormatFree(&out);
