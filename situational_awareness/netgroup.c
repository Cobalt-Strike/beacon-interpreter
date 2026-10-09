#include <windows.h>
#include <winnt.h>
#include <netapi32.h>
#include <beacon.h>

#define MAX_PREFERRED_LENGTH ((DWORD)-1)
#define LIST_GROUPS 0
#define TARGET_DOMAIN ((LPWSTR)NULL)
#define TARGET_GROUP L"Domain Admins"
#define ComputerNameDnsDomain 2

do {
    datap parser;
    DWORD result;
    DWORD records;
    DWORD index;
    DWORD i;
    DWORD column_count;
    DWORD total;
    DWORD read;
    DWORD_PTR resume;
    PNET_DISPLAY_GROUP display_buffer;
    PGROUP_USERS_INFO_0 user_buffer;
    formatp out;
    int output_length;
    char *output;
    short group_mode;
    LPWSTR target_domain;
    LPWSTR target_group;
    WCHAR default_domain[256];
    DWORD default_domain_size;

    group_mode = LIST_GROUPS;
    target_domain = TARGET_DOMAIN;
    target_group = TARGET_GROUP;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        group_mode = BeaconDataShort(&parser);
        target_domain = (LPWSTR)BeaconDataExtract(&parser, NULL);
        target_group = (LPWSTR)BeaconDataExtract(&parser, NULL);
        if (target_domain != NULL && target_domain[0] == 0) target_domain = TARGET_DOMAIN;
        if (target_group == NULL || target_group[0] == 0) target_group = TARGET_GROUP;
    }

    if (target_domain == TARGET_DOMAIN) {
        default_domain_size = 256;
        memset(default_domain, 0, sizeof(default_domain));
        if (GetComputerNameExW(ComputerNameDnsDomain, default_domain, &default_domain_size) == 0) {
            BeaconPrintf(CALLBACK_ERROR, "Warning, could not get default domain name, continuing against local system");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "Using Resolved domain of %S", default_domain);
            target_domain = default_domain;
        }
    }

    display_buffer = NULL;
    user_buffer = NULL;
    total = 0;
    read = 0;
    resume = 0;
    column_count = 0;
    BeaconFormatAlloc(&out, 4096);
    if (group_mode == LIST_GROUPS) {
        index = 0;
        do {
            result = NETAPI32$NetQueryDisplayInformation(target_domain, 3, index, 100, MAX_PREFERRED_LENGTH, &records, &display_buffer);
            if ((result == 0 || result == 234) && records != 0 && display_buffer != NULL) {
                for (i = 0; i < records; i++) {
                    BeaconFormatPrintf(&out, "Name:      %S\nComment:   %S\nGroup ID:  %lu\nAttributes: %lu\n--------------------------------\n", display_buffer[i].grpi3_name, display_buffer[i].grpi3_comment, display_buffer[i].grpi3_group_id, display_buffer[i].grpi3_attributes);
                    index = display_buffer[i].grpi3_next_index;
                }
                NETAPI32$NetApiBufferFree(display_buffer);
                display_buffer = NULL;
            } else {
                BeaconPrintf(CALLBACK_ERROR, "Error: %lu\n", result);
                break;
            }
        } while (result == 234);
    } else {
        do {
            result = NETAPI32$NetGroupGetUsers(target_domain, target_group, 0, &user_buffer, MAX_PREFERRED_LENGTH, &read, &total, &resume);
            if (result == 0 || result == 234) {
                for (i = 0; i < read; i++) {
                    column_count++;
                    if (column_count == 3) {
                        BeaconFormatPrintf(&out, "%-20S\n", user_buffer[i].grui0_name);
                        column_count = 0;
                    } else {
                        BeaconFormatPrintf(&out, "%-20S  ", user_buffer[i].grui0_name);
                    }
                }
                NETAPI32$NetApiBufferFree(user_buffer);
                user_buffer = NULL;
            } else {
                BeaconPrintf(CALLBACK_ERROR, "Error: %lu\n", result);
                break;
            }
        } while (result == 234);
    }

    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);
} while (0);
