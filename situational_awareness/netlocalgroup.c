#include <windows.h>
#include <winnt.h>
#include <netapi32.h>
#include <beacon.h>

#define MAX_PREFERRED_LENGTH ((DWORD)-1)
#define LIST_GROUPS 0
#define TARGET_SERVER ((LPWSTR)NULL)
#define TARGET_GROUP L"Administrators"

do {
    datap parser;
    DWORD result;
    DWORD read;
    DWORD total;
    DWORD i;
    DWORD member_column_count;
    DWORD_PTR resume;
    PLOCALGROUP_INFO_1 group_buffer;
    PLOCALGROUP_MEMBERS_INFO_3 member_buffer;
    formatp out;
    int output_length;
    char *output;
    short group_mode;
    LPWSTR target_server;
    LPWSTR target_group;

    group_mode = LIST_GROUPS;
    target_server = TARGET_SERVER;
    target_group = TARGET_GROUP;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        group_mode = BeaconDataShort(&parser);
        target_server = (LPWSTR)BeaconDataExtract(&parser, NULL);
        target_group = (LPWSTR)BeaconDataExtract(&parser, NULL);
        if (target_server != NULL && target_server[0] == 0) target_server = TARGET_SERVER;
        if (target_group == NULL || target_group[0] == 0) target_group = TARGET_GROUP;
    }

    read = 0;
    total = 0;
    resume = 0;
    member_column_count = 0;
    group_buffer = NULL;
    member_buffer = NULL;
    BeaconFormatAlloc(&out, 4096);
    if (group_mode == LIST_GROUPS) {
        do {
            result = NETAPI32$NetLocalGroupEnum(target_server, 1, &group_buffer, MAX_PREFERRED_LENGTH, &read, &total, &resume);
            if (result == 0 || result == 234) {
                for (i = 0; i < read; i++) {
                    BeaconFormatPrintf(&out, "Name:      %S\nComment:   %S\n--------------------------------\n", group_buffer[i].lgrpi1_name, group_buffer[i].lgrpi1_comment);
                }
                NETAPI32$NetApiBufferFree(group_buffer);
                group_buffer = NULL;
            } else {
                BeaconPrintf(CALLBACK_ERROR, "Error: %lu\n", result);
                break;
            }
        } while (result == 234);
    } else {
        do {
            result = NETAPI32$NetLocalGroupGetMembers(target_server, target_group, 3, &member_buffer, MAX_PREFERRED_LENGTH, &read, &total, &resume);
            if (result == 0 || result == 234) {
                for (i = 0; i < read; i++) {
                    member_column_count++;
                    if (member_column_count == 2) {
                        BeaconFormatPrintf(&out, "%-40S\n", member_buffer[i].lgrmi3_domainandname);
                        member_column_count = 0;
                    } else {
                        BeaconFormatPrintf(&out, "%-40S  ", member_buffer[i].lgrmi3_domainandname);
                    }
                }
                NETAPI32$NetApiBufferFree(member_buffer);
                member_buffer = NULL;
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
