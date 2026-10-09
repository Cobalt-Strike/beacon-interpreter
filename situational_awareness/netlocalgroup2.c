#include <windows.h>
#include <netapi32.h>
#include <advapi.h>
#include <beacon.h>

#define MAX_PREFERRED_LENGTH ((DWORD)-1)
#define OUTPUT_BUFFER_SIZE (1024 * 1024)
#define OUTPUT_FLUSH_THRESHOLD (64 * 1024)

ADVAPI32$ConvertSidToStringSidW: u32 (ptr, ptr);

void flush_output(formatp *out) {
    char *output;
    int output_length;

    output = BeaconFormatToString(out, &output_length);
    if (output != NULL && output_length > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatReset(out);
}

datap parser;
LPWSTR server;
LPWSTR group;
LPWSTR sid_string;
PLOCALGROUP_MEMBERS_INFO_2 members;
PLOCALGROUP_MEMBERS_INFO_2 member;
DWORD read_count;
DWORD total_count;
DWORD_PTR resume;
DWORD status;
DWORD i;
formatp out;

server = NULL;
group = L"Administrators";
if (__argc > 0) {
    BeaconDataParse(&parser, __argv, __argc);
    server = (LPWSTR)BeaconDataExtract(&parser, NULL);
    group = (LPWSTR)BeaconDataExtract(&parser, NULL);
    if (server != NULL && server[0] == 0) {
        server = NULL;
    }
    if (group == NULL || group[0] == 0) {
        group = L"Administrators";
    }
}

resume = 0;
BeaconFormatAlloc(&out, OUTPUT_BUFFER_SIZE);
do {
    members = NULL;
    read_count = 0;
    total_count = 0;
    status = NETAPI32$NetLocalGroupGetMembers(server, group, 2, &members, MAX_PREFERRED_LENGTH, &read_count, &total_count, &resume);
    if (status != NERR_Success && status != ERROR_MORE_DATA) {
        BeaconPrintf(CALLBACK_ERROR, "NetLocalGroupGetMembers failed for %S: %lu", group, status);
        if (members != NULL) {
            NETAPI32$NetApiBufferFree(members);
        }
        break;
    }

    member = members;
    for (i = 0; i < read_count; i++) {
        sid_string = NULL;
        ADVAPI32$ConvertSidToStringSidW(member->lgrmi2_sid, &sid_string);
        BeaconFormatPrintf(&out, "----------Local Group Member----------\n");
        BeaconFormatPrintf(&out, "Host: %S\n", server ? server : L"(local)");
        BeaconFormatPrintf(&out, "Group: %S\n", group);
        BeaconFormatPrintf(&out, "Member: %S\n", member->lgrmi2_domainandname ? member->lgrmi2_domainandname : L"");
        BeaconFormatPrintf(&out, "MemberSid: %S\n", sid_string ? sid_string : L"");
        BeaconFormatPrintf(&out, "MemberSidType: %lu\n", (DWORD)member->lgrmi2_sidusage);
        BeaconFormatPrintf(&out, "--------End Local Group Member--------\n\n");
        if (out.length >= OUTPUT_FLUSH_THRESHOLD) {
            flush_output(&out);
        }
        if (sid_string != NULL) {
            LocalFree(sid_string);
        }
        member++;
    }

    if (members != NULL) {
        NETAPI32$NetApiBufferFree(members);
    }
} while (status == ERROR_MORE_DATA);
flush_output(&out);
BeaconFormatFree(&out);
