#include <windows.h>
#include <netapi32.h>
#include <beacon.h>

#define MAX_PREFERRED_LENGTH ((DWORD)-1)
#define SV_TYPE_ALL ((DWORD)-1)
#define TARGET_DOMAIN ((LPWSTR)NULL)
#define ERROR_NO_BROWSER_SERVERS_FOUND 6118

typedef struct _SERVER_INFO_101 {
    DWORD sv101_platform_id;
    LPWSTR sv101_name;
    DWORD sv101_version_major;
    DWORD sv101_version_minor;
    DWORD sv101_type;
    LPWSTR sv101_comment;
} SERVER_INFO_101, *PSERVER_INFO_101, *LPSERVER_INFO_101;

NETAPI32$NetServerEnum: u32 (ptr, u32, ptr, u32, ptr, ptr, u32, ptr, ptr);

do {
    datap parser;
    LPSERVER_INFO_101 buffer;
    LPSERVER_INFO_101 current;
    DWORD entries_read;
    DWORD total_entries;
    LPWSTR domain_ptr;
    LPDWORD resume_handle_ptr;
    DWORD status;
    DWORD i;
    formatp out;
    int output_length;
    char *output;
    DWORD count;
    buffer = NULL;
    entries_read = 0;
    total_entries = 0;
    domain_ptr = TARGET_DOMAIN;
    resume_handle_ptr = NULL;
    count = 0;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        domain_ptr = (LPWSTR)BeaconDataExtract(&parser, NULL);
        if (domain_ptr != NULL && domain_ptr[0] == 0) domain_ptr = TARGET_DOMAIN;
    }

    status = NETAPI32$NetServerEnum(
        NULL,
        101,
        &buffer,
        MAX_PREFERRED_LENGTH,
        &entries_read,
        &total_entries,
        SV_TYPE_ALL,
        domain_ptr,
        resume_handle_ptr);

    if (status == ERROR_NO_BROWSER_SERVERS_FOUND) {
        BeaconPrintf(CALLBACK_OUTPUT, "No servers found.");
        break;
    }

    if (status != 0 && status != 234) {
        BeaconPrintf(CALLBACK_ERROR, "NetServerEnum failed: %lu", status);
        break;
    }

    BeaconFormatAlloc(&out, 2048);
    current = buffer;
    for (i = 0; i < entries_read; i++) {
        BeaconFormatPrintf(&out, "%S\n", current->sv101_name);
        current++;
        count++;
    }

    if (buffer != NULL) {
        NETAPI32$NetApiBufferFree(buffer);
    }

    if (count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "No servers found.");
    } else {
        output = BeaconFormatToString(&out, &output_length);
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatFree(&out);
} while (0);
