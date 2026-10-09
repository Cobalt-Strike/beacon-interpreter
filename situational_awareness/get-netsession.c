#include <windows.h>
#include <netapi32.h>
#include <beacon.h>

#define MAX_PREFERRED_LENGTH ((DWORD)-1)
#define TARGET_SERVER ((LPWSTR) L"127.0.0.1")

typedef struct _SESSION_INFO_10 {
    LPWSTR sesi10_cname;
    LPWSTR sesi10_username;
    DWORD sesi10_time;
    DWORD sesi10_idle_time;
} SESSION_INFO_10, *PSESSION_INFO_10, *LPSESSION_INFO_10;

NETAPI32$NetSessionEnum: u32 (ptr, ptr, ptr, u32, ptr, u32, ptr, ptr, ptr);

do {
    datap parser;
    LPSESSION_INFO_10 buffer;
    LPSESSION_INFO_10 current;
    DWORD entries;
    DWORD total;
    DWORD resume;
    DWORD status;
    DWORD i;
    DWORD count;
    formatp out;
    int output_length;
    char *output;
    LPWSTR client_name;
    LPWSTR user_name;
    LPWSTR target_server;

    target_server = TARGET_SERVER;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_server = (LPWSTR)BeaconDataExtract(&parser, NULL);
        if (target_server == NULL || target_server[0] == 0) target_server = TARGET_SERVER;
    }

    buffer = NULL;
    entries = 0;
    total = 0;
    resume = 0;
    count = 0;
    client_name = NULL;
    user_name = NULL;

    BeaconFormatAlloc(&out, 4096);
    do {
        status = NETAPI32$NetSessionEnum(target_server, client_name, user_name, 10, &buffer, MAX_PREFERRED_LENGTH, &entries, &total, &resume);
        if (status != 0 && status != 234) {
            if (buffer != NULL) NETAPI32$NetApiBufferFree(buffer);
            BeaconFormatFree(&out);
            BeaconPrintf(CALLBACK_ERROR, "NetSessionEnum failed: %lu", status);
            break;
        }

        current = buffer;
        for (i = 0; i < entries; i++) {
            BeaconFormatPrintf(&out, "\nClient: %S\n", current->sesi10_cname);
            BeaconFormatPrintf(&out, "User:   %S\n", current->sesi10_username);
            BeaconFormatPrintf(&out, "Active: %lu\n", current->sesi10_time);
            BeaconFormatPrintf(&out, "Idle:   %lu\n", current->sesi10_idle_time);
            BeaconFormatPrintf(&out, "--------------------\n");
            current++;
            count++;
        }

        if (buffer != NULL) {
            NETAPI32$NetApiBufferFree(buffer);
            buffer = NULL;
        }
    } while (status == 234);

    BeaconFormatPrintf(&out, "\nTotal of %lu entries enumerated\n", count);
    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);
} while (0);
