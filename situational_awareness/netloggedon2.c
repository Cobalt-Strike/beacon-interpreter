#include <windows.h>
#include <netapi32.h>
#include <beacon.h>

#define MAX_PREFERRED_LENGTH ((DWORD)-1)
#define TARGET_SERVER ((LPWSTR)NULL)
#define ComputerNameDnsFullyQualified 3

typedef struct _WKSTA_USER_INFO_1 {
    LPWSTR wkui1_username;
    LPWSTR wkui1_logon_domain;
    LPWSTR wkui1_oth_domains;
    LPWSTR wkui1_logon_server;
} WKSTA_USER_INFO_1, *PWKSTA_USER_INFO_1;

NETAPI32$NetWkstaUserEnum: u32 (ptr, u32, ptr, u32, ptr, ptr, ptr);

do {
    datap parser;
    PWKSTA_USER_INFO_1 buffer;
    DWORD entries;
    DWORD total;
    DWORD resume;
    DWORD status;
    DWORD i;
    formatp out;
    int output_length;
    char *output;
    DWORD count;
    WCHAR hostname[256];
    DWORD hostname_len;
    LPWSTR target_server;

    target_server = TARGET_SERVER;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_server = (LPWSTR)BeaconDataExtract(&parser, NULL);
        if (target_server != NULL && target_server[0] == 0) target_server = TARGET_SERVER;
    }

    buffer = NULL;
    entries = 0;
    total = 0;
    resume = 0;
    count = 0;
    hostname_len = 256;
    hostname[0] = 0;

    if (target_server == NULL) {
        GetComputerNameExW(ComputerNameDnsFullyQualified, hostname, &hostname_len);
    }

    status = NETAPI32$NetWkstaUserEnum(target_server, 1, &buffer, MAX_PREFERRED_LENGTH, &entries, &total, &resume);
    if (status != 0 && status != 234) {
        BeaconPrintf(CALLBACK_ERROR, "NetWkstaUserEnum failed: %lu", status);
        break;
    }

    BeaconFormatAlloc(&out, 4096);
    for (i = 0; i < entries; i++) {
        BeaconFormatPrintf(&out, "-----------Logged on User-----------\n");
        BeaconFormatPrintf(&out, "Host: %S\n", target_server ? target_server : hostname);
        BeaconFormatPrintf(&out, "Username: %S\n", buffer[i].wkui1_username);
        BeaconFormatPrintf(&out, "Domain: %S\n", buffer[i].wkui1_logon_domain);
        BeaconFormatPrintf(&out, "Oth_domains: %S\n", buffer[i].wkui1_oth_domains);
        BeaconFormatPrintf(&out, "Logon server: %S\n", buffer[i].wkui1_logon_server);
        BeaconFormatPrintf(&out, "---------End Logged on User---------\n\n");
        count++;
    }

    if (buffer != NULL) NETAPI32$NetApiBufferFree(buffer);
    if (count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "No logged on users found.");
    } else {
        output = BeaconFormatToString(&out, &output_length);
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatFree(&out);
} while (0);
