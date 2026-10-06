#include <windows.h>
#include <netapi32.h>
#include <beacon.h>

#define MAX_PREFERRED_LENGTH ((DWORD)-1)
#define TARGET_SERVER ((LPWSTR)NULL)
#define ADMIN_VIEW 0

typedef struct _SHARE_INFO_1 {
    LPWSTR shi1_netname;
    DWORD shi1_type;
    LPWSTR shi1_remark;
} SHARE_INFO_1, *PSHARE_INFO_1;

typedef struct _SHARE_INFO_2 {
    LPWSTR shi2_netname;
    DWORD shi2_type;
    LPWSTR shi2_remark;
    DWORD shi2_permissions;
    DWORD shi2_max_uses;
    DWORD shi2_current_uses;
    LPWSTR shi2_path;
    LPWSTR shi2_passwd;
} SHARE_INFO_2, *PSHARE_INFO_2;

NETAPI32$NetShareEnum: u32 (ptr, u32, ptr, u32, ptr, ptr, ptr);

do {
    datap parser;
    DWORD entries;
    DWORD total;
    DWORD resume;
    DWORD status;
    DWORD i;
    PSHARE_INFO_1 share1_buffer;
    PSHARE_INFO_2 share2_buffer;
    formatp out;
    int output_length;
    char *output;
    DWORD count;
    LPWSTR target_server;
    int admin_view;

    target_server = TARGET_SERVER;
    admin_view = ADMIN_VIEW;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_server = (LPWSTR)BeaconDataExtract(&parser, NULL);
        admin_view = BeaconDataInt(&parser);
        if (target_server != NULL && target_server[0] == 0) target_server = TARGET_SERVER;
    }

    share1_buffer = NULL;
    share2_buffer = NULL;
    entries = 0;
    total = 0;
    resume = 0;
    count = 0;
    BeaconFormatAlloc(&out, 4096);

    if (admin_view) {
        status = NETAPI32$NetShareEnum(target_server, 2, &share2_buffer, MAX_PREFERRED_LENGTH, &entries, &total, &resume);
        if (status != 0 && status != 234) {
            BeaconPrintf(CALLBACK_ERROR, "NetShareEnum failed: %lu", status);
            BeaconFormatFree(&out);
            break;
        }
        BeaconFormatPrintf(&out, "%-20s %-30s %-8s %s\n", "Share", "Local Path", "Uses", "Remark");
        for (i = 0; i < entries; i++) {
            BeaconFormatPrintf(&out, "%-20S %-30S %-8lu %S\n", share2_buffer[i].shi2_netname, share2_buffer[i].shi2_path, share2_buffer[i].shi2_current_uses, share2_buffer[i].shi2_remark);
            count++;
        }
        if (share2_buffer != NULL) NETAPI32$NetApiBufferFree(share2_buffer);
    } else {
        status = NETAPI32$NetShareEnum(target_server, 1, &share1_buffer, MAX_PREFERRED_LENGTH, &entries, &total, &resume);
        if (status != 0 && status != 234) {
            BeaconPrintf(CALLBACK_ERROR, "NetShareEnum failed: %lu", status);
            BeaconFormatFree(&out);
            break;
        }
        BeaconFormatPrintf(&out, "%-20s %s\n", "Share", "Remark");
        for (i = 0; i < entries; i++) {
            BeaconFormatPrintf(&out, "%-20S %S\n", share1_buffer[i].shi1_netname, share1_buffer[i].shi1_remark);
            count++;
        }
        if (share1_buffer != NULL) NETAPI32$NetApiBufferFree(share1_buffer);
    }

    if (count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "No shares found.");
    } else {
        output = BeaconFormatToString(&out, &output_length);
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatFree(&out);
} while (0);
