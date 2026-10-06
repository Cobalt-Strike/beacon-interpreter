#include <windows.h>
#include <winnt.h>
#include <netapi32.h>
#include <beacon.h>

#define FILTER_SCOPE 1
#define USE_DOMAIN_CONTROLLER 0

do {
    datap parser;
    LPVOID buffer;
    LPUSER_INFO_1 user1;
    LPUSER_INFO_0 user0;
    LPWSTR server;
    DWORD level;
    DWORD entries;
    DWORD total;
    DWORD resume;
    DWORD status;
    DWORD i;
    formatp out;
    int output_length;
    char *output;
    int filter_scope;
    int use_domain_controller;

    buffer = NULL;
    server = NULL;
    filter_scope = FILTER_SCOPE;
    use_domain_controller = USE_DOMAIN_CONTROLLER;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        use_domain_controller = BeaconDataInt(&parser);
        filter_scope = BeaconDataInt(&parser);
    }

    level = (filter_scope == 1) ? 0 : 1;
    entries = 0;
    total = 0;
    resume = 0;

    if (use_domain_controller) {
        NETAPI32$NetGetAnyDCName(NULL, NULL, &server);
    }

    BeaconFormatAlloc(&out, 4096);
    do {
        status = NETAPI32$NetUserEnum(server, level, 2, &buffer, ((DWORD)-1), &entries, &total, &resume);
        if (status != 0 && status != 234) {
            break;
        }

        if (level == 0) {
            user0 = (LPUSER_INFO_0)buffer;
            for (i = 0; i < entries; i++) {
                BeaconFormatPrintf(&out, "-- %S\n", user0[i].usri0_name);
            }
        } else {
            user1 = (LPUSER_INFO_1)buffer;
            for (i = 0; i < entries; i++) {
                if (filter_scope == 2 && !(user1[i].usri1_flags & 0x0010)) continue;
                if (filter_scope == 3 && !(user1[i].usri1_flags & 0x0002)) continue;
                if (filter_scope == 4 && (user1[i].usri1_flags & (0x0002 | 0x0010))) continue;
                BeaconFormatPrintf(&out, "-- %S\n", user1[i].usri1_name);
            }
        }

        if (buffer != NULL) {
            NETAPI32$NetApiBufferFree(buffer);
            buffer = NULL;
        }
    } while (status == 234);

    if (server != NULL) {
        NETAPI32$NetApiBufferFree(server);
    }

    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);
} while (0);
