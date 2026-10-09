#include <windows.h>
#include <netapi32.h>
#include <beacon.h>

#define MAX_PREFERRED_LENGTH ((DWORD)-1)
#define TARGET_SERVER ((LPWSTR) L"127.0.0.1")
#define RESOLVE_METHOD 1

typedef struct _SESSION_INFO_10 {
    LPWSTR sesi10_cname;
    LPWSTR sesi10_username;
    DWORD sesi10_time;
    DWORD sesi10_idle_time;
} SESSION_INFO_10, *LPSESSION_INFO_10;

typedef struct _WKSTA_INFO_100 {
    DWORD wki100_platform_id;
    LPWSTR wki100_computername;
    LPWSTR wki100_langroup;
    DWORD wki100_ver_major;
    DWORD wki100_ver_minor;
} WKSTA_INFO_100, *PWKSTA_INFO_100;

NETAPI32$NetSessionEnum: u32 (ptr, ptr, ptr, u32, ptr, u32, ptr, ptr, ptr);
NETAPI32$NetWkstaGetInfo: u32 (ptr, u32, ptr);

do {
    datap parser;
    LPSESSION_INFO_10 buffer;
    LPSESSION_INFO_10 current;
    DWORD entries, total, resume, status, i, count;
    PWKSTA_INFO_100 info;
    formatp out;
    int output_length;
    char *output;
    LPCWSTR clientname;
    LPWSTR target_server;
    char *dnsserver;
    short resolve_method;

    target_server = TARGET_SERVER;
    resolve_method = RESOLVE_METHOD;
    dnsserver = "";
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_server = (LPWSTR)BeaconDataExtract(&parser, NULL);
        resolve_method = BeaconDataShort(&parser);
        dnsserver = BeaconDataExtract(&parser, NULL);
        if (target_server == NULL || target_server[0] == 0) target_server = TARGET_SERVER;
        if (dnsserver == NULL) dnsserver = "";
    }

    buffer = NULL;
    entries = total = resume = count = 0;
    BeaconFormatAlloc(&out, 4096);
    BeaconFormatPrintf(&out, "[*] Resolving client IPs to hostnames using %s%s%s\n\n", (resolve_method == 0) ? "DNS" : "NetWkstaGetInfo", (resolve_method == 0 && dnsserver[0] != 0) ? " via " : "", (resolve_method == 0 && dnsserver[0] != 0) ? dnsserver : "");
    do {
        status = NETAPI32$NetSessionEnum(target_server, NULL, NULL, 10, &buffer, MAX_PREFERRED_LENGTH, &entries, &total, &resume);
        if (status != 0 && status != 234) break;
        current = buffer;
        for (i = 0; i < entries; i++) {
            BeaconFormatPrintf(&out, "---------------Session--------------\n");
            BeaconFormatPrintf(&out, "Client: %S\n", current->sesi10_cname);
            clientname = current->sesi10_cname;
            if (clientname && clientname[0] == L'\\' && clientname[1] == L'\\') clientname += 2;
            info = NULL;
            if (resolve_method == 1 && clientname) {
                if (NETAPI32$NetWkstaGetInfo(clientname, 100, &info) == 0 && info != NULL) {
                    BeaconFormatPrintf(&out, "ComputerName: %S\n", info->wki100_computername);
                    BeaconFormatPrintf(&out, "ComputerDomain: %S\n", info->wki100_langroup);
                    NETAPI32$NetApiBufferFree(info);
                } else {
                    BeaconFormatPrintf(&out, "ComputerName: NetWkstaGetInfo Failed\n");
                    BeaconFormatPrintf(&out, "ComputerDomain: NetWkstaGetInfo Failed\n");
                }
            } else if (resolve_method == 0) {
                BeaconFormatPrintf(&out, "ComputerName: DNS resolution is not implemented in this script port\n");
                BeaconFormatPrintf(&out, "ComputerDomain: DNS resolution is not implemented in this script port\n");
            }
            BeaconFormatPrintf(&out, "User: %S\n", current->sesi10_username);
            BeaconFormatPrintf(&out, "Active: %lu\n", current->sesi10_time);
            BeaconFormatPrintf(&out, "Idle: %lu\n", current->sesi10_idle_time);
            BeaconFormatPrintf(&out, "-------------End Session------------\n\n");
            current++;
            count++;
        }
        if (buffer) {
            NETAPI32$NetApiBufferFree(buffer);
            buffer = NULL;
        }
    } while (status == 234);
    BeaconFormatPrintf(&out, "\nTotal of %lu entries enumerated\n", count);
    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);
} while (0);
