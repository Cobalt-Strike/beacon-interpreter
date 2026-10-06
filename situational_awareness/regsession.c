#include <windows.h>
#include <advapi.h>
#include <winreg.h>
#include <winerror.h>
#include <beacon.h>

#define TARGET_HOST ((LPSTR)NULL)
#define ComputerNameDnsFullyQualified 3

do {
    datap parser;
    HKEY rootkey;
    HKEY remote;
    DWORD result;
    DWORD index;
    CHAR subkey[256];
    DWORD subkey_size;
    DWORD sessions;
    formatp out;
    int output_length;
    char *output;
    WCHAR whostname[256];
    DWORD host_len;
    char *target_host;

    rootkey = 0;
    remote = 0;
    sessions = 0;
    host_len = 256;
    whostname[0] = 0;
    target_host = TARGET_HOST;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_host = BeaconDataExtract(&parser, NULL);
        if (target_host != NULL && target_host[0] == 0) target_host = TARGET_HOST;
    }

    if (target_host == NULL) {
        ADVAPI32$RegOpenKeyExA(HKEY_USERS, NULL, 0, KEY_READ, &rootkey);
        GetComputerNameExW(ComputerNameDnsFullyQualified, whostname, &host_len);
    } else {
        result = ADVAPI32$RegConnectRegistryA(target_host, HKEY_USERS, &remote);
        if (result != 0) {
            BeaconPrintf(CALLBACK_ERROR, "RegConnectRegistryA failed: %lu", result);
            break;
        }
        result = ADVAPI32$RegOpenKeyExA(remote, NULL, 0, KEY_READ, &rootkey);
        if (result != 0) {
            ADVAPI32$RegCloseKey(remote);
            BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyExA failed: %lu", result);
            break;
        }
    }

    BeaconFormatAlloc(&out, 2048);
    BeaconFormatPrintf(&out, "[*] Querying %s registry...\n", target_host ? target_host : "local");
    index = 0;
    do {
        subkey_size = sizeof(subkey);
        result = ADVAPI32$RegEnumKeyExA(rootkey, index, subkey, &subkey_size, NULL, NULL, NULL, NULL);
        if (result == 0) {
            BOOL is_sid;
            DWORD j;
            is_sid = subkey[0]=='S' && subkey[1]=='-' && subkey[2]=='1' && subkey[3]=='-' && subkey[4]=='5' && subkey[5]=='-' && subkey[6]=='2' && subkey[7]=='1';
            if (is_sid) {
                for (j = 0; j < subkey_size; j++) if (subkey[j] == '_') { is_sid = FALSE; break; }
            }
            if (is_sid) {
                sessions++;
                BeaconFormatPrintf(&out, "-----------Registry Session---------\n");
                BeaconFormatPrintf(&out, "UserSid: %s\n", subkey);
                if (target_host == NULL) BeaconFormatPrintf(&out, "Host: %S\n", whostname);
                else BeaconFormatPrintf(&out, "Host: %s\n", target_host);
                BeaconFormatPrintf(&out, "---------End Registry Session-------\n\n");
            }
            index++;
        }
    } while (result == 0);

    BeaconFormatPrintf(&out, "[*] Found %lu sessions in the registry\n", sessions);
    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);

    if (rootkey) ADVAPI32$RegCloseKey(rootkey);
    if (remote) ADVAPI32$RegCloseKey(remote);
} while (0);
