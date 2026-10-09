#include <windows.h>
#include <wtsapi32.h>
#include <beacon.h>

do {
    WTS_SESSION_INFO *sessions;
    DWORD count;
    DWORD index;
    DWORD size;
    LPSTR username;
    LPSTR domain;
    LPSTR station;
    DWORD users;
    formatp out;
    int output_length;
    char *output;

    sessions = NULL;
    count = 0;
    users = 0;
    if (!WTSAPI32$WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
        BeaconPrintf(CALLBACK_ERROR, "WTSEnumerateSessionsA failed.");
        break;
    }

    BeaconFormatAlloc(&out, 4096);
    BeaconFormatPrintf(&out, "Enumerating sessions for local system:\n");
    for (index = 0; index < count; index++) {
        username = NULL;
        domain = NULL;
        station = NULL;
        if (WTSAPI32$WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, sessions[index].SessionId, WTSUserName, &username, &size) && username && username[0] != 0) {
            if (sessions[index].State == WTSActive || sessions[index].State == WTSDisconnected) {
                WTSAPI32$WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, sessions[index].SessionId, WTSDomainName, &domain, &size);
                if (sessions[index].State != WTSDisconnected) {
                    WTSAPI32$WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, sessions[index].SessionId, WTSWinStationName, &station, &size);
                }
                BeaconFormatPrintf(
                    &out,
                    "  - [%lu] %s: %s\\%s\n",
                    sessions[index].SessionId,
                    station ? station : "(Disconnected)",
                    domain ? domain : "(NULL)",
                    username
                );
                users++;
                if (domain) WTSAPI32$WTSFreeMemory(domain);
                if (station) WTSAPI32$WTSFreeMemory(station);
            }
            WTSAPI32$WTSFreeMemory(username);
        }
    }
    WTSAPI32$WTSFreeMemory(sessions);
    BeaconFormatPrintf(&out, "\nTotal of %lu entries enumerated\n", users);
    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);
} while (0);
