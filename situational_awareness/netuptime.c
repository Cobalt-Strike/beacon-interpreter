#include <windows.h>
#include <netapi32.h>
#include <beacon.h>

#define TARGET_SERVER ((LPWSTR)NULL)

typedef struct _STAT_WORKSTATION_0 {
    LARGE_INTEGER StatisticsStartTime;
    LARGE_INTEGER BytesReceived;
    LARGE_INTEGER SmbsReceived;
    LARGE_INTEGER PagingReadBytesRequested;
    LARGE_INTEGER NonPagingReadBytesRequested;
    LARGE_INTEGER CacheReadBytesRequested;
    LARGE_INTEGER NetworkReadBytesRequested;
    LARGE_INTEGER BytesTransmitted;
    LARGE_INTEGER SmbsTransmitted;
    LARGE_INTEGER PagingWriteBytesRequested;
    LARGE_INTEGER NonPagingWriteBytesRequested;
    LARGE_INTEGER CacheWriteBytesRequested;
    LARGE_INTEGER NetworkWriteBytesRequested;
    DWORD InitiallyFailedOperations;
    DWORD FailedCompletionOperations;
    DWORD ReadOperations;
    DWORD RandomReadOperations;
    DWORD ReadSmbs;
    DWORD LargeReadSmbs;
    DWORD SmallReadSmbs;
    DWORD WriteOperations;
    DWORD RandomWriteOperations;
    DWORD WriteSmbs;
    DWORD LargeWriteSmbs;
    DWORD SmallWriteSmbs;
    DWORD RawReadsDenied;
    DWORD RawWritesDenied;
    DWORD NetworkErrors;
    DWORD Sessions;
    DWORD FailedSessions;
    DWORD Reconnects;
    DWORD CoreConnects;
    DWORD Lanman20Connects;
    DWORD Lanman21Connects;
    DWORD LanmanNtConnects;
    DWORD ServerDisconnects;
    DWORD HungSessions;
    DWORD UseCount;
    DWORD FailedUseCount;
    DWORD CurrentCommands;
} STAT_WORKSTATION_0, *PSTAT_WORKSTATION_0;

NETAPI32$NetStatisticsGet: u32 (ptr, ptr, u32, u32, ptr);

do {
    datap parser;
    PSTAT_WORKSTATION_0 stats;
    DWORD status;
    SYSTEMTIME boot_time;
    FILETIME file_time;
    LPWSTR target_server;

    stats = NULL;
    target_server = TARGET_SERVER;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_server = (LPWSTR)BeaconDataExtract(&parser, NULL);
        if (target_server != NULL && target_server[0] == 0) target_server = TARGET_SERVER;
    }

    status = NETAPI32$NetStatisticsGet(target_server, L"LanmanWorkstation", 0, 0, &stats);
    if (status != 0 || stats == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Unable to retrieve uptime remotely: %lu", status);
        break;
    }

    file_time.dwLowDateTime = stats->StatisticsStartTime.u.LowPart;
    file_time.dwHighDateTime = stats->StatisticsStartTime.u.HighPart;
    FileTimeToSystemTime(&file_time, &boot_time);

    BeaconPrintf(
        CALLBACK_OUTPUT,
        "ServerName: %S\nBoot time: %04u-%02u-%02u %02u:%02u:%02u\n",
        target_server ? target_server : L"(local)",
        boot_time.wYear,
        boot_time.wMonth,
        boot_time.wDay,
        boot_time.wHour,
        boot_time.wMinute,
        boot_time.wSecond
    );

    NETAPI32$NetApiBufferFree(stats);
} while (0);
