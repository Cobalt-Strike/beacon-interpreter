#include <windows.h>
#include <netapi32.h>
#include <beacon.h>

#define TARGET_SERVER ((LPWSTR)NULL)

typedef struct _TIME_OF_DAY_INFO {
    DWORD tod_elapsedt;
    DWORD tod_msecs;
    DWORD tod_hours;
    DWORD tod_mins;
    DWORD tod_secs;
    DWORD tod_hunds;
    LONG tod_timezone;
    DWORD tod_tinterval;
    DWORD tod_day;
    DWORD tod_month;
    DWORD tod_year;
    DWORD tod_weekday;
} TIME_OF_DAY_INFO, *PTIME_OF_DAY_INFO;

NETAPI32$NetRemoteTOD: u32 (ptr, ptr);

do {
    datap parser;
    TIME_OF_DAY_INFO *info;
    DWORD status;
    LPCWSTR server;
    LPWSTR target_server;

    info = NULL;
    target_server = TARGET_SERVER;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_server = (LPWSTR)BeaconDataExtract(&parser, NULL);
        if (target_server != NULL && target_server[0] == 0) target_server = TARGET_SERVER;
    }
    server = target_server ? target_server : L"localhost";

    status = NETAPI32$NetRemoteTOD(target_server, &info);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "Unable to retrieve remote time: %lu", status);
        break;
    }

    BeaconPrintf(
        CALLBACK_OUTPUT,
        "Local time (GMT%+03d:00) at %S is %02lu/%02lu/%04lu %02lu:%02lu:%02lu",
        -info->tod_timezone / 60,
        server,
        info->tod_month,
        info->tod_day,
        info->tod_year,
        info->tod_hours,
        info->tod_mins,
        info->tod_secs
    );

    NETAPI32$NetApiBufferFree(info);
} while (0);
