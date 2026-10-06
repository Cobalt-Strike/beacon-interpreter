#include <windows.h>
#include <beacon.h>

#define TARGET_HOST ((LPSTR)NULL)
#define TARGET_SERVICE_NAME "wuauserv"

#define SC_MANAGER_CONNECT 0x0001
#define SERVICE_QUERY_CONFIG 0x0001
#define SERVICE_CONFIG_DESCRIPTION 1

typedef HANDLE SC_HANDLE;
typedef struct _SERVICE_DESCRIPTIONA {
    char *lpDescription;
} SERVICE_DESCRIPTIONA, *LPSERVICE_DESCRIPTIONA;

ADVAPI32$OpenSCManagerA: ptr (cstr, cstr, u32);
ADVAPI32$OpenServiceA: ptr (ptr, cstr, u32);
ADVAPI32$CloseServiceHandle: i32 (ptr);
ADVAPI32$QueryServiceConfig2A: i32 (ptr, u32, ptr, u32, ptr);

do {
    datap parser;
    SC_HANDLE manager;
    SC_HANDLE service;
    DWORD bytes_needed;
    DWORD result;
    LPSERVICE_DESCRIPTIONA description;
    formatp out;
    char *output;
    int output_length;
    char *target_host;
    char *target_service;

    target_host = TARGET_HOST;
    target_service = TARGET_SERVICE_NAME;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_host = BeaconDataExtract(&parser, NULL);
        target_service = BeaconDataExtract(&parser, NULL);
        if (target_host != NULL && target_host[0] == 0) target_host = TARGET_HOST;
        if (target_service == NULL || target_service[0] == 0) target_service = TARGET_SERVICE_NAME;
    }

    manager = ADVAPI32$OpenSCManagerA(target_host, NULL, SC_MANAGER_CONNECT);
    if (manager == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManagerA failed: %lu", GetLastError());
        break;
    }

    service = ADVAPI32$OpenServiceA(manager, target_service, SERVICE_QUERY_CONFIG);
    if (service == NULL) {
        ADVAPI32$CloseServiceHandle(manager);
        BeaconPrintf(CALLBACK_ERROR, "OpenServiceA failed: %lu", GetLastError());
        break;
    }

    bytes_needed = 0;
    ADVAPI32$QueryServiceConfig2A(service, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &bytes_needed);
    result = GetLastError();
    if (result != ERROR_INSUFFICIENT_BUFFER || bytes_needed == 0) {
        ADVAPI32$CloseServiceHandle(service);
        ADVAPI32$CloseServiceHandle(manager);
        BeaconPrintf(CALLBACK_ERROR, "QueryServiceConfig2A sizing failed: %lu", result);
        break;
    }

    description = (LPSERVICE_DESCRIPTIONA)malloc(bytes_needed);
    if (description == NULL) {
        ADVAPI32$CloseServiceHandle(service);
        ADVAPI32$CloseServiceHandle(manager);
        BeaconPrintf(CALLBACK_ERROR, "malloc failed");
        break;
    }

    if (!ADVAPI32$QueryServiceConfig2A(service, SERVICE_CONFIG_DESCRIPTION, description, bytes_needed, &bytes_needed)) {
        result = GetLastError();
        free(description);
        ADVAPI32$CloseServiceHandle(service);
        ADVAPI32$CloseServiceHandle(manager);
        BeaconPrintf(CALLBACK_ERROR, "QueryServiceConfig2A failed: %lu", result);
        break;
    }

    BeaconFormatAlloc(&out, 2048);
    BeaconFormatPrintf(&out, "SERVICE_NAME: %s\n", target_service);
    BeaconFormatPrintf(&out, "DESCRIPTION: %s\n", description->lpDescription ? description->lpDescription : "");
    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);

    free(description);
    ADVAPI32$CloseServiceHandle(service);
    ADVAPI32$CloseServiceHandle(manager);
} while (0);
