#include <windows.h>
#include <beacon.h>

#define TARGET_HOST ((LPSTR)NULL)
#define TARGET_SERVICE_NAME "wuauserv"

#define SERVICES_ACTIVE_DATABASEA "ServicesActive"
#define SC_MANAGER_CONNECT 0x0001
#define SERVICE_QUERY_CONFIG 0x0001
#define SERVICE_QUERY_STATUS 0x0004
#define SERVICE_NO_CHANGE ((DWORD)-1)
#define SC_GROUP_IDENTIFIERA '+'

typedef HANDLE SC_HANDLE;
typedef struct _QUERY_SERVICE_CONFIGA {
    DWORD dwServiceType;
    DWORD dwStartType;
    DWORD dwErrorControl;
    char *lpBinaryPathName;
    char *lpLoadOrderGroup;
    DWORD dwTagId;
    char *lpDependencies;
    char *lpServiceStartName;
    char *lpDisplayName;
} QUERY_SERVICE_CONFIGA, *LPQUERY_SERVICE_CONFIGA;
typedef struct _SERVICE_STATUS {
    DWORD dwServiceType;
    DWORD dwCurrentState;
    DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode;
    DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint;
    DWORD dwWaitHint;
} SERVICE_STATUS, *LPSERVICE_STATUS;

ADVAPI32$OpenSCManagerA: ptr (cstr, cstr, u32);
ADVAPI32$OpenServiceA: ptr (ptr, cstr, u32);
ADVAPI32$CloseServiceHandle: i32 (ptr);
ADVAPI32$QueryServiceConfigA: i32 (ptr, ptr, u32, ptr);
ADVAPI32$QueryServiceStatus: i32 (ptr, ptr);

char *service_state_name(DWORD state) {
    if (state == 1) return "STOPPED";
    if (state == 2) return "START_PENDING";
    if (state == 3) return "STOP_PENDING";
    if (state == 4) return "RUNNING";
    if (state == 5) return "CONTINUE_PENDING";
    if (state == 6) return "PAUSE_PENDING";
    return "UNKNOWN";
}

char *service_startup_name(DWORD value) {
    if (value == 0) return "BOOT_DRIVER";
    if (value == 1) return "SYSTEM_START_DRIVER";
    if (value == 2) return "AUTO_START";
    if (value == 3) return "DEMAND_START";
    if (value == 4) return "DISABLED";
    return "UNKNOWN";
}

char *service_error_name(DWORD value) {
    if (value == 0) return "IGNORE";
    if (value == 1) return "NORMAL";
    if (value == 2) return "SEVERE";
    if (value == 3) return "CRITICAL";
    return "UNKNOWN";
}

char *service_type_name(DWORD value) {
    if (value == 0x1) return "KERNEL_DRIVER";
    if (value == 0x2) return "FILE_DRIVER";
    if (value == 0x10) return "WIN32_OWN";
    if (value == 0x110) return "WIN32_OWN Interactive";
    if (value == 0x20) return "WIN32_SHARED";
    if (value == 0x120) return "WIN32_SHARED Interactive";
    if (value == 0x50) return "USER_OWN";
    if (value == 0xD0) return "USER_OWN Instance";
    if (value == 0x60) return "USER_SHARED";
    if (value == 0xE0) return "USER_SHARED Instance";
    return "UNKNOWN";
}

char *make_long_str(char *service_info) {
    DWORD i;

    i = 0;
    if (service_info == NULL || service_info[0] == 0) {
        return "";
    }
    if (service_info[0] == SC_GROUP_IDENTIFIERA) {
        return service_info;
    }
    while (!(service_info[i] == 0 && service_info[i + 1] == 0)) {
        if (service_info[i] == 0) {
            service_info[i] = ' ';
        }
        i++;
    }
    return service_info;
}

do {
    datap parser;
    SC_HANDLE manager;
    SC_HANDLE service;
    DWORD bytes_needed;
    DWORD result;
    LPQUERY_SERVICE_CONFIGA config;
    SERVICE_STATUS status;
    formatp out;
    char *output;
    int output_length;
    char *target_host;
    char *target_service;
    char *binary_path;
    char *load_order_group;
    char *display_name;
    char *service_start_name;
    char *dependencies_prefix;

    manager = NULL;
    service = NULL;
    config = NULL;
    result = ERROR_SUCCESS;
    target_host = TARGET_HOST;
    target_service = TARGET_SERVICE_NAME;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_host = BeaconDataExtract(&parser, NULL);
        target_service = BeaconDataExtract(&parser, NULL);
        if (target_host != NULL && target_host[0] == 0) target_host = TARGET_HOST;
        if (target_service == NULL || target_service[0] == 0) target_service = TARGET_SERVICE_NAME;
    }

    manager = ADVAPI32$OpenSCManagerA(target_host, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | GENERIC_READ);
    if (manager == NULL) {
        result = GetLastError();
        goto cleanup;
    }

    service = ADVAPI32$OpenServiceA(manager, target_service, GENERIC_READ);
    if (service == NULL) {
        result = GetLastError();
        goto cleanup;
    }

    bytes_needed = 0;
    ADVAPI32$QueryServiceConfigA(service, NULL, 0, &bytes_needed);
    result = GetLastError();
    if (result != ERROR_INSUFFICIENT_BUFFER || bytes_needed == 0) {
        goto cleanup;
    }

    config = (LPQUERY_SERVICE_CONFIGA)malloc(bytes_needed);
    if (config == NULL) {
        result = ERROR_NOT_ENOUGH_MEMORY;
        goto cleanup;
    }

    if (!ADVAPI32$QueryServiceConfigA(service, config, bytes_needed, &bytes_needed)) {
        result = GetLastError();
        goto cleanup;
    }

    if (!ADVAPI32$QueryServiceStatus(service, &status)) {
        result = GetLastError();
        goto cleanup;
    }
    result = ERROR_SUCCESS;

    binary_path = config->lpBinaryPathName ? config->lpBinaryPathName : "";
    load_order_group = config->lpLoadOrderGroup ? config->lpLoadOrderGroup : "";
    display_name = config->lpDisplayName ? config->lpDisplayName : "";
    service_start_name = config->lpServiceStartName ? config->lpServiceStartName : "";
    dependencies_prefix = (config->lpDependencies && config->lpDependencies[0] == SC_GROUP_IDENTIFIERA) ? "(GROUP) " : "";

    BeaconFormatAlloc(&out, 4096);
    BeaconFormatPrintf(&out, "SERVICE_NAME: %s\n", target_service);
    BeaconFormatPrintf(&out, "\t%-20s : %lx %s\n", "TYPE", config->dwServiceType, service_type_name(config->dwServiceType));
    BeaconFormatPrintf(&out, "\t%-20s : %lx %s\n", "START_TYPE", config->dwStartType, service_startup_name(config->dwStartType));
    BeaconFormatPrintf(&out, "\t%-20s : %lx %s\n", "ERROR_CONTROL", config->dwErrorControl, service_error_name(config->dwErrorControl));
    BeaconFormatPrintf(&out, "\t%-20s : %s\n", "BINARY_PATH_NAME", binary_path);
    BeaconFormatPrintf(&out, "\t%-20s : %s\n", "LOAD_ORDER_GROUP", load_order_group);
    BeaconFormatPrintf(&out, "\t%-20s : %ld\n", "TAG", config->dwTagId);
    BeaconFormatPrintf(&out, "\t%-20s : %s\n", "DISPLAY_NAME", display_name);
    BeaconFormatPrintf(&out, "\t%-20s : %s%s\n", "DEPENDENCIES", dependencies_prefix, make_long_str(config->lpDependencies));
    BeaconFormatPrintf(&out, "\t%-20s : %s\n", "SERVICE_START_NAME", service_start_name);
    BeaconFormatPrintf(&out, "\t%-20s : %s\n", "CURRENT_STATUS", service_state_name(status.dwCurrentState));

    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);

cleanup:
    if (config != NULL) {
        free(config);
    }
    if (service != NULL) {
        ADVAPI32$CloseServiceHandle(service);
    }
    if (manager != NULL) {
        ADVAPI32$CloseServiceHandle(manager);
    }
    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to query service: %u", result);
    }
} while (0);
