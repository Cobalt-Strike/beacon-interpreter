#include <windows.h>
#include <beacon.h>

#define TARGET_HOST ((LPSTR)NULL)
#define TARGET_SERVICE_NAME ""

#define SERVICES_ACTIVE_DATABASEA "ServicesActive"
#define SC_MANAGER_CONNECT 0x0001
#define SERVICE_WIN32 0x00000030
#define SERVICE_STATE_ALL 0x00000003
#define SC_STATUS_PROCESS_INFO 0
#define SC_ENUM_PROCESS_INFO 0
#define OUTPUT_BUFFER_SIZE (1024 * 1024)
#define OUTPUT_FLUSH_THRESHOLD (64 * 1024)

typedef HANDLE SC_HANDLE;

typedef struct _SERVICE_STATUS_PROCESS {
    DWORD dwServiceType;
    DWORD dwCurrentState;
    DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode;
    DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint;
    DWORD dwWaitHint;
    DWORD dwProcessId;
    DWORD dwServiceFlags;
} SERVICE_STATUS_PROCESS, *LPSERVICE_STATUS_PROCESS;

typedef struct _ENUM_SERVICE_STATUS_PROCESSA {
    char *lpServiceName;
    char *lpDisplayName;
    SERVICE_STATUS_PROCESS ServiceStatusProcess;
} ENUM_SERVICE_STATUS_PROCESSA, *LPENUM_SERVICE_STATUS_PROCESSA;

ADVAPI32$OpenSCManagerA: ptr (cstr, cstr, u32);
ADVAPI32$OpenServiceA: ptr (ptr, cstr, u32);
ADVAPI32$CloseServiceHandle: i32 (ptr);
ADVAPI32$QueryServiceStatusEx: i32 (ptr, u32, ptr, u32, ptr);
ADVAPI32$EnumServicesStatusExA: i32 (ptr, u32, u32, u32, ptr, u32, ptr, ptr, ptr, cstr);

char *service_status_name(DWORD state) {
    if (state == 1) return "STOPPED";
    if (state == 2) return "START_PENDING";
    if (state == 3) return "STOP_PENDING";
    if (state == 4) return "RUNNING";
    if (state == 5) return "CONTINUE_PENDING";
    if (state == 6) return "PAUSE_PENDING";
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

void flush_output(formatp *out) {
    char *output;
    int output_length;

    output = BeaconFormatToString(out, &output_length);
    if (output != NULL && output_length > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatReset(out);
}

void emit_status_block(formatp *out, char *service_name, char *display_name, SERVICE_STATUS_PROCESS *status, int include_display, char *flags_label) {
    char *name_value;
    char *display_value;

    name_value = service_name ? service_name : "";
    display_value = display_name ? display_name : "";

    BeaconFormatPrintf(out, "SERVICE_NAME: %s\n", name_value);
    if (include_display) {
        BeaconFormatPrintf(out, "DISPLAY_NAME: %s\n", display_value);
    }
    BeaconFormatPrintf(out, "\t%-20s : %d %s\n", "TYPE", status->dwServiceType, service_type_name(status->dwServiceType));
    BeaconFormatPrintf(out, "\t%-20s : %d %s\n", "STATE", status->dwCurrentState, service_status_name(status->dwCurrentState));
    BeaconFormatPrintf(out, "\t%-20s : %d\n", "WIN32_EXIT_CODE", status->dwWin32ExitCode);
    BeaconFormatPrintf(out, "\t%-20s : %d\n", "SERVICE_EXIT_CODE", status->dwServiceSpecificExitCode);
    BeaconFormatPrintf(out, "\t%-20s : %d\n", "CHECKPOINT", status->dwCheckPoint);
    BeaconFormatPrintf(out, "\t%-20s : %d\n", "WAIT_HINT", status->dwWaitHint);
    BeaconFormatPrintf(out, "\t%-20s : %d\n", "PID", status->dwProcessId);
    BeaconFormatPrintf(out, "\t%-20s : %d\n", flags_label, status->dwServiceFlags);
    if (include_display) {
        BeaconFormatPrintf(out, "\n");
    }
}

DWORD query_service(char *target_host, char *target_service) {
    SC_HANDLE manager;
    SC_HANDLE service;
    DWORD result;
    DWORD bytes_needed;
    SERVICE_STATUS_PROCESS status;
    formatp out;

    manager = NULL;
    service = NULL;
    result = ERROR_SUCCESS;
    bytes_needed = 0;

    manager = ADVAPI32$OpenSCManagerA(target_host, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | GENERIC_READ);
    if (manager == NULL) {
        result = GetLastError();
        goto query_cleanup;
    }

    service = ADVAPI32$OpenServiceA(manager, target_service, GENERIC_READ);
    if (service == NULL) {
        result = GetLastError();
        goto query_cleanup;
    }

    if (!ADVAPI32$QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, &status, sizeof(SERVICE_STATUS_PROCESS), &bytes_needed)) {
        result = GetLastError();
        goto query_cleanup;
    }

    BeaconFormatAlloc(&out, OUTPUT_BUFFER_SIZE);
    emit_status_block(&out, target_service, NULL, &status, 0, "Flags");
    flush_output(&out);
    BeaconFormatFree(&out);

query_cleanup:
    if (service != NULL) {
        ADVAPI32$CloseServiceHandle(service);
    }
    if (manager != NULL) {
        ADVAPI32$CloseServiceHandle(manager);
    }
    return result;
}

DWORD enumerate_services(char *target_host) {
    SC_HANDLE manager;
    LPENUM_SERVICE_STATUS_PROCESSA services;
    DWORD bytes_needed;
    DWORD count;
    DWORD resume_handle;
    DWORD result;
    DWORD i;
    BOOL enum_result;
    formatp out;

    manager = NULL;
    services = NULL;
    bytes_needed = 0;
    count = 0;
    resume_handle = 0;
    result = ERROR_SUCCESS;

    manager = ADVAPI32$OpenSCManagerA(target_host, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | GENERIC_READ);
    if (manager == NULL) {
        result = GetLastError();
        goto enum_cleanup;
    }

    enum_result = ADVAPI32$EnumServicesStatusExA(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytes_needed, &count, &resume_handle, NULL);
    if (!enum_result && bytes_needed) {
        services = (LPENUM_SERVICE_STATUS_PROCESSA)malloc(bytes_needed);
        if (services == NULL) {
            result = ERROR_NOT_ENOUGH_MEMORY;
            goto enum_cleanup;
        }

        enum_result = ADVAPI32$EnumServicesStatusExA(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, services, bytes_needed, &bytes_needed, &count, &resume_handle, NULL);
        if (!enum_result) {
            result = GetLastError();
            goto enum_cleanup;
        }
    } else {
        result = GetLastError();
        goto enum_cleanup;
    }

    BeaconFormatAlloc(&out, OUTPUT_BUFFER_SIZE);
    for (i = 0; i < count; i++) {
        emit_status_block(&out, services[i].lpServiceName, services[i].lpDisplayName, &services[i].ServiceStatusProcess, 1, "FLAGS");
        if (out.length >= OUTPUT_FLUSH_THRESHOLD) {
            flush_output(&out);
        }
    }
    flush_output(&out);
    BeaconFormatFree(&out);

enum_cleanup:
    if (services != NULL) {
        free(services);
    }
    if (manager != NULL) {
        ADVAPI32$CloseServiceHandle(manager);
    }
    return result;
}

do {
    datap parser;
    char *target_host;
    char *target_service;
    int target_service_length;
    DWORD result;

    target_host = TARGET_HOST;
    target_service = TARGET_SERVICE_NAME;
    target_service_length = 1;
    result = ERROR_SUCCESS;

    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_host = BeaconDataExtract(&parser, NULL);
        target_service = BeaconDataExtract(&parser, &target_service_length);
        if (target_host != NULL && target_host[0] == 0) target_host = TARGET_HOST;
        if (target_service == NULL) {
            target_service = TARGET_SERVICE_NAME;
            target_service_length = 1;
        }
    }

    if (target_service_length == 1) {
        result = enumerate_services(target_host);
    } else {
        result = query_service(target_host, target_service);
    }

    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to query service: %u", result);
    }
} while (0);
