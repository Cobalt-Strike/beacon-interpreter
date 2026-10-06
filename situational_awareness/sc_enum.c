#include <windows.h>
#include <beacon.h>

#define TARGET_HOST ((LPSTR)NULL)

#define SERVICES_ACTIVE_DATABASEA "ServicesActive"
#define SC_MANAGER_CONNECT 0x0001
#define SERVICE_QUERY_CONFIG 0x0001
#define SERVICE_WIN32 0x00000030
#define SERVICE_STATE_ALL 0x00000003
#define SC_ENUM_PROCESS_INFO 0
#define SERVICE_CONFIG_FAILURE_ACTIONS 2
#define SERVICE_CONFIG_TRIGGER_INFO 8
#define OUTPUT_BUFFER_SIZE (1024 * 1024)
#define OUTPUT_FLUSH_THRESHOLD (64 * 1024)
#define SC_GROUP_IDENTIFIERA '+'
#define RPC_S_OK 0

typedef HANDLE SC_HANDLE;
typedef char *RPC_CSTR;

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

typedef struct _SC_ACTION {
    DWORD Type;
    DWORD Delay;
} SC_ACTION, *LPSC_ACTION;

typedef struct _SERVICE_FAILURE_ACTIONSA {
    DWORD dwResetPeriod;
    char *lpRebootMsg;
    char *lpCommand;
    DWORD cActions;
    LPSC_ACTION lpsaActions;
} SERVICE_FAILURE_ACTIONSA, *LPSERVICE_FAILURE_ACTIONSA;

typedef struct _SERVICE_TRIGGER_SPECIFIC_DATA_ITEM {
    DWORD dwDataType;
    DWORD cbData;
    BYTE *pData;
} SERVICE_TRIGGER_SPECIFIC_DATA_ITEM, *PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM;

typedef struct _SERVICE_TRIGGER {
    DWORD dwTriggerType;
    DWORD dwAction;
    PVOID pTriggerSubtype;
    DWORD cDataItems;
    PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM pDataItems;
} SERVICE_TRIGGER, *PSERVICE_TRIGGER;

typedef struct _SERVICE_TRIGGER_INFO {
    DWORD cTriggers;
    PSERVICE_TRIGGER pTriggers;
    BYTE *pReserved;
} SERVICE_TRIGGER_INFO, *PSERVICE_TRIGGER_INFO;

ADVAPI32$OpenSCManagerA: ptr (cstr, cstr, u32);
ADVAPI32$OpenServiceA: ptr (ptr, cstr, u32);
ADVAPI32$CloseServiceHandle: i32 (ptr);
ADVAPI32$EnumServicesStatusExA: i32 (ptr, u32, u32, u32, ptr, u32, ptr, ptr, ptr, cstr);
ADVAPI32$QueryServiceConfigA: i32 (ptr, ptr, u32, ptr);
ADVAPI32$QueryServiceConfig2A: i32 (ptr, u32, ptr, u32, ptr);
RPCRT4$UuidToStringA: i32 (ptr, ptr);
RPCRT4$RpcStringFreeA: i32 (ptr);

char *service_status_name(DWORD state) {
    if (state == 1) return "STOPPED";
    if (state == 2) return "START_PENDING";
    if (state == 3) return "STOP_PENDING";
    if (state == 4) return "RUNNING";
    if (state == 5) return "CONTINUE_PENDING";
    if (state == 6) return "PAUSE_PENDING";
    if (state == 7) return "PAUSED";
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

char *failure_action_name(DWORD action) {
    if (action == 0) return "NONE";
    if (action == 1) return "RESTART";
    if (action == 2) return "REBOOT";
    if (action == 3) return "COMMAND";
    return "(FAILED TO RESOLVE)";
}

char *trigger_action_name(DWORD action) {
    if (action == 1) return "START_SERVICE";
    if (action == 2) return "STOP_SERVICE";
    return "(FAILED TO RESOLVE)";
}

char *trigger_type_name(DWORD type) {
    if (type == 1) return "DEVICE_ARRIVAL";
    if (type == 2) return "IP_UP_DOWN";
    if (type == 3) return "DOMAIN_JOIN_LEAVE";
    if (type == 4) return "FIREWALL_PORT_EVENT";
    if (type == 5) return "GROUP_POLICY_UPDATE";
    if (type == 6) return "NETWORK_ENDPOINT";
    if (type == 20) return "CUSTOM";
    return "(FAILED TO RESOLVE)";
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

DWORD append_service_config(formatp *out, SC_HANDLE service) {
    DWORD result;
    DWORD bytes_needed;
    LPQUERY_SERVICE_CONFIGA config;
    char *binary_path;
    char *load_order_group;
    char *display_name;
    char *service_start_name;

    result = ERROR_SUCCESS;
    bytes_needed = 0;
    config = NULL;

    ADVAPI32$QueryServiceConfigA(service, NULL, 0, &bytes_needed);
    result = GetLastError();
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return result;
    }

    config = (LPQUERY_SERVICE_CONFIGA)malloc(bytes_needed);
    if (config == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    if (!ADVAPI32$QueryServiceConfigA(service, config, bytes_needed, &bytes_needed)) {
        result = GetLastError();
        free(config);
        return result;
    }

    binary_path = config->lpBinaryPathName ? config->lpBinaryPathName : "";
    load_order_group = config->lpLoadOrderGroup ? config->lpLoadOrderGroup : "";
    display_name = config->lpDisplayName ? config->lpDisplayName : "";
    service_start_name = config->lpServiceStartName ? config->lpServiceStartName : "";

    BeaconFormatPrintf(out, "\t%-30s : %lx %s\n", "TYPE", config->dwServiceType, service_type_name(config->dwServiceType));
    BeaconFormatPrintf(out, "\t%-30s : %lx %s\n", "START_TYPE", config->dwStartType, service_startup_name(config->dwStartType));
    BeaconFormatPrintf(out, "\t%-30s : %lx %s\n", "ERROR_CONTROL", config->dwErrorControl, service_error_name(config->dwErrorControl));
    BeaconFormatPrintf(out, "\t%-30s : %s\n", "BINARY_PATH_NAME", binary_path);
    BeaconFormatPrintf(out, "\t%-30s : %s\n", "LOAD_ORDER_GROUP", load_order_group);
    BeaconFormatPrintf(out, "\t%-30s : %ld\n", "TAG", config->dwTagId);
    BeaconFormatPrintf(out, "\t%-30s : %s\n", "DISPLAY_NAME", display_name);
    BeaconFormatPrintf(
        out,
        "\t%-30s : %s%s\n",
        "DEPENDENCIES",
        (config->lpDependencies && config->lpDependencies[0] == SC_GROUP_IDENTIFIERA) ? "(GROUP) " : "",
        make_long_str(config->lpDependencies)
    );
    BeaconFormatPrintf(out, "\t%-30s : %s\n", "SERVICE_START_NAME", service_start_name);

    free(config);
    return ERROR_SUCCESS;
}

DWORD append_service_failure(formatp *out, SC_HANDLE service) {
    DWORD result;
    DWORD bytes_needed;
    DWORD i;
    LPSC_ACTION action;
    LPSERVICE_FAILURE_ACTIONSA actions;
    char *reboot_message;
    char *command_line;

    result = ERROR_SUCCESS;
    bytes_needed = 0;
    actions = NULL;

    ADVAPI32$QueryServiceConfig2A(service, SERVICE_CONFIG_FAILURE_ACTIONS, NULL, 0, &bytes_needed);
    result = GetLastError();
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return result;
    }

    actions = (LPSERVICE_FAILURE_ACTIONSA)malloc(bytes_needed);
    if (actions == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    if (!ADVAPI32$QueryServiceConfig2A(service, SERVICE_CONFIG_FAILURE_ACTIONS, actions, bytes_needed, &bytes_needed)) {
        result = GetLastError();
        free(actions);
        return result;
    }

    reboot_message = actions->lpRebootMsg ? actions->lpRebootMsg : "";
    command_line = actions->lpCommand ? actions->lpCommand : "";

    BeaconFormatPrintf(out, "\t%-30s : %lu\n", "RESET_PERIOD (in seconds)", actions->dwResetPeriod);
    BeaconFormatPrintf(out, "\t%-30s : %s\n", "REBOOT_MESSAGE", reboot_message);
    BeaconFormatPrintf(out, "\t%-30s : %s\n", "COMMAND_LINE", command_line);
    if (actions->lpsaActions != NULL) {
        for (i = 0; i < actions->cActions; i++) {
            action = &actions->lpsaActions[i];
            BeaconFormatPrintf(
                out,
                "\t%-30s : %s -- Delay = %lu milliseconds\n",
                "FAILURE_ACTIONS",
                failure_action_name(action->Type),
                action->Delay
            );
        }
    }

    free(actions);
    return ERROR_SUCCESS;
}

DWORD append_service_triggers(formatp *out, SC_HANDLE service) {
    DWORD result;
    DWORD bytes_needed;
    DWORD i;
    RPC_CSTR guid;
    PSERVICE_TRIGGER trigger;
    PSERVICE_TRIGGER_INFO trigger_info;

    result = ERROR_SUCCESS;
    bytes_needed = 0;
    guid = NULL;
    trigger = NULL;
    trigger_info = NULL;

    ADVAPI32$QueryServiceConfig2A(service, SERVICE_CONFIG_TRIGGER_INFO, NULL, 0, &bytes_needed);
    result = GetLastError();
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return result;
    }

    trigger_info = (PSERVICE_TRIGGER_INFO)malloc(bytes_needed);
    if (trigger_info == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    if (!ADVAPI32$QueryServiceConfig2A(service, SERVICE_CONFIG_TRIGGER_INFO, trigger_info, bytes_needed, &bytes_needed)) {
        result = GetLastError();
        free(trigger_info);
        return result;
    }

    if (trigger_info->cTriggers == 0) {
        BeaconFormatPrintf(out, "The service has not registered for any start or stop triggers.\n");
        free(trigger_info);
        return ERROR_SUCCESS;
    }

    for (i = 0; i < trigger_info->cTriggers; i++) {
        trigger = &trigger_info->pTriggers[i];
        guid = NULL;
        if (RPCRT4$UuidToStringA(trigger->pTriggerSubtype, &guid) != RPC_S_OK) {
            guid = NULL;
        }
        BeaconFormatPrintf(out, "\t%s\n", trigger_action_name(trigger->dwAction));
        BeaconFormatPrintf(
            out,
            "\t  %-20s : %s\n",
            trigger_type_name(trigger->dwTriggerType),
            guid ? (char *)guid : "(FAILED)"
        );
        if (guid != NULL) {
            RPCRT4$RpcStringFreeA(&guid);
            guid = NULL;
        }
        if ((trigger->dwTriggerType == 20 || trigger->dwTriggerType == 1 || trigger->dwTriggerType == 4 || trigger->dwTriggerType == 6) && trigger->cDataItems) {
            BeaconFormatPrintf(out, "Has trigger specific data items but currently this is unsupported\n");
        }
        BeaconFormatPrintf(out, "\n");
    }

    free(trigger_info);
    return ERROR_SUCCESS;
}

void append_service_details(formatp *out, SC_HANDLE manager, char *service_name) {
    SC_HANDLE service;
    DWORD result;

    service = ADVAPI32$OpenServiceA(manager, service_name, GENERIC_READ);
    if (service == NULL) {
        result = GetLastError();
        BeaconFormatPrintf(out, "Unable to query any additional service information: %lu\n", result);
        return;
    }

    result = append_service_config(out, service);
    if (result != ERROR_SUCCESS) {
        BeaconFormatPrintf(out, "\tUnable to query base configuration: %lu\n", result);
    }
    result = append_service_failure(out, service);
    if (result != ERROR_SUCCESS) {
        BeaconFormatPrintf(out, "\tUnable to query failure configuration: %lu\n", result);
    }
    result = append_service_triggers(out, service);
    if (result != ERROR_SUCCESS) {
        BeaconFormatPrintf(out, "\tUnable to query trigger configuration: %lu\n", result);
    }
    BeaconFormatPrintf(out, "\n");

    ADVAPI32$CloseServiceHandle(service);
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

void emit_service_block(formatp *out, SC_HANDLE manager, LPENUM_SERVICE_STATUS_PROCESSA service_info) {
    char *service_name;
    char *display_name;

    service_name = service_info->lpServiceName ? service_info->lpServiceName : "";
    display_name = service_info->lpDisplayName ? service_info->lpDisplayName : "";
    BeaconFormatPrintf(out, "SERVICE_NAME: %s\n", service_name);
    BeaconFormatPrintf(out, "DISPLAY_NAME: %s\n", display_name);
    BeaconFormatPrintf(out, "\t%-30s : %ld %s\n", "TYPE", service_info->ServiceStatusProcess.dwServiceType, service_type_name(service_info->ServiceStatusProcess.dwServiceType));
    BeaconFormatPrintf(out, "\t%-30s : %ld %s\n", "STATE", service_info->ServiceStatusProcess.dwCurrentState, service_status_name(service_info->ServiceStatusProcess.dwCurrentState));
    BeaconFormatPrintf(out, "\t%-30s : %ld\n", "WIN32_EXIT_CODE", service_info->ServiceStatusProcess.dwWin32ExitCode);
    BeaconFormatPrintf(out, "\t%-30s : %ld\n", "SERVICE_EXIT_CODE", service_info->ServiceStatusProcess.dwServiceSpecificExitCode);
    BeaconFormatPrintf(out, "\t%-30s : %ld\n", "CHECKPOINT", service_info->ServiceStatusProcess.dwCheckPoint);
    BeaconFormatPrintf(out, "\t%-30s : %ld\n", "WAIT_HINT", service_info->ServiceStatusProcess.dwWaitHint);
    BeaconFormatPrintf(out, "\t%-30s : %ld\n", "PID", service_info->ServiceStatusProcess.dwProcessId);
    BeaconFormatPrintf(out, "\t%-30s : %ld\n", "FLAGS", service_info->ServiceStatusProcess.dwServiceFlags);
    append_service_details(out, manager, service_info->lpServiceName);
}

DWORD enumerate_services(SC_HANDLE manager) {
    LPENUM_SERVICE_STATUS_PROCESSA services;
    DWORD bytes_needed;
    DWORD count;
    DWORD resume_handle;
    DWORD result;
    DWORD i;
    BOOL enum_result;
    formatp out;

    services = NULL;
    bytes_needed = 0;
    count = 0;
    resume_handle = 0;
    result = ERROR_SUCCESS;

    enum_result = ADVAPI32$EnumServicesStatusExA(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytes_needed, &count, &resume_handle, NULL);
    if (!enum_result && bytes_needed) {
        services = (LPENUM_SERVICE_STATUS_PROCESSA)malloc(bytes_needed);
        if (services == NULL) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        enum_result = ADVAPI32$EnumServicesStatusExA(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, services, bytes_needed, &bytes_needed, &count, &resume_handle, NULL);
        if (!enum_result) {
            result = GetLastError();
            free(services);
            return result;
        }
    } else {
        return GetLastError();
    }

    BeaconFormatAlloc(&out, OUTPUT_BUFFER_SIZE);
    for (i = 0; i < count; i++) {
        emit_service_block(&out, manager, &services[i]);
        if (out.length >= OUTPUT_FLUSH_THRESHOLD) {
            flush_output(&out);
        }
    }
    flush_output(&out);
    BeaconFormatFree(&out);

    free(services);
    return ERROR_SUCCESS;
}

do {
    datap parser;
    SC_HANDLE manager;
    DWORD result;
    char *target_host;

    target_host = TARGET_HOST;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_host = BeaconDataExtract(&parser, NULL);
        if (target_host != NULL && target_host[0] == 0) target_host = TARGET_HOST;
    }

    manager = ADVAPI32$OpenSCManagerA(target_host, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | GENERIC_READ);
    if (manager == NULL) {
        result = GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "Failed to connect to service manager: %lu", result);
        break;
    }

    result = enumerate_services(manager);
    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to query service: %lu", result);
    }

    ADVAPI32$CloseServiceHandle(manager);
} while (0);
