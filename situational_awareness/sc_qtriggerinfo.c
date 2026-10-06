#include <windows.h>
#include <beacon.h>

#define TARGET_HOST ((LPSTR)NULL)
#define TARGET_SERVICE_NAME "wuauserv"

#define SERVICES_ACTIVE_DATABASEA "ServicesActive"
#define SC_MANAGER_CONNECT 0x0001
#define SERVICE_QUERY_CONFIG 0x0001
#define SERVICE_CONFIG_TRIGGER_INFO 8
#define RPC_S_OK 0

typedef HANDLE SC_HANDLE;
typedef char *RPC_CSTR;
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
ADVAPI32$QueryServiceConfig2A: i32 (ptr, u32, ptr, u32, ptr);
RPCRT4$UuidToStringA: i32 (ptr, ptr);
RPCRT4$RpcStringFreeA: i32 (ptr);

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
    if (type > 0 && type < 21) return "";
    return "(FAILED TO RESOLVE)";
}

do {
    datap parser;
    SC_HANDLE manager;
    SC_HANDLE service;
    DWORD bytes_needed;
    DWORD result;
    DWORD i;
    RPC_CSTR guid_string;
    PSERVICE_TRIGGER trigger;
    PSERVICE_TRIGGER_INFO trigger_info;
    formatp out;
    char *output;
    int output_length;
    char *target_host;
    char *target_service;
    char *guid_display;

    manager = NULL;
    service = NULL;
    trigger_info = NULL;
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
    ADVAPI32$QueryServiceConfig2A(service, SERVICE_CONFIG_TRIGGER_INFO, NULL, 0, &bytes_needed);
    result = GetLastError();
    if (result != ERROR_INSUFFICIENT_BUFFER || bytes_needed == 0) {
        goto cleanup;
    }

    trigger_info = (PSERVICE_TRIGGER_INFO)malloc(bytes_needed);
    if (trigger_info == NULL) {
        result = ERROR_NOT_ENOUGH_MEMORY;
        goto cleanup;
    }

    if (!ADVAPI32$QueryServiceConfig2A(service, SERVICE_CONFIG_TRIGGER_INFO, trigger_info, bytes_needed, &bytes_needed)) {
        result = GetLastError();
        goto cleanup;
    }
    result = ERROR_SUCCESS;

    BeaconFormatAlloc(&out, 4096);
    if (trigger_info->cTriggers == 0) {
        BeaconFormatPrintf(&out, "The service %s has not registered for any start or stop triggers.\n", target_service);
    } else {
        BeaconFormatPrintf(&out, "SERVICE_NAME: %s\n\n", target_service);
        for (i = 0; i < trigger_info->cTriggers; i++) {
            trigger = &trigger_info->pTriggers[i];
            guid_string = NULL;
            RPCRT4$UuidToStringA(trigger->pTriggerSubtype, &guid_string);
            guid_display = guid_string ? guid_string : "(FAILED)";
            BeaconFormatPrintf(&out, "\t%s\n", trigger_action_name(trigger->dwAction));
            BeaconFormatPrintf(&out, "\t  %-20s : %s\n", trigger_type_name(trigger->dwTriggerType), guid_display);
            if (guid_string != NULL) {
                RPCRT4$RpcStringFreeA(&guid_string);
            }
            if ((trigger->dwTriggerType == 20 || trigger->dwTriggerType == 1 || trigger->dwTriggerType == 4 || trigger->dwTriggerType == 6) && trigger->cDataItems) {
                BeaconFormatPrintf(&out, "Has trigger specific data items but currently this is unsupported\n");
            }
            BeaconFormatPrintf(&out, "\n");
        }
    }

    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);

cleanup:
    if (trigger_info != NULL) {
        free(trigger_info);
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
