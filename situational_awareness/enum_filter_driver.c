#include <windows.h>
#include <advapi.h>
#include <winreg.h>
#include <winerror.h>
#include <beacon.h>

#define TARGET_HOST NULL
#define SERVICES_KEY "SYSTEM\\CurrentControlSet\\Services"
#define INSTANCES_KEY "Instances"
#define ALTITUDE_VALUE "Altitude"
void append_driver_row(formatp *out, char *service_name, DWORD altitude) {
    char *category;

    category = "other";
    if (altitude >= 360000 && altitude <= 389999) {
        category = "activitymonitor";
    } else if (altitude >= 320000 && altitude <= 329999) {
        category = "antivirus";
    } else if (altitude >= 260000 && altitude <= 269999) {
        category = "contentscreener";
    }

    BeaconFormatPrintf(out, "%s,%s,%lu\n", category, service_name, altitude);
}

do {
    datap parser;
    HKEY remote_key;
    HKEY root_key;
    HKEY service_key;
    HKEY instances_key;
    HKEY instance_subkey;
    DWORD service_index;
    DWORD instance_index;
    DWORD result;
    DWORD rows;
    char service_name[MAX_PATH];
    char instance_name[MAX_PATH];
    char altitude_string[MAX_PATH];
    DWORD service_name_size;
    DWORD instance_name_size;
    DWORD altitude_size;
    DWORD altitude_type;
    DWORD altitude_value;
    formatp out;
    char *output;
    int output_length;
    char *target_host;

    target_host = TARGET_HOST;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_host = BeaconDataExtract(&parser, NULL);
        if (target_host != NULL && target_host[0] == 0) target_host = TARGET_HOST;
    }

    remote_key = NULL;
    root_key = NULL;
    service_key = NULL;
    instances_key = NULL;
    instance_subkey = NULL;
    rows = 0;

    if (target_host == NULL) {
        result = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, SERVICES_KEY, 0, KEY_READ, &root_key);
    } else {
        result = ADVAPI32$RegConnectRegistryA(target_host, HKEY_LOCAL_MACHINE, &remote_key);
        if (result == ERROR_SUCCESS) {
            result = ADVAPI32$RegOpenKeyExA(remote_key, SERVICES_KEY, 0, KEY_READ, &root_key);
        }
    }

    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open Services key: %lu", result);
        break;
    }

    BeaconFormatAlloc(&out, 16384);

    service_index = 0;
    while (1) {
        service_name_size = MAX_PATH;
        result = ADVAPI32$RegEnumKeyExA(root_key, service_index, service_name, &service_name_size, NULL, NULL, NULL, NULL);
        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (result != ERROR_SUCCESS) {
            service_index++;
            continue;
        }

        if (ADVAPI32$RegOpenKeyExA(root_key, service_name, 0, KEY_READ, &service_key) == ERROR_SUCCESS) {
            if (ADVAPI32$RegOpenKeyExA(service_key, INSTANCES_KEY, 0, KEY_READ, &instances_key) == ERROR_SUCCESS) {
                instance_index = 0;
                while (1) {
                    instance_name_size = MAX_PATH;
                    result = ADVAPI32$RegEnumKeyExA(instances_key, instance_index, instance_name, &instance_name_size, NULL, NULL, NULL, NULL);
                    if (result == ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    if (result != ERROR_SUCCESS) {
                        instance_index++;
                        continue;
                    }

                    if (ADVAPI32$RegOpenKeyExA(instances_key, instance_name, 0, KEY_READ, &instance_subkey) == ERROR_SUCCESS) {
                        altitude_size = MAX_PATH;
                        altitude_type = 0;
                        if (ADVAPI32$RegQueryValueExA(instance_subkey, ALTITUDE_VALUE, NULL, &altitude_type, altitude_string, &altitude_size) == ERROR_SUCCESS) {
                            altitude_value = strtoul(altitude_string, NULL, 10);
                            append_driver_row(&out, service_name, altitude_value);
                            rows++;
                        }
                        ADVAPI32$RegCloseKey(instance_subkey);
                        instance_subkey = NULL;
                    }
                    instance_index++;
                }
                ADVAPI32$RegCloseKey(instances_key);
                instances_key = NULL;
            }
            ADVAPI32$RegCloseKey(service_key);
            service_key = NULL;
        }
        service_index++;
    }

    if (root_key != NULL) {
        ADVAPI32$RegCloseKey(root_key);
    }
    if (remote_key != NULL) {
        ADVAPI32$RegCloseKey(remote_key);
    }

    BeaconFormatPrintf(&out, "SUCCESS.\n");

    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);
} while (0);
