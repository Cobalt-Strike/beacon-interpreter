#include <windows.h>
#include <advapi.h>
#include <winreg.h>
#include <winerror.h>
#include <beacon.h>

#define TARGET_HOST ((LPSTR)NULL)
#define TARGET_HIVE HKEY_LOCAL_MACHINE
#define TARGET_HIVE_NAME "HKEY_LOCAL_MACHINE"
#define TARGET_KEY_PATH "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
#define TARGET_VALUE_NAME ""
#define RECURSIVE 0

char *g_hive_name;
int g_recursive;

HKEY hive_from_id(int hive_id) {
    if (hive_id == 0) return HKEY_CLASSES_ROOT;
    if (hive_id == 1) return HKEY_CURRENT_USER;
    if (hive_id == 3) return HKEY_USERS;
    return HKEY_LOCAL_MACHINE;
}

char *hive_name_from_id(int hive_id) {
    if (hive_id == 0) return "HKEY_CLASSES_ROOT";
    if (hive_id == 1) return "HKEY_CURRENT_USER";
    if (hive_id == 3) return "HKEY_USERS";
    return "HKEY_LOCAL_MACHINE";
}

char *reg_type_name(DWORD type) {
    if (type == 0) return "REG_NONE";
    if (type == REG_SZ) return "REG_SZ";
    if (type == REG_EXPAND_SZ) return "REG_EXPAND_SZ";
    if (type == REG_BINARY) return "REG_BINARY";
    if (type == REG_DWORD) return "REG_DWORD";
    if (type == REG_DWORD_BIG_ENDIAN) return "REGDWORD_BE";
    if (type == 6) return "REG_LINK";
    if (type == REG_MULTI_SZ) return "REG_MULTI_SZ";
    if (type == 8) return "REG_RESOURCE_LIST";
    if (type == 9) return "REG_FULL_RESOURCE_DESC";
    if (type == 10) return "REG_RESOURCE_REQ_LIST";
    if (type == REG_QWORD) return "REG_QWORD";
    return "UNKNOWN";
}

void key_timestamp(HKEY key, char *date_text) {
    FILETIME last_write;
    SYSTEMTIME system_time;
    SYSTEMTIME local_time;
    DWORD status;

    status = ADVAPI32$RegQueryInfoKeyA(key, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &last_write);
    if (status != ERROR_SUCCESS) {
        sprintf(date_text, "Unable to get time");
        BeaconPrintf(CALLBACK_ERROR, "Error calling RegQueryInfoKeyA with error code %d\n", status);
        return;
    }

    FileTimeToSystemTime(&last_write, &system_time);
    SystemTimeToTzSpecificLocalTime(NULL, &system_time, &local_time);
    sprintf(
        date_text,
        "%02i/%02i/%04i %02i:%02i:%02i",
        local_time.wMonth,
        local_time.wDay,
        local_time.wYear,
        local_time.wHour,
        local_time.wMinute,
        local_time.wSecond
    );
}

void append_key_header(formatp *out, HKEY key, char *path) {
    char date_text[32];

    key_timestamp(key, date_text);
    BeaconFormatPrintf(out, "%-24s %s\\%s\n", date_text, g_hive_name, path);
}

void append_value_query_header(formatp *out, HKEY key, char *path) {
    char date_text[32];

    key_timestamp(key, date_text);
    BeaconFormatPrintf(out, "%24s %s\\%s\n", date_text, g_hive_name, path);
}

void append_value(formatp *out, char *value_name, DWORD type, char *data, DWORD data_length) {
    DWORD dword_value;
    ULONGLONG qword_value;
    char *cursor;
    DWORD cursor_length;
    int i;
    int column_count;

    if (value_name == NULL) {
        value_name = "[NULL]";
    }

    BeaconFormatPrintf(out, "\t%-20s   %-15s ", value_name, reg_type_name(type));

    if (type == REG_BINARY) {
        column_count = 0;
        for (i = 0; i < data_length; i++) {
            if (column_count == 0) {
                BeaconFormatPrintf(out, "\n");
            }
            BeaconFormatPrintf(out, " %2.2x ", data[i] & 0xff);
            column_count++;
            if (column_count == 16) {
                column_count = 0;
            }
        }
        BeaconFormatPrintf(out, "\n");
    } else if ((type == REG_DWORD || type == REG_DWORD_BIG_ENDIAN) && data_length == 4) {
        dword_value = *(DWORD *)data;
        BeaconFormatPrintf(out, "%lu\n", dword_value);
    } else if (type == REG_QWORD && data_length == 8) {
        qword_value = *(ULONGLONG *)data;
        BeaconFormatPrintf(out, "%llu\n", qword_value);
    } else if (type == REG_SZ || type == REG_EXPAND_SZ) {
        BeaconFormatPrintf(out, "%s\n", data);
    } else if (type == REG_MULTI_SZ) {
        cursor = data;
        while (cursor[0] != 0) {
            cursor_length = strlen(cursor) + 1;
            BeaconFormatPrintf(out, "%s", cursor);
            if (cursor[cursor_length] != 0) {
                BeaconFormatPrintf(out, "\\0");
            }
            cursor += cursor_length;
        }
        BeaconFormatPrintf(out, "\n");
    } else {
        BeaconFormatPrintf(out, "None data type, or unhandled\n");
    }
}

void enum_key(formatp *out, HKEY key, char *path) {
    DWORD value_index;
    DWORD subkey_index;
    DWORD subkey_count;
    DWORD value_count;
    char value_name[512];
    char subkey_name[512];
    DWORD value_name_size;
    DWORD subkey_name_size;
    DWORD type;
    DWORD data_size;
    char data_buffer[2048];
    HKEY child_key;
    char child_path[1024];
    char date_text[32];
    DWORD result;
    int printed_values;

    append_key_header(out, key, path);
    subkey_count = 0;
    value_count = 0;
    result = ADVAPI32$RegQueryInfoKeyA(key, NULL, NULL, NULL, &subkey_count, NULL, NULL, &value_count, NULL, NULL, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        BeaconFormatPrintf(out, "failed to query info about key");
        return;
    }

    value_index = 0;
    printed_values = 0;
    while (1) {
        value_name_size = sizeof(value_name);
        data_size = sizeof(data_buffer);
        type = 0;
        memset(data_buffer, 0, sizeof(data_buffer));
        if (ADVAPI32$RegEnumValueA(key, value_index, value_name, &value_name_size, NULL, &type, data_buffer, &data_size) != ERROR_SUCCESS) {
            break;
        }
        append_value(out, value_name, type, data_buffer, data_size);
        printed_values = 1;
        value_index++;
    }
    if (printed_values) {
        BeaconFormatPrintf(out, "\n");
    }

    subkey_index = 0;
    while (1) {
        subkey_name_size = sizeof(subkey_name);
        if (ADVAPI32$RegEnumKeyExA(key, subkey_index, subkey_name, &subkey_name_size, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }
        child_key = NULL;
        if (g_recursive) {
            if (ADVAPI32$RegOpenKeyExA(key, subkey_name, 0, KEY_READ, &child_key) == ERROR_SUCCESS) {
                _snprintf(child_path, sizeof(child_path), "%s\\%s", path, subkey_name);
                enum_key(out, child_key, child_path);
                ADVAPI32$RegCloseKey(child_key);
            }
        } else {
            if (ADVAPI32$RegOpenKeyExA(key, subkey_name, 0, KEY_READ, &child_key) == ERROR_SUCCESS) {
                key_timestamp(child_key, date_text);
                BeaconFormatPrintf(out, "%-24s %s\\%s\\%s\n", date_text, g_hive_name, path, subkey_name);
                ADVAPI32$RegCloseKey(child_key);
            } else {
                BeaconFormatPrintf(out, "%-24s %s\\%s\\%s\n", "Unable to get time", g_hive_name, path, subkey_name);
            }
        }
        subkey_index++;
    }
}

do {
    datap parser;
    HKEY remote_key;
    HKEY root_key;
    HKEY target_hive;
    DWORD result;
    DWORD type;
    DWORD size;
    char data_buffer[2048];
    formatp out;
    char *output;
    int output_length;
    char *target_host;
    char *target_key_path;
    char *target_value_name;
    int hive_id;

    remote_key = NULL;
    root_key = NULL;
    target_host = TARGET_HOST;
    target_hive = TARGET_HIVE;
    target_key_path = TARGET_KEY_PATH;
    target_value_name = TARGET_VALUE_NAME;
    g_hive_name = TARGET_HIVE_NAME;
    g_recursive = RECURSIVE;

    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_host = BeaconDataExtract(&parser, NULL);
        hive_id = BeaconDataInt(&parser);
        target_hive = hive_from_id(hive_id);
        g_hive_name = hive_name_from_id(hive_id);
        target_key_path = BeaconDataExtract(&parser, NULL);
        target_value_name = BeaconDataExtract(&parser, NULL);
        g_recursive = BeaconDataInt(&parser);
        if (target_host != NULL && target_host[0] == 0) target_host = TARGET_HOST;
        if (target_key_path == NULL || target_key_path[0] == 0) target_key_path = TARGET_KEY_PATH;
        if (target_value_name == NULL) target_value_name = TARGET_VALUE_NAME;
    }

    if (target_host == NULL) {
        result = ADVAPI32$RegOpenKeyExA(target_hive, target_key_path, 0, KEY_READ, &root_key);
    } else {
        result = ADVAPI32$RegConnectRegistryA(target_host, target_hive, &remote_key);
        if (result == ERROR_SUCCESS) {
            result = ADVAPI32$RegOpenKeyExA(remote_key, target_key_path, 0, KEY_READ, &root_key);
        }
    }

    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to query Regkey, error value: %d", result);
        break;
    }

    BeaconFormatAlloc(&out, 16384);
    if (target_value_name != NULL && strlen(target_value_name) != 0) {
        size = sizeof(data_buffer);
        type = 0;
        memset(data_buffer, 0, sizeof(data_buffer));
        result = ADVAPI32$RegQueryValueExA(root_key, target_value_name, NULL, &type, data_buffer, &size);
        if (result == ERROR_SUCCESS) {
            append_value_query_header(&out, root_key, target_key_path);
            append_value(&out, target_value_name, type, data_buffer, size);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Failed to query Regkey, error value: %d", result);
        }
    } else {
        enum_key(&out, root_key, target_key_path);
    }

    ADVAPI32$RegCloseKey(root_key);
    if (remote_key != NULL) {
        ADVAPI32$RegCloseKey(remote_key);
    }

    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);
} while (0);
