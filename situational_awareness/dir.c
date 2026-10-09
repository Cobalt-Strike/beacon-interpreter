#include <windows.h>
#include <file.h>
#include <beacon.h>

#define TARGET_PATH "C:\\Users"
#define RECURSIVE 0

formatp g_out;
DWORD g_file_count;
DWORD g_dir_count;
ULONGLONG g_total_bytes;
unsigned short g_recursive;

void append_entry(WIN32_FIND_DATAA *entry, char *parent) {
    SYSTEMTIME utc_time;
    SYSTEMTIME local_time;
    ULONGLONG file_size;
    char type_name[16];

    FileTimeToSystemTime(&entry->ftLastWriteTime, &utc_time);
    SystemTimeToTzSpecificLocalTime(NULL, &utc_time, &local_time);

    if ((entry->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        if ((entry->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            type_name[0] = '<';
            type_name[1] = 'j';
            type_name[2] = 'u';
            type_name[3] = 'n';
            type_name[4] = 'c';
            type_name[5] = 't';
            type_name[6] = 'i';
            type_name[7] = 'o';
            type_name[8] = 'n';
            type_name[9] = '>';
            type_name[10] = 0;
        } else {
            type_name[0] = '<';
            type_name[1] = 'd';
            type_name[2] = 'i';
            type_name[3] = 'r';
            type_name[4] = '>';
            type_name[5] = 0;
        }
        g_dir_count++;
        BeaconFormatPrintf(
            &g_out,
            "\t%02u/%02u/%02u %02u:%02u%16s %s\n",
            local_time.wMonth,
            local_time.wDay,
            local_time.wYear,
            local_time.wHour,
            local_time.wMinute,
            type_name,
            entry->cFileName
        );
    } else {
        file_size = ((ULONGLONG)entry->nFileSizeHigh << 32) | entry->nFileSizeLow;
        g_file_count++;
        g_total_bytes += file_size;
        BeaconFormatPrintf(
            &g_out,
            "\t%02u/%02u/%02u %02u:%02u%16lld %s\n",
            local_time.wMonth,
            local_time.wDay,
            local_time.wYear,
            local_time.wHour,
            local_time.wMinute,
            file_size,
            entry->cFileName
        );
    }
}

void list_dir(char *path) {
    WIN32_FIND_DATAA entry;
    HANDLE handle;
    char query[MAX_PATH];
    char child_path[MAX_PATH];

    if (path == NULL || path[0] == 0) {
        return;
    }

    _snprintf(query, MAX_PATH, "%s\\*", path);
    handle = FindFirstFileA(query, &entry);
    if (handle == INVALID_HANDLE_VALUE) {
        BeaconFormatPrintf(&g_out, "Failed to enumerate %s (error %lu)\n", path, GetLastError());
        return;
    }

    do {
        append_entry(&entry, path);

        if (
            g_recursive &&
            strcmp(entry.cFileName, ".") != 0 &&
            strcmp(entry.cFileName, "..") != 0 &&
            (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
            (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0
        ) {
            _snprintf(child_path, MAX_PATH, "%s\\%s", path, entry.cFileName);
            list_dir(child_path);
        }
    } while (FindNextFileA(handle, &entry));

    FindClose(handle);
}

do {
    datap parser;
    char *target_path;
    char *output;
    int output_length;

    target_path = TARGET_PATH;
    g_recursive = RECURSIVE;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_path = BeaconDataExtract(&parser, NULL);
        g_recursive = BeaconDataShort(&parser);
        if (target_path == NULL || target_path[0] == 0) {
            BeaconPrintf(CALLBACK_ERROR, "dir requires a target path when arguments are supplied.");
            break;
        }
    }

    g_file_count = 0;
    g_dir_count = 0;
    g_total_bytes = 0;

    BeaconFormatAlloc(&g_out, 16384);
    BeaconFormatPrintf(&g_out, "Contents of %s:\n", target_path);
    list_dir(target_path);
    BeaconFormatPrintf(&g_out, "\t%32lld Total File Size for %lu File(s)\n", g_total_bytes, g_file_count);
    BeaconFormatPrintf(&g_out, "\t%55lu Dir(s)\n", g_dir_count);

    output = BeaconFormatToString(&g_out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&g_out);
} while (0);
