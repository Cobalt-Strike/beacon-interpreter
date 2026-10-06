#include <winnt.h>
#include <windows.h>
#include <file.h>

#include <beacon.h>

#define SEARCH_ROOT "%SystemRoot%\\System32\\GroupPolicy"
#define SEARCH_ROOT_WOW64 "%SystemRoot%\\Sysnative\\GroupPolicy"
#define SEARCH_FILENAME "audit.csv"

formatp g_out;
DWORD g_match_count;

void append_csv_file(char *path) {
    HANDLE file_handle;
    DWORD file_size;
    DWORD bytes_read;
    char *buffer;

    file_handle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) {
        BeaconFormatPrintf(&g_out, "Failed to open %s (error %lu)\n", path, GetLastError());
        return;
    }

    file_size = GetFileSize(file_handle, NULL);
    if (file_size == INVALID_FILE_SIZE || file_size == 0) {
        CloseHandle(file_handle);
        return;
    }

    buffer = (char *)malloc(file_size + 1);
    if (buffer == NULL) {
        CloseHandle(file_handle);
        return;
    }

    bytes_read = 0;
    if (ReadFile(file_handle, buffer, file_size, &bytes_read, NULL)) {
        buffer[bytes_read] = 0;
        BeaconFormatPrintf(&g_out, "File: %s\n", path);
        BeaconFormatPrintf(&g_out, "%s\n", buffer);
        g_match_count++;
    }

    free(buffer);
    CloseHandle(file_handle);
}

void find_audit_csv(char *root_path) {
    WIN32_FIND_DATAA entry;
    HANDLE find_handle;
    char query[MAX_PATH];
    char child_path[MAX_PATH];

    _snprintf(query, MAX_PATH, "%s\\*", root_path);
    find_handle = FindFirstFileA(query, &entry);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (strcmp(entry.cFileName, ".") == 0 || strcmp(entry.cFileName, "..") == 0) {
            continue;
        }

        _snprintf(child_path, MAX_PATH, "%s\\%s", root_path, entry.cFileName);
        if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            find_audit_csv(child_path);
        } else if (_stricmp(entry.cFileName, SEARCH_FILENAME) == 0) {
            append_csv_file(child_path);
        }
    } while (FindNextFileA(find_handle, &entry));

    FindClose(find_handle);
}

do {
    datap parser;
    int iswow64;
    char *search_root;
    char expanded_root[MAX_PATH];
    char *output;
    int output_length;

    iswow64 = 0;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        iswow64 = BeaconDataInt(&parser);
    }

    search_root = iswow64 ? SEARCH_ROOT_WOW64 : SEARCH_ROOT;
    g_match_count = 0;
    BeaconFormatAlloc(&g_out, 32768);
    if (ExpandEnvironmentStringsA(search_root, expanded_root, MAX_PATH) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "ExpandEnvironmentStringsA failed: %lu", GetLastError());
        break;
    }

    BeaconFormatPrintf(&g_out, "Searching %s for %s\n\n", expanded_root, SEARCH_FILENAME);
    find_audit_csv(expanded_root);
    if (g_match_count == 0) {
        BeaconFormatPrintf(&g_out, "No audit.csv files found.\n");
    }

    output = BeaconFormatToString(&g_out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&g_out);
} while (0);
