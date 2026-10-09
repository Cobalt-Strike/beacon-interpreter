#include <windows.h>
#include <file.h>
#include <winerror.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <beacon.h>

#define TARGET_MODULE_NAME "ntdll"
#define TARGET_PROCESS_NAME ""

BOOL list_modules(formatp *buffer, DWORD pid, const char *module_search) {
    MODULEENTRY32 module;
    HANDLE snapshot;
    BOOL more;
    BOOL found;

    module.dwSize = sizeof(MODULEENTRY32);
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    found = FALSE;
    more = Module32First(snapshot, &module);
    while (more) {
        if (SHLWAPI$StrStrIA(module.szExePath, module_search)) {
            BeaconFormatPrintf(buffer, "    %s\n", module.szExePath);
            found = TRUE;
        }
        more = Module32Next(snapshot, &module);
    }

    CloseHandle(snapshot);
    return found;
}

do {
    datap parser;
    PROCESSENTRY32 process;
    HANDLE snapshot;
    BOOL more;
    DWORD count;
    formatp buffer;
    int output_length;
    char *output;
    char *module_search;
    char *process_search;
    const char *process_filter;

    module_search = TARGET_MODULE_NAME;
    process_search = TARGET_PROCESS_NAME;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        module_search = BeaconDataExtract(&parser, NULL);
        process_search = BeaconDataExtract(&parser, NULL);
        if (module_search == NULL || module_search[0] == 0) {
            BeaconPrintf(CALLBACK_ERROR, "findLoadedModule requires a module search string.");
            break;
        }
        if (process_search == NULL) process_search = "";
    }

    if (strlen(process_search) > 0) {
        process_filter = process_search;
    } else {
        process_filter = NULL;
    }
    process.dwSize = sizeof(PROCESSENTRY32);
    count = 0;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Unable to list processes: %lu", GetLastError());
        break;
    }

    BeaconFormatAlloc(&buffer, 4096);
    more = Process32First(snapshot, &process);
    while (more) {
        if (process_filter == NULL || SHLWAPI$StrStrIA(process.szExeFile, process_filter)) {
            if (list_modules(&buffer, process.th32ProcessID, module_search)) {
                BeaconFormatPrintf(&buffer, "%-10lu : %s\n", process.th32ProcessID, process.szExeFile);
                count++;
            }
        }
        more = Process32Next(snapshot, &process);
    }

    CloseHandle(snapshot);

    if (count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully enumerated all processes, but did not find the requested module.");
    } else {
        output = BeaconFormatToString(&buffer, &output_length);
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatFree(&buffer);
} while (0);
