#include <windows.h>
#include <winnt.h>
#include <version.h>
#include <psapi.h>
#include <beacon.h>

#define TARGET_PID 0

void flush_output(formatp *buffer) {
    int output_length;
    char *output;

    output = BeaconFormatToString(buffer, &output_length);
    if (output != NULL && output_length > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatReset(buffer);
}

int print_single_module(formatp *buffer, char *path) {
    DWORD version_size;
    DWORD unused;
    LPSTR version_info;
    WORD *translation;
    UINT translation_size;
    char query_description[256];
    char query_company[256];
    LPVOID description;
    LPVOID company;
    UINT value_size;

    version_size = VERSION$GetFileVersionInfoSizeA(path, &unused);
    if (version_size == 0) {
        BeaconFormatPrintf(buffer, "%-60s ERROR: Could not GetFileVersionInfoSizeA() on the DLL.\n", path);
        return 1;
    }

    version_info = (LPSTR)GlobalAlloc(0x0040, version_size);
    if (version_info == NULL) {
        BeaconFormatPrintf(buffer, "ERROR: Could not allocate memory\n");
        return 1;
    }

    translation = NULL;
    translation_size = 0;
    description = NULL;
    company = NULL;
    value_size = 0;

    VERSION$GetFileVersionInfoA(path, 0, version_size, version_info);
    VERSION$VerQueryValueA(version_info, "\\VarFileInfo\\Translation", &translation, &translation_size);
    if (translation != NULL && translation_size >= sizeof(WORD) * 2) {
        sprintf(query_description, "\\StringFileInfo\\%04x%04x\\FileDescription", translation[0], translation[1]);
        sprintf(query_company, "\\StringFileInfo\\%04x%04x\\CompanyName", translation[0], translation[1]);
        VERSION$VerQueryValueA(version_info, query_description, &description, &value_size);
        VERSION$VerQueryValueA(version_info, query_company, &company, &value_size);
    }

    BeaconFormatPrintf(
        buffer,
        "%-60s %-25s%-25s\n",
        path,
        company ? (char *)company : "",
        description ? (char *)description : ""
    );

    GlobalFree((HGLOBAL)version_info);
    return 0;
}

do {
    datap parser;
    HANDLE process;
    HMODULE *modules;
    DWORD module_bytes;
    DWORD module_bytes_returned;
    unsigned int i;
    DWORD pid;
    char module_name[MAX_PATH];
    formatp buffer;
    int output_length;
    char *output;
    int pid_arg;

    pid_arg = TARGET_PID;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        pid_arg = BeaconDataInt(&parser);
    }

    pid = pid_arg == 0 ? GetCurrentProcessId() : pid_arg;
    process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (process == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "ERROR: Failed to open process.\n");
        break;
    }

    module_bytes = 0;
    if (!PSAPI$EnumProcessModulesEx(process, 0, 0, &module_bytes, LIST_MODULES_ALL) || module_bytes == 0) {
        CloseHandle(process);
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to enumerate modules (not cross arch compatible)\n");
        break;
    }

    modules = (HMODULE *)LocalAlloc(0x0040, module_bytes);
    if (modules == NULL) {
        CloseHandle(process);
        BeaconPrintf(CALLBACK_OUTPUT, "ERROR: Could not allocate memory\n");
        break;
    }

    if (!PSAPI$EnumProcessModulesEx(process, modules, module_bytes, &module_bytes_returned, LIST_MODULES_ALL)) {
        LocalFree(modules);
        CloseHandle(process);
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to enumerate modules (not cross arch compatible)\n");
        break;
    }

    BeaconFormatAlloc(&buffer, 8192);
    BeaconFormatPrintf(&buffer, "Printing modules of process ID: %lu\n", pid);

    for (i = 0; i < (module_bytes_returned / sizeof(HMODULE)); i++) {
        if (PSAPI$GetModuleFileNameExA(process, modules[i], module_name, sizeof(module_name))) {
            if (buffer.length > 7600) {
                flush_output(&buffer);
            }
            print_single_module(&buffer, module_name);
        }
    }

    output = BeaconFormatToString(&buffer, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&buffer);
    LocalFree(modules);
    CloseHandle(process);
} while (0);
