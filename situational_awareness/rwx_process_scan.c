#include <windows.h>
#include <winnt.h>
#include <tlhelp32.h>
#include <file.h>
#include <beacon.h>

#define RWX_THRESHOLD_BYTES (400 * 1024)

DWORD base_protect(DWORD protect) {
    return protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
}

BOOL is_large_rwx_region(PMEMORY_BASIC_INFORMATION mbi) {
    if (mbi->State != MEM_COMMIT) {
        return FALSE;
    }

    if (mbi->RegionSize <= RWX_THRESHOLD_BYTES) {
        return FALSE;
    }

    if (mbi->Protect == 0) {
        return FALSE;
    }

    return base_protect(mbi->Protect) == PAGE_EXECUTE_READWRITE;
}

void append_table_header(formatp *buffer) {
    BeaconFormatPrintf(buffer, "%-32s %-8s %-18s %-12s\n", "Process", "PID", "Address", "Size");
    BeaconFormatPrintf(buffer, "%-32s %-8s %-18s %-12s\n", "-------", "---", "-------", "----");
}

void scan_process_regions(formatp *buffer, DWORD pid, char *name, DWORD *count) {
    HANDLE process;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T result;
    SIZE_T next;
    char *address;

    process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (process == NULL) {
        return;
    }

    address = (char *)0;

    while (TRUE) {
        result = VirtualQueryEx(process, address, &mbi, sizeof(mbi));
        if (result == 0) {
            break;
        }

        if (is_large_rwx_region(&mbi)) {
            (*count)++;
            BeaconFormatPrintf(
                buffer,
                "%-32s %-8lu 0x%p %-12llu\n",
                name,
                pid,
                mbi.BaseAddress,
                (unsigned long long)mbi.RegionSize
            );
        }

        next = (SIZE_T)mbi.BaseAddress + mbi.RegionSize;
        if (next <= (SIZE_T)address) {
            break;
        }

        address = (char *)next;
    }
    CloseHandle(process);
}

do {
    HANDLE snapshot;
    PROCESSENTRY32 entry;
    formatp buffer;
    int output_length;
    char *output;
    DWORD count = 0;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed");
        break;
    }

    BeaconFormatAlloc(&buffer, 8192);
    append_table_header(&buffer);

    entry.dwSize = sizeof(entry);
    if (!Process32First(snapshot, &entry)) {
        BeaconPrintf(CALLBACK_ERROR, "Process32First failed");
        BeaconFormatFree(&buffer);
        CloseHandle(snapshot);
        break;
    }

    do {
        scan_process_regions(&buffer, entry.th32ProcessID, entry.szExeFile, &count);
        entry.dwSize = sizeof(entry);
    } while (Process32Next(snapshot, &entry));

    if (count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "No RWX allocations larger than %lu bytes found.", (unsigned long)RWX_THRESHOLD_BYTES);
    } else {
        output = BeaconFormatToString(&buffer, &output_length);
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }

    BeaconFormatFree(&buffer);
    CloseHandle(snapshot);
} while (0);
