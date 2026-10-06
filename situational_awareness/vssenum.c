#include <windows.h>
#include <file.h>
#include <ntapi.h>
#include <beacon.h>

#define FSCTL_SRV_ENUMERATE_SNAPSHOTS 0x00144064
#define OUTPUT_BUFFER_SIZE (1024 * 1024)
#define OUTPUT_FLUSH_THRESHOLD (64 * 1024)

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

void flush_output(formatp *out) {
    char *output;
    int output_length;

    output = BeaconFormatToString(out, &output_length);
    if (output != NULL && output_length > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatReset(out);
}

datap parser;
LPWSTR host;
LPWSTR share;
WCHAR path[MAX_PATH];
HANDLE handle;
IO_STATUS_BLOCK io;
char first_buffer[16];
char *snapshot_buffer;
DWORD volumes;
DWORD returned;
DWORD bytes;
ULONG snapshot_len;
NTSTATUS status;
WCHAR *entry;
DWORD i;
formatp out;

host = L"localhost";
share = L"C$";
if (__argc > 0) {
    BeaconDataParse(&parser, __argv, __argc);
    host = (LPWSTR)BeaconDataExtract(&parser, NULL);
    share = (LPWSTR)BeaconDataExtract(&parser, NULL);
    if (host == NULL || host[0] == 0) {
        host = L"localhost";
    }
    if (share == NULL || share[0] == 0) {
        share = L"C$";
    }
}

_snwprintf(path, MAX_PATH, L"\\\\%ls\\%ls", host, share);
BeaconPrintf(CALLBACK_OUTPUT, "Target = %S", path);

handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
if (handle == INVALID_HANDLE_VALUE) {
    BeaconPrintf(CALLBACK_ERROR, "CreateFileW failed: %lu", GetLastError());
} else {
    status = NTDLL$NtFsControlFile(handle, NULL, NULL, NULL, &io, FSCTL_SRV_ENUMERATE_SNAPSHOTS, NULL, 0, first_buffer, sizeof(first_buffer));
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "NtFsControlFile sizing failed: 0x%08lx", status);
    } else {
        memcpy(&volumes, first_buffer, 4);
        memcpy(&returned, first_buffer + 4, 4);
        memcpy(&bytes, first_buffer + 8, 4);
        snapshot_len = 12 + bytes;
        snapshot_buffer = (char *)calloc(1, snapshot_len);
        if (snapshot_buffer == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Allocation failed for snapshot buffer.");
        } else {
            status = NTDLL$NtFsControlFile(handle, NULL, NULL, NULL, &io, FSCTL_SRV_ENUMERATE_SNAPSHOTS, NULL, 0, snapshot_buffer, snapshot_len);
            if (status != 0) {
                BeaconPrintf(CALLBACK_ERROR, "NtFsControlFile failed: 0x%08lx", status);
            } else {
                memcpy(&returned, snapshot_buffer + 4, 4);
                entry = (WCHAR *)(snapshot_buffer + 12);
                BeaconFormatAlloc(&out, OUTPUT_BUFFER_SIZE);
                for (i = 0; i < returned; i++) {
                    BeaconFormatPrintf(&out, "%S\n", entry);
                    if (out.length >= OUTPUT_FLUSH_THRESHOLD) {
                        flush_output(&out);
                    }
                    entry += wcslen(entry) + 1;
                }
                BeaconFormatPrintf(&out, "Found and enumerated %lu snapshots\n", returned);
                flush_output(&out);
                BeaconFormatFree(&out);
            }
            free(snapshot_buffer);
        }
    }
    CloseHandle(handle);
}
