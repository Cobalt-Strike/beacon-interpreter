#include <windows.h>
#include <beacon.h>

#define DIVISOR_MB 1048576ULL

typedef union _ULARGE_INTEGER {
    struct {
        DWORD LowPart;
        DWORD HighPart;
    } u;
    unsigned long long QuadPart;
} ULARGE_INTEGER, *PULARGE_INTEGER;

do {
    MEMORYSTATUSEX memory;
    ULARGE_INTEGER total_bytes;
    ULARGE_INTEGER free_bytes;
    formatp buffer;
    int output_length;
    char *output;

    memory.dwLength = sizeof(memory);
    if (GlobalMemoryStatusEx(&memory) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Error fetching memory.");
        break;
    }

    if (GetDiskFreeSpaceExA(NULL, NULL, &total_bytes, &free_bytes) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Error fetching disk space.");
        break;
    }

    BeaconFormatAlloc(&buffer, 256);
    BeaconFormatPrintf(
        &buffer,
        "Memory Used:\t%lluMB/%lluMB\n",
        (memory.ullTotalPhys - memory.ullAvailPhys) / DIVISOR_MB,
        memory.ullTotalPhys / DIVISOR_MB
    );
    BeaconFormatPrintf(&buffer, "Free Space:\t%llu MB\n", free_bytes.QuadPart / DIVISOR_MB);
    BeaconFormatPrintf(&buffer, "Total Space:\t%llu MB\n", total_bytes.QuadPart / DIVISOR_MB);

    output = BeaconFormatToString(&buffer, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&buffer);
} while (0);
