#include <wintypes.h>
#include <winbaseapi.h>
#include <beacon.h>

formatp buffer;
int output_length;
char *output;
ULONGLONG ticks;
ULONGLONG total_seconds;
ULONGLONG days;
ULONGLONG hours;
ULONGLONG minutes;
ULONGLONG seconds;
SYSTEMTIME local_time;
FILETIME current_file_time;
FILETIME boot_file_time;
ULONGLONG file_time_value;

ticks = GetTickCount64();
total_seconds = ticks / 1000;
days = total_seconds / 86400;
hours = (total_seconds / 3600) % 24;
minutes = (total_seconds / 60) % 60;
seconds = total_seconds % 60;

GetLocalTime(&local_time);
SystemTimeToFileTime(&local_time, &current_file_time);

file_time_value = ((ULONGLONG)current_file_time.dwHighDateTime << 32) | (ULONGLONG)current_file_time.dwLowDateTime;
file_time_value -= ticks * 10000;
boot_file_time.dwLowDateTime = (DWORD)file_time_value;
boot_file_time.dwHighDateTime = (DWORD)(file_time_value >> 32);

FileTimeToSystemTime(&boot_file_time, &local_time);

BeaconFormatAlloc(&buffer, 512);
BeaconFormatPrintf(&buffer, "Uptime: %llu days, %llu hours, %llu minutes, %llu seconds\n", days, hours, minutes, seconds);
BeaconFormatPrintf(
    &buffer,
    "Boot time: %04u-%02u-%02u %02u:%02u:%02u\n",
    local_time.wYear,
    local_time.wMonth,
    local_time.wDay,
    local_time.wHour,
    local_time.wMinute,
    local_time.wSecond
);

output = BeaconFormatToString(&buffer, &output_length);
BeaconOutput(CALLBACK_OUTPUT, output, output_length);
BeaconFormatFree(&buffer);
