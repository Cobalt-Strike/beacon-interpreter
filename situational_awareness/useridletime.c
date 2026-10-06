#include <windows.h>
#include <beacon.h>

typedef struct tagLASTINPUTINFO {
    UINT cbSize;
    DWORD dwTime;
} LASTINPUTINFO, *PLASTINPUTINFO;

USER32$GetLastInputInfo: u32 (ptr);

formatp buffer;
int output_length;
char *output;
LASTINPUTINFO input_info;
DWORD tick_count;
DWORD idle_seconds;
DWORD days;
DWORD hours;
DWORD minutes;
DWORD seconds;
DWORD remaining_seconds;

input_info.cbSize = sizeof(LASTINPUTINFO);
input_info.dwTime = 0;

if (!GetLastInputInfo(&input_info)) {
    BeaconPrintf(CALLBACK_ERROR, "GetLastInputInfo failed.");
} else {
    tick_count = GetTickCount();
    idle_seconds = (tick_count - input_info.dwTime) / 1000;
    days = idle_seconds / 86400;
    remaining_seconds = idle_seconds - (days * 86400);
    hours = remaining_seconds / 3600;
    remaining_seconds = remaining_seconds - (hours * 3600);
    minutes = remaining_seconds / 60;
    seconds = remaining_seconds - (minutes * 60);

    BeaconFormatAlloc(&buffer, 256);
    BeaconFormatPrintf(
        &buffer,
        "Current user idle time: %lu days, %lu hours, %lu minutes, %lu seconds\n",
        days,
        hours,
        minutes,
        seconds
    );

    output = BeaconFormatToString(&buffer, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&buffer);
}
