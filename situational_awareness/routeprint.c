#include <windows.h>
#include <winerror.h>
#include <winsock2.h>
#include <ws2_32.h>
#include <iphlpapi.h>
#include <iptypes.h>
#include <iprtrmib.h>
#include <beacon.h>

typedef struct _MIB_IPFORWARDTABLE {
    DWORD dwNumEntries;
    MIB_IPFORWARDROW table[1];
} MIB_IPFORWARDTABLE, *PMIB_IPFORWARDTABLE;

void ipv4_to_string(DWORD address, char *buffer) {
    char *value;
    value = (char *)WS2_32$inet_ntoa(address);
    if (value == NULL) {
        buffer[0] = 0;
        return;
    }
    strcpy(buffer, value);
}

do {
    PMIB_IPFORWARDTABLE routes;
    PMIB_IPFORWARDROW route;
    PIP_ADAPTER_INFO adapters;
    PIP_ADAPTER_INFO current_adapter;
    ULONG route_size;
    ULONG adapter_size;
    DWORD error;
    unsigned int i;
    formatp buffer;
    int output_length;
    char *output;
    char destination[18];
    char netmask[18];
    char gateway[18];
    char default_gateway[16];

    routes = NULL;
    adapters = NULL;
    route_size = 0;
    adapter_size = 0;

    if (IPHLPAPI$GetAdaptersInfo(NULL, &adapter_size) == ERROR_BUFFER_OVERFLOW) {
        adapters = (PIP_ADAPTER_INFO)LocalAlloc(0x0040, adapter_size);
    }

    if (adapters == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate adapter info buffer.");
        break;
    }

    if (IPHLPAPI$GetIpForwardTable(NULL, &route_size, TRUE) != ERROR_INSUFFICIENT_BUFFER) {
        LocalFree(adapters);
        BeaconPrintf(CALLBACK_ERROR, "Failed to size route table.");
        break;
    }

    routes = (PMIB_IPFORWARDTABLE)LocalAlloc(0x0040, route_size);
    if (routes == NULL) {
        LocalFree(adapters);
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate route table buffer.");
        break;
    }

    error = IPHLPAPI$GetAdaptersInfo(adapters, &adapter_size);
    if (error != NO_ERROR) {
        LocalFree(routes);
        LocalFree(adapters);
        BeaconPrintf(CALLBACK_ERROR, "GetAdaptersInfo failed: %lu", error);
        break;
    }

    error = IPHLPAPI$GetIpForwardTable(routes, &route_size, TRUE);
    if (error != NO_ERROR) {
        LocalFree(routes);
        LocalFree(adapters);
        BeaconPrintf(CALLBACK_ERROR, "GetIpForwardTable failed: %lu", error);
        break;
    }

    BeaconFormatAlloc(&buffer, 4096);
    sprintf(default_gateway, "%s", adapters->GatewayList.IpAddress.String);
    BeaconFormatPrintf(&buffer, "===========================================================================\n");
    BeaconFormatPrintf(&buffer, "Interface List\n");
    current_adapter = adapters;
    while (current_adapter != NULL) {
        BeaconFormatPrintf(&buffer, "0x%lu ........................... %s\n", current_adapter->Index, current_adapter->Description);
        current_adapter = current_adapter->Next;
    }
    BeaconFormatPrintf(&buffer, "===========================================================================\n");

    BeaconFormatPrintf(&buffer, "===========================================================================\n");
    BeaconFormatPrintf(&buffer, "Active Routes:\n");
    BeaconFormatPrintf(
        &buffer,
        "%-27s%-17s%-14s%-11s%-10s\n",
        "Network Destination",
        "Netmask",
        "Gateway",
        "Interface",
        "Metric"
    );
    for (i = 0; i < routes->dwNumEntries; i++) {
        route = &routes->table[i];
        ipv4_to_string(route->dwForwardDest, destination);
        ipv4_to_string(route->dwForwardMask, netmask);
        ipv4_to_string(route->dwForwardNextHop, gateway);
        BeaconFormatPrintf(
            &buffer,
            "%17s%17s%17s%16ld%9ld\n",
            destination,
            netmask,
            gateway,
            route->dwForwardIfIndex,
            route->dwForwardMetric1
        );
    }
    BeaconFormatPrintf(&buffer, "Default Gateway:%18s\n", default_gateway);
    BeaconFormatPrintf(&buffer, "===========================================================================\n");
    BeaconFormatPrintf(&buffer, "Persistent Routes:\n");

    output = BeaconFormatToString(&buffer, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&buffer);
    LocalFree(routes);
    LocalFree(adapters);
} while (0);
