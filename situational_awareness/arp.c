#include <windows.h>
#include <winerror.h>
#include <iphlpapi.h>
#include <beacon.h>

#define ANY_SIZE 1

typedef struct _MIB_IPNETROW {
    DWORD dwIndex;
    DWORD dwPhysAddrLen;
    BYTE bPhysAddr[8];
    DWORD dwAddr;
    DWORD dwType;
} MIB_IPNETROW, *PMIB_IPNETROW;

typedef struct _MIB_IPNETTABLE {
    DWORD dwNumEntries;
    MIB_IPNETROW table[ANY_SIZE];
} MIB_IPNETTABLE, *PMIB_IPNETTABLE;

char *arp_type_name(DWORD arp_type) {
    if (arp_type == 1) return "other";
    if (arp_type == 2) return "invalid";
    if (arp_type == 3) return "dynamic";
    if (arp_type == 4) return "static";
    return "unknown";
}

void ipv4_to_string(unsigned int address, char *buffer) {
    sprintf(
        buffer,
        "%u.%u.%u.%u",
        address & 0xff,
        (address >> 8) & 0xff,
        (address >> 16) & 0xff,
        (address >> 24) & 0xff
    );
}

void mac_to_string(DWORD length, BYTE *address, char *buffer) {
    if (length != 6) {
        strcpy(buffer, "INVALID MAC LENGTH");
        return;
    }

    sprintf(
        buffer,
        "%02X-%02X-%02X-%02X-%02X-%02X",
        address[0],
        address[1],
        address[2],
        address[3],
        address[4],
        address[5]
    );
}

do {
    MIB_IPNETTABLE *table;
    MIB_IPNETROW *row;
    ULONG size;
    char *row_base;
    DWORD row_size;
    DWORD last_index;
    DWORD i;
    DWORD count;
    formatp buffer;
    int output_length;
    char *output;
    char ip_buffer[20];
    char mac_buffer[24];

    table = NULL;
    size = 0;
    row_base = NULL;
    row_size = sizeof(MIB_IPNETROW);
    last_index = -1;
    count = 0;

    IPHLPAPI$GetIpNetTable(NULL, &size, TRUE);
    if (size == 0) {
        BeaconPrintf(CALLBACK_ERROR, "GetIpNetTable did not return a buffer size.");
        break;
    }

    table = (MIB_IPNETTABLE *)LocalAlloc(0x0040, size);
    if (table == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Could not allocate memory for ARP table.");
        break;
    }

    if (IPHLPAPI$GetIpNetTable(table, &size, TRUE) != NO_ERROR) {
        LocalFree(table);
        BeaconPrintf(CALLBACK_ERROR, "Could not retrieve ARP table.");
        break;
    }

    BeaconFormatAlloc(&buffer, 4096);
    row_base = ((char *)table) + sizeof(DWORD);
    for (i = 0; i < table->dwNumEntries; i++) {
        row = (MIB_IPNETROW *)(row_base + (i * row_size));
        if (row->dwIndex != last_index) {
            last_index = row->dwIndex;
            BeaconFormatPrintf(&buffer, "\nInterface 0x%X\n", row->dwIndex);
            BeaconFormatPrintf(&buffer, "%-24s %-24s %-12s\n", "Internet Address", "Physical Address", "Type");
            BeaconFormatPrintf(&buffer, "%-24s %-24s %-12s\n", "----------------", "----------------", "----");
        }

        ipv4_to_string(row->dwAddr, ip_buffer);
        if (row->dwPhysAddrLen > 0) {
            mac_to_string(row->dwPhysAddrLen, row->bPhysAddr, mac_buffer);
        } else {
            mac_buffer[0] = 0;
        }

        BeaconFormatPrintf(
            &buffer,
            "%-24s %-24s %-12s\n",
            ip_buffer,
            mac_buffer,
            arp_type_name(row->dwType)
        );
        count++;
    }

    if (count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "No ARP entries found.");
    } else {
        output = BeaconFormatToString(&buffer, &output_length);
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }

    BeaconFormatFree(&buffer);
    LocalFree(table);
} while (0);
