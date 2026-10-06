#include <windows.h>
#include <winsock2.h>
#include <ws2_32.h>
#include <dnsapi.h>
#include <beacon.h>

#define TARGET_NAME "localhost"
#define TARGET_DNS_SERVER ""
#define DNS_RECORD_TYPE 0x0001

#define DNS_QUERY_WIRE_ONLY 0x00000010
#define DNS_FREE_RECORD_LIST_DEEP 1

#define DNS_TYPE_A 0x0001
#define DNS_TYPE_NS 0x0002
#define DNS_TYPE_CNAME 0x0005
#define DNS_TYPE_PTR 0x000c
#define DNS_TYPE_MX 0x000f
#define DNS_TYPE_TEXT 0x0010
#define DNS_TYPE_AAAA 0x001c
#define DNS_TYPE_SRV 0x0021

typedef struct _IP4_ARRAY {
    DWORD AddrCount;
    DWORD AddrArray[1];
} IP4_ARRAY, *PIP4_ARRAY;

typedef struct _IP6_ADDRESS {
    BYTE IP6Byte[16];
} IP6_ADDRESS, *PIP6_ADDRESS;

typedef struct _DNS_A_DATA {
    DWORD IpAddress;
} DNS_A_DATA, *PDNS_A_DATA;

typedef struct _DNS_PTR_DATAA {
    LPSTR pNameHost;
} DNS_PTR_DATAA, *PDNS_PTR_DATAA;

typedef struct _DNS_MX_DATAA {
    LPSTR pNameExchange;
    WORD wPreference;
    WORD Pad;
} DNS_MX_DATAA, *PDNS_MX_DATAA;

typedef struct _DNS_TXT_DATAA {
    DWORD dwStringCount;
    LPSTR *pStringArray;
} DNS_TXT_DATAA, *PDNS_TXT_DATAA;

typedef struct _DNS_AAAA_DATA {
    IP6_ADDRESS Ip6Address;
} DNS_AAAA_DATA, *PDNS_AAAA_DATA;

typedef struct _DNS_SRV_DATAA {
    LPSTR pNameTarget;
    WORD wPriority;
    WORD wWeight;
    WORD wPort;
    WORD Pad;
} DNS_SRV_DATAA, *PDNS_SRV_DATAA;

typedef struct _DNS_RECORDA {
    struct _DNS_RECORDA *pNext;
    LPSTR pName;
    WORD wType;
    WORD wDataLength;
    DWORD Flags;
    DWORD dwTtl;
    DWORD dwReserved;
    union {
        DNS_A_DATA A;
        DNS_PTR_DATAA NS;
        DNS_PTR_DATAA CNAME;
        DNS_PTR_DATAA PTR;
        DNS_MX_DATAA MX;
        DNS_TXT_DATAA TXT;
        DNS_AAAA_DATA AAAA;
        DNS_SRV_DATAA SRV;
    } Data;
} DNS_RECORDA, *PDNS_RECORDA;

void ipv4_to_string(DWORD address, char *buffer) {
    sprintf(
        buffer,
        "%lu.%lu.%lu.%lu",
        address & 0xff,
        (address >> 8) & 0xff,
        (address >> 16) & 0xff,
        (address >> 24) & 0xff
    );
}

void ipv6_to_string(PIP6_ADDRESS address, char *buffer) {
    int i;
    int offset;

    offset = 0;
    for (i = 0; i < 16; i += 2) {
        offset += sprintf(
            buffer + offset,
            "%02x%02x",
            (unsigned int)address->IP6Byte[i],
            (unsigned int)address->IP6Byte[i + 1]
        );
        if (i != 14) {
            buffer[offset++] = ':';
            buffer[offset] = 0;
        }
    }
}

char *record_type_name(WORD record_type) {
    if (record_type == DNS_TYPE_A) return "A";
    if (record_type == DNS_TYPE_NS) return "NS";
    if (record_type == DNS_TYPE_CNAME) return "CNAME";
    if (record_type == DNS_TYPE_PTR) return "PTR";
    if (record_type == DNS_TYPE_MX) return "MX";
    if (record_type == DNS_TYPE_TEXT) return "TXT";
    if (record_type == DNS_TYPE_AAAA) return "AAAA";
    if (record_type == DNS_TYPE_SRV) return "SRV";
    return "UNKNOWN";
}

void append_record(formatp *buffer, PDNS_RECORDA record) {
    DWORD i;
    char address_buffer[64];

    if (record->wType == DNS_TYPE_A) {
        ipv4_to_string(record->Data.A.IpAddress, address_buffer);
        BeaconFormatPrintf(buffer, "%-8s %-40s %s\n", "A", record->pName, address_buffer);
        return;
    }

    if (record->wType == DNS_TYPE_AAAA) {
        ipv6_to_string(&record->Data.AAAA.Ip6Address, address_buffer);
        BeaconFormatPrintf(buffer, "%-8s %-40s %s\n", "AAAA", record->pName, address_buffer);
        return;
    }

    if (record->wType == DNS_TYPE_NS) {
        BeaconFormatPrintf(buffer, "%-8s %-40s %s\n", "NS", record->pName, record->Data.NS.pNameHost);
        return;
    }

    if (record->wType == DNS_TYPE_CNAME) {
        BeaconFormatPrintf(buffer, "%-8s %-40s %s\n", "CNAME", record->pName, record->Data.CNAME.pNameHost);
        return;
    }

    if (record->wType == DNS_TYPE_PTR) {
        BeaconFormatPrintf(buffer, "%-8s %-40s %s\n", "PTR", record->pName, record->Data.PTR.pNameHost);
        return;
    }

    if (record->wType == DNS_TYPE_MX) {
        BeaconFormatPrintf(
            buffer,
            "%-8s %-40s %s (pref=%u)\n",
            "MX",
            record->pName,
            record->Data.MX.pNameExchange,
            record->Data.MX.wPreference
        );
        return;
    }

    if (record->wType == DNS_TYPE_SRV) {
        BeaconFormatPrintf(
            buffer,
            "%-8s %-40s %s (port=%u priority=%u weight=%u)\n",
            "SRV",
            record->pName,
            record->Data.SRV.pNameTarget,
            record->Data.SRV.wPort,
            record->Data.SRV.wPriority,
            record->Data.SRV.wWeight
        );
        return;
    }

    if (record->wType == DNS_TYPE_TEXT) {
        for (i = 0; i < record->Data.TXT.dwStringCount; i++) {
            BeaconFormatPrintf(buffer, "%-8s %-40s %s\n", "TXT", record->pName, record->Data.TXT.pStringArray[i]);
        }
        return;
    }

    BeaconFormatPrintf(buffer, "%-8s %-40s unsupported record data\n", record_type_name(record->wType), record->pName);
}

do {
    datap parser;
    PDNS_RECORDA records;
    PDNS_RECORDA current;
    PIP4_ARRAY server_list;
    formatp buffer;
    int output_length;
    char *output;
    DWORD status;
    DWORD count;
    char *target_name;
    char *target_dns_server;
    WORD dns_record_type;

    records = NULL;
    current = NULL;
    server_list = NULL;
    count = 0;
    target_name = TARGET_NAME;
    target_dns_server = TARGET_DNS_SERVER;
    dns_record_type = DNS_RECORD_TYPE;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_name = BeaconDataExtract(&parser, NULL);
        target_dns_server = BeaconDataExtract(&parser, NULL);
        dns_record_type = BeaconDataShort(&parser);
        if (target_name == NULL || target_name[0] == 0) target_name = TARGET_NAME;
        if (target_dns_server == NULL) target_dns_server = TARGET_DNS_SERVER;
        if (dns_record_type == 0) dns_record_type = DNS_RECORD_TYPE;
    }

    if (strlen(target_dns_server) != 0) {
        server_list = (PIP4_ARRAY)LocalAlloc(0x0040, sizeof(IP4_ARRAY));
        if (server_list == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to allocate DNS server list.");
            break;
        }
        server_list->AddrCount = 1;
        server_list->AddrArray[0] = WS2_32$inet_addr((char *)target_dns_server);
        if (server_list->AddrArray[0] == ((DWORD)-1)) {
            LocalFree(server_list);
            BeaconPrintf(CALLBACK_ERROR, "Invalid DNS server IP: %s", target_dns_server);
            break;
        }
    }

    status = DNSAPI$DnsQuery_A(target_name, dns_record_type, DNS_QUERY_WIRE_ONLY, server_list, &records, NULL);
    if (server_list != NULL) {
        LocalFree(server_list);
    }

    if (status != 0 || records == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "DnsQuery_A failed with status %lu", status);
        break;
    }

    BeaconFormatAlloc(&buffer, 2048);
    BeaconFormatPrintf(&buffer, "%-8s %-40s %s\n", "Type", "Name", "Value");
    BeaconFormatPrintf(&buffer, "%-8s %-40s %s\n", "----", "----", "-----");

    current = records;
    while (current != NULL) {
        append_record(&buffer, current);
        count++;
        current = current->pNext;
    }

    if (count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "No DNS records found for %s", target_name);
    } else {
        output = BeaconFormatToString(&buffer, &output_length);
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }

    BeaconFormatFree(&buffer);
    DNSAPI$DnsFree(records, DNS_FREE_RECORD_LIST_DEEP);
} while (0);
