#include <windows.h>
#include <dnsapi.h>
#include <beacon.h>

#define DnsFreeFlat 0

typedef struct _DNS_CACHE_ENTRY {
    struct _DNS_CACHE_ENTRY *pNext;
    PWSTR pszName;
    unsigned short wType;
    unsigned short wDataLength;
    unsigned long dwFlags;
} DNSCACHEENTRY, *PDNSCACHEENTRY;

DNSAPI$DnsGetCacheDataTable: u32 (ptr);

void flush_dns_output(formatp *buffer) {
    int output_length;
    char *output;

    output = BeaconFormatToString(buffer, &output_length);
    if (output != NULL && output_length > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatReset(buffer);
}

char *utf16_to_utf8(WCHAR *input) {
    int length;
    char *buffer;

    length = WideCharToMultiByte(65001, 0, input, -1, NULL, 0, NULL, NULL);
    if (length == 0) {
        return NULL;
    }

    buffer = (char *)LocalAlloc(0x0040, length);
    if (buffer == NULL) {
        return NULL;
    }

    if (WideCharToMultiByte(65001, 0, input, -1, buffer, length, NULL, NULL) == 0) {
        LocalFree(buffer);
        return NULL;
    }

    return buffer;
}

do {
    PDNSCACHEENTRY entry;
    PDNSCACHEENTRY current;
    PDNSCACHEENTRY next;
    formatp buffer;
    int output_length;
    char *output;
    char *name;

    entry = NULL;

    DNSAPI$DnsGetCacheDataTable(&entry);
    if (entry == NULL || entry->pNext == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "No results found\n");
        if (entry != NULL) {
            DNSAPI$DnsFree(entry, DnsFreeFlat);
        }
        break;
    }

    BeaconFormatAlloc(&buffer, 8192);

    current = entry->pNext;
    while (current != NULL) {
        next = current->pNext;
        name = utf16_to_utf8(current->pszName);
        if (name != NULL) {
            if (buffer.length > 7600) {
                flush_dns_output(&buffer);
            }
            BeaconFormatPrintf(&buffer, "Cache record: %s   | TYPE %d\n", name, current->wType);
            LocalFree(name);
        }
        DNSAPI$DnsFree(current, DnsFreeFlat);
        current = next;
    }

    output = BeaconFormatToString(&buffer, &output_length);
    if (output != NULL && output_length > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }

    BeaconFormatFree(&buffer);
    DNSAPI$DnsFree(entry, DnsFreeFlat);
} while (0);
