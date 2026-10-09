#include <windows.h>
#include <winsock2.h>
#include <ws2_32.h>
#include <iphlpapi.h>
#include <iptypes.h>
#include <winreg.h>
#include <advapi.h>
#include <beacon.h>

#define GAA_FLAGS (GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS)
#define IfOperStatusUp 1

typedef struct in6_addr {
    BYTE Byte[16];
} IN6_ADDR;

typedef struct sockaddr_in6 {
    short sin6_family;
    u_short sin6_port;
    u_long sin6_flowinfo;
    IN6_ADDR sin6_addr;
    u_long sin6_scope_id;
} SOCKADDR_IN6;

WS2_32$InetNtopW: ptr (u32, ptr, ptr, size_t);

char *adapter_type_string(DWORD if_type) {
    if (if_type == IF_TYPE_ETHERNET_CSMACD) return "Ethernet adapter";
    if (if_type == IF_TYPE_IEEE80211) return "Wireless LAN adapter";
    if (if_type == IF_TYPE_TUNNEL) return "Tunnel adapter";
    if (if_type == IF_TYPE_PPP) return "PPP adapter";
    return "Unknown adapter";
}

char *node_type_string(UINT node_type) {
    if (node_type == BROADCAST_NODETYPE) return "Broadcast";
    if (node_type == PEER_TO_PEER_NODETYPE) return "Peer-Peer";
    if (node_type == MIXED_NODETYPE) return "Mixed";
    if (node_type == HYBRID_NODETYPE) return "Hybrid";
    return "Unknown";
}

void wide_to_utf8(char *output, int output_size, WCHAR *input) {
    if (output == NULL || output_size <= 0) return;
    output[0] = 0;
    if (input == NULL) return;
    if (WideCharToMultiByte(65001, 0, input, -1, output, output_size, NULL, NULL) == 0) {
        output[0] = 0;
    }
}

void format_mac_address(BYTE *address, DWORD address_length, char *output, int output_size) {
    int position;
    DWORD i;

    output[0] = 0;
    position = 0;
    for (i = 0; i < address_length && position < output_size - 4; i++) {
        if (i == address_length - 1) {
            position += MSVCRT$sprintf(output + position, "%02X", (int)address[i]);
        } else {
            position += MSVCRT$sprintf(output + position, "%02X-", (int)address[i]);
        }
    }
}

void format_ipv4_address(struct _SOCKADDR *address, char *output, int output_size) {
    SOCKADDR_IN *address4;
    BYTE *bytes;

    output[0] = 0;
    if (address == NULL) return;
    address4 = (SOCKADDR_IN *)address;
    bytes = (BYTE *)&address4->sin_addr;
    MSVCRT$sprintf(output, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

void format_ipv6_address(struct _SOCKADDR *address, char *output, int output_size) {
    SOCKADDR_IN6 *address6;
    WCHAR wide_output[80];

    output[0] = 0;
    if (address == NULL) return;
    address6 = (SOCKADDR_IN6 *)address;
    MSVCRT$memset(wide_output, 0, sizeof(wide_output));
    if (WS2_32$InetNtopW(AF_INET6, &address6->sin6_addr, wide_output, 80) != NULL) {
        wide_to_utf8(output, output_size, wide_output);
    } else {
        MSVCRT$strcpy(output, "::?");
    }
}

void prefix_length_to_subnet_mask(UINT8 prefix_length, char *output, int output_size) {
    DWORD mask;

    mask = 0;
    if (prefix_length > 0 && prefix_length <= 32) {
        mask = 0xffffffff;
        mask = mask << (32 - prefix_length);
    }
    MSVCRT$sprintf(output, "%d.%d.%d.%d",
        (mask >> 24) & 0xff,
        (mask >> 16) & 0xff,
        (mask >> 8) & 0xff,
        mask & 0xff);
}

void format_duid(BYTE *duid, DWORD duid_length, char *output, int output_size) {
    int position;
    DWORD i;

    output[0] = 0;
    position = 0;
    for (i = 0; i < duid_length && position < output_size - 4; i++) {
        if (i == duid_length - 1) {
            position += MSVCRT$sprintf(output + position, "%02X", (int)duid[i]);
        } else {
            position += MSVCRT$sprintf(output + position, "%02X-", (int)duid[i]);
        }
    }
}

void format_unix_time(DWORD unix_time, char *output, int output_size) {
    char *day_names[7];
    char *month_names[12];
    ULONGLONG filetime64;
    FILETIME filetime_utc;
    FILETIME filetime_local;
    SYSTEMTIME system_time;
    int hour12;
    char *ampm;

    output[0] = 0;
    if (unix_time == 0) return;

    day_names[0] = "Sunday";
    day_names[1] = "Monday";
    day_names[2] = "Tuesday";
    day_names[3] = "Wednesday";
    day_names[4] = "Thursday";
    day_names[5] = "Friday";
    day_names[6] = "Saturday";
    month_names[0] = "January";
    month_names[1] = "February";
    month_names[2] = "March";
    month_names[3] = "April";
    month_names[4] = "May";
    month_names[5] = "June";
    month_names[6] = "July";
    month_names[7] = "August";
    month_names[8] = "September";
    month_names[9] = "October";
    month_names[10] = "November";
    month_names[11] = "December";

    filetime64 = ((ULONGLONG)unix_time + 11644473600ULL) * 10000000ULL;
    filetime_utc.dwLowDateTime = (DWORD)(filetime64 & 0xffffffff);
    filetime_utc.dwHighDateTime = (DWORD)(filetime64 >> 32);
    if (!KERNEL32$FileTimeToLocalFileTime(&filetime_utc, &filetime_local)) return;
    if (!KERNEL32$FileTimeToSystemTime(&filetime_local, &system_time)) return;

    hour12 = (int)system_time.wHour - (((int)system_time.wHour / 12) * 12);
    if (hour12 == 0) hour12 = 12;
    ampm = (system_time.wHour >= 12) ? "PM" : "AM";
    MSVCRT$sprintf(output, "%s, %s %d, %d %d:%02d:%02d %s",
        day_names[system_time.wDayOfWeek],
        month_names[system_time.wMonth - 1],
        system_time.wDay,
        system_time.wYear,
        hour12,
        system_time.wMinute,
        system_time.wSecond,
        ampm);
}

void get_dhcp_lease_info(char *adapter_name, DWORD *lease_obtained, DWORD *lease_expires, char *dhcp_server, int dhcp_server_size) {
    char registry_path[512];
    HKEY key;
    DWORD size;
    DWORD type;

    *lease_obtained = 0;
    *lease_expires = 0;
    dhcp_server[0] = 0;
    key = NULL;
    MSVCRT$sprintf(registry_path, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s", adapter_name);

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, registry_path, 0, KEY_READ, &key) == ERROR_SUCCESS) {
        size = sizeof(DWORD);
        type = 0;
        ADVAPI32$RegQueryValueExA(key, "LeaseObtainedTime", NULL, &type, (LPBYTE)lease_obtained, &size);
        size = sizeof(DWORD);
        type = 0;
        ADVAPI32$RegQueryValueExA(key, "LeaseTerminatesTime", NULL, &type, (LPBYTE)lease_expires, &size);
        size = (DWORD)dhcp_server_size;
        type = 0;
        ADVAPI32$RegQueryValueExA(key, "DhcpServer", NULL, &type, (LPBYTE)dhcp_server, &size);
        ADVAPI32$RegCloseKey(key);
    }
}

int get_netbios_option(char *adapter_name) {
    char registry_path[512];
    HKEY key;
    DWORD value;
    DWORD size;
    DWORD type;
    int result;

    value = 0;
    size = sizeof(DWORD);
    type = 0;
    result = 0;
    key = NULL;
    MSVCRT$sprintf(registry_path, "SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_%s", adapter_name);

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, registry_path, 0, KEY_READ, &key) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(key, "NetbiosOptions", NULL, &type, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            result = (int)value;
        }
        ADVAPI32$RegCloseKey(key);
    }
    return result;
}

void print_search_list(formatp *out, PFIXED_INFO fixed_info) {
    HKEY key;
    DWORD size;
    DWORD type;
    char *search_list;
    char *token;
    char delimiter;
    DWORD i;
    DWORD start;
    int first;
    int printed;

    key = NULL;
    size = 0;
    type = 0;
    search_list = NULL;
    printed = 0;

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", 0, KEY_READ, &key) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(key, "SearchList", NULL, &type, NULL, &size) == ERROR_SUCCESS && size > 1) {
            search_list = (char *)malloc(size + 1);
            if (search_list != NULL) {
                MSVCRT$memset(search_list, 0, size + 1);
                if (ADVAPI32$RegQueryValueExA(key, "SearchList", NULL, &type, (LPBYTE)search_list, &size) == ERROR_SUCCESS && search_list[0] != 0) {
                    first = 1;
                    start = 0;
                    i = 0;
                    while (1) {
                        if (search_list[i] == ',' || search_list[i] == 0) {
                            delimiter = search_list[i];
                            if (delimiter == ',') search_list[i] = 0;
                            token = search_list + start;
                            while (*token == ' ') token++;
                            if (*token != 0) {
                                if (first) {
                                    BeaconFormatPrintf(out, "   DNS Suffix Search List. . . . . . : %s\n", token);
                                    first = 0;
                                } else {
                                    BeaconFormatPrintf(out, "                                       %s\n", token);
                                }
                                printed = 1;
                            }
                            if (delimiter == 0) break;
                            start = i + 1;
                        }
                        i++;
                    }
                }
                free(search_list);
            }
        }
        ADVAPI32$RegCloseKey(key);
    }

    if (!printed && fixed_info->DomainName[0] != 0) {
        BeaconFormatPrintf(out, "   DNS Suffix Search List. . . . . . : %s\n", fixed_info->DomainName);
    }
}

void print_global_section(formatp *out, PFIXED_INFO fixed_info) {
    BeaconFormatPrintf(out, "\nWindows IP Configuration\n\n");
    BeaconFormatPrintf(out, "   Host Name . . . . . . . . . . . . : %s\n", fixed_info->HostName);
    BeaconFormatPrintf(out, "   Primary Dns Suffix  . . . . . . . : %s\n", fixed_info->DomainName);
    BeaconFormatPrintf(out, "   Node Type . . . . . . . . . . . . : %s\n", node_type_string(fixed_info->NodeType));
    BeaconFormatPrintf(out, "   IP Routing Enabled. . . . . . . . : %s\n", fixed_info->EnableRouting ? "Yes" : "No");
    BeaconFormatPrintf(out, "   WINS Proxy Enabled. . . . . . . . : %s\n", fixed_info->EnableProxy ? "Yes" : "No");
    print_search_list(out, fixed_info);
}

void print_adapter_section(formatp *out, PIP_ADAPTER_ADDRESSES adapter) {
    char address_text[128];
    char mask_text[32];
    char mac_text[32];
    char friendly_name[512];
    char description[512];
    char dns_suffix[512];
    char dhcp_server[64];
    char time_text[128];
    char duid_text[560];
    PIP_ADAPTER_UNICAST_ADDRESS unicast;
    PIP_ADAPTER_GATEWAY_ADDRESS gateway;
    PIP_ADAPTER_DNS_SERVER_ADDRESS dns_server;
    PIP_ADAPTER_DNS_SUFFIX suffix;
    SOCKADDR_IN6 *address6;
    DWORD lease_obtained;
    DWORD lease_expires;
    int has_dhcpv6_info;
    int first;
    int netbios_option;

    if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) return;

    wide_to_utf8(friendly_name, sizeof(friendly_name), adapter->FriendlyName);
    wide_to_utf8(description, sizeof(description), adapter->Description);
    wide_to_utf8(dns_suffix, sizeof(dns_suffix), adapter->DnsSuffix);

    BeaconFormatPrintf(out, "\n%s %s:\n\n", adapter_type_string(adapter->IfType), friendly_name);

    if (adapter->OperStatus != IfOperStatusUp) {
        BeaconFormatPrintf(out, "   Media State . . . . . . . . . . . : Media disconnected\n");
    }

    BeaconFormatPrintf(out, "   Connection-specific DNS Suffix  . : %s\n", dns_suffix);
    BeaconFormatPrintf(out, "   Description . . . . . . . . . . . : %s\n", description);

    if (adapter->PhysicalAddressLength > 0) {
        format_mac_address(adapter->PhysicalAddress, adapter->PhysicalAddressLength, mac_text, sizeof(mac_text));
        BeaconFormatPrintf(out, "   Physical Address. . . . . . . . . : %s\n", mac_text);
    }

    BeaconFormatPrintf(out, "   DHCP Enabled. . . . . . . . . . . : %s\n", (adapter->Flags & IP_ADAPTER_DHCP_ENABLED) ? "Yes" : "No");
    BeaconFormatPrintf(out, "   Autoconfiguration Enabled . . . . : Yes\n");

    if (adapter->OperStatus != IfOperStatusUp) {
        return;
    }

    unicast = adapter->FirstUnicastAddress;
    while (unicast != NULL) {
        if (unicast->Address.lpSockaddr != NULL && unicast->Address.lpSockaddr->sa_family == AF_INET6) {
            address6 = (SOCKADDR_IN6 *)unicast->Address.lpSockaddr;
            format_ipv6_address(unicast->Address.lpSockaddr, address_text, sizeof(address_text));
            if (address6->sin6_addr.Byte[0] == 0xfe && address6->sin6_addr.Byte[1] == 0x80) {
                BeaconFormatPrintf(out, "   Link-local IPv6 Address . . . . . : %s%%%lu(Preferred) \n", address_text, (unsigned long)address6->sin6_scope_id);
            } else {
                BeaconFormatPrintf(out, "   IPv6 Address. . . . . . . . . . . : %s(Preferred) \n", address_text);
            }
        }
        unicast = unicast->Next;
    }

    unicast = adapter->FirstUnicastAddress;
    while (unicast != NULL) {
        if (unicast->Address.lpSockaddr != NULL && unicast->Address.lpSockaddr->sa_family == AF_INET) {
            format_ipv4_address(unicast->Address.lpSockaddr, address_text, sizeof(address_text));
            BeaconFormatPrintf(out, "   IPv4 Address. . . . . . . . . . . : %s(Preferred) \n", address_text);
            prefix_length_to_subnet_mask(unicast->OnLinkPrefixLength, mask_text, sizeof(mask_text));
            BeaconFormatPrintf(out, "   Subnet Mask . . . . . . . . . . . : %s\n", mask_text);
        }
        unicast = unicast->Next;
    }

    if (adapter->Flags & IP_ADAPTER_DHCP_ENABLED) {
        get_dhcp_lease_info(adapter->AdapterName, &lease_obtained, &lease_expires, dhcp_server, sizeof(dhcp_server));
        if (lease_obtained != 0) {
            format_unix_time(lease_obtained, time_text, sizeof(time_text));
            if (time_text[0] != 0) {
                BeaconFormatPrintf(out, "   Lease Obtained. . . . . . . . . . : %s\n", time_text);
            }
        }
        if (lease_expires != 0) {
            format_unix_time(lease_expires, time_text, sizeof(time_text));
            if (time_text[0] != 0) {
                BeaconFormatPrintf(out, "   Lease Expires . . . . . . . . . . : %s\n", time_text);
            }
        }
    }

    gateway = adapter->FirstGatewayAddress;
    if (gateway != NULL) {
        if (gateway->Address.lpSockaddr != NULL && gateway->Address.lpSockaddr->sa_family == AF_INET) {
            format_ipv4_address(gateway->Address.lpSockaddr, address_text, sizeof(address_text));
        } else if (gateway->Address.lpSockaddr != NULL && gateway->Address.lpSockaddr->sa_family == AF_INET6) {
            format_ipv6_address(gateway->Address.lpSockaddr, address_text, sizeof(address_text));
        } else {
            address_text[0] = 0;
        }
        BeaconFormatPrintf(out, "   Default Gateway . . . . . . . . . : %s\n", address_text);
        gateway = gateway->Next;
        while (gateway != NULL) {
            if (gateway->Address.lpSockaddr != NULL && gateway->Address.lpSockaddr->sa_family == AF_INET) {
                format_ipv4_address(gateway->Address.lpSockaddr, address_text, sizeof(address_text));
            } else if (gateway->Address.lpSockaddr != NULL && gateway->Address.lpSockaddr->sa_family == AF_INET6) {
                format_ipv6_address(gateway->Address.lpSockaddr, address_text, sizeof(address_text));
            } else {
                address_text[0] = 0;
            }
            BeaconFormatPrintf(out, "                                       %s\n", address_text);
            gateway = gateway->Next;
        }
    } else {
        BeaconFormatPrintf(out, "   Default Gateway . . . . . . . . . : \n");
    }

    if (adapter->Flags & IP_ADAPTER_DHCP_ENABLED) {
        address_text[0] = 0;
        if (adapter->Dhcpv4Server.iSockaddrLength > 0 && adapter->Dhcpv4Server.lpSockaddr != NULL && adapter->Dhcpv4Server.lpSockaddr->sa_family == AF_INET) {
            format_ipv4_address(adapter->Dhcpv4Server.lpSockaddr, address_text, sizeof(address_text));
            if (MSVCRT$strcmp(address_text, "0.0.0.0") != 0 && MSVCRT$strcmp(address_text, "255.255.255.255") != 0) {
                BeaconFormatPrintf(out, "   DHCP Server . . . . . . . . . . . : %s\n", address_text);
            }
        } else {
            get_dhcp_lease_info(adapter->AdapterName, &lease_obtained, &lease_expires, dhcp_server, sizeof(dhcp_server));
            if (dhcp_server[0] != 0 && MSVCRT$strcmp(dhcp_server, "255.255.255.255") != 0) {
                BeaconFormatPrintf(out, "   DHCP Server . . . . . . . . . . . : %s\n", dhcp_server);
            }
        }
    }

    has_dhcpv6_info = 0;
    unicast = adapter->FirstUnicastAddress;
    while (unicast != NULL) {
        if (unicast->Address.lpSockaddr != NULL && unicast->Address.lpSockaddr->sa_family == AF_INET6) {
            has_dhcpv6_info = 1;
            break;
        }
        unicast = unicast->Next;
    }
    if (has_dhcpv6_info) {
        BeaconFormatPrintf(out, "   DHCPv6 IAID . . . . . . . . . . . : %lu\n", (unsigned long)adapter->Dhcpv6Iaid);
        if (adapter->Dhcpv6ClientDuidLength > 0) {
            format_duid(adapter->Dhcpv6ClientDuid, adapter->Dhcpv6ClientDuidLength, duid_text, sizeof(duid_text));
            BeaconFormatPrintf(out, "   DHCPv6 Client DUID. . . . . . . . : %s\n", duid_text);
        }
    }

    dns_server = adapter->FirstDnsServerAddress;
    first = 1;
    while (dns_server != NULL) {
        address_text[0] = 0;
        if (dns_server->Address.lpSockaddr != NULL && dns_server->Address.lpSockaddr->sa_family == AF_INET) {
            format_ipv4_address(dns_server->Address.lpSockaddr, address_text, sizeof(address_text));
        } else if (dns_server->Address.lpSockaddr != NULL && dns_server->Address.lpSockaddr->sa_family == AF_INET6) {
            format_ipv6_address(dns_server->Address.lpSockaddr, address_text, sizeof(address_text));
        }
        if (first) {
            BeaconFormatPrintf(out, "   DNS Servers . . . . . . . . . . . : %s\n", address_text);
            first = 0;
        } else {
            BeaconFormatPrintf(out, "                                       %s\n", address_text);
        }
        dns_server = dns_server->Next;
    }

    netbios_option = get_netbios_option(adapter->AdapterName);
    BeaconFormatPrintf(out, "   NetBIOS over Tcpip. . . . . . . . : %s\n", (netbios_option == 2) ? "Disabled" : "Enabled");

    suffix = adapter->FirstDnsSuffix;
    first = 1;
    while (suffix != NULL) {
        if (suffix->String[0] != 0) {
            wide_to_utf8(dns_suffix, sizeof(dns_suffix), suffix->String);
            if (dns_suffix[0] != 0) {
                if (first) {
                    BeaconFormatPrintf(out, "   Connection-specific DNS Suffix Search List :\n");
                    first = 0;
                }
                BeaconFormatPrintf(out, "                                       %s\n", dns_suffix);
            }
        }
        suffix = suffix->Next;
    }
}

do {
    WSADATA wsa_data;
    PIP_ADAPTER_ADDRESSES adapters;
    PIP_ADAPTER_ADDRESSES current;
    PFIXED_INFO fixed_info;
    ULONG adapter_buffer_size;
    ULONG fixed_info_size;
    DWORD result;
    formatp out;
    char *output;
    int output_length;

    adapters = NULL;
    fixed_info = NULL;

    if (WS2_32$WSAStartup(WINSOCK_VERSION, &wsa_data) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "WSAStartup failed");
        break;
    }

    BeaconFormatAlloc(&out, 65536);

    adapter_buffer_size = 0;
    result = IPHLPAPI$GetAdaptersAddresses(AF_UNSPEC, GAA_FLAGS, NULL, NULL, &adapter_buffer_size);
    if (result != ERROR_BUFFER_OVERFLOW) {
        BeaconFormatFree(&out);
        WS2_32$WSACleanup();
        BeaconPrintf(CALLBACK_ERROR, "GetAdaptersAddresses failed: %lu", result);
        break;
    }

    adapters = (PIP_ADAPTER_ADDRESSES)malloc(adapter_buffer_size);
    if (adapters == NULL) {
        BeaconFormatFree(&out);
        WS2_32$WSACleanup();
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed for adapter addresses");
        break;
    }

    result = IPHLPAPI$GetAdaptersAddresses(AF_UNSPEC, GAA_FLAGS, NULL, adapters, &adapter_buffer_size);
    if (result != ERROR_SUCCESS) {
        free(adapters);
        BeaconFormatFree(&out);
        WS2_32$WSACleanup();
        BeaconPrintf(CALLBACK_ERROR, "GetAdaptersAddresses failed: %lu", result);
        break;
    }

    fixed_info_size = 0;
    result = IPHLPAPI$GetNetworkParams(NULL, &fixed_info_size);
    if (result != ERROR_BUFFER_OVERFLOW) {
        free(adapters);
        BeaconFormatFree(&out);
        WS2_32$WSACleanup();
        BeaconPrintf(CALLBACK_ERROR, "GetNetworkParams failed to get buffer size");
        break;
    }

    fixed_info = (PFIXED_INFO)malloc(fixed_info_size);
    if (fixed_info == NULL) {
        free(adapters);
        BeaconFormatFree(&out);
        WS2_32$WSACleanup();
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed for network params");
        break;
    }

    result = IPHLPAPI$GetNetworkParams(fixed_info, &fixed_info_size);
    if (result != NO_ERROR) {
        free(fixed_info);
        free(adapters);
        BeaconFormatFree(&out);
        WS2_32$WSACleanup();
        BeaconPrintf(CALLBACK_ERROR, "GetNetworkParams failed");
        break;
    }

    print_global_section(&out, fixed_info);
    current = adapters;
    while (current != NULL) {
        print_adapter_section(&out, current);
        current = current->Next;
    }

    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);
    free(fixed_info);
    free(adapters);
    WS2_32$WSACleanup();
} while (0);
