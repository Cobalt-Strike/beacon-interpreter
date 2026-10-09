#include <windows.h>
#include <winerror.h>
#include <winnt.h>
#include <winsock2.h>
#include <ws2_32.h>
#include <iphlpapi.h>
#include <iprtrmib.h>
#include <tcpmib.h>
#include <udpmib.h>
#include <beacon.h>

#define NETSTAT_OPTIONS 0x1111

#define SHOW_TCP4  0x0001
#define SHOW_TCP6  0x0010
#define SHOW_UDP4  0x0100
#define SHOW_UDP6  0x1000

#define HOSTNAMELEN 256
#define PORTNAMELEN 32
#define ADDRESSLEN 512

char *tcp_state_name(DWORD state) {
    if (state == 1) return "CLOSED";
    if (state == 2) return "LISTENING";
    if (state == 3) return "SYN_SENT";
    if (state == 4) return "SYN_RCVD";
    if (state == 5) return "ESTABLISHED";
    if (state == 6) return "FIN_WAIT1";
    if (state == 7) return "FIN_WAIT2";
    if (state == 8) return "CLOSE_WAIT";
    if (state == 9) return "CLOSING";
    if (state == 10) return "LAST_ACK";
    if (state == 11) return "TIME_WAIT";
    if (state == 12) return "DELETE_TCB";
    return "???";
}

void ipv4_to_string(UINT ip, CHAR name[]) {
    UINT network_ip;
    network_ip = WS2_32$htonl(ip);
    sprintf(
        name,
        "%u.%u.%u.%u",
        (network_ip >> 24) & 0xff,
        (network_ip >> 16) & 0xff,
        (network_ip >> 8) & 0xff,
        network_ip & 0xff
    );
}

void ipv6_to_string(UCHAR addr[16], CHAR name[]) {
    USHORT parts[8];
    parts[0] = WS2_32$htons(*(USHORT *)&addr[0]);
    parts[1] = WS2_32$htons(*(USHORT *)&addr[2]);
    parts[2] = WS2_32$htons(*(USHORT *)&addr[4]);
    parts[3] = WS2_32$htons(*(USHORT *)&addr[6]);
    parts[4] = WS2_32$htons(*(USHORT *)&addr[8]);
    parts[5] = WS2_32$htons(*(USHORT *)&addr[10]);
    parts[6] = WS2_32$htons(*(USHORT *)&addr[12]);
    parts[7] = WS2_32$htons(*(USHORT *)&addr[14]);
    sprintf(
        name,
        "%x:%x:%x:%x:%x:%x:%x:%x",
        parts[0],
        parts[1],
        parts[2],
        parts[3],
        parts[4],
        parts[5],
        parts[6],
        parts[7]
    );
}

void port_to_string(UINT port, CHAR name[]) {
    WORD network_port;
    network_port = WS2_32$htons((WORD)port);
    sprintf(name, "%u", network_port);
}

void resolve_pid(DWORD pid, char *name, DWORD *size) {
    HANDLE process;
    DWORD local_size;

    local_size = MAX_PATH;
    process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (process == NULL) {
        name[0] = 0;
        *size = 0;
        return;
    }
    if (QueryFullProcessImageNameA(process, 0, name, &local_size)) {
        name[local_size] = 0;
        *size = local_size;
    } else {
        name[0] = 0;
        *size = 0;
    }
    CloseHandle(process);
}

void append_header(formatp *buffer) {
    BeaconFormatPrintf(buffer, "Active Connections\n\n");
    BeaconFormatPrintf(buffer, "%-6s %-48s %-48s %-13s %s\n", "Proto", "Local Address", "Foreign Address", "State", "Process (PID)");
    BeaconFormatPrintf(buffer, "%-6s %-48s %-48s %-13s %s\n", "-----", "-------------", "---------------", "-----", "-------------");
}

void append_tcp4(formatp *buffer, DWORD *count) {
    MIB_TCPTABLE_OWNER_PID stack_table;
    PMIB_TCPTABLE_OWNER_PID table;
    PMIB_TCPROW_OWNER_PID row;
    DWORD error;
    DWORD size;
    DWORD table_allocated;
    DWORD i;
    CHAR host_ip[HOSTNAMELEN];
    CHAR host_port[PORTNAMELEN];
    CHAR remote_ip[HOSTNAMELEN];
    CHAR remote_port[PORTNAMELEN];
    CHAR host[ADDRESSLEN];
    CHAR remote[ADDRESSLEN];
    CHAR process_name[MAX_PATH + 1];
    DWORD process_size;

    table = &stack_table;
    table_allocated = FALSE;
    size = sizeof(stack_table);
    error = IPHLPAPI$GetExtendedTcpTable(table, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (error != NO_ERROR && error != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    if (error == ERROR_INSUFFICIENT_BUFFER) {
        if (size == 0) {
            return;
        }
        table = (PMIB_TCPTABLE_OWNER_PID)LocalAlloc(0x0040, size);
        if (table == NULL) {
            return;
        }
        table_allocated = TRUE;
        if (IPHLPAPI$GetExtendedTcpTable(table, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
            LocalFree(table);
            return;
        }
    }

    for (i = 0; i < table->dwNumEntries; i++) {
        row = &table->table[i];
        ipv4_to_string(row->dwLocalAddr, host_ip);
        port_to_string(row->dwLocalPort, host_port);
        sprintf(host, "%s:%s", host_ip, host_port);

        if (row->dwState == MIB_TCP_STATE_LISTEN) {
            strcpy(remote, "*:*");
        } else {
            ipv4_to_string(row->dwRemoteAddr, remote_ip);
            port_to_string(row->dwRemotePort, remote_port);
            sprintf(remote, "%s:%s", remote_ip, remote_port);
        }
        resolve_pid(row->dwOwningPid, process_name, &process_size);
        BeaconFormatPrintf(
            buffer,
            "%-6s %-48s %-48s %-13s %s(%lu)\n",
            "TCP",
            host,
            remote,
            tcp_state_name(row->dwState),
            process_name,
            row->dwOwningPid
        );
        (*count)++;
    }
    if (table_allocated) {
        LocalFree(table);
    }
}

void append_tcp6(formatp *buffer, DWORD *count) {
    MIB_TCP6TABLE_OWNER_PID stack_table;
    PMIB_TCP6TABLE_OWNER_PID table;
    PMIB_TCP6ROW_OWNER_PID row;
    DWORD error;
    DWORD size;
    DWORD table_allocated;
    DWORD i;
    CHAR host_ip[HOSTNAMELEN];
    CHAR host_port[PORTNAMELEN];
    CHAR remote_ip[HOSTNAMELEN];
    CHAR remote_port[PORTNAMELEN];
    CHAR host[ADDRESSLEN];
    CHAR remote[ADDRESSLEN];
    CHAR process_name[MAX_PATH + 1];
    DWORD process_size;

    table = &stack_table;
    table_allocated = FALSE;
    size = sizeof(stack_table);
    error = IPHLPAPI$GetExtendedTcpTable(table, &size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (error != NO_ERROR && error != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    if (error == ERROR_INSUFFICIENT_BUFFER) {
        if (size == 0) {
            return;
        }
        table = (PMIB_TCP6TABLE_OWNER_PID)LocalAlloc(0x0040, size);
        if (table == NULL) {
            return;
        }
        table_allocated = TRUE;
        if (IPHLPAPI$GetExtendedTcpTable(table, &size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
            LocalFree(table);
            return;
        }
    }

    for (i = 0; i < table->dwNumEntries; i++) {
        row = &table->table[i];
        ipv6_to_string(row->ucLocalAddr, host_ip);
        port_to_string(row->dwLocalPort, host_port);
        sprintf(host, "[%s]:%s", host_ip, host_port);

        if (row->dwState == MIB_TCP_STATE_LISTEN) {
            strcpy(remote, "*:*");
        } else {
            ipv6_to_string(row->ucRemoteAddr, remote_ip);
            port_to_string(row->dwRemotePort, remote_port);
            sprintf(remote, "[%s]:%s", remote_ip, remote_port);
        }
        resolve_pid(row->dwOwningPid, process_name, &process_size);
        BeaconFormatPrintf(
            buffer,
            "%-6s %-48s %-48s %-13s %s(%lu)\n",
            "TCP6",
            host,
            remote,
            tcp_state_name(row->dwState),
            process_name,
            row->dwOwningPid
        );
        (*count)++;
    }
    if (table_allocated) {
        LocalFree(table);
    }
}

void append_udp4(formatp *buffer, DWORD *count) {
    MIB_UDPTABLE_OWNER_PID stack_table;
    PMIB_UDPTABLE_OWNER_PID table;
    PMIB_UDPROW_OWNER_PID row;
    DWORD error;
    DWORD size;
    DWORD table_allocated;
    DWORD i;
    CHAR host_ip[HOSTNAMELEN];
    CHAR host_port[PORTNAMELEN];
    CHAR host[ADDRESSLEN];
    CHAR process_name[MAX_PATH + 1];
    DWORD process_size;

    table = &stack_table;
    table_allocated = FALSE;
    size = sizeof(stack_table);
    error = IPHLPAPI$GetExtendedUdpTable(table, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (error != NO_ERROR && error != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    if (error == ERROR_INSUFFICIENT_BUFFER) {
        if (size == 0) {
            return;
        }
        table = (PMIB_UDPTABLE_OWNER_PID)LocalAlloc(0x0040, size);
        if (table == NULL) {
            return;
        }
        table_allocated = TRUE;
        if (IPHLPAPI$GetExtendedUdpTable(table, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
            LocalFree(table);
            return;
        }
    }

    for (i = 0; i < table->dwNumEntries; i++) {
        row = &table->table[i];
        ipv4_to_string(row->dwLocalAddr, host_ip);
        port_to_string(row->dwLocalPort, host_port);
        sprintf(host, "%s:%s", host_ip, host_port);
        resolve_pid(row->dwOwningPid, process_name, &process_size);
        BeaconFormatPrintf(
            buffer,
            "%-6s %-48s %-48s %-13s %s(%lu)\n",
            "UDP",
            host,
            "*:*",
            "",
            process_name,
            row->dwOwningPid
        );
        (*count)++;
    }
    if (table_allocated) {
        LocalFree(table);
    }
}

void append_udp6(formatp *buffer, DWORD *count) {
    MIB_UDP6TABLE_OWNER_PID stack_table;
    PMIB_UDP6TABLE_OWNER_PID table;
    PMIB_UDP6ROW_OWNER_PID row;
    DWORD error;
    DWORD size;
    DWORD table_allocated;
    DWORD i;
    CHAR host_ip[HOSTNAMELEN];
    CHAR host_port[PORTNAMELEN];
    CHAR host[ADDRESSLEN];
    CHAR process_name[MAX_PATH + 1];
    DWORD process_size;

    table = &stack_table;
    table_allocated = FALSE;
    size = sizeof(stack_table);
    error = IPHLPAPI$GetExtendedUdpTable(table, &size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (error != NO_ERROR && error != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    if (error == ERROR_INSUFFICIENT_BUFFER) {
        if (size == 0) {
            return;
        }
        table = (PMIB_UDP6TABLE_OWNER_PID)LocalAlloc(0x0040, size);
        if (table == NULL) {
            return;
        }
        table_allocated = TRUE;
        if (IPHLPAPI$GetExtendedUdpTable(table, &size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
            LocalFree(table);
            return;
        }
    }

    for (i = 0; i < table->dwNumEntries; i++) {
        row = &table->table[i];
        ipv6_to_string(row->ucLocalAddr, host_ip);
        port_to_string(row->dwLocalPort, host_port);
        sprintf(host, "[%s]:%s", host_ip, host_port);
        resolve_pid(row->dwOwningPid, process_name, &process_size);
        BeaconFormatPrintf(
            buffer,
            "%-6s %-48s %-48s %-13s %s(%lu)\n",
            "UDP6",
            host,
            "*:*",
            "",
            process_name,
            row->dwOwningPid
        );
        (*count)++;
    }
    if (table_allocated) {
        LocalFree(table);
    }
}

do {
    datap parser;
    formatp buffer;
    int output_length;
    char *output;
    DWORD count;
    DWORD netstat_options;

    netstat_options = NETSTAT_OPTIONS;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        netstat_options = BeaconDataInt(&parser);
        if (netstat_options == 0) netstat_options = NETSTAT_OPTIONS;
    }

    count = 0;
    BeaconFormatAlloc(&buffer, 8192);
    append_header(&buffer);

    if (netstat_options & SHOW_TCP4) {
        append_tcp4(&buffer, &count);
    }
    if (netstat_options & SHOW_TCP6) {
        append_tcp6(&buffer, &count);
    }
    if (netstat_options & SHOW_UDP4) {
        append_udp4(&buffer, &count);
    }
    if (netstat_options & SHOW_UDP6) {
        append_udp6(&buffer, &count);
    }

    if (count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "No active connections found.");
    } else {
        output = BeaconFormatToString(&buffer, &output_length);
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatFree(&buffer);
} while (0);
