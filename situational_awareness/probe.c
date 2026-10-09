#include <windows.h>
#include <winsock2.h>
#include <ws2_32.h>
#include <beacon.h>

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 445
#define DEFAULT_TIMEOUT_SECONDS 5

struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    size_t ai_addrlen;
    char *ai_canonname;
    struct _SOCKADDR *ai_addr;
    struct addrinfo *ai_next;
};

WS2_32$getaddrinfo: u32 (cstr, cstr, ptr, ptr);
WS2_32$freeaddrinfo: void (ptr);
WS2_32$__WSAFDIsSet: i32 (size_t, ptr);

do {
    datap parser;
    char *host;
    char *host_arg;
    int port;
    int port_arg;
    int timeout_seconds;
    int timeout_arg;
    char port_text[16];
    WSADATA wsa_data;
    struct addrinfo hints;
    struct addrinfo *results;
    SOCKET socket_handle;
    u_long nonblocking;
    fd_set write_set;
    struct timeval timeout;
    BOOL port_open;

    host = DEFAULT_HOST;
    port = DEFAULT_PORT;
    timeout_seconds = DEFAULT_TIMEOUT_SECONDS;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);

        host_arg = BeaconDataExtract(&parser, NULL);
        if (host_arg != NULL && host_arg[0] != 0) {
            host = host_arg;
        }

        port_arg = BeaconDataInt(&parser);
        if (port_arg > 0) {
            port = port_arg;
        }

        timeout_arg = BeaconDataInt(&parser);
        if (timeout_arg > 0) {
            timeout_seconds = timeout_arg;
        }
    }

    if (port <= 0 || port > 65535) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid port: %d", port);
        break;
    }
    if (WS2_32$WSAStartup(WINSOCK_VERSION, &wsa_data) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "WSAStartup failed.");
        break;
    }

    results = NULL;
    port_open = FALSE;
    MSVCRT$memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    MSVCRT$sprintf(port_text, "%d", port);
    if (WS2_32$getaddrinfo(host, port_text, &hints, &results) == ERROR_SUCCESS) {
        if (results != NULL) {
            socket_handle = WS2_32$socket(results->ai_family, results->ai_socktype, results->ai_protocol);
            if (socket_handle != INVALID_SOCKET) {
                nonblocking = 1;
                WS2_32$ioctlsocket(socket_handle, FIONBIO, &nonblocking);

                write_set.fd_count = 1;
                write_set.fd_array[0] = socket_handle;
                timeout.tv_sec = timeout_seconds;
                timeout.tv_usec = 0;
                WS2_32$connect(socket_handle, results->ai_addr, (DWORD)results->ai_addrlen);
                WS2_32$select(1, NULL, &write_set, NULL, &timeout);

                if (WS2_32$__WSAFDIsSet(socket_handle, &write_set)) {
                    port_open = TRUE;
                }
                WS2_32$closesocket(socket_handle);
            }
        }
    }

    if (results != NULL) {
        WS2_32$freeaddrinfo(results);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%s:%d %s", host, port, port_open ? "OPEN" : "FAILED");
    WS2_32$WSACleanup();
} while (0); 
