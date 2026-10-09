#include <windows.h>
#include <winnt.h>
#include <advapi.h>
#include <secur32.h>
#include <ntsecapi.h>
#include <beacon.h>

void print_time_utc(formatp *out, char *prefix, LARGE_INTEGER *value) {
    FILETIME ft;
    SYSTEMTIME st;

    if ((value->u.LowPart == 0 && value->u.HighPart == 0) || (value->u.LowPart == ((DWORD)-1) && value->u.HighPart == 0x7fffffff)) {
        BeaconFormatPrintf(out, "%s: Unset\n", prefix);
        return;
    }

    ft.dwLowDateTime = value->u.LowPart;
    ft.dwHighDateTime = value->u.HighPart;
    if (!FileTimeToSystemTime(&ft, &st)) {
        BeaconFormatPrintf(out, "%s: conversion failed\n", prefix);
        return;
    }

    BeaconFormatPrintf(out, "%s: %04u-%02u-%02u %02u:%02u:%02u\n", prefix, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

char *logon_type_name(SECURITY_LOGON_TYPE type) {
    if (type == UndefinedLogonType) return "UndefinedLogonType";
    if (type == Interactive) return "Interactive";
    if (type == Network) return "Network";
    if (type == Batch) return "Batch";
    if (type == Service) return "Service";
    if (type == Proxy) return "Proxy";
    if (type == Unlock) return "Unlock";
    if (type == NetworkCleartext) return "NetworkCleartext";
    if (type == NewCredentials) return "NewCredentials";
    if (type == RemoteInteractive) return "RemoteInteractive";
    if (type == CachedInteractive) return "CachedInteractive";
    if (type == CachedRemoteInteractive) return "CachedRemoteInteractive";
    if (type == CachedUnlock) return "CachedUnlock";
    return "Unknown";
}

do {
    HANDLE token;
    DWORD length;
    TOKEN_STATISTICS stats;
    PSECURITY_LOGON_SESSION_DATA data;
    NTSTATUS status;
    formatp out;
    int output_length;
    char *output;

    token = NULL;
    data = NULL;
    length = 0;
    if (!ADVAPI32$OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: %lu", GetLastError());
        break;
    }

    if (!ADVAPI32$GetTokenInformation(token, TokenStatistics, &stats, sizeof(stats), &length)) {
        CloseHandle(token);
        BeaconPrintf(CALLBACK_ERROR, "GetTokenInformation failed: %lu", GetLastError());
        break;
    }

    status = SECUR32$LsaGetLogonSessionData(&stats.AuthenticationId, &data);
    if (status != 0 || data == NULL) {
        CloseHandle(token);
        BeaconPrintf(CALLBACK_ERROR, "LsaGetLogonSessionData failed: 0x%lx", status);
        break;
    }

    BeaconFormatAlloc(&out, 2048);
    BeaconFormatPrintf(&out, "UserName: %S\\%S\n", data->LogonDomain.Buffer ? data->LogonDomain.Buffer : L"", data->UserName.Buffer ? data->UserName.Buffer : L"");
    BeaconFormatPrintf(&out, "Authentication Package: %S\n", data->AuthenticationPackage.Buffer ? data->AuthenticationPackage.Buffer : L"");
    BeaconFormatPrintf(&out, "Logon Type: %s\n", logon_type_name(data->LogonType));
    BeaconFormatPrintf(&out, "Session id: %lu\nLogon Server: %S\nDnsDomainName: %S\nUPN: %S\nProfile Path: %S\nHomeDirectory: %S\n", data->Session, data->LogonServer.Buffer ? data->LogonServer.Buffer : L"", data->DnsDomainName.Buffer ? data->DnsDomainName.Buffer : L"", data->Upn.Buffer ? data->Upn.Buffer : L"", data->ProfilePath.Buffer ? data->ProfilePath.Buffer : L"", data->HomeDirectory.Buffer ? data->HomeDirectory.Buffer : L"");
    print_time_utc(&out, "Logon Time", &data->LogonTime);
    print_time_utc(&out, "Password last changed", &data->PasswordLastSet);
    print_time_utc(&out, "Password can change", &data->PasswordCanChange);
    print_time_utc(&out, "Password must change", &data->PasswordMustChange);

    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);

    SECUR32$LsaFreeReturnBuffer(data);
    CloseHandle(token);
} while (0);
