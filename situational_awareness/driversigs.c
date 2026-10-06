#include <windows.h>
#include <winreg.h>
#include <file.h>
#include <advapi.h>
#include <wincrypt.h>
#include <beacon.h>

#define SC_MANAGER_ENUMERATE_SERVICE 0x0004
#define SC_ENUM_PROCESS_INFO 0
#define SERVICE_KERNEL_DRIVER 0x00000001
#define SERVICE_FILE_SYSTEM_DRIVER 0x00000002
#define SERVICE_DRIVER (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER)
#define SERVICE_ACTIVE 0x00000001

#define CERT_SECTION_TYPE_ANY 0x00ff
#define WIN_CERT_REVISION_2_0 0x0200
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA 0x0002
#define X509_ASN_ENCODING 0x00000001
#define PKCS_7_ASN_ENCODING 0x00010000
#define CERT_NAME_SIMPLE_DISPLAY_TYPE 4

typedef HANDLE SC_HANDLE;
typedef void *PCCERT_CONTEXT;

typedef struct _SERVICE_STATUS_PROCESS {
    DWORD dwServiceType;
    DWORD dwCurrentState;
    DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode;
    DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint;
    DWORD dwWaitHint;
    DWORD dwProcessId;
    DWORD dwServiceFlags;
} SERVICE_STATUS_PROCESS;

typedef struct _ENUM_SERVICE_STATUS_PROCESSW {
    LPWSTR lpServiceName;
    LPWSTR lpDisplayName;
    SERVICE_STATUS_PROCESS ServiceStatusProcess;
} ENUM_SERVICE_STATUS_PROCESSW, *LPENUM_SERVICE_STATUS_PROCESSW;

typedef struct _WIN_CERTIFICATE {
    DWORD dwLength;
    WORD wRevision;
    WORD wCertificateType;
    BYTE bCertificate[1];
} WIN_CERTIFICATE, *LPWIN_CERTIFICATE;

typedef struct _CRYPT_VERIFY_MESSAGE_PARA_SCRIPT {
    DWORD cbSize;
    DWORD dwMsgAndCertEncodingType;
    ULONG_PTR hCryptProv;
    void *pfnGetSignerCertificate;
    void *pvGetArg;
} CRYPT_VERIFY_MESSAGE_PARA_SCRIPT, *PCRYPT_VERIFY_MESSAGE_PARA_SCRIPT;

ADVAPI32$OpenSCManagerA: ptr (ptr, ptr, u32);
ADVAPI32$EnumServicesStatusExW: u32 (ptr, u32, u32, u32, ptr, u32, ptr, ptr, ptr, ptr);
ADVAPI32$CloseServiceHandle: u32 (ptr);
IMAGEHLP$ImageEnumerateCertificates: u32 (ptr, u16, ptr, ptr, u32);
IMAGEHLP$ImageGetCertificateHeader: u32 (ptr, u32, ptr);
IMAGEHLP$ImageGetCertificateData: u32 (ptr, u32, ptr, ptr);
CRYPT32$CryptVerifyMessageSignature: u32 (ptr, u32, ptr, u32, ptr, ptr, ptr);
CRYPT32$CertGetNameStringW: u32 (ptr, u32, u32, ptr, ptr, u32);
CRYPT32$CertFreeCertificateContext: u32 (ptr);

BOOL is_security_publisher(WCHAR *name) {
    if (name == NULL || name[0] == 0) return FALSE;
    if (MSVCRT$_wcsicmp(name, L"Carbon Black, Inc.") == 0) return TRUE;
    if (MSVCRT$_wcsicmp(name, L"CrowdStrike, Inc.") == 0) return TRUE;
    if (MSVCRT$_wcsicmp(name, L"Cylance, Inc.") == 0) return TRUE;
    if (MSVCRT$_wcsicmp(name, L"FireEye, Inc.") == 0) return TRUE;
    if (MSVCRT$_wcsicmp(name, L"McAfee, Inc.") == 0) return TRUE;
    if (MSVCRT$_wcsicmp(name, L"Sentinel Labs, Inc.") == 0) return TRUE;
    if (MSVCRT$_wcsicmp(name, L"Symantec Corporation") == 0) return TRUE;
    if (MSVCRT$_wcsicmp(name, L"Tanium Inc.") == 0) return TRUE;
    return FALSE;
}

BOOL normalize_driver_path(WCHAR *image_path, WCHAR *file_path, DWORD cch_file_path) {
    WCHAR windows_dir[MAX_PATH];

    if (image_path == NULL || image_path[0] == 0 || file_path == NULL || cch_file_path == 0) {
        return FALSE;
    }

    file_path[0] = 0;
    if (MSVCRT$_wcsnicmp(image_path, L"\\SystemRoot\\", 12) == 0) {
        windows_dir[0] = 0;
        if (KERNEL32$GetWindowsDirectoryW(windows_dir, MAX_PATH) == 0) {
            return FALSE;
        }
        MSVCRT$wcscpy(file_path, windows_dir);
        MSVCRT$wcscat(file_path, L"\\");
        MSVCRT$wcscat(file_path, image_path + 12);
        return TRUE;
    }

    if (MSVCRT$_wcsnicmp(image_path, L"System32\\", 9) == 0) {
        windows_dir[0] = 0;
        if (KERNEL32$GetWindowsDirectoryW(windows_dir, MAX_PATH) == 0) {
            return FALSE;
        }
        MSVCRT$wcscpy(file_path, windows_dir);
        MSVCRT$wcscat(file_path, L"\\");
        MSVCRT$wcscat(file_path, image_path);
        return TRUE;
    }

    if (MSVCRT$_wcsnicmp(image_path, L"\\??\\", 4) == 0) {
        MSVCRT$wcscpy(file_path, image_path + 4);
        return TRUE;
    }

    if (image_path[0] != L'\\') {
        windows_dir[0] = 0;
        if (KERNEL32$GetWindowsDirectoryW(windows_dir, MAX_PATH) == 0) {
            return FALSE;
        }
        MSVCRT$wcscpy(file_path, windows_dir);
        MSVCRT$wcscat(file_path, L"\\");
        MSVCRT$wcscat(file_path, image_path);
        return TRUE;
    }

    MSVCRT$wcscpy(file_path, image_path);
    return TRUE;
}

DWORD validate_driver(WCHAR *image_path, formatp *out) {
    DWORD status;
    DWORD certificate_count;
    DWORD certificate_length;
    DWORD i;
    HANDLE file_handle;
    WCHAR file_path[MAX_PATH * 2];
    WCHAR certificate_name[MAX_PATH];
    WIN_CERTIFICATE certificate_header;
    LPWIN_CERTIFICATE certificate;
    CRYPT_VERIFY_MESSAGE_PARA_SCRIPT verify_params;
    PCCERT_CONTEXT certificate_context;

    status = ERROR_SUCCESS;
    certificate_count = 0;
    file_handle = INVALID_HANDLE_VALUE;
    certificate = NULL;
    certificate_context = NULL;
    MSVCRT$memset(file_path, 0, sizeof(file_path));

    if (!normalize_driver_path(image_path, file_path, MAX_PATH * 2)) {
        BeaconFormatPrintf(out, "WARNING: invalid driver path %S\n", image_path ? image_path : L"");
        return ERROR_BAD_ARGUMENTS;
    }

    file_handle = KERNEL32$CreateFileW(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) {
        status = KERNEL32$GetLastError();
        BeaconFormatPrintf(out, "WARNING: CreateFileW(%S) failed (%lu)\n", file_path, status);
        return status;
    }

    if (!IMAGEHLP$ImageEnumerateCertificates(file_handle, CERT_SECTION_TYPE_ANY, &certificate_count, NULL, 0)) {
        status = KERNEL32$GetLastError();
        BeaconFormatPrintf(out, "WARNING: IMAGEHLP$ImageEnumerateCertificates failed. (%lu)\n", status);
        KERNEL32$CloseHandle(file_handle);
        return status;
    }

    for (i = 0; i < certificate_count; i++) {
        MSVCRT$memset(&certificate_header, 0, sizeof(certificate_header));
        if (!IMAGEHLP$ImageGetCertificateHeader(file_handle, i, &certificate_header)) {
            status = KERNEL32$GetLastError();
            BeaconFormatPrintf(out, "WARNING: IMAGEHLP$ImageGetCertificateHeader failed. (%lu)\n", status);
            continue;
        }

        certificate_length = certificate_header.dwLength;
        if (certificate_length < sizeof(WIN_CERTIFICATE)) {
            BeaconFormatPrintf(out, "WARNING: invalid certificate length for %S\n", file_path);
            continue;
        }

        certificate = (LPWIN_CERTIFICATE)calloc(1, certificate_length);
        if (certificate == NULL) {
            BeaconFormatPrintf(out, "WARNING: certificate allocation failed (%lu)\n", ERROR_OUTOFMEMORY);
            continue;
        }

        if (!IMAGEHLP$ImageGetCertificateData(file_handle, i, certificate, &certificate_length)) {
            status = KERNEL32$GetLastError();
            BeaconFormatPrintf(out, "WARNING: IMAGEHLP$ImageGetCertificateData failed. (%lu)\n", status);
            free(certificate);
            certificate = NULL;
            continue;
        }

        MSVCRT$memset(&verify_params, 0, sizeof(verify_params));
        verify_params.cbSize = sizeof(verify_params);
        verify_params.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        certificate_context = NULL;

        if (!CRYPT32$CryptVerifyMessageSignature(&verify_params, i, certificate->bCertificate, certificate->dwLength, NULL, NULL, &certificate_context)) {
            status = KERNEL32$GetLastError();
            BeaconFormatPrintf(out, "WARNING: CRYPT32$CryptVerifyMessageSignature failed. (%lu)\n", status);
            free(certificate);
            certificate = NULL;
            continue;
        }

        MSVCRT$memset(certificate_name, 0, sizeof(certificate_name));
        CRYPT32$CertGetNameStringW(certificate_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, certificate_name, MAX_PATH);
        if (is_security_publisher(certificate_name)) {
            BeaconFormatPrintf(out, "FOUND: %S -> %S\n", image_path, certificate_name);
        }

        if (certificate_context != NULL) {
            CRYPT32$CertFreeCertificateContext(certificate_context);
            certificate_context = NULL;
        }
        free(certificate);
        certificate = NULL;
    }

    KERNEL32$CloseHandle(file_handle);
    return ERROR_SUCCESS;
}

DWORD enumerate_loaded_drivers(formatp *out) {
    DWORD result;
    DWORD bytes_needed;
    DWORD services_returned;
    DWORD i;
    BYTE *services;
    SC_HANDLE scm_handle;
    HKEY key_handle;
    WCHAR registry_path[MAX_PATH * 2];
    WCHAR driver_path[MAX_PATH * 2];
    DWORD length;
    LPENUM_SERVICE_STATUS_PROCESSW service;

    result = ERROR_SUCCESS;
    bytes_needed = 0;
    services_returned = 0;
    services = NULL;
    scm_handle = NULL;
    key_handle = NULL;

    scm_handle = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scm_handle == NULL) {
        result = KERNEL32$GetLastError();
        BeaconFormatPrintf(out, "ADVAPI32$OpenSCManagerA failed. (%lu)\n", result);
        return result;
    }

    if (!ADVAPI32$EnumServicesStatusExW(scm_handle, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_ACTIVE, NULL, 0, &bytes_needed, &services_returned, NULL, NULL)) {
        result = KERNEL32$GetLastError();
        if (result != ERROR_MORE_DATA) {
            BeaconFormatPrintf(out, "ADVAPI32$EnumServicesStatusExW failed. (%lu)\n", result);
            ADVAPI32$CloseServiceHandle(scm_handle);
            return result;
        }
    }

    services = (BYTE *)calloc(1, bytes_needed);
    if (services == NULL) {
        BeaconFormatPrintf(out, "Out of memory\n");
        ADVAPI32$CloseServiceHandle(scm_handle);
        return ERROR_OUTOFMEMORY;
    }

    if (!ADVAPI32$EnumServicesStatusExW(scm_handle, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_ACTIVE, services, bytes_needed, &bytes_needed, &services_returned, NULL, NULL)) {
        result = KERNEL32$GetLastError();
        BeaconFormatPrintf(out, "ADVAPI32$EnumServicesStatusExW failed. (%lu)\n", result);
        free(services);
        ADVAPI32$CloseServiceHandle(scm_handle);
        return result;
    }

    for (i = 0; i < services_returned; i++) {
        service = (LPENUM_SERVICE_STATUS_PROCESSW)(services + (i * sizeof(ENUM_SERVICE_STATUS_PROCESSW)));
        MSVCRT$memset(registry_path, 0, sizeof(registry_path));
        MSVCRT$memset(driver_path, 0, sizeof(driver_path));
        MSVCRT$wcscpy(registry_path, L"SYSTEM\\CurrentControlSet\\Services\\");
        MSVCRT$wcscat(registry_path, service->lpServiceName);

        result = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, registry_path, 0, KEY_QUERY_VALUE, &key_handle);
        if (result != ERROR_SUCCESS) {
            BeaconFormatPrintf(out, "ADVAPI32$RegOpenKeyExW failed. (%lu)\n", result);
            continue;
        }

        length = sizeof(driver_path);
        result = ADVAPI32$RegQueryValueExW(key_handle, L"ImagePath", NULL, NULL, (LPBYTE)driver_path, &length);
        if (result != ERROR_SUCCESS) {
            BeaconFormatPrintf(out, "WARNING: Failed to get ImagePath for %S\n", service->lpServiceName);
            result = ERROR_SUCCESS;
        } else if (validate_driver(driver_path, out) != ERROR_SUCCESS) {
            BeaconFormatPrintf(out, "WARNING: validate_driver failed for %S\n", driver_path);
        }

        ADVAPI32$RegCloseKey(key_handle);
        key_handle = NULL;
    }

    free(services);
    ADVAPI32$CloseServiceHandle(scm_handle);
    return ERROR_SUCCESS;
}

do {
    formatp out;
    char *output;
    int output_length;

    BeaconFormatAlloc(&out, 8192);
    if (enumerate_loaded_drivers(&out) != ERROR_SUCCESS) {
        BeaconFormatPrintf(&out, "enumerate_loaded_drivers failed");
    }
    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);
} while (0);
