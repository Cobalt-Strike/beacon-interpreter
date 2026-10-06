#include <windows.h>
#include <file.h>
#include <advapi.h>
#include <wincrypt.h>
#include <beacon.h>

#define TARGET_FILE_PATH "C:\\Windows\\System32\\notepad.exe"

BOOL hash_file(char *path, ALG_ID algorithm, DWORD provider, char *algorithm_name) {
    HCRYPTPROV provider_handle;
    HCRYPTHASH hash_handle;
    HANDLE file_handle;
    DWORD bytes_read;
    BYTE read_buffer[0x512];
    BYTE digest[32];
    char hash_text[128];
    DWORD digest_size;
    DWORD i;

    file_handle = CreateFileA((char *)path, FILE_READ_ACCESS, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if (file_handle == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Error: Could not find file \"%s\"", path);
        return FALSE;
    }

    if (!ADVAPI32$CryptAcquireContextA(&provider_handle, NULL, NULL, provider, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(file_handle);
        BeaconPrintf(CALLBACK_ERROR, "Error: Could not initialize crypto context");
        return FALSE;
    }

    if (!ADVAPI32$CryptCreateHash((void *)provider_handle, algorithm, NULL, 0, &hash_handle)) {
        ADVAPI32$CryptReleaseContext((void *)provider_handle, 0);
        CloseHandle(file_handle);
        BeaconPrintf(CALLBACK_ERROR, "Error: CryptCreateHash failed");
        return FALSE;
    }

    while (ReadFile(file_handle, read_buffer, sizeof(read_buffer), &bytes_read, NULL)) {
        if (bytes_read == 0) {
            break;
        }
        ADVAPI32$CryptHashData((void *)hash_handle, read_buffer, bytes_read, 0);
    }

    digest_size = sizeof(digest);
    hash_text[0] = 0;
    if (ADVAPI32$CryptGetHashParam((void *)hash_handle, HP_HASHVAL, digest, &digest_size, 0)) {
        for (i = 0; i < digest_size; i++) {
            char digits[3];
            sprintf(digits, "%02X", digest[i]);
            strcat(hash_text, digits);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "%s Hash for %s: %s", algorithm_name, path, hash_text);
    }

    ADVAPI32$CryptDestroyHash((void *)hash_handle);
    ADVAPI32$CryptReleaseContext((void *)provider_handle, 0);
    CloseHandle(file_handle);
    return TRUE;
}

do {
    datap parser;
    char *target_file;

    target_file = TARGET_FILE_PATH;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_file = BeaconDataExtract(&parser, NULL);
        if (target_file == NULL || target_file[0] == 0) target_file = TARGET_FILE_PATH;
    }

    hash_file(target_file, CALG_MD5, PROV_RSA_FULL, "MD5");
} while (0);
