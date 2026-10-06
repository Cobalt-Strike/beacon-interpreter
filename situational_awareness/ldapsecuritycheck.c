#include <windows.h>
#include <beacon.h>
#include <netapi32.h>

#define LDAP_SUCCESS 0
#define LDAP_STRONG_AUTH_REQUIRED 8
#define LDAP_SASL_BIND_IN_PROGRESS 14
#define LDAP_INVALID_CREDENTIALS 49
#define LDAP_VERSION3 3
#define LDAP_OPT_VERSION 0x11
#define LDAP_OPT_SSL 0x0a
#define LDAP_OPT_ERROR_NUMBER 0x31
#define LDAP_OPT_SIGN 0x95
#define LDAP_OPT_ENCRYPT 0x96
#define LDAP_OPT_ON ((void *)1)

#define SEC_E_OK 0
#define SEC_I_CONTINUE_NEEDED 0x00090312
#define SEC_I_COMPLETE_NEEDED 0x00090313
#define SEC_I_COMPLETE_AND_CONTINUE 0x00090314
#define SECPKG_CRED_OUTBOUND 2
#define SECBUFFER_VERSION 0
#define SECBUFFER_TOKEN 2
#define ISC_REQ_DELEGATE 0x00000001
#define ISC_REQ_MUTUAL_AUTH 0x00000002
#define ISC_REQ_ALLOCATE_MEMORY 0x00000100
#define SECURITY_NATIVE_DREP 0x00000010

typedef void LDAP;
typedef LONG SECURITY_STATUS;
typedef WCHAR SEC_WCHAR;

typedef struct _SecHandle {
    ULONG_PTR dwLower;
    ULONG_PTR dwUpper;
} SecHandle, CredHandle, CtxtHandle, *PCredHandle, *PCtxtHandle;

typedef struct _SecBuffer {
    ULONG cbBuffer;
    ULONG BufferType;
    void *pvBuffer;
} SecBuffer, *PSecBuffer;

typedef struct _SecBufferDesc {
    ULONG ulVersion;
    ULONG cBuffers;
    PSecBuffer pBuffers;
} SecBufferDesc, *PSecBufferDesc;

typedef struct _SecurityInteger {
    ULONG LowPart;
    LONG HighPart;
} TimeStamp, *PTimeStamp;

typedef struct berval {
    ULONG bv_len;
    char *bv_val;
} BERVAL, *PBERVAL;

typedef struct _DOMAIN_CONTROLLER_INFOA_SCRIPT {
    LPSTR DomainControllerName;
    LPSTR DomainControllerAddress;
    ULONG DomainControllerAddressType;
    GUID DomainGuid;
    LPSTR DomainName;
    LPSTR DnsForestName;
    ULONG Flags;
    LPSTR DcSiteName;
    LPSTR ClientSiteName;
} DOMAIN_CONTROLLER_INFOA_SCRIPT, *PDOMAIN_CONTROLLER_INFOA_SCRIPT;

WLDAP32$ldap_initW: cdecl ptr (ptr, u32);
WLDAP32$ldap_set_optionW: cdecl u32 (ptr, u32, ptr);
WLDAP32$ldap_get_optionW: cdecl u32 (ptr, u32, ptr);
WLDAP32$ldap_connect: cdecl u32 (ptr, ptr);
WLDAP32$ldap_sasl_bind_sW: cdecl u32 (ptr, ptr, ptr, ptr, ptr, ptr, ptr);
WLDAP32$ldap_unbind_s: cdecl u32 (ptr);
WLDAP32$ber_bvfree: cdecl void (ptr);
SECUR32$AcquireCredentialsHandleW: u32 (ptr, ptr, u32, ptr, ptr, ptr, ptr, ptr, ptr);
SECUR32$InitializeSecurityContextW: u32 (ptr, ptr, ptr, u32, u32, u32, ptr, u32, ptr, ptr, ptr, ptr);
SECUR32$FreeCredentialsHandle: u32 (ptr);
SECUR32$DeleteSecurityContext: u32 (ptr);
SECUR32$FreeContextBuffer: u32 (ptr);
NETAPI32$DsGetDcNameA: u32 (ptr, ptr, ptr, ptr, u32, ptr);

BOOL good_sspi_status(SECURITY_STATUS status) {
    if (status == SEC_E_OK) return TRUE;
    if (status == SEC_I_CONTINUE_NEEDED) return TRUE;
    if (status == SEC_I_COMPLETE_NEEDED) return TRUE;
    if (status == SEC_I_COMPLETE_AND_CONTINUE) return TRUE;
    return FALSE;
}

BOOL check_ldap(WCHAR *dc, WCHAR *spn, BOOL ssl) {
    CredHandle credential;
    CtxtHandle context;
    TimeStamp expiry;
    SecBuffer output_buffer;
    SecBufferDesc output_desc;
    SecBuffer output_buffer2;
    SecBufferDesc output_desc2;
    SecBuffer input_buffer;
    SecBufferDesc input_desc;
    BERVAL cred;
    PBERVAL server_response;
    PSecBuffer ticket;
    LDAP *ldap;
    SECURITY_STATUS security_status;
    ULONG result;
    ULONG ldap_result;
    ULONG context_attr;
    ULONG version;
    int count;
    BOOL credential_acquired;
    BOOL context_initialized;
    BOOL ret;

    MSVCRT$memset(&credential, 0, sizeof(credential));
    MSVCRT$memset(&context, 0, sizeof(context));
    MSVCRT$memset(&expiry, 0, sizeof(expiry));
    MSVCRT$memset(&output_buffer, 0, sizeof(output_buffer));
    MSVCRT$memset(&output_desc, 0, sizeof(output_desc));
    MSVCRT$memset(&output_buffer2, 0, sizeof(output_buffer2));
    MSVCRT$memset(&output_desc2, 0, sizeof(output_desc2));
    MSVCRT$memset(&input_buffer, 0, sizeof(input_buffer));
    MSVCRT$memset(&input_desc, 0, sizeof(input_desc));

    output_buffer.BufferType = SECBUFFER_TOKEN;
    output_desc.ulVersion = SECBUFFER_VERSION;
    output_desc.cBuffers = 1;
    output_desc.pBuffers = &output_buffer;
    output_buffer2.BufferType = SECBUFFER_TOKEN;
    output_desc2.ulVersion = SECBUFFER_VERSION;
    output_desc2.cBuffers = 1;
    output_desc2.pBuffers = &output_buffer2;

    server_response = NULL;
    ticket = NULL;
    ldap = NULL;
    credential_acquired = FALSE;
    context_initialized = FALSE;
    ret = FALSE;
    count = 0;
    version = LDAP_VERSION3;

    security_status = SECUR32$AcquireCredentialsHandleW(NULL, L"NTLM", SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &credential, &expiry);
    if (security_status != SEC_E_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[-] AcquireCredentialsHandleW failed: %d\n", security_status);
        return FALSE;
    }
    credential_acquired = TRUE;

    ldap = WLDAP32$ldap_initW(dc, ssl ? 636 : 389);
    if (ldap == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to establish LDAP connection");
        goto cleanup;
    }

    WLDAP32$ldap_set_optionW(ldap, LDAP_OPT_VERSION, &version);
    if (ssl) {
        result = 0;
        WLDAP32$ldap_get_optionW(ldap, LDAP_OPT_SSL, &result);
        if (result == 0) WLDAP32$ldap_set_optionW(ldap, LDAP_OPT_SSL, LDAP_OPT_ON);
        result = 0;
        WLDAP32$ldap_get_optionW(ldap, LDAP_OPT_SIGN, &result);
        if (result == 0) WLDAP32$ldap_set_optionW(ldap, LDAP_OPT_SIGN, LDAP_OPT_ON);
        result = 0;
        WLDAP32$ldap_get_optionW(ldap, LDAP_OPT_ENCRYPT, &result);
        if (result == 0) WLDAP32$ldap_set_optionW(ldap, LDAP_OPT_ENCRYPT, LDAP_OPT_ON);
    }

    result = WLDAP32$ldap_connect(ldap, NULL);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_connect failed: %lu", result);
        goto cleanup;
    }

    do {
        if (count > 5) {
            BeaconPrintf(CALLBACK_ERROR, "[-] stuck in loop");
            break;
        }
        count++;

        if (server_response == NULL) {
            security_status = SECUR32$InitializeSecurityContextW(
                &credential,
                NULL,
                spn,
                ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_DELEGATE,
                0,
                SECURITY_NATIVE_DREP,
                NULL,
                0,
                &context,
                &output_desc,
                &context_attr,
                &expiry);
            ticket = output_desc.pBuffers;
            context_initialized = TRUE;
        } else {
            input_buffer.cbBuffer = server_response->bv_len;
            input_buffer.BufferType = SECBUFFER_TOKEN;
            input_buffer.pvBuffer = server_response->bv_val;
            input_desc.ulVersion = SECBUFFER_VERSION;
            input_desc.cBuffers = 1;
            input_desc.pBuffers = &input_buffer;
            security_status = SECUR32$InitializeSecurityContextW(
                &credential,
                &context,
                spn,
                ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_DELEGATE,
                0,
                SECURITY_NATIVE_DREP,
                &input_desc,
                0,
                &context,
                &output_desc2,
                &context_attr,
                &expiry);
            ticket = output_desc2.pBuffers;
        }

        if (!good_sspi_status(security_status)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] InitializeSecurityContextW failed: 0x%08x\n", security_status);
            goto cleanup;
        }

        if (ticket == NULL || ticket->pvBuffer == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "[-] InitializeSecurityContextW returned no token: %d\n", security_status);
            goto cleanup;
        }

        cred.bv_len = ticket->cbBuffer;
        cred.bv_val = (char *)ticket->pvBuffer;
        WLDAP32$ldap_sasl_bind_sW(ldap, L"", L"GSSAPI", &cred, NULL, NULL, &server_response);
        ldap_result = 0;
        WLDAP32$ldap_get_optionW(ldap, LDAP_OPT_ERROR_NUMBER, &ldap_result);

        if (server_response == NULL || server_response->bv_val == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "[-] no token back from ldap_sasl_bind_sW");
            goto cleanup;
        }

        if (ssl) {
            if (ldap_result == LDAP_INVALID_CREDENTIALS) {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] LDAPS://%S REQUIRES channel binding (LDAP_INVALID_CREDENTIALS)\n", dc ? dc : L"target");
                ret = TRUE;
                goto cleanup;
            } else if (ldap_result == LDAP_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] LDAPS://%S does NOT require channel binding (bind succeeded)\n", dc ? dc : L"target");
                ret = FALSE;
                goto cleanup;
            } else if (ldap_result == LDAP_SASL_BIND_IN_PROGRESS) {
                continue;
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[-] LDAPS unknown issue (error: %lu)\n", ldap_result);
                goto cleanup;
            }
        } else {
            if (ldap_result == LDAP_STRONG_AUTH_REQUIRED) {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] LDAP://%S REQUIRES signing\n", dc ? dc : L"target");
                ret = TRUE;
                goto cleanup;
            } else if (ldap_result == LDAP_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] LDAP://%S does NOT require signing\n", dc ? dc : L"target");
                ret = FALSE;
                goto cleanup;
            } else if (ldap_result == LDAP_SASL_BIND_IN_PROGRESS) {
                continue;
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[-] LDAP unknown issue (error: %lu)\n", ldap_result);
                goto cleanup;
            }
        }
    } while (ldap_result == LDAP_SASL_BIND_IN_PROGRESS);

cleanup:
    if (server_response != NULL) {
        WLDAP32$ber_bvfree(server_response);
    }
    if (context_initialized) {
        SECUR32$DeleteSecurityContext(&context);
    }
    if (output_desc.pBuffers != NULL && output_desc.pBuffers->pvBuffer != NULL) {
        SECUR32$FreeContextBuffer(output_desc.pBuffers->pvBuffer);
    }
    if (output_desc2.pBuffers != NULL && output_desc2.pBuffers->pvBuffer != NULL) {
        SECUR32$FreeContextBuffer(output_desc2.pBuffers->pvBuffer);
    }
    if (ldap != NULL) {
        WLDAP32$ldap_unbind_s(ldap);
    }
    if (credential_acquired) {
        SECUR32$FreeCredentialsHandle(&credential);
    }
    return ret;
}

do {
    datap parser;
    WCHAR *target_dc;
    WCHAR final_dc[256];
    WCHAR final_spn[256];
    PDOMAIN_CONTROLLER_INFOA_SCRIPT dc_info;
    DWORD status;
    char *dc_name;

    target_dc = NULL;
    dc_info = NULL;
    MSVCRT$memset(final_dc, 0, sizeof(final_dc));
    MSVCRT$memset(final_spn, 0, sizeof(final_spn));

    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_dc = (WCHAR *)BeaconDataExtract(&parser, NULL);
        if (target_dc != NULL && target_dc[0] == 0) {
            target_dc = NULL;
        }
    }

    if (target_dc == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No DC specified, attempting auto-discovery...\n");
        status = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &dc_info);
        if (status == ERROR_SUCCESS && dc_info != NULL) {
            dc_name = dc_info->DomainControllerName;
            if (dc_name != NULL && dc_name[0] == '\\' && dc_name[1] == '\\') {
                dc_name += 2;
            }
            MSVCRT$_snwprintf(final_dc, 256, L"%hs", dc_name);
            final_dc[255] = 0;
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Auto-discovered DC: %S\n", final_dc);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to auto-discover DC (error: %d)\n", status);
            BeaconPrintf(CALLBACK_ERROR, "[-] Please specify DC manually: ldapsecuritycheck <DC>\n");
            break;
        }
    } else {
        MSVCRT$_snwprintf(final_dc, 256, L"%s", target_dc);
        final_dc[255] = 0;
    }

    MSVCRT$_snwprintf(final_spn, 256, L"ldap/%s", final_dc);
    final_spn[255] = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Target DC: %S\n", final_dc);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Target SPN: %S\n", final_spn);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Testing LDAP signing requirements...\n");
    check_ldap(final_dc, final_spn, FALSE);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Testing LDAPS channel binding requirements...\n");
    check_ldap(final_dc, final_spn, TRUE);

    if (dc_info != NULL) {
        NETAPI32$NetApiBufferFree(dc_info);
    }
} while (0);
