#include <windows.h>
#include <beacon.h>

#define LDAP_SUCCESS 0
#define LDAP_PORT 389
#define LDAP_VERSION3 3
#define LDAP_AUTH_NEGOTIATE 0x0486
#define LDAP_SCOPE_SUBTREE 2
#define LDAP_OPT_VERSION 0x11
#define OUTPUT_BUFFER_SIZE (1024 * 1024)
#define OUTPUT_FLUSH_THRESHOLD (64 * 1024)

typedef void LDAP;
typedef void LDAPMessage;
typedef void BerElement;

WLDAP32$ldap_initA: cdecl ptr (ptr, u32);
WLDAP32$ldap_set_optionA: cdecl u32 (ptr, u32, ptr);
WLDAP32$ldap_bind_sA: cdecl u32 (ptr, ptr, ptr, u32);
WLDAP32$ldap_search_sA: cdecl u32 (ptr, ptr, u32, ptr, ptr, u32, ptr);
WLDAP32$ldap_count_entries: cdecl u32 (ptr, ptr);
WLDAP32$ldap_first_entry: cdecl ptr (ptr, ptr);
WLDAP32$ldap_next_entry: cdecl ptr (ptr, ptr);
WLDAP32$ldap_get_dnA: cdecl cstr (ptr, ptr);
WLDAP32$ldap_first_attributeA: cdecl cstr (ptr, ptr, ptr);
WLDAP32$ldap_next_attributeA: cdecl cstr (ptr, ptr, ptr);
WLDAP32$ldap_get_valuesA: cdecl ptr (ptr, ptr, cstr);
WLDAP32$ldap_value_freeA: cdecl u32 (ptr);
WLDAP32$ldap_memfreeA: cdecl void (ptr);
WLDAP32$ber_free: cdecl void (ptr, i32);
WLDAP32$ldap_msgfree: cdecl u32 (ptr);
WLDAP32$ldap_unbind: cdecl u32 (ptr);

void flush_output(formatp *out) {
    char *output;
    int output_length;

    output = BeaconFormatToString(out, &output_length);
    if (output != NULL && output_length > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatReset(out);
}

char *wide_to_utf8(WCHAR *input) {
    int length;
    char *buffer;

    if (input == NULL || input[0] == 0) {
        return NULL;
    }

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

char *domain_to_config_base(char *domain) {
    char *buffer;
    char *out;
    char *cursor;

    if (domain == NULL || domain[0] == 0) {
        return NULL;
    }

    buffer = (char *)LocalAlloc(0x0040, 1024);
    if (buffer == NULL) {
        return NULL;
    }

    strcpy(buffer, "CN=Configuration");
    out = buffer + strlen(buffer);
    cursor = domain;
    while (*cursor != 0 && (out - buffer) < 1010) {
        *out++ = ',';
        *out++ = 'D';
        *out++ = 'C';
        *out++ = '=';
        while (*cursor != 0 && *cursor != '.' && (out - buffer) < 1022) {
            *out++ = *cursor++;
        }
        if (*cursor == '.') {
            cursor++;
        }
    }
    *out = 0;
    return buffer;
}

char *attrs[5] = { "cn", "dNSHostName", "certificateTemplates", "cACertificateDN", NULL };
datap parser;
char *host;
char *base_dn;
char *domain;
char *config_base;
LPWSTR domain_arg;
LDAP *ld;
LDAPMessage *results;
LDAPMessage *entry;
BerElement *ber;
char *dn;
char *attr;
char **values;
char **cursor;
ULONG version;
ULONG status;
ULONG entry_count;
int explicit_domain;
int success;
formatp out;

host = NULL;
base_dn = "";
domain = NULL;
config_base = NULL;
explicit_domain = 0;
success = 1;
if (__argc > 0) {
    BeaconDataParse(&parser, __argv, __argc);
    domain_arg = (LPWSTR)BeaconDataExtract(&parser, NULL);
    domain = wide_to_utf8(domain_arg);
    if (domain != NULL && domain[0] != 0) {
        explicit_domain = 1;
        config_base = domain_to_config_base(domain);
        if (config_base != NULL) {
            base_dn = config_base;
        }
    }
}

ld = WLDAP32$ldap_initA(host, LDAP_PORT);
    if (ld == NULL) {
    if (explicit_domain) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_initA failed.");
        success = 0;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Found 0 CAs in the domain");
    }
} else {
    version = LDAP_VERSION3;
    WLDAP32$ldap_set_optionA(ld, LDAP_OPT_VERSION, &version);
    status = WLDAP32$ldap_bind_sA(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (status != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_bind_sA failed: %lu", status);
        success = 0;
    } else {
        status = WLDAP32$ldap_search_sA(ld, base_dn, LDAP_SCOPE_SUBTREE, "(objectClass=pKIEnrollmentService)", attrs, 0, &results);
        if (status != LDAP_SUCCESS || results == NULL) {
            if (explicit_domain) {
                BeaconPrintf(CALLBACK_ERROR, "ADCS LDAP search failed: %lu", status);
                success = 0;
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Found 0 CAs in the domain");
            }
        } else {
            entry_count = WLDAP32$ldap_count_entries(ld, results);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Found %lu CAs in the domain", entry_count);
            BeaconFormatAlloc(&out, OUTPUT_BUFFER_SIZE);
            entry = WLDAP32$ldap_first_entry(ld, results);
            while (entry != NULL) {
                dn = WLDAP32$ldap_get_dnA(ld, entry);
                BeaconFormatPrintf(&out, "--------------------\n");
                BeaconFormatPrintf(&out, "CA DN: %s\n", dn ? dn : "");
                if (dn != NULL) WLDAP32$ldap_memfreeA(dn);
                ber = NULL;
                attr = WLDAP32$ldap_first_attributeA(ld, entry, &ber);
                while (attr != NULL) {
                    values = (char **)WLDAP32$ldap_get_valuesA(ld, entry, attr);
                    cursor = values;
                    while (cursor != NULL && *cursor != NULL) {
                        BeaconFormatPrintf(&out, "%s: %s\n", attr, *cursor);
                        if (out.length >= OUTPUT_FLUSH_THRESHOLD) {
                            flush_output(&out);
                        }
                        cursor++;
                    }
                    if (values != NULL) WLDAP32$ldap_value_freeA(values);
                    WLDAP32$ldap_memfreeA(attr);
                    attr = WLDAP32$ldap_next_attributeA(ld, entry, ber);
                }
                if (ber != NULL) WLDAP32$ber_free(ber, 0);
                entry = WLDAP32$ldap_next_entry(ld, entry);
            }
            flush_output(&out);
            BeaconFormatFree(&out);
            WLDAP32$ldap_msgfree(results);
        }
    }
    WLDAP32$ldap_unbind(ld);
}
if (success) {
    BeaconPrintf(CALLBACK_OUTPUT, "\nadcs_enum SUCCESS.");
}
if (config_base != NULL) {
    LocalFree(config_base);
}
if (domain != NULL) {
    LocalFree(domain);
}
