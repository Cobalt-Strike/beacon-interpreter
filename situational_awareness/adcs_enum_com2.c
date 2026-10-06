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

WLDAP32$ldap_initA: cdecl ptr (ptr, u32);
WLDAP32$ldap_set_optionA: cdecl u32 (ptr, u32, ptr);
WLDAP32$ldap_bind_sA: cdecl u32 (ptr, ptr, ptr, u32);
WLDAP32$ldap_search_sA: cdecl u32 (ptr, ptr, u32, ptr, ptr, u32, ptr);
WLDAP32$ldap_count_entries: cdecl u32 (ptr, ptr);
WLDAP32$ldap_first_entry: cdecl ptr (ptr, ptr);
WLDAP32$ldap_next_entry: cdecl ptr (ptr, ptr);
WLDAP32$ldap_get_dnA: cdecl cstr (ptr, ptr);
WLDAP32$ldap_memfreeA: cdecl void (ptr);
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

datap parser;
char *host;
char *base_dn;
LDAP *ld;
LDAPMessage *results;
LDAPMessage *entry;
char *dn;
ULONG version;
ULONG status;
ULONG entry_count;
int explicit_target;
int success;
formatp out;

host = NULL;
base_dn = "";
explicit_target = 0;
success = 1;
if (__argc > 0) {
    BeaconDataParse(&parser, __argv, __argc);
    host = BeaconDataExtract(&parser, NULL);
    base_dn = BeaconDataExtract(&parser, NULL);
    if (host != NULL && host[0] == 0) {
        host = NULL;
    } else if (host != NULL) {
        explicit_target = 1;
    }
    if (base_dn == NULL) {
        base_dn = "";
    } else if (base_dn[0] != 0) {
        explicit_target = 1;
    }
}

ld = WLDAP32$ldap_initA(host, LDAP_PORT);
if (ld == NULL) {
    if (explicit_target) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_initA failed.");
        success = 0;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Found 0 certificate templates");
    }
} else {
    version = LDAP_VERSION3;
    WLDAP32$ldap_set_optionA(ld, LDAP_OPT_VERSION, &version);
    status = WLDAP32$ldap_bind_sA(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (status != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_bind_sA failed: %lu", status);
        success = 0;
    } else {
        status = WLDAP32$ldap_search_sA(ld, base_dn, LDAP_SCOPE_SUBTREE, "(objectClass=pKICertificateTemplate)", NULL, 0, &results);
        if (status != LDAP_SUCCESS || results == NULL) {
            if (explicit_target) {
                BeaconPrintf(CALLBACK_ERROR, "ADCS certificate template LDAP search failed: %lu", status);
                success = 0;
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Found 0 certificate templates");
            }
        } else {
            entry_count = WLDAP32$ldap_count_entries(ld, results);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Found %lu certificate templates", entry_count);
            BeaconFormatAlloc(&out, OUTPUT_BUFFER_SIZE);
            entry = WLDAP32$ldap_first_entry(ld, results);
            while (entry != NULL) {
                dn = WLDAP32$ldap_get_dnA(ld, entry);
                BeaconFormatPrintf(&out, "ADCS Certificate Template: %s\n", dn ? dn : "");
                if (dn != NULL) WLDAP32$ldap_memfreeA(dn);
                if (out.length >= OUTPUT_FLUSH_THRESHOLD) {
                    flush_output(&out);
                }
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
    BeaconPrintf(CALLBACK_OUTPUT, "\nadcs_enum_com2 SUCCESS.");
}
