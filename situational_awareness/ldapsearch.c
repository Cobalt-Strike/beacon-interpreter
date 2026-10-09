#include <windows.h>
#include <beacon.h>

#define LDAP_SUCCESS 0
#define LDAP_PORT 389
#define LDAPS_PORT 636
#define LDAP_VERSION3 3
#define LDAP_AUTH_NEGOTIATE 0x0486
#define LDAP_SCOPE_BASE 0
#define LDAP_SCOPE_ONELEVEL 1
#define LDAP_SCOPE_SUBTREE 2
#define LDAP_OPT_VERSION 0x11

#define MAX_ATTRS 32
#define MAX_RESULTS 100
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

char *attrs[MAX_ATTRS];
datap parser;
char *host;
char *base_dn;
char *filter;
char *attr_text;
ULONG max_results;
ULONG scope;
ULONG scope_arg;
ULONG ldaps;
LDAP *ld;
LDAPMessage *results;
LDAPMessage *entry;
BerElement *ber;
char *dn;
char *attr;
char **values;
char **value_cursor;
ULONG version;
ULONG status;
ULONG count;
ULONG shown;
int attr_count;
char *token;
formatp out;

host = NULL;
base_dn = "";
filter = "(objectClass=*)";
attr_text = NULL;
max_results = 25;
scope = LDAP_SCOPE_SUBTREE;
ldaps = 0;

if (__argc > 0) {
    BeaconDataParse(&parser, __argv, __argc);
    filter = BeaconDataExtract(&parser, NULL);
    attr_text = BeaconDataExtract(&parser, NULL);
    max_results = BeaconDataInt(&parser);
    scope_arg = BeaconDataInt(&parser);
    host = BeaconDataExtract(&parser, NULL);
    base_dn = BeaconDataExtract(&parser, NULL);
    ldaps = BeaconDataInt(&parser);
    if (host != NULL && host[0] == 0) host = NULL;
    if (base_dn == NULL) base_dn = "";
    if (filter == NULL || filter[0] == 0) filter = "(objectClass=*)";
    if (attr_text != NULL && attr_text[0] == 0) attr_text = NULL;
    if (scope_arg == 1) scope = LDAP_SCOPE_BASE;
    else if (scope_arg == 2) scope = LDAP_SCOPE_ONELEVEL;
    else scope = LDAP_SCOPE_SUBTREE;
}

attr_count = 0;
if (attr_text != NULL) {
    token = strtok(attr_text, ",");
    while (token != NULL && attr_count < (MAX_ATTRS - 1)) {
        attrs[attr_count] = token;
        attr_count++;
        token = strtok(NULL, ",");
    }
}
attrs[attr_count] = NULL;

ld = WLDAP32$ldap_initA(host, ldaps ? LDAPS_PORT : LDAP_PORT);
if (ld == NULL) {
    BeaconPrintf(CALLBACK_ERROR, "ldap_initA failed.");
} else {
    version = LDAP_VERSION3;
    WLDAP32$ldap_set_optionA(ld, LDAP_OPT_VERSION, &version);
    status = WLDAP32$ldap_bind_sA(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (status != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_bind_sA failed: %lu", status);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Base DN: %s", base_dn);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Filter: %s", filter);
        results = NULL;
        status = WLDAP32$ldap_search_sA(ld, base_dn, scope, filter, attr_count ? attrs : NULL, 0, &results);
        if (status != LDAP_SUCCESS || results == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "ldap_search_sA failed: %lu", status);
        } else {
            count = WLDAP32$ldap_count_entries(ld, results);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Result count: %lu", count);
            BeaconFormatAlloc(&out, OUTPUT_BUFFER_SIZE);
            shown = 0;
            entry = WLDAP32$ldap_first_entry(ld, results);
            while (entry != NULL && (max_results == 0 || shown < max_results)) {
                dn = WLDAP32$ldap_get_dnA(ld, entry);
                BeaconFormatPrintf(&out, "--------------------\n");
                BeaconFormatPrintf(&out, "dn: %s\n", dn ? dn : "");
                if (dn != NULL) WLDAP32$ldap_memfreeA(dn);

                ber = NULL;
                attr = WLDAP32$ldap_first_attributeA(ld, entry, &ber);
                while (attr != NULL) {
                    values = (char **)WLDAP32$ldap_get_valuesA(ld, entry, attr);
                    value_cursor = values;
                    while (value_cursor != NULL && *value_cursor != NULL) {
                        BeaconFormatPrintf(&out, "%s: %s\n", attr, *value_cursor);
                        if (out.length >= OUTPUT_FLUSH_THRESHOLD) {
                            flush_output(&out);
                        }
                        value_cursor++;
                    }
                    if (values != NULL) WLDAP32$ldap_value_freeA(values);
                    WLDAP32$ldap_memfreeA(attr);
                    attr = WLDAP32$ldap_next_attributeA(ld, entry, ber);
                }
                if (ber != NULL) WLDAP32$ber_free(ber, 0);
                shown++;
                entry = WLDAP32$ldap_next_entry(ld, entry);
            }
            flush_output(&out);
            BeaconFormatFree(&out);
            WLDAP32$ldap_msgfree(results);
        }
    }
    WLDAP32$ldap_unbind(ld);
}
