#include <windows.h>
#include <combaseapi.h>
#include <oaidl.h>
#include <oleauto.h>
#include <beacon.h>

#define S_FALSE 1
#define RPC_E_CHANGED_MODE 0x80010106

#define NET_FW_IP_PROTOCOL_TCP 6
#define NET_FW_IP_PROTOCOL_UDP 17
#define NET_FW_IP_VERSION_V4 0
#define NET_FW_IP_VERSION_V6 1
#define NET_FW_PROFILE2_DOMAIN 1
#define NET_FW_PROFILE2_PRIVATE 2
#define NET_FW_PROFILE2_PUBLIC 4
#define NET_FW_RULE_DIR_IN 1
#define NET_FW_RULE_DIR_OUT 2
#define NET_FW_ACTION_BLOCK 0
#define NET_FW_ACTION_ALLOW 1
#define OUTPUT_BUFFER_SIZE (1024 * 1024)
#define OUTPUT_FLUSH_THRESHOLD (64 * 1024)

typedef struct IUnknown IUnknown;

typedef struct _IEnumVARIANTVtbl {
    HRESULT (stdcall *QueryInterface)(void *This, REFIID riid, void **ppvObject);
    ULONG (stdcall *AddRef)(void *This);
    ULONG (stdcall *Release)(void *This);
    HRESULT (stdcall *Next)(void *This, ULONG count, VARIANT *values, ULONG *fetched);
    HRESULT (stdcall *Skip)(void *This, ULONG count);
    HRESULT (stdcall *Reset)(void *This);
    HRESULT (stdcall *Clone)(void *This, void **enumerator);
} IEnumVARIANTVtbl;

typedef struct _IEnumVARIANT {
    IEnumVARIANTVtbl *lpVtbl;
} IEnumVARIANT;

typedef struct _INetFwPolicy2Vtbl {
    HRESULT (stdcall *QueryInterface)(void *This, REFIID riid, void **ppvObject);
    ULONG (stdcall *AddRef)(void *This);
    ULONG (stdcall *Release)(void *This);
    void *GetTypeInfoCount;
    void *GetTypeInfo;
    void *GetIDsOfNames;
    void *Invoke;
    void *get_CurrentProfileTypes;
    void *get_FirewallEnabled;
    void *put_FirewallEnabled;
    void *get_ExcludedInterfaces;
    void *put_ExcludedInterfaces;
    void *get_BlockAllInboundTraffic;
    void *put_BlockAllInboundTraffic;
    void *get_NotificationsDisabled;
    void *put_NotificationsDisabled;
    void *get_UnicastResponsesToMulticastBroadcastDisabled;
    void *put_UnicastResponsesToMulticastBroadcastDisabled;
    HRESULT (stdcall *get_Rules)(void *This, void **rules);
} INetFwPolicy2Vtbl;

typedef struct _INetFwRulesVtbl {
    HRESULT (stdcall *QueryInterface)(void *This, REFIID riid, void **ppvObject);
    ULONG (stdcall *AddRef)(void *This);
    ULONG (stdcall *Release)(void *This);
    void *GetTypeInfoCount;
    void *GetTypeInfo;
    void *GetIDsOfNames;
    void *Invoke;
    HRESULT (stdcall *get_Count)(void *This, LONG *count);
    void *Add;
    void *Remove;
    void *Item;
    HRESULT (stdcall *get__NewEnum)(void *This, void **enumerator);
} INetFwRulesVtbl;

typedef struct _INetFwRuleVtbl {
    HRESULT (stdcall *QueryInterface)(void *This, REFIID riid, void **ppvObject);
    ULONG (stdcall *AddRef)(void *This);
    ULONG (stdcall *Release)(void *This);
    void *GetTypeInfoCount;
    void *GetTypeInfo;
    void *GetIDsOfNames;
    void *Invoke;
    HRESULT (stdcall *get_Name)(void *This, BSTR *value);
    void *put_Name;
    HRESULT (stdcall *get_Description)(void *This, BSTR *value);
    void *put_Description;
    HRESULT (stdcall *get_ApplicationName)(void *This, BSTR *value);
    void *put_ApplicationName;
    HRESULT (stdcall *get_ServiceName)(void *This, BSTR *value);
    void *put_ServiceName;
    HRESULT (stdcall *get_Protocol)(void *This, LONG *value);
    void *put_Protocol;
    HRESULT (stdcall *get_LocalPorts)(void *This, BSTR *value);
    void *put_LocalPorts;
    HRESULT (stdcall *get_RemotePorts)(void *This, BSTR *value);
    void *put_RemotePorts;
    HRESULT (stdcall *get_LocalAddresses)(void *This, BSTR *value);
    void *put_LocalAddresses;
    HRESULT (stdcall *get_RemoteAddresses)(void *This, BSTR *value);
    void *put_RemoteAddresses;
    HRESULT (stdcall *get_IcmpTypesAndCodes)(void *This, BSTR *value);
    void *put_IcmpTypesAndCodes;
    HRESULT (stdcall *get_Direction)(void *This, LONG *value);
    void *put_Direction;
    HRESULT (stdcall *get_Interfaces)(void *This, VARIANT *value);
    void *put_Interfaces;
    HRESULT (stdcall *get_InterfaceTypes)(void *This, BSTR *value);
    void *put_InterfaceTypes;
    HRESULT (stdcall *get_Enabled)(void *This, VARIANT_BOOL *value);
    void *put_Enabled;
    HRESULT (stdcall *get_Grouping)(void *This, BSTR *value);
    void *put_Grouping;
    HRESULT (stdcall *get_Profiles)(void *This, LONG *value);
    void *put_Profiles;
    HRESULT (stdcall *get_EdgeTraversal)(void *This, VARIANT_BOOL *value);
    void *put_EdgeTraversal;
    HRESULT (stdcall *get_Action)(void *This, LONG *value);
    void *put_Action;
} INetFwRuleVtbl;

typedef struct _INetFwPolicy2 {
    INetFwPolicy2Vtbl *lpVtbl;
} INetFwPolicy2;

typedef struct _INetFwRules {
    INetFwRulesVtbl *lpVtbl;
} INetFwRules;

typedef struct _INetFwRule {
    INetFwRuleVtbl *lpVtbl;
} INetFwRule;

int hresult_succeeded(HRESULT hr) {
    return hr >= 0;
}

int hresult_failed(HRESULT hr) {
    return hr < 0;
}

void init_policy_guids(GUID *clsid, GUID *iid) {
    clsid->Data1 = 0xE2B3C97F;
    clsid->Data2 = 0x6AE1;
    clsid->Data3 = 0x41AC;
    clsid->Data4[0] = 0x81;
    clsid->Data4[1] = 0x7A;
    clsid->Data4[2] = 0xF6;
    clsid->Data4[3] = 0xF9;
    clsid->Data4[4] = 0x21;
    clsid->Data4[5] = 0x66;
    clsid->Data4[6] = 0xD7;
    clsid->Data4[7] = 0xDD;

    iid->Data1 = 0x98325047;
    iid->Data2 = 0xC671;
    iid->Data3 = 0x4174;
    iid->Data4[0] = 0x8D;
    iid->Data4[1] = 0x81;
    iid->Data4[2] = 0xDE;
    iid->Data4[3] = 0xFC;
    iid->Data4[4] = 0xD3;
    iid->Data4[5] = 0xF0;
    iid->Data4[6] = 0x31;
    iid->Data4[7] = 0x86;
}

void init_enumvariant_iid(GUID *iid) {
    iid->Data1 = 0x00020404;
    iid->Data2 = 0x0000;
    iid->Data3 = 0x0000;
    iid->Data4[0] = 0xC0;
    iid->Data4[1] = 0x00;
    iid->Data4[2] = 0x00;
    iid->Data4[3] = 0x00;
    iid->Data4[4] = 0x00;
    iid->Data4[5] = 0x00;
    iid->Data4[6] = 0x00;
    iid->Data4[7] = 0x46;
}

void init_rule_iid(GUID *iid) {
    iid->Data1 = 0xAF230D27;
    iid->Data2 = 0xBABA;
    iid->Data3 = 0x4E42;
    iid->Data4[0] = 0xAC;
    iid->Data4[1] = 0xED;
    iid->Data4[2] = 0xF5;
    iid->Data4[3] = 0x24;
    iid->Data4[4] = 0xF2;
    iid->Data4[5] = 0x2C;
    iid->Data4[6] = 0xFC;
    iid->Data4[7] = 0xE2;
}

void release_unknown(void *value) {
    IUnknown *unknown;

    if (value != NULL) {
        unknown = (IUnknown *)value;
        unknown->lpVtbl->Release(unknown);
    }
}

void release_enum_variant(IEnumVARIANT *value) {
    if (value != NULL) {
        value->lpVtbl->Release(value);
    }
}

void release_policy(INetFwPolicy2 *value) {
    if (value != NULL) {
        value->lpVtbl->Release(value);
    }
}

void release_rules(INetFwRules *value) {
    if (value != NULL) {
        value->lpVtbl->Release(value);
    }
}

void release_rule(INetFwRule *value) {
    if (value != NULL) {
        value->lpVtbl->Release(value);
    }
}

HRESULT query_enum_variant(void *unknown_value, IEnumVARIANT **enum_out) {
    GUID iid;
    IUnknown *unknown;

    *enum_out = NULL;
    if (unknown_value == NULL) {
        return 1;
    }
    init_enumvariant_iid(&iid);
    unknown = (IUnknown *)unknown_value;
    return unknown->lpVtbl->QueryInterface(unknown, &iid, enum_out);
}

HRESULT query_firewall_rule(void *dispatch, INetFwRule **rule_out) {
    GUID iid;
    IUnknown *unknown;

    *rule_out = NULL;
    if (dispatch == NULL) {
        return 1;
    }
    init_rule_iid(&iid);
    unknown = (IUnknown *)dispatch;
    return unknown->lpVtbl->QueryInterface(unknown, &iid, rule_out);
}

void flush_output(formatp *out) {
    char *output;
    int output_length;

    output = BeaconFormatToString(out, &output_length);
    if (output_length > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
}

void flush_and_reset_output(formatp *out) {
    flush_output(out);
    BeaconFormatReset(out);
}

void print_bstr_property(formatp *out, char *label, BSTR value) {
    BeaconFormatPrintf(out, "%s%S\n", label, value ? value : L"N/A");
}

void print_rule_bstr_property(formatp *out, INetFwRule *rule, char *label, int property_id) {
    BSTR text;
    HRESULT hr;

    text = NULL;
    hr = 1;
    if (property_id == 1) {
        hr = rule->lpVtbl->get_Name(rule, &text);
    } else if (property_id == 2) {
        hr = rule->lpVtbl->get_Description(rule, &text);
    } else if (property_id == 3) {
        hr = rule->lpVtbl->get_ApplicationName(rule, &text);
    } else if (property_id == 4) {
        hr = rule->lpVtbl->get_ServiceName(rule, &text);
    } else if (property_id == 5) {
        hr = rule->lpVtbl->get_LocalPorts(rule, &text);
    } else if (property_id == 6) {
        hr = rule->lpVtbl->get_RemotePorts(rule, &text);
    } else if (property_id == 7) {
        hr = rule->lpVtbl->get_IcmpTypesAndCodes(rule, &text);
    } else if (property_id == 8) {
        hr = rule->lpVtbl->get_LocalAddresses(rule, &text);
    } else if (property_id == 9) {
        hr = rule->lpVtbl->get_RemoteAddresses(rule, &text);
    } else if (property_id == 10) {
        hr = rule->lpVtbl->get_InterfaceTypes(rule, &text);
    } else if (property_id == 11) {
        hr = rule->lpVtbl->get_Grouping(rule, &text);
    }

    if (hresult_succeeded(hr)) {
        print_bstr_property(out, label, text);
    }
}

void print_rule_port_property(formatp *out, INetFwRule *rule, char *label, int remote) {
    BSTR text;
    HRESULT hr;

    text = NULL;
    if (remote) {
        hr = rule->lpVtbl->get_RemotePorts(rule, &text);
    } else {
        hr = rule->lpVtbl->get_LocalPorts(rule, &text);
    }

    if (hresult_succeeded(hr)) {
        print_bstr_property(out, label, text);
    }
}

void print_rule_interfaces(formatp *out, INetFwRule *rule) {
    VARIANT interface_array;
    VARIANT interface_string;
    SAFEARRAY *array;
    SAFEARRAYBOUND *bound;
    LONG index;
    LONG upper;
    HRESULT hr;

    OLEAUT32$VariantInit(&interface_array);
    OLEAUT32$VariantInit(&interface_string);

    hr = rule->lpVtbl->get_Interfaces(rule, &interface_array);
    if (hresult_succeeded(hr) && interface_array.vt != VT_EMPTY && interface_array.parray != NULL) {
        array = interface_array.parray;
        bound = (SAFEARRAYBOUND *)&array->rgsabound;
        upper = (LONG)bound->cElements;
        for (index = bound->lLbound; index < upper; index++) {
            OLEAUT32$VariantInit(&interface_string);
            hr = OLEAUT32$SafeArrayGetElement(array, &index, &interface_string);
            if (hresult_succeeded(hr)) {
                print_bstr_property(out, "Interfaces:       ", interface_string.bstrVal);
            }
        }
    }
}

void dump_rule(formatp *out, INetFwRule *rule) {
    HRESULT hr;
    LONG long_value;
    LONG profile_mask;
    VARIANT_BOOL enabled;

    BeaconFormatPrintf(out, "---------------------------------------------\n");

    print_rule_bstr_property(out, rule, "Name:             ", 1);
    print_rule_bstr_property(out, rule, "Description:      ", 2);
    print_rule_bstr_property(out, rule, "Application Name: ", 3);
    print_rule_bstr_property(out, rule, "Service Name:     ", 4);

    long_value = 0;
    hr = rule->lpVtbl->get_Protocol(rule, &long_value);
    if (hresult_succeeded(hr)) {
        if (long_value == NET_FW_IP_PROTOCOL_TCP) {
            BeaconFormatPrintf(out, "IP Protocol:      TCP\n");
        } else if (long_value == NET_FW_IP_PROTOCOL_UDP) {
            BeaconFormatPrintf(out, "IP Protocol:      UDP\n");
        }

        if (long_value != NET_FW_IP_VERSION_V4 && long_value != NET_FW_IP_VERSION_V6) {
            print_rule_port_property(out, rule, "Local Ports:      ", 0);
            print_rule_port_property(out, rule, "Remote Ports:      ", 1);
        } else {
            print_rule_bstr_property(out, rule, "ICMP TypeCode:      ", 7);
        }
    }

    print_rule_bstr_property(out, rule, "LocalAddresses:   ", 8);
    print_rule_bstr_property(out, rule, "RemoteAddresses:  ", 9);

    profile_mask = 0;
    hr = rule->lpVtbl->get_Profiles(rule, &profile_mask);
    if (hresult_succeeded(hr)) {
        if (profile_mask & NET_FW_PROFILE2_DOMAIN) {
            BeaconFormatPrintf(out, "Profile:  Domain\n");
        }
        if (profile_mask & NET_FW_PROFILE2_PRIVATE) {
            BeaconFormatPrintf(out, "Profile:  Private\n");
        }
        if (profile_mask & NET_FW_PROFILE2_PUBLIC) {
            BeaconFormatPrintf(out, "Profile:  Public\n");
        }
    }

    long_value = 0;
    hr = rule->lpVtbl->get_Direction(rule, &long_value);
    if (hresult_succeeded(hr)) {
        if (long_value == NET_FW_RULE_DIR_IN) {
            BeaconFormatPrintf(out, "Direction:        In\n");
        } else if (long_value == NET_FW_RULE_DIR_OUT) {
            BeaconFormatPrintf(out, "Direction:        Out\n");
        }
    }

    long_value = 0;
    hr = rule->lpVtbl->get_Action(rule, &long_value);
    if (hresult_succeeded(hr)) {
        if (long_value == NET_FW_ACTION_BLOCK) {
            BeaconFormatPrintf(out, "Action:           Block\n");
        } else if (long_value == NET_FW_ACTION_ALLOW) {
            BeaconFormatPrintf(out, "Action:           Allow\n");
        }
    }

    print_rule_interfaces(out, rule);
    print_rule_bstr_property(out, rule, "Interface Types:  ", 10);

    enabled = 0;
    hr = rule->lpVtbl->get_Enabled(rule, &enabled);
    if (hresult_succeeded(hr)) {
        BeaconFormatPrintf(out, "Enabled:          %s\n", enabled ? "TRUE" : "FALSE");
    }

    print_rule_bstr_property(out, rule, "Grouping:         ", 11);

    enabled = 0;
    hr = rule->lpVtbl->get_EdgeTraversal(rule, &enabled);
    if (hresult_succeeded(hr)) {
        BeaconFormatPrintf(out, "Edge Traversal:   %s\n", enabled ? "TRUE" : "FALSE");
    }
}

HRESULT initialize_firewall_policy(formatp *out, INetFwPolicy2 **policy_out) {
    GUID clsid;
    GUID iid;
    HRESULT hr;

    *policy_out = NULL;
    init_policy_guids(&clsid, &iid);
    hr = OLE32$CoCreateInstance(&clsid, NULL, CLSCTX_INPROC_SERVER, &iid, policy_out);
    if (hresult_failed(hr)) {
        BeaconFormatPrintf(out, "CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
    }
    return hr;
}

void list_rules() {
    HRESULT com_hr;
    HRESULT hr;
    INetFwPolicy2 *policy;
    INetFwRules *rules;
    IEnumVARIANT *enumerator;
    INetFwRule *rule;
    void *unknown_enum;
    VARIANT item;
    ULONG fetched;
    LONG count;
    formatp out;

    policy = NULL;
    rules = NULL;
    enumerator = NULL;
    rule = NULL;
    unknown_enum = NULL;
    count = 0;
    BeaconFormatAlloc(&out, OUTPUT_BUFFER_SIZE);

    com_hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (com_hr != RPC_E_CHANGED_MODE && hresult_failed(com_hr)) {
        BeaconFormatPrintf(&out, "CoInitialize failed: 0x%08lx\n", com_hr);
        flush_output(&out);
        BeaconFormatFree(&out);
        return;
    }

    hr = initialize_firewall_policy(&out, &policy);
    if (hresult_failed(hr)) {
        goto cleanup;
    }

    hr = policy->lpVtbl->get_Rules(policy, &rules);
    if (hresult_failed(hr)) {
        BeaconFormatPrintf(&out, "get_Rules failed: 0x%08lx\n", hr);
        goto cleanup;
    }

    hr = rules->lpVtbl->get_Count(rules, &count);
    if (hresult_failed(hr)) {
        BeaconFormatPrintf(&out, "get_Count failed: 0x%08lx\n", hr);
        goto cleanup;
    }
    BeaconFormatPrintf(&out, "The number of rules in the Windows Firewall are %d\n", count);

    hr = rules->lpVtbl->get__NewEnum(rules, &unknown_enum);
    if (hresult_succeeded(hr)) {
        hr = query_enum_variant(unknown_enum, &enumerator);
    }
    release_unknown(unknown_enum);
    unknown_enum = NULL;

    OLEAUT32$VariantInit(&item);
    while (hresult_succeeded(hr) && hr != S_FALSE && enumerator != NULL) {
        OLEAUT32$VariantClear(&item);
        fetched = 0;
        hr = enumerator->lpVtbl->Next(enumerator, 1, &item, &fetched);
        if (hr == S_FALSE || fetched == 0) {
            break;
        }
        if (hresult_succeeded(hr) && item.vt != VT_DISPATCH) {
            hr = OLEAUT32$VariantChangeType(&item, &item, 0, VT_DISPATCH);
        }
        if (hresult_succeeded(hr) && item.pdispVal != NULL) {
            hr = query_firewall_rule(item.pdispVal, &rule);
        }
        if (hresult_succeeded(hr) && rule != NULL) {
            dump_rule(&out, rule);
            if (out.length >= OUTPUT_FLUSH_THRESHOLD) {
                flush_and_reset_output(&out);
            }
            release_rule(rule);
            rule = NULL;
        }
    }
    OLEAUT32$VariantClear(&item);

cleanup:
    release_rule(rule);
    release_enum_variant(enumerator);
    release_rules(rules);
    release_policy(policy);
    if (com_hr == S_OK) {
        OLE32$CoUninitialize();
    }
    flush_output(&out);
    BeaconFormatFree(&out);
}

list_rules();
