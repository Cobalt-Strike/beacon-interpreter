#include <windows.h>
#include <combaseapi.h>
#include <oaidl.h>
#include <oleauto.h>
#include <beacon.h>

#define RPC_E_CHANGED_MODE 0x80010106
#define CLSCTX_ALL 0x17
#define RPC_C_AUTHN_WINNT 10
#define RPC_C_AUTHZ_NONE 0
#define RPC_C_AUTHN_LEVEL_DEFAULT 0
#define RPC_C_IMP_LEVEL_IMPERSONATE 3
#define EOAC_DYNAMIC_CLOAKING 0x40
#define WBEM_INFINITE 0xffffffff
#define WBEM_FLAG_BIDIRECTIONAL 0
#define VARIANT_ALPHABOOL 2

#define WMI_QUERY_LANGUAGE L"WQL"
#define WMI_QUERY_PROCESSES L"SELECT * FROM Win32_Process"
#define WMI_KEYS_PROCESSES L"Name,ProcessId,ParentProcessId,SessionId,CommandLine"
#define RESULTS_OUTPUT_FORMAT "%-32S %10S %16S %10S %-80S\n"

typedef struct _IWbemLocatorVtbl {
    HRESULT (stdcall *QueryInterface)(void *This, REFIID riid, void **ppvObject);
    ULONG (stdcall *AddRef)(void *This);
    ULONG (stdcall *Release)(void *This);
    HRESULT (stdcall *ConnectServer)(void *This, BSTR resource, BSTR user, BSTR password, BSTR locale, LONG flags, BSTR authority, void *context, void **services);
} IWbemLocatorVtbl;

typedef struct _IWbemServicesVtbl {
    HRESULT (stdcall *QueryInterface)(void *This, REFIID riid, void **ppvObject);
    ULONG (stdcall *AddRef)(void *This);
    ULONG (stdcall *Release)(void *This);
    void *OpenNamespace;
    void *CancelAsyncCall;
    void *QueryObjectSink;
    void *GetObject;
    void *GetObjectAsync;
    void *PutClass;
    void *PutClassAsync;
    void *DeleteClass;
    void *DeleteClassAsync;
    void *CreateClassEnum;
    void *CreateClassEnumAsync;
    void *PutInstance;
    void *PutInstanceAsync;
    void *DeleteInstance;
    void *DeleteInstanceAsync;
    void *CreateInstanceEnum;
    void *CreateInstanceEnumAsync;
    HRESULT (stdcall *ExecQuery)(void *This, BSTR language, BSTR query, LONG flags, void *context, void **enumerator);
} IWbemServicesVtbl;

typedef struct _IEnumWbemClassObjectVtbl {
    HRESULT (stdcall *QueryInterface)(void *This, REFIID riid, void **ppvObject);
    ULONG (stdcall *AddRef)(void *This);
    ULONG (stdcall *Release)(void *This);
    HRESULT (stdcall *Reset)(void *This);
    HRESULT (stdcall *Next)(void *This, LONG timeout, ULONG count, void **objects, ULONG *returned);
    void *NextAsync;
    void *Clone;
    void *Skip;
} IEnumWbemClassObjectVtbl;

typedef struct _IWbemClassObjectVtbl {
    HRESULT (stdcall *QueryInterface)(void *This, REFIID riid, void **ppvObject);
    ULONG (stdcall *AddRef)(void *This);
    ULONG (stdcall *Release)(void *This);
    void *GetQualifierSet;
    HRESULT (stdcall *Get)(void *This, LPCWSTR name, LONG flags, VARIANT *value, LONG *type, LONG *flavor);
    void *Put;
    void *Delete;
    HRESULT (stdcall *GetNames)(void *This, LPCWSTR qualifier, LONG flags, VARIANT *qualifier_value, SAFEARRAY **names);
} IWbemClassObjectVtbl;

typedef struct _IWbemLocator {
    IWbemLocatorVtbl *lpVtbl;
} IWbemLocator;

typedef struct _IWbemServices {
    IWbemServicesVtbl *lpVtbl;
} IWbemServices;

typedef struct _IEnumWbemClassObject {
    IEnumWbemClassObjectVtbl *lpVtbl;
} IEnumWbemClassObject;

typedef struct _IWbemClassObject {
    IWbemClassObjectVtbl *lpVtbl;
} IWbemClassObject;

typedef struct _WMI_CONTEXT {
    IWbemLocator *locator;
    IWbemServices *services;
    IEnumWbemClassObject *enumerator;
    BSTR language;
    BSTR query;
} WMI_CONTEXT;

int hresult_failed(HRESULT hr) {
    return hr < 0;
}

void safe_bstr_free(BSTR value) {
    if (value != NULL) {
        OLEAUT32$SysFreeString(value);
    }
}

void release_locator(IWbemLocator *value) {
    if (value != NULL) {
        value->lpVtbl->Release(value);
    }
}

void release_services(IWbemServices *value) {
    if (value != NULL) {
        value->lpVtbl->Release(value);
    }
}

void release_enum(IEnumWbemClassObject *value) {
    if (value != NULL) {
        value->lpVtbl->Release(value);
    }
}

void release_object(IWbemClassObject *value) {
    if (value != NULL) {
        value->lpVtbl->Release(value);
    }
}

void flush_output(formatp *buffer) {
    int output_length;
    char *output;

    output = BeaconFormatToString(buffer, &output_length);
    if (output != NULL && output_length > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatReset(buffer);
}

HRESULT wmi_initialize(WMI_CONTEXT *wmi) {
    HRESULT hr;

    memset(wmi, 0, sizeof(WMI_CONTEXT));
    wmi->language = OLEAUT32$SysAllocString(WMI_QUERY_LANGUAGE);
    if (wmi->language == NULL) {
        return 0x80041006;
    }

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (hr == RPC_E_CHANGED_MODE) {
        hr = S_OK;
    } else if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "OLE32$CoInitializeEx failed: 0x%08lx", hr);
        return hr;
    }

    hr = OLE32$CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_DYNAMIC_CLOAKING, NULL);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to set security, token impersonation may not work\n");
    }

    return S_OK;
}

HRESULT wmi_connect(WMI_CONTEXT *wmi, LPWSTR resource) {
    HRESULT hr;
    GUID clsid_wbem_locator;
    GUID iid_iwbem_locator;
    BSTR bstr_resource;

    clsid_wbem_locator.Data1 = 0x4590F811;
    clsid_wbem_locator.Data2 = 0x1D3A;
    clsid_wbem_locator.Data3 = 0x11D0;
    clsid_wbem_locator.Data4[0] = 0x89;
    clsid_wbem_locator.Data4[1] = 0x1F;
    clsid_wbem_locator.Data4[2] = 0x00;
    clsid_wbem_locator.Data4[3] = 0xAA;
    clsid_wbem_locator.Data4[4] = 0x00;
    clsid_wbem_locator.Data4[5] = 0x4B;
    clsid_wbem_locator.Data4[6] = 0x2E;
    clsid_wbem_locator.Data4[7] = 0x24;

    iid_iwbem_locator.Data1 = 0xDC12A687;
    iid_iwbem_locator.Data2 = 0x737F;
    iid_iwbem_locator.Data3 = 0x11CF;
    iid_iwbem_locator.Data4[0] = 0x88;
    iid_iwbem_locator.Data4[1] = 0x4D;
    iid_iwbem_locator.Data4[2] = 0x00;
    iid_iwbem_locator.Data4[3] = 0xAA;
    iid_iwbem_locator.Data4[4] = 0x00;
    iid_iwbem_locator.Data4[5] = 0x4B;
    iid_iwbem_locator.Data4[6] = 0x2E;
    iid_iwbem_locator.Data4[7] = 0x24;

    bstr_resource = OLEAUT32$SysAllocString(resource);
    if (bstr_resource == NULL) {
        return 0x80041006;
    }

    hr = OLE32$CoCreateInstance(&clsid_wbem_locator, NULL, CLSCTX_ALL, &iid_iwbem_locator, &wmi->locator);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "OLE32$CoCreateInstance failed: 0x%08lx", hr);
        safe_bstr_free(bstr_resource);
        return hr;
    }

    hr = wmi->locator->lpVtbl->ConnectServer(wmi->locator, bstr_resource, NULL, NULL, NULL, 0, NULL, NULL, &wmi->services);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "ConnectServer to %ls failed: 0x%08lx", bstr_resource, hr);
        safe_bstr_free(bstr_resource);
        return hr;
    }

    hr = OLE32$CoSetProxyBlanket(wmi->services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_DYNAMIC_CLOAKING);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "OLE32$CoSetProxyBlanket failed: 0x%08lx", hr);
        safe_bstr_free(bstr_resource);
        return hr;
    }

    safe_bstr_free(bstr_resource);
    return S_OK;
}

HRESULT wmi_query(WMI_CONTEXT *wmi, LPWSTR query) {
    HRESULT hr;

    if (wmi->query != NULL) {
        OLEAUT32$SysFreeString(wmi->query);
        wmi->query = NULL;
    }
    release_enum(wmi->enumerator);
    wmi->enumerator = NULL;

    wmi->query = OLEAUT32$SysAllocString(query);
    if (wmi->query == NULL) {
        return 0x80041006;
    }

    hr = wmi->services->lpVtbl->ExecQuery(wmi->services, wmi->language, wmi->query, WBEM_FLAG_BIDIRECTIONAL, NULL, &wmi->enumerator);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "ExecQuery failed: 0x%08lx", hr);
        release_enum(wmi->enumerator);
        wmi->enumerator = NULL;
        return hr;
    }

    return S_OK;
}

BSTR property_to_bstr(IWbemClassObject *object, BSTR name, formatp *output) {
    HRESULT hr;
    VARIANT value;
    BSTR result;

    OLEAUT32$VariantInit(&value);
    result = NULL;
    hr = object->lpVtbl->Get(object, name, 0, &value, NULL, NULL);
    if (hresult_failed(hr)) {
        BeaconFormatPrintf(output, "[!] Failed to read WMI property %S: 0x%08lx\n", name, hr);
        result = OLEAUT32$SysAllocString(L"*ERROR*");
    } else if (value.vt == VT_EMPTY) {
        result = OLEAUT32$SysAllocString(L"(EMPTY)");
    } else if (value.vt == VT_NULL) {
        result = OLEAUT32$SysAllocString(L"(NULL)");
    } else {
        hr = OLEAUT32$VariantChangeType(&value, &value, VARIANT_ALPHABOOL, VT_BSTR);
        if (hresult_failed(hr)) {
            result = OLEAUT32$SysAllocString(L"*ERROR*");
        } else {
            result = OLEAUT32$SysAllocString(value.bstrVal);
        }
    }
    OLEAUT32$VariantClear(&value);
    return result;
}

void wmi_finalize(WMI_CONTEXT *wmi) {
    release_enum(wmi->enumerator);
    release_services(wmi->services);
    release_locator(wmi->locator);
    safe_bstr_free(wmi->language);
    safe_bstr_free(wmi->query);
    OLE32$CoUninitialize();
}

HRESULT task_list(LPWSTR resource) {
    WMI_CONTEXT wmi;
    HRESULT hr;
    WCHAR keys[128];
    WCHAR *columns[5];
    WCHAR *cursor;
    IWbemClassObject *object;
    ULONG returned;
    BSTR values[5];
    DWORD index;
    formatp output;
    int output_initialized;

    output_initialized = 0;
    hr = wmi_initialize(&wmi);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Wmi_Initialize failed: 0x%08lx", hr);
        return hr;
    }

    hr = wmi_connect(&wmi, resource);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Wmi_Connect failed: 0x%08lx", hr);
        wmi_finalize(&wmi);
        return hr;
    }

    hr = wmi_query(&wmi, WMI_QUERY_PROCESSES);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Wmi_Query failed: 0x%08lx", hr);
        wmi_finalize(&wmi);
        return hr;
    }

    wcscpy(keys, WMI_KEYS_PROCESSES);
    columns[0] = keys;
    index = 1;
    cursor = keys;
    while (*cursor != 0 && index < 5) {
        if (*cursor == L',') {
            *cursor = 0;
            columns[index] = cursor + 1;
            index++;
        }
        cursor++;
    }

    BeaconFormatAlloc(&output, 8192);
    output_initialized = 1;
    BeaconFormatPrintf(&output, RESULTS_OUTPUT_FORMAT, columns[0], columns[1], columns[2], columns[3], columns[4]);

    object = NULL;
    returned = 0;
    hr = wmi.enumerator->lpVtbl->Next(wmi.enumerator, WBEM_INFINITE, 1, &object, &returned);
    while (hr == S_OK && returned > 0) {
        if (object == NULL) {
            hr = wmi.enumerator->lpVtbl->Next(wmi.enumerator, WBEM_INFINITE, 1, &object, &returned);
            continue;
        }
        for (index = 0; index < 5; index++) {
            values[index] = property_to_bstr(object, columns[index], &output);
        }
        if (output.length > 7600) {
            flush_output(&output);
        }
        BeaconFormatPrintf(
            &output,
            RESULTS_OUTPUT_FORMAT,
            values[0] ? values[0] : L"",
            values[1] ? values[1] : L"",
            values[2] ? values[2] : L"",
            values[3] ? values[3] : L"",
            values[4] ? values[4] : L""
        );
        for (index = 0; index < 5; index++) {
            safe_bstr_free(values[index]);
        }
        release_object(object);
        object = NULL;
        returned = 0;
        hr = wmi.enumerator->lpVtbl->Next(wmi.enumerator, WBEM_INFINITE, 1, &object, &returned);
    }

    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Wmi_ParseResults failed: 0x%08lx", hr);
        release_object(object);
        goto cleanup;
    }

    hr = S_OK;

cleanup:
    if (output_initialized) {
        flush_output(&output);
        BeaconFormatFree(&output);
    }
    wmi_finalize(&wmi);
    return hr;
}

datap parser;
LPWSTR resource;
HRESULT hr;

resource = L"\\\\.\\root\\cimv2";
if (__argc > 0) {
    BeaconDataParse(&parser, __argv, __argc);
    resource = (LPWSTR)BeaconDataExtract(&parser, NULL);
    if (resource == NULL || resource[0] == 0) {
        resource = L"\\\\.\\root\\cimv2";
    }
}

hr = task_list(resource);
if (hr != S_OK) {
    BeaconPrintf(CALLBACK_ERROR, "task_list failed: 0x%08lx", hr);
}
