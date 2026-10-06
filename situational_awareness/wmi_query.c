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
#define WBEM_FLAG_ALWAYS 0
#define WBEM_FLAG_NONSYSTEM_ONLY 0x40
#define VARIANT_ALPHABOOL 2

#define WMI_QUERY_LANGUAGE L"WQL"
#define DEFAULT_NAMESPACE L"root\\cimv2"
#define DEFAULT_QUERY L"select * from win32_process"
#define OUTPUT_BUFFER_SIZE (1024 * 1024)
#define OUTPUT_FLUSH_THRESHOLD (64 * 1024)

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

HRESULT wmi_exec_query(WMI_CONTEXT *wmi, LPWSTR query) {
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

void flush_output(formatp *output_buffer) {
    char *output;
    int output_length;

    output = BeaconFormatToString(output_buffer, &output_length);
    if (output != NULL && output_length > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatReset(output_buffer);
}

void append_bstr_row(formatp *output, BSTR *values, DWORD count) {
    DWORD index;

    for (index = 0; index < count; index++) {
        if (index > 0) {
            BeaconFormatPrintf(output, ", ");
        }
        BeaconFormatPrintf(output, "%S", values[index] ? values[index] : L"(NULL)");
    }
    BeaconFormatPrintf(output, "\n");
}

HRESULT collect_columns(WMI_CONTEXT *wmi, BSTR **columns_out, DWORD *column_count_out, formatp *output) {
    HRESULT hr;
    IWbemClassObject *object;
    ULONG returned;
    SAFEARRAY *properties;
    LONG lower;
    LONG upper;
    LONG index;
    BSTR current_name;
    BSTR *columns;
    BSTR *new_columns;
    DWORD column_count;
    VARIANT value;

    object = NULL;
    returned = 0;
    properties = NULL;
    columns = NULL;
    column_count = 0;

    hr = wmi->enumerator->lpVtbl->Next(wmi->enumerator, WBEM_INFINITE, 1, &object, &returned);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "pEnumerator->Next failed: 0x%08lx", hr);
        return hr;
    }
    if (returned == 0 || object == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "No results");
        return 1;
    }

    hr = object->lpVtbl->GetNames(object, NULL, WBEM_FLAG_ALWAYS | WBEM_FLAG_NONSYSTEM_ONLY, NULL, &properties);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "pWbemClassObjectResult->GetNames failed: 0x%08lx", hr);
        release_object(object);
        return hr;
    }

    hr = OLEAUT32$SafeArrayGetLBound(properties, 1, &lower);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "OLEAUT32$SafeArrayGetLBound failed: 0x%08lx", hr);
        OLEAUT32$SafeArrayDestroy(properties);
        release_object(object);
        return hr;
    }

    hr = OLEAUT32$SafeArrayGetUBound(properties, 1, &upper);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "OLEAUT32$SafeArrayGetUBound failed: 0x%08lx", hr);
        OLEAUT32$SafeArrayDestroy(properties);
        release_object(object);
        return hr;
    }

    for (index = lower; index <= upper; index++) {
        current_name = NULL;
        hr = OLEAUT32$SafeArrayGetElement(properties, &index, &current_name);
        if (hresult_failed(hr)) {
            BeaconFormatPrintf(output, "[!] SafeArrayGetElement(%ld) failed: 0x%08lx\n", index, hr);
            continue;
        }

        OLEAUT32$VariantInit(&value);
        hr = object->lpVtbl->Get(object, current_name, 0, &value, NULL, NULL);
        if (hresult_failed(hr)) {
            BeaconFormatPrintf(output, "[!] Failed to inspect WMI property %S: 0x%08lx\n", current_name, hr);
            OLEAUT32$VariantClear(&value);
            safe_bstr_free(current_name);
            continue;
        }

        if ((value.vt & VT_BYREF) != 0) {
            BeaconFormatPrintf(output, "%S is a reference, so skip\n", current_name);
            safe_bstr_free(current_name);
        } else {
            new_columns = (BSTR *)realloc(columns, sizeof(BSTR) * (column_count + 1));
            if (new_columns == NULL) {
                OLEAUT32$VariantClear(&value);
                safe_bstr_free(current_name);
                OLEAUT32$SafeArrayDestroy(properties);
                release_object(object);
                free(columns);
                return 0x80041006;
            }
            columns = new_columns;
            columns[column_count] = current_name;
            column_count++;
        }
        OLEAUT32$VariantClear(&value);
    }

    OLEAUT32$SafeArrayDestroy(properties);
    release_object(object);

    hr = wmi->enumerator->lpVtbl->Reset(wmi->enumerator);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Reset failed: 0x%08lx", hr);
        for (index = 0; index < (LONG)column_count; index++) {
            safe_bstr_free(columns[index]);
        }
        free(columns);
        return hr;
    }

    *columns_out = columns;
    *column_count_out = column_count;
    return S_OK;
}

void free_columns(BSTR *columns, DWORD count) {
    DWORD index;

    if (columns == NULL) {
        return;
    }
    for (index = 0; index < count; index++) {
        safe_bstr_free(columns[index]);
    }
    free(columns);
}

void wmi_finalize(WMI_CONTEXT *wmi) {
    release_enum(wmi->enumerator);
    release_services(wmi->services);
    release_locator(wmi->locator);
    safe_bstr_free(wmi->language);
    safe_bstr_free(wmi->query);
    OLE32$CoUninitialize();
}

void run_wmi_query(LPWSTR resource, LPWSTR query) {
    WMI_CONTEXT wmi;
    HRESULT hr;
    BSTR *columns;
    DWORD column_count;
    IWbemClassObject *object;
    ULONG returned;
    BSTR *values;
    DWORD index;
    formatp output;

    columns = NULL;
    values = NULL;
    column_count = 0;

    hr = wmi_initialize(&wmi);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Wmi_Initialize failed: 0x%08lx", hr);
        return;
    }

    hr = wmi_connect(&wmi, resource);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Wmi_Connect failed: 0x%08lx", hr);
        wmi_finalize(&wmi);
        return;
    }

    hr = wmi_exec_query(&wmi, query);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Wmi_Query failed: 0x%08lx", hr);
        wmi_finalize(&wmi);
        return;
    }

    BeaconFormatAlloc(&output, OUTPUT_BUFFER_SIZE);
    hr = collect_columns(&wmi, &columns, &column_count, &output);
    if (hresult_failed(hr) || column_count == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Wmi_ParseAllResults failed: 0x%08lx", hr);
        flush_output(&output);
        BeaconFormatFree(&output);
        free_columns(columns, column_count);
        wmi_finalize(&wmi);
        return;
    }

    values = (BSTR *)calloc(column_count, sizeof(BSTR));
    if (values == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Allocation failed for WMI row.");
        flush_output(&output);
        BeaconFormatFree(&output);
        free_columns(columns, column_count);
        wmi_finalize(&wmi);
        return;
    }

    append_bstr_row(&output, columns, column_count);

    object = NULL;
    returned = 0;
    while (wmi.enumerator->lpVtbl->Next(wmi.enumerator, WBEM_INFINITE, 1, &object, &returned) == S_OK && returned > 0) {
        for (index = 0; index < column_count; index++) {
            values[index] = property_to_bstr(object, columns[index], &output);
        }
        append_bstr_row(&output, values, column_count);
        if (output.length >= OUTPUT_FLUSH_THRESHOLD) {
            flush_output(&output);
        }
        for (index = 0; index < column_count; index++) {
            safe_bstr_free(values[index]);
            values[index] = NULL;
        }
        release_object(object);
        object = NULL;
        returned = 0;
    }

    flush_output(&output);
    BeaconFormatFree(&output);
    free(values);
    free_columns(columns, column_count);
    wmi_finalize(&wmi);
}

datap parser;
LPWSTR system_name;
LPWSTR namespace_name;
LPWSTR query;
LPWSTR resource;
WCHAR resource_buffer[512];

system_name = L".";
namespace_name = DEFAULT_NAMESPACE;
query = DEFAULT_QUERY;
resource = L"\\\\.\\root\\cimv2";

if (__argc > 0) {
    BeaconDataParse(&parser, __argv, __argc);
    system_name = (LPWSTR)BeaconDataExtract(&parser, NULL);
    namespace_name = (LPWSTR)BeaconDataExtract(&parser, NULL);
    query = (LPWSTR)BeaconDataExtract(&parser, NULL);
    resource = (LPWSTR)BeaconDataExtract(&parser, NULL);

    if (system_name == NULL || system_name[0] == 0) {
        system_name = L".";
    }
    if (namespace_name == NULL || namespace_name[0] == 0) {
        namespace_name = DEFAULT_NAMESPACE;
    }
    if (query == NULL || query[0] == 0) {
        query = DEFAULT_QUERY;
    }
    if (resource == NULL || resource[0] == 0) {
        _snwprintf(resource_buffer, 512, L"\\\\%ls\\%ls", system_name, namespace_name);
        resource = resource_buffer;
    }
}

run_wmi_query(resource, query);
