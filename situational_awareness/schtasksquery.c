#include <windows.h>
#include <combaseapi.h>
#include <oaidl.h>
#include <oleauto.h>
#include <beacon.h>

#define RPC_E_CHANGED_MODE 0x80010106
#define DISPATCH_METHOD 0x1
#define TASK_STATE_UNKNOWN 0
#define TASK_STATE_DISABLED 1
#define TASK_STATE_QUEUED 2
#define TASK_STATE_READY 3
#define TASK_STATE_RUNNING 4

typedef struct _ITaskServiceVtbl {
    HRESULT (stdcall *QueryInterface)(void *This, REFIID riid, void **ppvObject);
    ULONG (stdcall *AddRef)(void *This);
    ULONG (stdcall *Release)(void *This);
    HRESULT (stdcall *GetTypeInfoCount)(void *This, UINT *pctinfo);
    HRESULT (stdcall *GetTypeInfo)(void *This, UINT iTInfo, LCID lcid, void **ppTInfo);
    HRESULT (stdcall *GetIDsOfNames)(void *This, REFIID riid, LPOLESTR *names, UINT count, LCID lcid, DISPID *dispids);
    HRESULT (stdcall *Invoke)(void *This, DISPID dispid, REFIID riid, LCID lcid, WORD flags, DISPPARAMS *params, VARIANT *result, void *excepinfo, UINT *argerr);
    HRESULT (stdcall *GetFolder)(void *This, BSTR path, void **folder);
    void *GetRunningTasks;
    void *NewTask;
    void *Connect;
    void *get_Connected;
    void *get_TargetServer;
    void *get_ConnectedUser;
    void *get_ConnectedDomain;
    void *get_HighestVersion;
} ITaskServiceVtbl;

typedef struct _ITaskFolderVtbl {
    HRESULT (stdcall *QueryInterface)(void *This, REFIID riid, void **ppvObject);
    ULONG (stdcall *AddRef)(void *This);
    ULONG (stdcall *Release)(void *This);
    HRESULT (stdcall *GetTypeInfoCount)(void *This, UINT *pctinfo);
    HRESULT (stdcall *GetTypeInfo)(void *This, UINT iTInfo, LCID lcid, void **ppTInfo);
    HRESULT (stdcall *GetIDsOfNames)(void *This, REFIID riid, LPOLESTR *names, UINT count, LCID lcid, DISPID *dispids);
    HRESULT (stdcall *Invoke)(void *This, DISPID dispid, REFIID riid, LCID lcid, WORD flags, DISPPARAMS *params, VARIANT *result, void *excepinfo, UINT *argerr);
    void *get_Name;
    void *get_Path;
    void *GetFolder;
    void *GetFolders;
    void *CreateFolder;
    void *DeleteFolder;
    HRESULT (stdcall *GetTask)(void *This, BSTR path, void **task);
} ITaskFolderVtbl;

typedef struct _IRegisteredTaskVtbl {
    HRESULT (stdcall *QueryInterface)(void *This, REFIID riid, void **ppvObject);
    ULONG (stdcall *AddRef)(void *This);
    ULONG (stdcall *Release)(void *This);
    HRESULT (stdcall *GetTypeInfoCount)(void *This, UINT *pctinfo);
    HRESULT (stdcall *GetTypeInfo)(void *This, UINT iTInfo, LCID lcid, void **ppTInfo);
    HRESULT (stdcall *GetIDsOfNames)(void *This, REFIID riid, LPOLESTR *names, UINT count, LCID lcid, DISPID *dispids);
    HRESULT (stdcall *Invoke)(void *This, DISPID dispid, REFIID riid, LCID lcid, WORD flags, DISPPARAMS *params, VARIANT *result, void *excepinfo, UINT *argerr);
    HRESULT (stdcall *get_Name)(void *This, BSTR *name);
    HRESULT (stdcall *get_Path)(void *This, BSTR *path);
    HRESULT (stdcall *get_State)(void *This, LONG *state);
    HRESULT (stdcall *get_Enabled)(void *This, VARIANT_BOOL *enabled);
    void *put_Enabled;
    void *Run;
    void *RunEx;
    void *GetInstances;
    HRESULT (stdcall *get_LastRunTime)(void *This, DWORD64 *date);
    void *get_LastTaskResult;
    void *get_NumberOfMissedRuns;
    HRESULT (stdcall *get_NextRunTime)(void *This, DWORD64 *date);
    void *get_Definition;
    HRESULT (stdcall *get_Xml)(void *This, BSTR *xml);
} IRegisteredTaskVtbl;

typedef struct _ITaskService {
    ITaskServiceVtbl *lpVtbl;
} ITaskService;

typedef struct _ITaskFolder {
    ITaskFolderVtbl *lpVtbl;
} ITaskFolder;

typedef struct _IRegisteredTask {
    IRegisteredTaskVtbl *lpVtbl;
} IRegisteredTask;

void init_iid_null(GUID *iid) {
    memset(iid, 0, sizeof(GUID));
}

void init_task_guids(GUID *clsid, GUID *iid) {
    clsid->Data1 = 0x0f87369f;
    clsid->Data2 = 0xa4e5;
    clsid->Data3 = 0x4cfc;
    clsid->Data4[0] = 0xbd;
    clsid->Data4[1] = 0x3e;
    clsid->Data4[2] = 0x73;
    clsid->Data4[3] = 0xe6;
    clsid->Data4[4] = 0x15;
    clsid->Data4[5] = 0x45;
    clsid->Data4[6] = 0x72;
    clsid->Data4[7] = 0xdd;

    iid->Data1 = 0x2faba4c7;
    iid->Data2 = 0x4da9;
    iid->Data3 = 0x4013;
    iid->Data4[0] = 0x96;
    iid->Data4[1] = 0x97;
    iid->Data4[2] = 0x20;
    iid->Data4[3] = 0xcc;
    iid->Data4[4] = 0x3f;
    iid->Data4[5] = 0xd4;
    iid->Data4[6] = 0x0f;
    iid->Data4[7] = 0x85;
}

char *task_state_name(LONG state) {
    if (state == TASK_STATE_DISABLED) return "DISABLED";
    if (state == TASK_STATE_QUEUED) return "QUEUED";
    if (state == TASK_STATE_READY) return "READY";
    if (state == TASK_STATE_RUNNING) return "RUNNING";
    return "UNKNOWN";
}

int hresult_succeeded(HRESULT hr) {
    return hr >= 0;
}

int hresult_failed(HRESULT hr) {
    return hr < 0;
}

void safe_bstr_free(BSTR value) {
    if (value != NULL) {
        OLEAUT32$SysFreeString(value);
    }
}

void release_service(ITaskService *value) {
    if (value != NULL) {
        value->lpVtbl->Release(value);
    }
}

void release_folder(ITaskFolder *value) {
    if (value != NULL) {
        value->lpVtbl->Release(value);
    }
}

void release_task(IRegisteredTask *value) {
    if (value != NULL) {
        value->lpVtbl->Release(value);
    }
}

HRESULT invoke_connect(ITaskService *service, LPWSTR server) {
    HRESULT hr;
    GUID iid_null;
    LPOLESTR method_name;
    DISPID dispid;
    DISPPARAMS params;
    VARIANT *args;
    UINT argerr;
    int i;

    init_iid_null(&iid_null);
    method_name = L"Connect";
    dispid = 0;
    hr = service->lpVtbl->GetIDsOfNames(service, &iid_null, &method_name, 1, 0, &dispid);
    if (hresult_failed(hr)) {
        return hr;
    }

    memset(&params, 0, sizeof(params));
    argerr = 0;
    args = NULL;

    if (server != NULL && server[0] != 0) {
        args = (VARIANT *)calloc(4, sizeof(VARIANT));
        if (args == NULL) {
            return 0x8007000e;
        }
        for (i = 0; i < 4; i++) {
            OLEAUT32$VariantInit(&args[i]);
            args[i].vt = VT_EMPTY;
        }
        args[3].vt = VT_BSTR;
        args[3].bstrVal = OLEAUT32$SysAllocString(server);
        params.rgvarg = args;
        params.cArgs = 4;
    }

    hr = service->lpVtbl->Invoke(service, dispid, &iid_null, 0, DISPATCH_METHOD, &params, NULL, NULL, &argerr);

    if (server != NULL && server[0] != 0) {
        safe_bstr_free(args[3].bstrVal);
        free(args);
    }

    return hr;
}

HRESULT connect_task_service(LPWSTR server, ITaskService **service_out) {
    HRESULT hr;
    GUID clsid;
    GUID iid;
    ITaskService *service;

    *service_out = NULL;
    service = NULL;
    init_task_guids(&clsid, &iid);

    hr = OLE32$CoCreateInstance(&clsid, NULL, CLSCTX_INPROC_SERVER, &iid, &service);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to initialize Task Scheduler interface");
        return hr;
    }

    hr = invoke_connect(service, server);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not connect to requested target %lx\n", hr);
        release_service(service);
        return hr;
    }

    *service_out = service;
    return S_OK;
}

BSTR format_date(DWORD64 date_value) {
    VARIANT value;
    BSTR output;
    HRESULT hr;

    OLEAUT32$VariantInit(&value);
    value.vt = VT_DATE;
    value.date = date_value;
    output = NULL;
    hr = OLEAUT32$VarFormatDateTime(&value, 0, 0, &output);
    if (hresult_failed(hr) || output == NULL) {
        output = OLEAUT32$SysAllocString(L"");
    }
    OLEAUT32$VariantClear(&value);
    return output;
}

void print_task(IRegisteredTask *task) {
    BSTR text;
    BSTR date_text;
    VARIANT_BOOL enabled;
    LONG state;
    DWORD64 date_value;
    HRESULT hr;

    text = NULL;
    hr = task->lpVtbl->get_Name(task, &text);
    if (hresult_succeeded(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "Name: %S\n", text);
        safe_bstr_free(text);
    }

    text = NULL;
    hr = task->lpVtbl->get_Path(task, &text);
    if (hresult_succeeded(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "Path: %S\n", text);
        safe_bstr_free(text);
    }

    enabled = 0;
    task->lpVtbl->get_Enabled(task, &enabled);
    BeaconPrintf(CALLBACK_OUTPUT, "Enabled: %s\n", enabled == -1 ? "True" : "False");

    date_value = 0;
    task->lpVtbl->get_LastRunTime(task, &date_value);
    date_text = format_date(date_value);
    BeaconPrintf(CALLBACK_OUTPUT, "Last Run: %S\n", date_text);
    safe_bstr_free(date_text);

    date_value = 0;
    task->lpVtbl->get_NextRunTime(task, &date_value);
    date_text = format_date(date_value);
    BeaconPrintf(CALLBACK_OUTPUT, "Next Run: %S\n", date_text);
    safe_bstr_free(date_text);

    state = TASK_STATE_UNKNOWN;
    task->lpVtbl->get_State(task, &state);
    BeaconPrintf(CALLBACK_OUTPUT, "Current State: %s\n", task_state_name(state));

    text = NULL;
    hr = task->lpVtbl->get_Xml(task, &text);
    if (hresult_succeeded(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "%S\n", text);
        safe_bstr_free(text);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to get xml for this task\n");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "--------------------------------\n");
}

void get_task(LPWSTR server, LPWSTR taskname) {
    HRESULT hr;
    ITaskService *service;
    ITaskFolder *root_folder;
    IRegisteredTask *task;
    BSTR root_path;
    BSTR task_path;

    service = NULL;
    root_folder = NULL;
    task = NULL;
    root_path = NULL;
    task_path = NULL;

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (hresult_failed(hr) && hr != RPC_E_CHANGED_MODE) {
        BeaconPrintf(CALLBACK_ERROR, "Could not initialize com");
        return;
    }

    hr = connect_task_service(server, &service);
    if (hresult_failed(hr)) {
        goto end;
    }

    root_path = OLEAUT32$SysAllocString(L"\\");
    hr = service->lpVtbl->GetFolder(service, root_path, &root_folder);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get Root Folder pointer: %lx", hr);
        goto end;
    }

    task_path = OLEAUT32$SysAllocString(taskname);
    hr = root_folder->lpVtbl->GetTask(root_folder, task_path, &task);
    if (hresult_succeeded(hr)) {
        print_task(task);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Could not find a task at given path of %S\n", task_path);
        BeaconPrintf(CALLBACK_OUTPUT, "When using query you must give the full path and name of the task you are looking for\n");
    }

end:
    release_task(task);
    release_folder(root_folder);
    release_service(service);
    safe_bstr_free(task_path);
    safe_bstr_free(root_path);
    OLE32$CoUninitialize();
}

datap parser;
LPWSTR host;
LPWSTR task;

host = L"";
task = L"\\Microsoft\\Windows\\Autochk\\Proxy";
if (__argc > 0) {
    BeaconDataParse(&parser, __argv, __argc);
    host = (LPWSTR)BeaconDataExtract(&parser, NULL);
    task = (LPWSTR)BeaconDataExtract(&parser, NULL);
    if (host == NULL) {
        host = L"";
    }
    if (task == NULL || task[0] == 0) {
        task = L"\\Microsoft\\Windows\\Autochk\\Proxy";
    }
}

get_task(host, task);
