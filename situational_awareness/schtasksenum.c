#include <windows.h>
#include <combaseapi.h>
#include <oaidl.h>
#include <oleauto.h>
#include <beacon.h>

#define RPC_E_CHANGED_MODE 0x80010106
#define DISPATCH_METHOD 0x1
#define DISPATCH_PROPERTYGET 0x2
#define DISPID_VALUE 0
#define TASK_ENUM_HIDDEN 1
#define TASK_STATE_UNKNOWN 0
#define TASK_STATE_DISABLED 1
#define TASK_STATE_QUEUED 2
#define TASK_STATE_READY 3
#define TASK_STATE_RUNNING 4

typedef struct IUnknown IUnknown;

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
    HRESULT (stdcall *get_Name)(void *This, BSTR *name);
    HRESULT (stdcall *get_Path)(void *This, BSTR *path);
    void *GetFolder;
    HRESULT (stdcall *GetFolders)(void *This, LONG flags, void **folders);
    void *CreateFolder;
    void *DeleteFolder;
    void *GetTask;
    HRESULT (stdcall *GetTasks)(void *This, LONG flags, void **tasks);
} ITaskFolderVtbl;

typedef struct _ITaskFolderCollectionVtbl {
    HRESULT (stdcall *QueryInterface)(void *This, REFIID riid, void **ppvObject);
    ULONG (stdcall *AddRef)(void *This);
    ULONG (stdcall *Release)(void *This);
    HRESULT (stdcall *GetTypeInfoCount)(void *This, UINT *pctinfo);
    HRESULT (stdcall *GetTypeInfo)(void *This, UINT iTInfo, LCID lcid, void **ppTInfo);
    HRESULT (stdcall *GetIDsOfNames)(void *This, REFIID riid, LPOLESTR *names, UINT count, LCID lcid, DISPID *dispids);
    HRESULT (stdcall *Invoke)(void *This, DISPID dispid, REFIID riid, LCID lcid, WORD flags, DISPPARAMS *params, VARIANT *result, void *excepinfo, UINT *argerr);
    HRESULT (stdcall *get_Count)(void *This, LONG *count);
    void *get_Item;
    HRESULT (stdcall *get__NewEnum)(void *This, void **enumerator);
} ITaskFolderCollectionVtbl;

typedef struct _IRegisteredTaskCollectionVtbl {
    HRESULT (stdcall *QueryInterface)(void *This, REFIID riid, void **ppvObject);
    ULONG (stdcall *AddRef)(void *This);
    ULONG (stdcall *Release)(void *This);
    HRESULT (stdcall *GetTypeInfoCount)(void *This, UINT *pctinfo);
    HRESULT (stdcall *GetTypeInfo)(void *This, UINT iTInfo, LCID lcid, void **ppTInfo);
    HRESULT (stdcall *GetIDsOfNames)(void *This, REFIID riid, LPOLESTR *names, UINT count, LCID lcid, DISPID *dispids);
    HRESULT (stdcall *Invoke)(void *This, DISPID dispid, REFIID riid, LCID lcid, WORD flags, DISPPARAMS *params, VARIANT *result, void *excepinfo, UINT *argerr);
    HRESULT (stdcall *get_Count)(void *This, LONG *count);
    void *get_Item;
    HRESULT (stdcall *get__NewEnum)(void *This, void **enumerator);
} IRegisteredTaskCollectionVtbl;

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

typedef struct _ITaskFolderCollection {
    ITaskFolderCollectionVtbl *lpVtbl;
} ITaskFolderCollection;

typedef struct _IRegisteredTaskCollection {
    IRegisteredTaskCollectionVtbl *lpVtbl;
} IRegisteredTaskCollection;

typedef struct _IRegisteredTask {
    IRegisteredTaskVtbl *lpVtbl;
} IRegisteredTask;

typedef struct _FolderNode {
    ITaskFolder *folder;
    void *next;
} FolderNode;

typedef struct _FolderQueue {
    FolderNode *head;
    FolderNode *tail;
} FolderQueue;

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

void init_task_folder_iid(GUID *iid) {
    iid->Data1 = 0x8cfac062;
    iid->Data2 = 0xa080;
    iid->Data3 = 0x4c15;
    iid->Data4[0] = 0x9a;
    iid->Data4[1] = 0x88;
    iid->Data4[2] = 0xaa;
    iid->Data4[3] = 0x7c;
    iid->Data4[4] = 0x2a;
    iid->Data4[5] = 0xf8;
    iid->Data4[6] = 0x0d;
    iid->Data4[7] = 0xfc;
}

void init_registered_task_iid(GUID *iid) {
    iid->Data1 = 0x9c86f320;
    iid->Data2 = 0xdee3;
    iid->Data3 = 0x4dd1;
    iid->Data4[0] = 0xb9;
    iid->Data4[1] = 0x72;
    iid->Data4[2] = 0xa3;
    iid->Data4[3] = 0x03;
    iid->Data4[4] = 0xf2;
    iid->Data4[5] = 0x6b;
    iid->Data4[6] = 0x06;
    iid->Data4[7] = 0x1e;
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

void release_folder_collection(ITaskFolderCollection *value) {
    if (value != NULL) {
        value->lpVtbl->Release(value);
    }
}

void release_task_collection(IRegisteredTaskCollection *value) {
    if (value != NULL) {
        value->lpVtbl->Release(value);
    }
}

void release_task(IRegisteredTask *value) {
    if (value != NULL) {
        value->lpVtbl->Release(value);
    }
}

void queue_init(FolderQueue *queue) {
    queue->head = NULL;
    queue->tail = NULL;
}

int queue_push(FolderQueue *queue, ITaskFolder *folder) {
    FolderNode *node;

    node = (FolderNode *)calloc(1, sizeof(FolderNode));
    if (node == NULL) {
        return 0;
    }
    node->folder = folder;
    node->next = NULL;
    if (queue->tail == NULL) {
        queue->head = node;
        queue->tail = node;
    } else {
        queue->tail->next = node;
        queue->tail = node;
    }
    return 1;
}

ITaskFolder *queue_pop(FolderQueue *queue) {
    FolderNode *node;
    ITaskFolder *folder;

    node = queue->head;
    if (node == NULL) {
        return NULL;
    }
    queue->head = (FolderNode *)node->next;
    if (queue->head == NULL) {
        queue->tail = NULL;
    }
    folder = node->folder;
    free(node);
    return folder;
}

void queue_clear(FolderQueue *queue) {
    ITaskFolder *folder;

    folder = queue_pop(queue);
    while (folder != NULL) {
        release_folder(folder);
        folder = queue_pop(queue);
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

HRESULT query_variant_object(VARIANT *value, GUID *iid, void **out) {
    IUnknown *unknown;

    *out = NULL;
    unknown = NULL;
    if (value->vt == VT_DISPATCH && value->pdispVal != NULL) {
        unknown = (IUnknown *)value->pdispVal;
    } else if (value->vt == VT_UNKNOWN && value->punkVal != NULL) {
        unknown = (IUnknown *)value->punkVal;
    }
    if (unknown == NULL) {
        return 1;
    }
    return unknown->lpVtbl->QueryInterface(unknown, iid, out);
}

HRESULT invoke_folder_collection_item(ITaskFolderCollection *collection, LONG item_index, ITaskFolder **folder_out) {
    HRESULT hr;
    GUID iid_null;
    GUID folder_iid;
    DISPPARAMS params;
    VARIANT arg;
    VARIANT result;
    UINT argerr;

    *folder_out = NULL;
    init_iid_null(&iid_null);
    init_task_folder_iid(&folder_iid);
    memset(&params, 0, sizeof(params));
    OLEAUT32$VariantInit(&arg);
    OLEAUT32$VariantInit(&result);

    arg.vt = VT_I4;
    arg.lVal = item_index;
    params.rgvarg = &arg;
    params.cArgs = 1;
    argerr = 0;

    hr = collection->lpVtbl->Invoke(collection, DISPID_VALUE, &iid_null, 0, DISPATCH_PROPERTYGET, &params, &result, NULL, &argerr);
    if (hresult_succeeded(hr)) {
        hr = query_variant_object(&result, &folder_iid, folder_out);
    }
    OLEAUT32$VariantClear(&result);
    return hr;
}

HRESULT invoke_task_collection_item(IRegisteredTaskCollection *collection, LONG item_index, IRegisteredTask **task_out) {
    HRESULT hr;
    GUID iid_null;
    GUID task_iid;
    DISPPARAMS params;
    VARIANT arg;
    VARIANT result;
    UINT argerr;

    *task_out = NULL;
    init_iid_null(&iid_null);
    init_registered_task_iid(&task_iid);
    memset(&params, 0, sizeof(params));
    OLEAUT32$VariantInit(&arg);
    OLEAUT32$VariantInit(&result);

    arg.vt = VT_I4;
    arg.lVal = item_index;
    params.rgvarg = &arg;
    params.cArgs = 1;
    argerr = 0;

    hr = collection->lpVtbl->Invoke(collection, DISPID_VALUE, &iid_null, 0, DISPATCH_PROPERTYGET, &params, &result, NULL, &argerr);
    if (hresult_succeeded(hr)) {
        hr = query_variant_object(&result, &task_iid, task_out);
    }
    OLEAUT32$VariantClear(&result);
    return hr;
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

void print_task(IRegisteredTask *task, formatp *output) {
    BSTR text;
    BSTR date_text;
    VARIANT_BOOL enabled;
    LONG state;
    DWORD64 date_value;
    HRESULT hr;

    text = NULL;
    hr = task->lpVtbl->get_Name(task, &text);
    if (hresult_succeeded(hr)) {
        BEACON$BeaconFormatPrintf(output, "Name: %S\n", text);
        safe_bstr_free(text);
    }

    text = NULL;
    hr = task->lpVtbl->get_Path(task, &text);
    if (hresult_succeeded(hr)) {
        BEACON$BeaconFormatPrintf(output, "Path: %S\n", text);
        safe_bstr_free(text);
    }

    enabled = 0;
    task->lpVtbl->get_Enabled(task, &enabled);
    BEACON$BeaconFormatPrintf(output, "Enabled: %s\n", enabled == -1 ? "True" : "False");

    date_value = 0;
    task->lpVtbl->get_LastRunTime(task, &date_value);
    date_text = format_date(date_value);
    BEACON$BeaconFormatPrintf(output, "Last Run: %S\n", date_text);
    safe_bstr_free(date_text);

    date_value = 0;
    task->lpVtbl->get_NextRunTime(task, &date_value);
    date_text = format_date(date_value);
    BEACON$BeaconFormatPrintf(output, "Next Run: %S\n", date_text);
    safe_bstr_free(date_text);

    state = TASK_STATE_UNKNOWN;
    task->lpVtbl->get_State(task, &state);
    BEACON$BeaconFormatPrintf(output, "Current State: %s\n", task_state_name(state));

    text = NULL;
    hr = task->lpVtbl->get_Xml(task, &text);
    if (hresult_succeeded(hr)) {
        BEACON$BeaconFormatPrintf(output, "%S\n", text);
        safe_bstr_free(text);
    } else {
        BEACON$BeaconFormatPrintf(output, "Failed to get xml for this task\n");
    }
    BEACON$BeaconFormatPrintf(output, "--------------------------------\n");
}

int enqueue_subfolders(ITaskFolder *folder, FolderQueue *queue) {
    HRESULT hr;
    ITaskFolderCollection *collection;
    LONG count;
    LONG i;
    ITaskFolder *child;

    collection = NULL;
    count = 0;

    hr = folder->lpVtbl->GetFolders(folder, 0, &collection);
    if (hresult_failed(hr) || collection == NULL) {
        return 0;
    }

    hr = collection->lpVtbl->get_Count(collection, &count);
    if (hresult_failed(hr)) {
        release_folder_collection(collection);
        return 0;
    }

    for (i = 1; i <= count; i++) {
        child = NULL;
        hr = invoke_folder_collection_item(collection, i, &child);
        if (hresult_succeeded(hr) && child != NULL) {
            if (!queue_push(queue, child)) {
                release_folder(child);
            }
        }
    }

    release_folder_collection(collection);
    return 1;
}

void print_folder_tasks(ITaskFolder *folder, long *task_number, formatp *output) {
    HRESULT hr;
    IRegisteredTaskCollection *collection;
    LONG count;
    LONG i;
    IRegisteredTask *task;
    BSTR folder_name;
    HRESULT name_hr;

    collection = NULL;
    folder_name = NULL;
    count = 0;

    hr = folder->lpVtbl->GetTasks(folder, TASK_ENUM_HIDDEN, &collection);
    if (hresult_failed(hr) || collection == NULL) {
        name_hr = folder->lpVtbl->get_Name(folder, &folder_name);
        if (hresult_succeeded(name_hr)) {
            BEACON$BeaconFormatPrintf(output, "[!] Failed to get tasks for folder %S: %lx\n", folder_name, hr);
            safe_bstr_free(folder_name);
        }
        return;
    }

    hr = collection->lpVtbl->get_Count(collection, &count);
    if (hresult_succeeded(hr)) {
        for (i = 1; i <= count; i++) {
            task = NULL;
            hr = invoke_task_collection_item(collection, i, &task);
            if (hresult_succeeded(hr) && task != NULL) {
                (*task_number)++;
                BEACON$BeaconFormatPrintf(output, "Task %ld\n", *task_number);
                print_task(task, output);
                release_task(task);
            }
        }
    }

    release_task_collection(collection);
}

void flush_formatted_output(formatp *output) {
    char *output_text;
    int output_size;
    int offset;
    int chunk_size;
    int max_chunk;

    output_text = NULL;
    output_size = 0;
    offset = 0;
    max_chunk = 16384;

    output_text = BEACON$BeaconFormatToString(output, &output_size);
    if (output_text == NULL || output_size <= 0) {
        return;
    }

    while (offset < output_size) {
        chunk_size = output_size - offset;
        if (chunk_size > max_chunk) {
            chunk_size = max_chunk;
        }
        BeaconOutput(CALLBACK_OUTPUT, output_text + offset, chunk_size);
        offset += chunk_size;
    }
}

void enum_tasks(LPWSTR server) {
    HRESULT hr;
    ITaskService *service;
    ITaskFolder *current;
    BSTR root_path;
    FolderQueue queue;
    long task_number;
    formatp output;
    int com_initialized;

    service = NULL;
    current = NULL;
    root_path = NULL;
    task_number = 0;
    com_initialized = 0;
    queue_init(&queue);
    BEACON$BeaconFormatAlloc(&output, 4 * 1024 * 1024);

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (hresult_failed(hr) && hr != RPC_E_CHANGED_MODE) {
        BeaconPrintf(CALLBACK_ERROR, "Could not initialize com");
        goto end;
    }
    if (hresult_succeeded(hr)) {
        com_initialized = 1;
    }

    hr = connect_task_service(server, &service);
    if (hresult_failed(hr)) {
        goto end;
    }

    root_path = OLEAUT32$SysAllocString(L"\\");
    hr = service->lpVtbl->GetFolder(service, root_path, &current);
    if (hresult_failed(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get Root Folder pointer: %lx", hr);
        goto end;
    }

    while (current != NULL) {
        if (enqueue_subfolders(current, &queue)) {
            print_folder_tasks(current, &task_number, &output);
        }
        release_folder(current);
        current = queue_pop(&queue);
    }

    flush_formatted_output(&output);

end:
    if (current != NULL) {
        release_folder(current);
    }
    queue_clear(&queue);
    release_service(service);
    safe_bstr_free(root_path);
    BEACON$BeaconFormatFree(&output);
    if (com_initialized) {
        OLE32$CoUninitialize();
    }
}

datap parser;
LPWSTR host;

host = L"";
if (__argc > 0) {
    BeaconDataParse(&parser, __argv, __argc);
    host = (LPWSTR)BeaconDataExtract(&parser, NULL);
    if (host == NULL) {
        host = L"";
    }
}

enum_tasks(host);
