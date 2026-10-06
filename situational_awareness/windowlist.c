#include <windows.h>
#include <beacon.h>

#define GW_HWNDNEXT 2

USER32$GetTopWindow: ptr (ptr);
USER32$GetWindow: ptr (ptr, u32);
USER32$IsWindowVisible: u32 (ptr);
USER32$GetWindowTextA: u32 (ptr, ptr, i32);

formatp output_buffer;
datap parser;
HWND hwnd;
BOOL show_all_windows;
DWORD window_count;

void flush_output(formatp *buffer) {
    int output_length;
    char *output;

    output = BeaconFormatToString(buffer, &output_length);
    if (output != NULL && output_length > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatReset(buffer);
}

void append_window(HWND window_handle) {
    char window_name[128];
    DWORD window_length;
    BOOL visible;

    window_name[0] = 0;
    window_length = GetWindowTextA(window_handle, window_name, 127);
    if (window_name[0] != 0 && window_length) {
        visible = IsWindowVisible(window_handle);
        if (output_buffer.length > 7600) {
            flush_output(&output_buffer);
        }
        if (show_all_windows) {
            BeaconFormatPrintf(
                &output_buffer,
                "%-40s : %s\n",
                window_name,
                visible ? "Visible" : "Hidden"
            );
            window_count++;
        } else if (visible) {
            BeaconFormatPrintf(&output_buffer, "%s\n", window_name);
            window_count++;
        }
    }
}

show_all_windows = FALSE;
if (__argc > 0) {
    BeaconDataParse(&parser, __argv, __argc);
    show_all_windows = BeaconDataInt(&parser);
}

window_count = 0;
BeaconFormatAlloc(&output_buffer, 8192);

for (hwnd = GetTopWindow(NULL); hwnd != NULL; hwnd = GetWindow(hwnd, GW_HWNDNEXT)) {
    append_window(hwnd);
}

flush_output(&output_buffer);
BeaconFormatFree(&output_buffer);
