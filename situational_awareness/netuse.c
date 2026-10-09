#include <windows.h>
#include <winerror.h>
#include <beacon.h>

#define CMD_ADD 1
#define CMD_LIST 2
#define CMD_DELETE 3

#define NETUSE_COMMAND CMD_LIST
#define TARGET_DEVICE L"Z:"
#define TARGET_SHARE L"\\\\127.0.0.1\\C$"
#define TARGET_USERNAME ((LPWSTR)NULL)
#define TARGET_PASSWORD ((LPWSTR)NULL)
#define PERSIST_CONNECTION 0
#define REQUIRE_PRIVACY 0
#define FORCE_DELETE 0

#define RESOURCE_CONNECTED 0x00000001
#define RESOURCETYPE_ANY 0x00000000
#define RESOURCETYPE_DISK 0x00000001
#define CONNECT_UPDATE_PROFILE 0x00000001
#define CONNECT_TEMPORARY 0x00000004
#define CONNECT_ENCRYPTED 0x00008000

typedef struct _NETRESOURCEW {
    DWORD dwScope;
    DWORD dwType;
    DWORD dwDisplayType;
    DWORD dwUsage;
    LPWSTR lpLocalName;
    LPWSTR lpRemoteName;
    LPWSTR lpComment;
    LPWSTR lpProvider;
} NETRESOURCEW, *LPNETRESOURCEW;

MPR$WNetAddConnection2W: u32 (ptr, ptr, ptr, u32);
MPR$WNetCancelConnection2W: u32 (ptr, u32, u32);
MPR$WNetOpenEnumW: u32 (u32, u32, u32, ptr, ptr);
MPR$WNetEnumResourceW: u32 (ptr, ptr, ptr, ptr);
MPR$WNetCloseEnum: u32 (ptr);
MPR$WNetGetResourceInformationW: u32 (ptr, ptr, ptr, ptr);
MPR$WNetGetUserW: u32 (ptr, ptr, ptr);

do {
    datap parser;
    DWORD result;
    DWORD flags;
    short command;
    LPWSTR target_share;
    LPWSTR target_username;
    LPWSTR target_password;
    LPWSTR target_device;
    LPWSTR list_target;
    short persist_connection;
    short require_privacy;
    short force_delete;

    command = NETUSE_COMMAND;
    target_share = TARGET_SHARE;
    target_username = TARGET_USERNAME;
    target_password = TARGET_PASSWORD;
    target_device = TARGET_DEVICE;
    list_target = NULL;
    persist_connection = PERSIST_CONNECTION;
    require_privacy = REQUIRE_PRIVACY;
    force_delete = FORCE_DELETE;

    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        command = BeaconDataShort(&parser);
        if (command == CMD_ADD) {
            target_share = (LPWSTR)BeaconDataExtract(&parser, NULL);
            target_username = (LPWSTR)BeaconDataExtract(&parser, NULL);
            target_password = (LPWSTR)BeaconDataExtract(&parser, NULL);
            target_device = (LPWSTR)BeaconDataExtract(&parser, NULL);
            persist_connection = BeaconDataShort(&parser);
            require_privacy = BeaconDataShort(&parser);
            if (target_share == NULL || target_share[0] == 0) {
                BeaconPrintf(CALLBACK_ERROR, "netuse add requires a share path.");
                break;
            }
            if (target_username != NULL && target_username[0] == 0) target_username = NULL;
            if (target_password != NULL && target_password[0] == 0) target_password = NULL;
            if (target_device != NULL && target_device[0] == 0) target_device = NULL;
        } else if (command == CMD_LIST) {
            list_target = (LPWSTR)BeaconDataExtract(&parser, NULL);
            if (list_target != NULL && list_target[0] != 0) {
                BeaconPrintf(CALLBACK_ERROR, "netuse list target arguments are not supported by this script port. Run without a target to list local connections.");
                break;
            }
        } else if (command == CMD_DELETE) {
            target_device = (LPWSTR)BeaconDataExtract(&parser, NULL);
            persist_connection = BeaconDataShort(&parser);
            force_delete = BeaconDataShort(&parser);
            if (target_device == NULL || target_device[0] == 0) {
                BeaconPrintf(CALLBACK_ERROR, "netuse delete requires a device or connection name.");
                break;
            }
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Unsupported netuse command: %d", command);
            break;
        }
    }

    if (command == CMD_ADD) {
        NETRESOURCEW resource;
        resource.dwScope = 0;
        resource.dwType = RESOURCETYPE_DISK;
        resource.dwDisplayType = 0;
        resource.dwUsage = 0;
        resource.lpLocalName = target_device;
        resource.lpRemoteName = target_share;
        resource.lpComment = NULL;
        resource.lpProvider = NULL;
        flags = persist_connection ? CONNECT_UPDATE_PROFILE : CONNECT_TEMPORARY;
        if (require_privacy) flags |= CONNECT_ENCRYPTED;
        result = MPR$WNetAddConnection2W(&resource, target_password, target_username, flags);
        if (result == NO_ERROR) BeaconPrintf(CALLBACK_OUTPUT, "The command completed successfully.");
        else BeaconPrintf(CALLBACK_ERROR, "Unable to map share: %lu", result);
        break;
    }

    if (command == CMD_DELETE) {
        flags = persist_connection ? CONNECT_UPDATE_PROFILE : 0;
        result = MPR$WNetCancelConnection2W(target_device ? target_device : target_share, flags, force_delete);
        if (result == NO_ERROR) BeaconPrintf(CALLBACK_OUTPUT, "%S was deleted successfully.", target_device ? target_device : target_share);
        else BeaconPrintf(CALLBACK_ERROR, "Unable to delete share: %lu", result);
        break;
    }

    {
        HANDLE hEnum;
        DWORD buffer_size;
        DWORD entries;
        NETRESOURCEW *resources;
        formatp out;
        int output_length;
        char *output;
        DWORD i;

        hEnum = NULL;
        buffer_size = 16384;
        entries = ((DWORD)-1);
        resources = (NETRESOURCEW *)LocalAlloc(0x0040, buffer_size);
        if (resources == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Allocation failed.");
            break;
        }
        result = MPR$WNetOpenEnumW(RESOURCE_CONNECTED, RESOURCETYPE_ANY, 0, NULL, &hEnum);
        if (result != NO_ERROR) {
            LocalFree(resources);
            BeaconPrintf(CALLBACK_ERROR, "WNetOpenEnumW failed: %lu", result);
            break;
        }
        BeaconFormatAlloc(&out, 4096);
        BeaconFormatPrintf(&out, "%-12s %-8s %-32s %-32s\n", L"Status", L"Local", L"Remote", L"Network");
        while ((result = MPR$WNetEnumResourceW(hEnum, &entries, resources, &buffer_size)) == NO_ERROR) {
            for (i = 0; i < entries; i++) {
                BeaconFormatPrintf(&out, "%-12S %-8S %-32S %-32S\n", L"OK", resources[i].lpLocalName ? resources[i].lpLocalName : L"", resources[i].lpRemoteName ? resources[i].lpRemoteName : L"", resources[i].lpProvider ? resources[i].lpProvider : L"");
            }
            entries = ((DWORD)-1);
            buffer_size = 16384;
        }
        output = BeaconFormatToString(&out, &output_length);
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
        BeaconFormatFree(&out);
        MPR$WNetCloseEnum(hEnum);
        LocalFree(resources);
    }
} while (0);
