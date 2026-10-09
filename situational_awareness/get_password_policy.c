#include <windows.h>
#include <winnt.h>
#include <netapi32.h>
#include <beacon.h>

#define TARGET_SERVER ((LPWSTR)NULL)
#define DWORD_NEVER ((DWORD)-1)

do {
    datap parser;
    USER_MODALS_INFO_0 *modal0;
    USER_MODALS_INFO_3 *modal3;
    DWORD status;
    DWORD result;
    char number_buffer[256];
    formatp out;
    int output_length;
    char *output;
    LPWSTR target_server;

    target_server = TARGET_SERVER;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        target_server = (LPWSTR)BeaconDataExtract(&parser, NULL);
        if (target_server != NULL && target_server[0] == 0) target_server = TARGET_SERVER;
    }

    modal0 = NULL;
    modal3 = NULL;
    BeaconFormatAlloc(&out, 1024);

    status = NETAPI32$NetUserModalsGet(target_server, 0, &modal0);
    if (status != 0 || modal0 == NULL) {
        BeaconFormatPrintf(&out, "A system error has occurred(modal 0): %d\n", status);
        output = BeaconFormatToString(&out, &output_length);
        BeaconOutput(CALLBACK_OUTPUT, output, output_length);
        BeaconFormatFree(&out);
        break;
    }

    BeaconFormatPrintf(&out, "Minimum password length:  %lu\n", modal0->usrmod0_min_passwd_len);
    result = modal0->usrmod0_max_passwd_age / 86400;
    BeaconFormatPrintf(&out, "Maximum password age (days): %s\n", (result > 1000) ? "Unlimited" : _ultoa(result, number_buffer, 10));
    BeaconFormatPrintf(&out, "Minimum password age (days): %lu\n", modal0->usrmod0_min_passwd_age / 86400);
    BeaconFormatPrintf(&out, "Forced log off time (seconds):  %s\n", (modal0->usrmod0_force_logoff == DWORD_NEVER) ? "Never" : _ultoa(modal0->usrmod0_force_logoff, number_buffer, 10));
    BeaconFormatPrintf(&out, "Password history length:  %s\n", (modal0->usrmod0_password_hist_len == 0) ? "None" : _ultoa(modal0->usrmod0_password_hist_len, number_buffer, 10));
    NETAPI32$NetApiBufferFree(modal0);

    status = NETAPI32$NetUserModalsGet(target_server, 3, &modal3);
    if (status == 0 && modal3 != NULL) {
        result = modal3->usrmod3_lockout_duration;
        BeaconFormatPrintf(&out, "Lockout duration (minutes):  %s\n", (result == DWORD_NEVER) ? "Until Admin Unlock" : _ultoa(result / 60, number_buffer, 10));
        BeaconFormatPrintf(&out, "Lockout observation window (minutes):  %lu\n", modal3->usrmod3_lockout_observation_window / 60);
        result = modal3->usrmod3_lockout_threshold;
        BeaconFormatPrintf(&out, "Lockout threshold:  %s\n", (result == 0) ? "Accounts don't lock" : _ultoa(result, number_buffer, 10));
        NETAPI32$NetApiBufferFree(modal3);
    } else {
        BeaconFormatPrintf(&out, "A system error has occurred(modal 3): %d\n", status);
    }

    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);
} while (0);
