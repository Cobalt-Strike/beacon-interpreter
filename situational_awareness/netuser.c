#include <windows.h>
#include <winnt.h>
#include <netapi32.h>
#include <beacon.h>

#define TARGET_USERNAME L"Administrator"
#define TARGET_HOSTNAME ((LPCWSTR)NULL)
#define ComputerNameDnsDomain 2

#define TICKSTO1970 0x019db1ded53e8000ULL
#define TICKSPERSEC 10000000ULL
#define LOCALE_USER_DEFAULT 0x0400
#define DATE_SHORTDATE 0x00000001
#define TIME_NOSECONDS 0x00000002

DWORD get_time_in_seconds() {
    LARGE_INTEGER time;
    FILETIME file_time;
    GetSystemTimeAsFileTime(&file_time);
    time.u.LowPart = file_time.dwLowDateTime;
    time.u.HighPart = file_time.dwHighDateTime;
    time.QuadPart = time.QuadPart - TICKSTO1970;
    time.QuadPart = time.QuadPart / TICKSPERSEC;
    return time.u.LowPart;
}

void print_date_time(formatp *out, DWORD seconds) {
    LARGE_INTEGER time;
    FILETIME file_time;
    SYSTEMTIME system_time;
    WCHAR date_buffer[80];
    WCHAR time_buffer[80];

    time.QuadPart = ((LONGLONG)seconds * TICKSPERSEC) + TICKSTO1970;
    file_time.dwLowDateTime = time.u.LowPart;
    file_time.dwHighDateTime = time.u.HighPart;
    FileTimeToLocalFileTime(&file_time, &file_time);
    FileTimeToSystemTime(&file_time, &system_time);
    GetDateFormatW(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &system_time, NULL, date_buffer, 80);
    GetDateFormatW(LOCALE_USER_DEFAULT, TIME_NOSECONDS, &system_time, NULL, time_buffer, 80);
    BeaconFormatPrintf(out, "%S %S", date_buffer, time_buffer);
}

do {
    datap parser;
    LPUSER_INFO_4 user;
    PGROUP_USERS_INFO_0 groups;
    PLOCALGROUP_USERS_INFO_0 local_groups;
    PUSER_MODALS_INFO_0 modals;
    DWORD group_read, group_total, local_read, local_total, i;
    NET_API_STATUS status;
    DWORD lastset;
    WCHAR default_domain[256];
    DWORD default_size;
    formatp out;
    int output_length;
    char *output;
    LPCWSTR host;
    LPWSTR username;
    LPWSTR domain_arg;

    user = NULL;
    groups = NULL;
    local_groups = NULL;
    modals = NULL;
    username = TARGET_USERNAME;
    domain_arg = (LPWSTR)TARGET_HOSTNAME;
    if (__argc > 0) {
        BeaconDataParse(&parser, __argv, __argc);
        username = (LPWSTR)BeaconDataExtract(&parser, NULL);
        domain_arg = (LPWSTR)BeaconDataExtract(&parser, NULL);
        if (username == NULL || username[0] == 0) username = TARGET_USERNAME;
        if (domain_arg != NULL && domain_arg[0] == 0) domain_arg = (LPWSTR)TARGET_HOSTNAME;
    }

    host = TARGET_HOSTNAME;
    if (domain_arg != NULL) host = domain_arg;
    default_size = 256;
    if (host == NULL) {
        if (GetComputerNameExW(ComputerNameDnsDomain, default_domain, &default_size)) {
            host = default_domain;
        }
    }

    status = NETAPI32$NetUserGetInfo(host, username, 4, &user);
    if (status != 0 || user == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get user info: %lu", status);
        break;
    }

    NETAPI32$NetUserModalsGet(host, 0, &modals);
    lastset = get_time_in_seconds() - user->usri4_password_age;
    BeaconFormatAlloc(&out, 4096);
    BeaconFormatPrintf(&out, "User name:\t\t\t%S\n", user->usri4_name ? user->usri4_name : L"");
    BeaconFormatPrintf(&out, "Full Name:\t\t\t%S\n", user->usri4_full_name ? user->usri4_full_name : L"");
    BeaconFormatPrintf(&out, "User's comment:\t\t%S\n", user->usri4_usr_comment ? user->usri4_usr_comment : L"");
    BeaconFormatPrintf(&out, "Country code:\t\t\t%lu\n\n", user->usri4_country_code);
    BeaconFormatPrintf(&out, "Flags (account details hex):\t%lx\n", user->usri4_flags);
    BeaconFormatPrintf(&out, "Account enabled:\t\t\t%s\n", (user->usri4_flags & UF_ACCOUNTDISABLE) ? "No" : "Yes");
    BeaconFormatPrintf(&out, "Trusted for delegation:\t\t%s\n", (user->usri4_flags & UF_TRUSTED_FOR_DELEGATION) ? "Yes" : "No");
    BeaconFormatPrintf(&out, "Dont require preauth:\t\t%s\n", (user->usri4_flags & UF_DONT_REQUIRE_PREAUTH) ? "Yes" : "No");
    BeaconFormatPrintf(&out, "Account expires:\t\t\t");
    if (user->usri4_acct_expires == TIMEQ_FOREVER) BeaconFormatPrintf(&out, "Never");
    else print_date_time(&out, user->usri4_acct_expires);
    BeaconFormatPrintf(&out, "\n\nPassword last set:\t\t");
    print_date_time(&out, lastset);
    BeaconFormatPrintf(&out, "\nPassword expires:\t\t\t");
    if ((user->usri4_flags & UF_DONT_EXPIRE_PASSWD) || (modals && modals->usrmod0_max_passwd_age == TIMEQ_FOREVER)) BeaconFormatPrintf(&out, "Never");
    else if (modals) print_date_time(&out, lastset + modals->usrmod0_max_passwd_age);
    BeaconFormatPrintf(&out, "\nPassword required:\t\t%s\n", (user->usri4_flags & UF_PASSWD_NOTREQD) ? "No" : "Yes");
    BeaconFormatPrintf(&out, "User may change password:\t%s\n", (user->usri4_flags & UF_PASSWD_CANT_CHANGE) ? "No" : "Yes");
    BeaconFormatPrintf(&out, "Workstations allowed:\t\t%S\n", (user->usri4_workstations == NULL || user->usri4_workstations[0] == 0) ? L"ALL" : user->usri4_workstations);
    BeaconFormatPrintf(&out, "Script path:\t\t\t%S\n", user->usri4_script_path ? user->usri4_script_path : L"");
    BeaconFormatPrintf(&out, "User profile:\t\t\t%S\n", user->usri4_profile ? user->usri4_profile : L"");
    BeaconFormatPrintf(&out, "Home directory:\t\t\t%S\n", user->usri4_home_dir ? user->usri4_home_dir : L"");
    BeaconFormatPrintf(&out, "Last logon:\t\t\t");
    print_date_time(&out, user->usri4_last_logon);
    BeaconFormatPrintf(&out, "\n");

    group_read = group_total = local_read = local_total = 0;
    NETAPI32$NetUserGetLocalGroups(NULL, username, 0, 0, &local_groups, ((DWORD)-1), &local_read, &local_total);
    NETAPI32$NetUserGetGroups(host, username, 0, &groups, ((DWORD)-1), &group_read, &group_total);
    if (local_groups) {
        BeaconFormatPrintf(&out, "Local Group Memberships:\n");
        for (i = 0; i < local_total; i++) BeaconFormatPrintf(&out, "\t%S\n", local_groups[i].lgrui0_name);
    }
    if (groups) {
        BeaconFormatPrintf(&out, "Global Group memberships:\n");
        for (i = 0; i < group_total; i++) BeaconFormatPrintf(&out, "\t%S\n", groups[i].grui0_name);
    }

    output = BeaconFormatToString(&out, &output_length);
    BeaconOutput(CALLBACK_OUTPUT, output, output_length);
    BeaconFormatFree(&out);

    if (user) NETAPI32$NetApiBufferFree(user);
    if (groups) NETAPI32$NetApiBufferFree(groups);
    if (local_groups) NETAPI32$NetApiBufferFree(local_groups);
    if (modals) NETAPI32$NetApiBufferFree(modals);
} while (0);
