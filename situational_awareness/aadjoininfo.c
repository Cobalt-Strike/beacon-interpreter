#include <windows.h>
#include <beacon.h>

typedef void *PCCERT_CONTEXT;

typedef enum _DSREG_JOIN_TYPE {
    DSREG_UNKNOWN_JOIN = 0,
    DSREG_DEVICE_JOIN = 1,
    DSREG_WORKPLACE_JOIN = 2
} DSREG_JOIN_TYPE;

typedef struct _DSREG_USER_INFO {
    LPWSTR pszUserEmail;
    LPWSTR pszUserKeyId;
    LPWSTR pszUserKeyName;
} DSREG_USER_INFO, *PDSREG_USER_INFO;

typedef struct _DSREG_JOIN_INFO {
    DSREG_JOIN_TYPE joinType;
    PCCERT_CONTEXT pJoinCertificate;
    LPWSTR pszDeviceId;
    LPWSTR pszIdpDomain;
    LPWSTR pszTenantId;
    LPWSTR pszJoinUserEmail;
    LPWSTR pszTenantDisplayName;
    LPWSTR pszMdmEnrollmentUrl;
    LPWSTR pszMdmTermsOfUseUrl;
    LPWSTR pszMdmComplianceUrl;
    LPWSTR pszUserSettingSyncUrl;
    PDSREG_USER_INFO pUserInfo;
} DSREG_JOIN_INFO, *PDSREG_JOIN_INFO;

NETAPI32$NetGetAadJoinInformation: u32 (ptr, ptr);
NETAPI32$NetFreeAadJoinInformation: void (ptr);

DWORD result;
PDSREG_JOIN_INFO join_info;
LPWSTR tenant_id;
datap parser;

join_info = NULL;
tenant_id = NULL;

if (__argc > 0) {
    BeaconDataParse(&parser, __argv, __argc);
    tenant_id = (LPWSTR)BeaconDataExtract(&parser, NULL);
    if (tenant_id != NULL && tenant_id[0] == 0) {
        tenant_id = NULL;
    }
}

result = NETAPI32$NetGetAadJoinInformation(tenant_id, &join_info);
if (result != 0 || join_info == NULL) {
    BeaconPrintf(CALLBACK_ERROR, "NetGetAadJoinInformation failed: %lu. Host may not be cloud joined.", result);
} else {
    BeaconPrintf(CALLBACK_OUTPUT, "================== AAD/Entra ID Join Info ==================");
    if (join_info->joinType == DSREG_DEVICE_JOIN) {
        BeaconPrintf(CALLBACK_OUTPUT, "%-20s: %s", "Join Type", "Device join");
    } else if (join_info->joinType == DSREG_WORKPLACE_JOIN) {
        BeaconPrintf(CALLBACK_OUTPUT, "%-20s: %s", "Join Type", "Workplace join");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "%-20s: %s", "Join Type", "Unknown");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "%-20s: %S", "Device ID", join_info->pszDeviceId ? join_info->pszDeviceId : L"");
    BeaconPrintf(CALLBACK_OUTPUT, "%-20s: %S", "IDP Domain", join_info->pszIdpDomain ? join_info->pszIdpDomain : L"");
    BeaconPrintf(CALLBACK_OUTPUT, "%-20s: %S", "Tenant ID", join_info->pszTenantId ? join_info->pszTenantId : L"");
    BeaconPrintf(CALLBACK_OUTPUT, "%-20s: %S", "Tenant Display Name", join_info->pszTenantDisplayName ? join_info->pszTenantDisplayName : L"");
    BeaconPrintf(CALLBACK_OUTPUT, "%-20s: %S", "Join User Email", join_info->pszJoinUserEmail ? join_info->pszJoinUserEmail : L"");

    if (join_info->joinType == DSREG_DEVICE_JOIN && join_info->pUserInfo != NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "====================== Join User Info ======================");
        BeaconPrintf(CALLBACK_OUTPUT, "%-20s: %S", "User Email", join_info->pUserInfo->pszUserEmail ? join_info->pUserInfo->pszUserEmail : L"");
        BeaconPrintf(CALLBACK_OUTPUT, "%-20s: %S", "User Key ID", join_info->pUserInfo->pszUserKeyId ? join_info->pUserInfo->pszUserKeyId : L"");
        BeaconPrintf(CALLBACK_OUTPUT, "%-20s: %S", "User Key Name", join_info->pUserInfo->pszUserKeyName ? join_info->pUserInfo->pszUserKeyName : L"");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Join user info was null or host is not device joined.");
    }

    NETAPI32$NetFreeAadJoinInformation(join_info);
}
