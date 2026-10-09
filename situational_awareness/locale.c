#include <windows.h>
#include <beacon.h>

#define BUFFER_SIZE 85
#define LOCALE_SENGLANGUAGE 0x00001001
#define LOCALE_SLOCALIZEDCOUNTRYNAME 0x00000006
#define DATE_LONGDATE 0x00000002

WCHAR locale_name[BUFFER_SIZE];
WCHAR language[BUFFER_SIZE];
WCHAR date_string[BUFFER_SIZE];
WCHAR country[BUFFER_SIZE];
LCID lcid;

if (!GetSystemDefaultLocaleName(locale_name, BUFFER_SIZE)) {
    BeaconPrintf(CALLBACK_ERROR, "Error retrieving system locale information: %lu", GetLastError());
} else if (!GetLocaleInfoEx(locale_name, LOCALE_SENGLANGUAGE, language, BUFFER_SIZE)) {
    BeaconPrintf(CALLBACK_ERROR, "Error retrieving language: %lu", GetLastError());
} else {
    lcid = LocaleNameToLCID(locale_name, 0);
    if (!lcid) {
        BeaconPrintf(CALLBACK_ERROR, "Error mapping Locale Name to LCID: %lu", GetLastError());
    } else if (!GetDateFormatEx(locale_name, DATE_LONGDATE, NULL, NULL, date_string, BUFFER_SIZE, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "Error retrieving date: %lu", GetLastError());
    } else if (!GetLocaleInfoEx(locale_name, LOCALE_SLOCALIZEDCOUNTRYNAME, country, BUFFER_SIZE)) {
        BeaconPrintf(CALLBACK_ERROR, "Error retrieving country: %lu", GetLastError());
    } else {
        BeaconPrintf(
        CALLBACK_OUTPUT,
        "Locale: %S (%S)\nLCID: %x\nDate: %S\nCountry: %S\n",
        language,
        locale_name,
        lcid,
        date_string,
        country
        );
    }
}
