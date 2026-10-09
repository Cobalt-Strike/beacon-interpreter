# TrustedSec Situation Awareness Example Scripts

This folder contains example scripts for use in the Beacon Interpreter.

Most of the examples here are based on, inspired by, and/or directly ported from the TrustedSec Situational Awareness BOF project:

- https://github.com/trustedsec/CS-Situational-Awareness-BOF

The scripts in this folder were adapted to fit the Beacon Interpreter execution model and header surface.

## Examples

- `adv_audit_policies.c`: Searches Group Policy audit configuration files and prints discovered advanced audit policy data.
- `arp.c`: Enumerates the local ARP table and formats interface, IP, MAC, and entry type information.
- `dir.c`: Lists files and directories for a target path with timestamps, size, and simple summary counts.
- `enumLocalSessions.c`: Enumerates local logon sessions and prints basic session metadata.
- `enum_filter_driver.c`: Enumerates minifilter drivers from the registry and prints altitude/category information.
- `env.c`: Prints the current process environment strings.
- `findLoadedModule.c`: Searches running processes for a specific loaded module name.
- `get-netsession.c`: Enumerates active network sessions with client, user, active, and idle time details.
- `get-netsession2.c`: Enumerates network sessions and supplements them with workstation information.
- `get_password_policy.c`: Queries local or remote password policy and lockout settings.
- `get_session_info.c`: Retrieves LSA logon session data for the current token and prints key session fields.
- `ipconfig.c`: Prints host and adapter IP configuration details including addresses, gateways, and DNS servers.
- `listdns.c`: Enumerates cached DNS entries from the local resolver cache.
- `listmods.c`: Lists modules loaded in a target process and prints version/path details when available.
- `locale.c`: Prints locale, language, and regional formatting information for the current host.
- `md5.c`: Computes and prints the MD5 hash of a target file.
- `netgroup.c`: Lists domain groups or members of a target domain group.
- `netlocalgroup.c`: Lists local groups or members of a target local group.
- `netloggedon.c`: Enumerates users currently logged on to a workstation.
- `netloggedon2.c`: Enumerates logged-on users and prints host context alongside each entry.
- `netshares.c`: Enumerates network shares and optionally prints administrative share details.
- `netstat.c`: Prints TCP and UDP connection tables with addresses, state, and owning PID information.
- `nettime.c`: Queries remote time-of-day information and prints the reported timestamp.
- `netuptime.c`: Queries workstation statistics and prints the remote boot time.
- `netuse.c`: Adds, removes, or lists mapped network resources.
- `netuser.c`: Retrieves detailed information about a target user account and its group memberships.
- `netuserenum.c`: Enumerates user accounts locally or via a domain controller, with optional filtering.
- `netview.c`: Enumerates visible servers on the network browser surface.
- `notepad.c`: Finds Notepad windows and prints basic window metadata.
- `nslookup.c`: Performs DNS queries for a target name and formats returned record data.
- `probe.c`: Tests whether a target TCP port is reachable within a timeout.
- `reg_query.c`: Reads specific registry values or enumerates registry keys and values, optionally recursively.
- `regsession.c`: Enumerates user SID hives under `HKEY_USERS` to approximate registry-backed sessions.
- `resources.c`: Enumerates and prints module resource information from the current process image.
- `routeprint.c`: Prints adapter information and the active IPv4 route table.
- `rwx_process_scan.c`: Scans process memory regions for RWX pages and prints suspicious mappings.
- `sc_enum.c`: Enumerates Windows services and prints service name, state, PID, and display name.
- `sc_qc.c`: Queries and prints detailed service configuration for a target service.
- `sc_qdescription.c`: Queries and prints the configured description for a target service.
- `sc_qfailure.c`: Queries and prints configured service failure actions.
- `sc_qtriggerinfo.c`: Queries and prints service trigger configuration data.
- `sc_query.c`: Queries a specific service or enumerates all services with current state information.
- `sha1.c`: Computes and prints the SHA-1 hash of a target file.
- `sha256.c`: Computes and prints the SHA-256 hash of a target file.
- `uptime.c`: Prints local system uptime based on tick count data.
- `useridletime.c`: Prints the current user idle duration from `GetLastInputInfo`.
- `windowlist.c`: Enumerates top-level windows and prints their titles and visibility state.

