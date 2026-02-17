/**
 * Q2Admin
 * VPN detection
 */

#pragma once

#define VPNAPIHOST      "vpnapi.io"
#define FALLBACKHOST    "api.ipapi.is"

// states of VPN check
typedef enum {
    VPN_UNKNOWN,    // unchecked, not known
    VPN_CHECKING,   // mid-lookup
    VPN_POSITIVE,   // confirmed, vpn address
    VPN_NEGATIVE,   // confirmed, non-vpn address
} vpn_state_t;

// Properties will be non-null if state == VPN_POSITIVE
typedef struct {
    vpn_state_t     state;
    qboolean        is_vpn;
    qboolean        is_proxy;
    qboolean        is_tor;
    qboolean        is_relay;
    char            network[50];
    char            asn[16];
} vpn_t;

#define VPN_CACHE_SIZE 512

typedef struct {
    netadr_t addr;
    vpn_state_t result;
    float expiry;
    char network[50];
    char asn[16];
} vpn_cache_entry_t;

extern qboolean vpn_kick;
extern qboolean vpn_ban;
extern qboolean vpn_enable;
extern char vpn_api_key[33];
extern char vpn_host[50];

// cache TTLs (seconds)
extern int vpn_cache_ttl_positive;
extern int vpn_cache_ttl_negative;
extern int vpn_cache_ttl_error;

// fallback API (ipapi.is)
extern qboolean vpn_fallback_enable;
extern char vpn_fallback_host[50];
extern char vpn_fallback_api_key[33];

void FinishVPNLookup(download_t *download, int code, byte *buff, int len);
void FinishFallbackLookup(download_t *download, int code, byte *buff, int len);
qboolean isVPN(int clientnum);
void LookupVPNStatus(edict_t *ent);
void LookupVPNFallback(edict_t *ent);
vpn_cache_entry_t *vpn_cache_lookup(netadr_t *addr);
void vpn_cache_store(netadr_t *addr, vpn_state_t result, const char *network, const char *asn, int ttl);
void vpn_add_ban(int clientnum);
void vpnUsersRun(int startarg, edict_t *ent, int client);
