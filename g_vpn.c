/**
 * Basic VPN detection. Sadly, as VPN services have become
 * mainstream, some abusive players have started using them
 * to hide their identities to enable abuse.
 *
 * The feature will query an API for the player's IP address
 * to find out if it's from a VPN provider. If so, q2admin
 * can be configured to kick this player or just identity them.
 *
 * Current provider is https://vpnapi.io. There is a free
 * account option that allows for up to 1000 queries per day.
 * You'll need to register on that site and add the API key
 * to your config.
 */

#include "g_local.h"

char vpn_host[50] = VPNAPIHOST;

int vpn_cache_ttl_positive = 86400;   // 24 hours
int vpn_cache_ttl_negative = 3600;    // 1 hour
int vpn_cache_ttl_error = 300;        // 5 minutes

qboolean vpn_fallback_enable = qtrue;
char vpn_fallback_host[50] = FALLBACKHOST;
char vpn_fallback_api_key[33] = "";

static vpn_cache_entry_t vpn_cache[VPN_CACHE_SIZE];
static int vpn_cache_count = 0;

/**
 * Look up an IP in the VPN cache. Returns NULL if not found or expired.
 */
vpn_cache_entry_t *vpn_cache_lookup(netadr_t *addr)
{
    for (int j = 0; j < vpn_cache_count; j++) {
        if (NET_IsEqualBaseAdr(addr, &vpn_cache[j].addr)) {
            if (vpn_cache[j].expiry > ltime) {
                return &vpn_cache[j];
            }
            return NULL;  // expired
        }
    }
    return NULL;
}

/**
 * Store a VPN lookup result in the cache. Evicts oldest entry if full.
 */
void vpn_cache_store(netadr_t *addr, vpn_state_t result, const char *network, const char *asn, int ttl)
{
    vpn_cache_entry_t *entry;
    int oldest = 0;
    float oldest_time = 0;
    int expired_slot = -1;

    // when vpn_ban is on, skip caching VPN-positive results (ban list handles them)
    if (vpn_ban && result == VPN_POSITIVE) {
        return;
    }

    // check if already cached (update in-place)
    for (int j = 0; j < vpn_cache_count; j++) {
        if (NET_IsEqualBaseAdr(addr, &vpn_cache[j].addr)) {
            entry = &vpn_cache[j];
            goto update;
        }
        // track first expired slot for reuse
        if (expired_slot == -1 && vpn_cache[j].expiry <= ltime) {
            expired_slot = j;
        }
        if (vpn_cache[j].expiry < oldest_time || j == 0) {
            oldest_time = vpn_cache[j].expiry;
            oldest = j;
        }
    }

    // prefer: expired slot > new slot > evict oldest
    if (expired_slot != -1) {
        entry = &vpn_cache[expired_slot];
    } else if (vpn_cache_count < VPN_CACHE_SIZE) {
        entry = &vpn_cache[vpn_cache_count++];
    } else {
        entry = &vpn_cache[oldest];
    }

update:
    entry->addr = *addr;
    entry->result = result;
    entry->expiry = ltime + ttl;
    q2a_memset(entry->network, 0, sizeof(entry->network));
    q2a_memset(entry->asn, 0, sizeof(entry->asn));
    if (network) {
        q2a_strncpy(entry->network, network, sizeof(entry->network) - 1);
    }
    if (asn) {
        q2a_strncpy(entry->asn, asn, sizeof(entry->asn) - 1);
    }
}

/**
 * Programmatically create a ban entry for a VPN IP address.
 */
void vpn_add_ban(int clientnum)
{
    baninfo_t *ban;
    char *addr;
    static const char *ban_msg = "VPN connections not allowed, please reconnect without it";
    int msg_len;

    // check if already banned to avoid duplicates (O(1) hash lookup)
    if (ban_ip_exists(&proxyinfo[clientnum].address)) {
        return;
    }

    ban = gi.TagMalloc(sizeof(baninfo_t), TAG_LEVEL);
    q2a_memset(ban, 0, sizeof(baninfo_t));

    ban->addr = proxyinfo[clientnum].address;
    ban->addr.mask_bits = (ban->addr.type == NA_IP6) ? 128 : 32;
    ban->exclude = qtrue;
    ban->loadType = LT_PERM;
    ban->type = NICKALL;

    msg_len = q2a_strlen(ban_msg);
    ban->msg = gi.TagMalloc(msg_len + 1, TAG_LEVEL);
    q2a_strncpy(ban->msg, ban_msg, msg_len + 1);

    // prepend to ban list and hash table
    ban->next = banhead;
    banhead = ban;
    ban_hash_insert(ban);

    addr = net_addressToString(&proxyinfo[clientnum].address, qfalse, qfalse, qtrue);
    gi.cprintf(NULL, PRINT_HIGH, "Auto-banned VPN IP: %s (AS%s)\n", addr, proxyinfo[clientnum].vpn.asn);

    // persist to ban file
    Q_snprintf(buffer, sizeof(buffer), "%s/%s", moddir, configfile_ban->string);
    FILE *banfp = fopen(buffer, "at");
    if (banfp) {
        fprintf(banfp, "BAN: IP %s MSG \"%s\"\n", addr, ban_msg);
        fclose(banfp);
    }
}

/**
 * Initiates a lookup for the VPN status of a player edict using CURL. This is
 * a non-blocking call that will finish on a later framerun.
 */
void LookupVPNStatus(edict_t *ent)
{
    char *request;
    proxyinfo_t *pi;
    char *addr;

    int i = getEntOffset(ent) - 1;
    if (!vpn_enable) {
        return;
    }
    pi = &proxyinfo[i];

    // already checking or already checked
    if (pi->vpn.state >= VPN_CHECKING) {
        return;
    }

    // check VPN cache first
    vpn_cache_entry_t *cached = vpn_cache_lookup(&pi->address);
    if (cached) {
        pi->vpn.state = cached->result;
        if (cached->result == VPN_POSITIVE) {
            q2a_strncpy(pi->vpn.network, cached->network, sizeof(pi->vpn.network) - 1);
            q2a_strncpy(pi->vpn.asn, cached->asn, sizeof(pi->vpn.asn) - 1);
            pi->vpn.is_vpn = qtrue;
            gi.cprintf(NULL, PRINT_HIGH, "%s is using a VPN (%s) [cached]\n", NAME(i), pi->vpn.asn);
            if (vpn_kick) {
                addCmdQueue(i, QCMD_DISCONNECT, 1, 0, "VPN connections not allowed");
            }
            if (vpn_ban) {
                vpn_add_ban(i);
            }
        }
        return;
    }

    addr = net_addressToString(&pi->address, qfalse, qfalse, qfalse);
    request = va("/api/%s?key=%s", addr, vpn_api_key);
    proxyinfo[i].vpn.state = VPN_CHECKING;
    proxyinfo[i].dl.initiator = ent;
    proxyinfo[i].dl.onFinish = FinishVPNLookup;
    proxyinfo[i].dl.generation = proxyinfo[i].generation;
    proxyinfo[i].dl.type = DL_VPNAPI;
    proxyinfo[i].dl.host[0] = '\0';  // use default vpn_host
    Q_strncpy(pi->dl.path, request, sizeof(pi->dl.path)-1);

    if (!HTTP_QueueDownload(&proxyinfo[i].dl)) {
        proxyinfo[i].vpn.state = VPN_UNKNOWN;
    }
}

/**
 * Handle a confirmed VPN-positive result from either primary or fallback API.
 * Caches, kicks, bans, and re-checks ban list for ASN-based bans.
 */
static void vpn_handle_positive(int i, edict_t *ent)
{
    vpn_t *v = &proxyinfo[i].vpn;

    gi.cprintf(NULL, PRINT_HIGH, "%s is using a VPN (%s)\n", NAME(i), v->asn);

    // cache the result
    vpn_cache_store(&proxyinfo[i].address, VPN_POSITIVE, v->network, v->asn, vpn_cache_ttl_positive);

    if (vpn_kick) {
        Q_snprintf(buffer, sizeof(buffer), "VPN connections not allowed, please reconnect without it\n");
        gi.cprintf(ent, PRINT_HIGH, buffer);
        addCmdQueue(i, QCMD_DISCONNECT, 1, 0, buffer);
    }

    if (vpn_ban) {
        vpn_add_ban(i);
    }

    // re-run ban check now that VPN status and ASN are known (Fix 7)
    if (checkCheckIfBanned(ent, i)) {
        // only queue disconnect if one isn't already pending from vpn_kick above
        if (!vpn_kick) {
            gi.cprintf(NULL, PRINT_HIGH, "%s: %s (IP = %s)\n", proxyinfo[i].name, currentBanMsg, IP(i));
            gi.cprintf(ent, PRINT_HIGH, "%s\n", currentBanMsg);
            addCmdQueue(i, QCMD_DISCONNECT, 1, 0, currentBanMsg);
        }
    }
}

/**
 * Callback when CURL finishes download for primary VPN API (vpnapi.io).
 * Parse resulting JSON.
 */
void FinishVPNLookup(download_t *download, int code, byte *buff, int len)
{
    vpn_t *v;
    json_t mem[32];
    const json_t *root, *security, *net;
    int i = getEntOffset(download->initiator) - 1;

    // client disconnected or slot reused since this request was made
    if (download->generation != proxyinfo[i].generation) {
        return;
    }

    v = &proxyinfo[i].vpn;

    // HTTP/curl error — no response body
    if (!buff) {
        gi.dprintf("VPN API error for %s (HTTP %d)\n", IP(i), code);
        if (vpn_fallback_enable) {
            LookupVPNFallback(download->initiator);
        } else {
            v->state = VPN_UNKNOWN;
            vpn_cache_store(&proxyinfo[i].address, VPN_UNKNOWN, NULL, NULL, vpn_cache_ttl_error);
        }
        return;
    }

    root = json_create(buff, mem, sizeof(mem)/sizeof(*mem));
    if (!root) {
        gi.dprintf("VPN API json parsing error for %s\n", IP(i));
        if (vpn_fallback_enable) {
            LookupVPNFallback(download->initiator);
        } else {
            v->state = VPN_UNKNOWN;
            vpn_cache_store(&proxyinfo[i].address, VPN_UNKNOWN, NULL, NULL, vpn_cache_ttl_error);
        }
        return;
    }

    security = json_getProperty(root, "security");
    if (!security) {
        // API rate limit or malformed response (no "security" field)
        gi.dprintf("VPN API rate limited or invalid response for %s\n", IP(i));
        if (vpn_fallback_enable) {
            LookupVPNFallback(download->initiator);
        } else {
            v->state = VPN_UNKNOWN;
            vpn_cache_store(&proxyinfo[i].address, VPN_UNKNOWN, NULL, NULL, vpn_cache_ttl_error);
        }
        return;
    }

    v->is_vpn = Q_stricmp(json_getPropertyValue(security, "vpn"), "true") == 0;
    v->is_proxy = Q_stricmp(json_getPropertyValue(security, "proxy"), "true") == 0;
    v->is_tor = Q_stricmp(json_getPropertyValue(security, "tor"), "true") == 0;
    v->is_relay = Q_stricmp(json_getPropertyValue(security, "relay"), "true") == 0;

    if (v->is_vpn || v->is_proxy || v->is_tor || v->is_relay) {
        v->state = VPN_POSITIVE;
        net = json_getProperty(root, "network");
        if (net) {
            q2a_strncpy(v->network, json_getPropertyValue(net, "network"), sizeof(v->network));
            q2a_strncpy(v->asn, json_getPropertyValue(net, "autonomous_system_number"), sizeof(v->asn));
        }
        vpn_handle_positive(i, download->initiator);
    } else {
        v->state = VPN_NEGATIVE;
        // double-check with fallback (catches VPNs that vpnapi.io misses)
        if (vpn_fallback_enable) {
            LookupVPNFallback(download->initiator);
        } else {
            vpn_cache_store(&proxyinfo[i].address, VPN_NEGATIVE, NULL, NULL, vpn_cache_ttl_negative);
        }
    }
}

/**
 * Initiate a fallback VPN lookup using ipapi.is.
 * Called when primary API fails, is rate-limited, or returns negative (double-check).
 */
void LookupVPNFallback(edict_t *ent)
{
    char *request;
    proxyinfo_t *pi;
    char *addr;

    int i = getEntOffset(ent) - 1;
    if (!vpn_enable || !vpn_fallback_enable) {
        return;
    }
    pi = &proxyinfo[i];

    addr = net_addressToString(&pi->address, qfalse, qfalse, qfalse);

    if (vpn_fallback_api_key[0]) {
        request = va("/?q=%s&key=%s", addr, vpn_fallback_api_key);
    } else {
        request = va("/?q=%s", addr);
    }

    pi->dl.initiator = ent;
    pi->dl.onFinish = FinishFallbackLookup;
    pi->dl.generation = pi->generation;
    pi->dl.type = DL_VPNFALLBACK;
    Q_strncpy(pi->dl.path, request, sizeof(pi->dl.path) - 1);
    Q_strncpy(pi->dl.host, vpn_fallback_host, sizeof(pi->dl.host) - 1);

    if (!HTTP_QueueDownload(&pi->dl)) {
        // fallback also failed to queue — cache as error
        pi->vpn.state = VPN_UNKNOWN;
        vpn_cache_store(&pi->address, VPN_UNKNOWN, NULL, NULL, vpn_cache_ttl_error);
    }
}

/**
 * Callback when CURL finishes download for fallback API (ipapi.is).
 * ipapi.is returns flat JSON: { "is_vpn": true, "is_datacenter": true, ... , "asn": { "asn": 12345, ... } }
 */
void FinishFallbackLookup(download_t *download, int code, byte *buff, int len)
{
    vpn_t *v;
    json_t mem[64];
    const json_t *root, *asn_obj;
    const char *val;
    qboolean detected = qfalse;
    int i = getEntOffset(download->initiator) - 1;

    if (download->generation != proxyinfo[i].generation) {
        return;
    }

    v = &proxyinfo[i].vpn;

    if (!buff) {
        gi.dprintf("Fallback VPN API error for %s (HTTP %d)\n", IP(i), code);
        if (v->state != VPN_POSITIVE) {
            v->state = VPN_UNKNOWN;
        }
        vpn_cache_store(&proxyinfo[i].address, v->state, v->network, v->asn, vpn_cache_ttl_error);
        return;
    }

    root = json_create(buff, mem, sizeof(mem) / sizeof(*mem));
    if (!root) {
        gi.dprintf("Fallback VPN API json parsing error for %s\n", IP(i));
        if (v->state != VPN_POSITIVE) {
            v->state = VPN_UNKNOWN;
        }
        vpn_cache_store(&proxyinfo[i].address, v->state, v->network, v->asn, vpn_cache_ttl_error);
        return;
    }

    // ipapi.is returns flat booleans at root level
    val = json_getPropertyValue(root, "is_vpn");
    if (val && Q_stricmp(val, "true") == 0) {
        v->is_vpn = qtrue;
        detected = qtrue;
    }

    val = json_getPropertyValue(root, "is_datacenter");
    if (val && Q_stricmp(val, "true") == 0) {
        detected = qtrue;
    }

    val = json_getPropertyValue(root, "is_proxy");
    if (val && Q_stricmp(val, "true") == 0) {
        v->is_proxy = qtrue;
        detected = qtrue;
    }

    val = json_getPropertyValue(root, "is_tor");
    if (val && Q_stricmp(val, "true") == 0) {
        v->is_tor = qtrue;
        detected = qtrue;
    }

    // extract ASN info
    asn_obj = json_getProperty(root, "asn");
    if (asn_obj) {
        // ipapi.is returns asn as integer, normalize to "AS<number>" format
        val = json_getPropertyValue(asn_obj, "asn");
        if (val) {
            Q_snprintf(v->asn, sizeof(v->asn), "AS%s", val);
        }
        val = json_getPropertyValue(asn_obj, "org");
        if (val) {
            q2a_strncpy(v->network, val, sizeof(v->network) - 1);
        }
    }

    if (detected) {
        v->state = VPN_POSITIVE;
        vpn_handle_positive(i, download->initiator);
    } else {
        // confirmed clean by both APIs
        if (v->state != VPN_POSITIVE) {
            v->state = VPN_NEGATIVE;
        }
        vpn_cache_store(&proxyinfo[i].address, VPN_NEGATIVE, NULL, NULL, vpn_cache_ttl_negative);
    }
}

/**
 * Whether the client is coming from a VPN connection or not.
 */
qboolean isVPN(int clientnum)
{
    if (!VALIDCLIENT(clientnum)) {
        return qfalse;
    }
    if (!vpn_enable) {
        return qfalse;
    }
    return proxyinfo[clientnum].vpn.state == VPN_POSITIVE;
}

/**
 * Display any players currently connected via a VPN
 */
void vpnUsersRun(int startarg, edict_t *ent, int client)
{
    int i;
    if (!vpn_enable) {
        gi.cprintf(NULL, PRINT_HIGH, "VPN tracking is currently disabled\n");
        return;
    }

    for (i=0; i<(int)maxclients->value; i++) {
        if (!proxyinfo[i].inuse) {
            continue;
        }

        if (proxyinfo[i].vpn.state == VPN_POSITIVE) {
            gi.cprintf(NULL, PRINT_HIGH, "  %s [%s - %s]\n", proxyinfo[i].name, proxyinfo[i].vpn.network, proxyinfo[i].vpn.asn);
        }
    }
}
