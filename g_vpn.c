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
void vpn_cache_store(netadr_t *addr, vpn_state_t result, const char *network, const char *asn)
{
    vpn_cache_entry_t *entry;
    int oldest = 0;
    float oldest_time = 0;

    // check if already cached (update in-place)
    for (int j = 0; j < vpn_cache_count; j++) {
        if (NET_IsEqualBaseAdr(addr, &vpn_cache[j].addr)) {
            entry = &vpn_cache[j];
            goto update;
        }
        if (vpn_cache[j].expiry < oldest_time || j == 0) {
            oldest_time = vpn_cache[j].expiry;
            oldest = j;
        }
    }

    // new entry
    if (vpn_cache_count < VPN_CACHE_SIZE) {
        entry = &vpn_cache[vpn_cache_count++];
    } else {
        entry = &vpn_cache[oldest];
    }

update:
    entry->addr = *addr;
    entry->result = result;
    entry->expiry = ltime + VPN_CACHE_TTL;
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
    baninfo_t *existing;
    baninfo_t *ban;
    char *addr;

    // check if already banned to avoid duplicates
    existing = banhead;
    while (existing) {
        if (NET_IsEqualBaseAdr(&existing->addr, &proxyinfo[clientnum].address)) {
            return;
        }
        existing = existing->next;
    }

    ban = gi.TagMalloc(sizeof(baninfo_t), TAG_LEVEL);
    q2a_memset(ban, 0, sizeof(baninfo_t));

    ban->addr = proxyinfo[clientnum].address;
    ban->vpn = qtrue;
    q2a_strncpy(ban->asnumber, proxyinfo[clientnum].vpn.asn, sizeof(ban->asnumber) - 1);
    ban->loadType = LT_PERM;
    ban->type = NICKALL;

    // prepend to ban list
    ban->next = banhead;
    banhead = ban;

    addr = net_addressToString(&proxyinfo[clientnum].address, qfalse, qfalse, qtrue);
    gi.cprintf(NULL, PRINT_HIGH, "Auto-banned VPN IP: %s (AS%s)\n", addr, ban->asnumber);

    // persist to ban file
    Q_snprintf(buffer, sizeof(buffer), "%s/%s", moddir, configfile_ban->string);
    FILE *banfp = fopen(buffer, "at");
    if (banfp) {
        fprintf(banfp, "BAN: IP %s VPN \"AS%s\"\n", addr, ban->asnumber);
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
    Q_strncpy(pi->dl.path, request, sizeof(pi->dl.path)-1);

    HTTP_QueueDownload(&proxyinfo[i].dl);
}

/**
 * Callback when CURL finishes download. Parse resulting JSON
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

    if (!buff) {
        proxyinfo[i].vpn.state = VPN_UNKNOWN;
        return;
    }

    v = &proxyinfo[i].vpn;
    root = json_create(buff, mem, sizeof(mem)/sizeof(*mem));
    if (!root) {
        gi.dprintf("json parsing error\n");
        return;
    }

    security = json_getProperty(root, "security");
    if (security) {
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
        } else {
            v->state = VPN_NEGATIVE;
        }

        if (v->state == VPN_POSITIVE) {
            gi.cprintf(NULL, PRINT_HIGH, "%s is using a VPN (%s)\n", NAME(i), v->asn);
        }
    }

    // cache the result for future lookups from the same IP
    vpn_cache_store(&proxyinfo[i].address, v->state, v->network, v->asn);

    if (v->state == VPN_POSITIVE && vpn_kick) {
        Q_snprintf(buffer, sizeof(buffer), "VPN connections not allowed, please reconnect without it\n");
        gi.cprintf(download->initiator, PRINT_HIGH, buffer);
        addCmdQueue(i, QCMD_DISCONNECT, 1, 0, buffer);
    }

    if (v->state == VPN_POSITIVE && vpn_ban) {
        vpn_add_ban(i);
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
