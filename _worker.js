/**
 * Total-ECH Pages 完整版 (DoH + 前端查询)
 * 路由： /      -> 查询页面
 *       /api/query -> JSON API
 *       /ech   -> DoH 注入 ECH
 *       /doh   -> DoH 纯转发
 */

// ========== 上游配置 ==========
const UPSTREAM_DNS_GOOGLE = 'https://dns.google/dns-query';
const UPSTREAM_DNS_ALI = 'https://dns.alidns.com/dns-query';
const UPSTREAM_JSON_GOOGLE = 'https://dns.google/resolve';
const UPSTREAM_JSON_ALI = 'https://dns.alidns.com/resolve';

// ========== 静态配置 ==========
const TWITTER_DOMAINS = [
    "twimg.com", "twitter.com", "x.com", "t.co",
    "cloudflare-dns.com", "pages.dev", "workers.dev", "cloudflare.com", "lss1.ccwu.cc"
];
const DEFAULT_TWITTER_IP = "104.18.10.118";

const META_DOMAINS = [
    "facebook.com", "messenger.com", "instagram.com",
    "whatsapp.com", "fb.com", "meta.com"
];
const DEFAULT_META_IP = "157.240.1.35";

const META_ECH_CONFIG = "AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAA=";

// ⚠️ 请替换为您的完整 CIDR 列表
const RAW_META_CIDRS = [ /* 您的 Meta CIDR */ ];
const RAW_CF_CIDRS   = [ /* 您的 Cloudflare CIDR */ ];

// 内存缓存
const cacheMap = new Map();
const CACHE_TTL = 3600 * 1000;

let compiledMeta = null;
let compiledCF = null;
function getCompiledMeta() {
    if (!compiledMeta) compiledMeta = compileCidrs(RAW_META_CIDRS);
    return compiledMeta;
}
function getCompiledCF() {
    if (!compiledCF) compiledCF = compileCidrs(RAW_CF_CIDRS);
    return compiledCF;
}

// ========== Worker 入口 ==========
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;

        // 前端查询 API
        if (path === '/api/query') {
            return handleApiQuery(url);
        }

        // DoH 注入 ECH
        if (path === '/ech') {
            return handleDoHRequest(request, true, ctx);
        }

        // DoH 纯转发
        if (path === '/doh') {
            return handleDoHRequest(request, false, ctx);
        }

        // 默认返回前端页面
        return new Response(getHtml(), {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
    }
};

// ========== DoH 处理 (ech / doh) ==========
async function handleDoHRequest(request, injectEch, ctx) {
    const url = new URL(request.url);

    // 读取自定义参数（同时支持 URL 参数和请求头）
    const config = {
        ip4:     url.searchParams.get('ip4')     || request.headers.get('X-Ip4')     || '',
        ip6:     url.searchParams.get('ip6')     || request.headers.get('X-Ip6')     || '',
        metaIp4: url.searchParams.get('metaIp4') || request.headers.get('X-MetaIp4') || '',
        metaIp6: url.searchParams.get('metaIp6') || request.headers.get('X-MetaIp6') || '',
        cfDomain:url.searchParams.get('cf')      || request.headers.get('X-CF')      || '',
        echDomain:url.searchParams.get('ech')    || request.headers.get('X-ECH')     || 'cloudflare-ech.com'
    };

    // POST 二进制 DNS 报文
    if (request.method === 'POST') {
        const rawBuffer = await request.arrayBuffer();
        if (injectEch) {
            return handleDnsQuery(rawBuffer, config, ctx);
        } else {
            const res = await forwardQuery(rawBuffer);
            return dnsResponse(await res.arrayBuffer());
        }
    }

    // GET 参数 ?dns=base64url
    if (request.method === 'GET' && url.searchParams.get('dns')) {
        const dnsParam = url.searchParams.get('dns');
        const safeBase64 = dnsParam.replace(/ /g, '+').replace(/-/g, '+').replace(/_/g, '/');
        const dnsQuery = Uint8Array.from(atob(safeBase64), c => c.charCodeAt(0));
        if (injectEch) {
            return handleDnsQuery(dnsQuery.buffer, config, ctx);
        } else {
            const res = await forwardQuery(dnsQuery.buffer);
            return dnsResponse(await res.arrayBuffer());
        }
    }

    return new Response('OK', { status: 200, headers: { 'Access-Control-Allow-Origin': '*' } });
}

// ========== DNS 核心逻辑 (带 ECH 注入) ==========
async function handleDnsQuery(rawBuffer, config, ctx) {
    try {
        const query = parseDnsPacket(rawBuffer);
        if (!query || query.questions.length === 0) return forwardQuery(rawBuffer);

        const { id, questions } = query;
        const qType = questions[0].type;
        const qName = questions[0].name.toLowerCase().replace(/\.$/, "");

        // 特殊假名
        if (qName === "cf.ech" || qName === "fb.ech") {
            if (qType === 65) {
                const randomTtl = Math.floor(Math.random() * (10800 - 7200 + 1)) + 7200;
                if (qName === "cf.ech") {
                    const echRdata = await fetchCleanEchRdata(config.echDomain, ctx);
                    return dnsResponse(createMultiAnsResponse(id, qName, 65, echRdata ? [echRdata] : [], echRdata ? randomTtl : 60));
                }
                if (qName === "fb.ech") {
                    const echRdata = packHttpsParams(1, ".", [
                        { key: 'alpn', val: 'h2,h3' },
                        { key: 'ech', val: META_ECH_CONFIG }
                    ]);
                    return dnsResponse(createMultiAnsResponse(id, qName, 65, [echRdata], randomTtl));
                }
            } else {
                return dnsResponse(createMultiAnsResponse(id, qName, qType, [], 3600));
            }
        }

        // 静态域名
        const isTwitter = TWITTER_DOMAINS.some(d => qName === d || qName.endsWith("." + d));
        const isMeta    = META_DOMAINS.some(d => qName === d || qName.endsWith("." + d));

        if (isTwitter || isMeta) {
            if (qType === 28) return dnsResponse(createMultiAnsResponse(id, qName, 28, [], 3600));

            if (qType === 65) {
                if (isTwitter) {
                    const echRdata = await fetchCleanEchRdata(config.echDomain, ctx);
                    return dnsResponse(createMultiAnsResponse(id, qName, 65, echRdata ? [echRdata] : [], echRdata ? 3600 : 60));
                }
                if (isMeta) {
                    const echRdata = packHttpsParams(1, ".", [
                        { key: 'alpn', val: 'h2,h3' },
                        { key: 'ech', val: META_ECH_CONFIG }
                    ]);
                    return dnsResponse(createMultiAnsResponse(id, qName, 65, [echRdata], 3600));
                }
            }

            if (qType === 1) {
                let ipStrings = [];
                if (isTwitter && config.ip4) {
                    ipStrings = parseIpList(config.ip4);
                } else if (isMeta && config.metaIp4) {
                    ipStrings = parseIpList(config.metaIp4);
                } else if (isTwitter && config.cfDomain) {
                    const cfIps = await fetchReplacementIps(config.cfDomain, 1, ctx);
                    if (cfIps) ipStrings = cfIps.map(bytesToIp);
                } else {
                    ipStrings = isTwitter ? [DEFAULT_TWITTER_IP] : [DEFAULT_META_IP];
                }

                if (ipStrings.length > 0) {
                    const finalBytes = ipStrings.map(ipToBytes);
                    return dnsResponse(createMultiAnsResponse(id, qName, 1, finalBytes, 300));
                }
                return forwardQuery(rawBuffer);
            }
            return forwardQuery(rawBuffer);
        }

        // CIDR 归属探测
        let ownerData = await getOwnerFromCache(qName);
        let probedIps = null;
        if (!ownerData) {
            const probeResult = await activeProbeOwner(qName, ctx);
            if (probeResult) {
                ownerData = probeResult.owner;
                probedIps = probeResult.ips;
            }
        }

        if (qType === 65) {
            if (ownerData === 'META') {
                const echRdata = packHttpsParams(1, ".", [
                    { key: 'alpn', val: 'h2,h3' },
                    { key: 'ech', val: META_ECH_CONFIG }
                ]);
                return dnsResponse(createMultiAnsResponse(id, qName, 65, [echRdata], 300));
            }
            if (ownerData === 'CF') {
                const echRdata = await fetchCleanEchRdata(config.echDomain, ctx);
                return dnsResponse(createMultiAnsResponse(id, qName, 65, echRdata ? [echRdata] : [], echRdata ? 300 : 60));
            }
            return forwardQuery(rawBuffer);
        }

        if (qType === 1 || qType === 28) {
            if (ownerData === 'CF') {
                if (qType === 1 && config.ip4) {
                    return dnsResponse(createMultiAnsResponse(id, qName, 1, parseIpList(config.ip4).map(ipToBytes), 300));
                }
                if (qType === 28 && config.ip6) {
                    return dnsResponse(createMultiAnsResponse(id, qName, 28, parseIpList(config.ip6).map(ipv6ToBytes), 300));
                }
                if (config.cfDomain) {
                    const replaceIps = await fetchReplacementIps(config.cfDomain, qType, ctx);
                    if (replaceIps && replaceIps.length > 0) return dnsResponse(createMultiAnsResponse(id, qName, qType, replaceIps, 300));
                }
            }
            if (ownerData === 'META') {
                if (qType === 1 && config.metaIp4) {
                    return dnsResponse(createMultiAnsResponse(id, qName, 1, parseIpList(config.metaIp4).map(ipToBytes), 300));
                }
                if (qType === 28 && config.metaIp6) {
                    return dnsResponse(createMultiAnsResponse(id, qName, 28, parseIpList(config.metaIp6).map(ipv6ToBytes), 300));
                }
                let rawIps = [];
                if (qType === 1 && probedIps && probedIps.length > 0) {
                    rawIps = probedIps.filter(ip => !ip.includes(':')).map(ipToBytes);
                }
                if (rawIps.length === 0) {
                    const res = await forwardQuery(rawBuffer);
                    const buf = await res.arrayBuffer();
                    const ips = extractIpsFromPacket(buf);
                    rawIps = qType === 1
                        ? ips.filter(ip => !ip.includes(':')).map(ipToBytes)
                        : ips.filter(ip => ip.includes(':')).map(ipv6ToBytes);
                }
                if (rawIps.length > 0) return dnsResponse(createMultiAnsResponse(id, qName, qType, rawIps, 300));
                return dnsResponse(createMultiAnsResponse(id, qName, qType, [], 60));
            }
            return forwardQuery(rawBuffer);
        }
        return forwardQuery(rawBuffer);
    } catch (err) {
        console.error(`DNS Logic Error: ${err.message}`);
        throw new Error(`DNS Logic Error: ${err.message}`);
    }
}

// ========== 前端 API 查询 (JSON) ==========
async function handleApiQuery(url) {
    const domain = url.searchParams.get('domain');
    const type = url.searchParams.get('type')?.toUpperCase() || 'A';

    if (!domain) return json({ error: '缺少 domain 参数' }, 400);
    if (!['A', 'AAAA', 'HTTPS'].includes(type)) return json({ error: '不支持的类型' }, 400);

    const config = {
        ip4:     url.searchParams.get('ip4')     || '',
        ip6:     url.searchParams.get('ip6')     || '',
        metaIp4: url.searchParams.get('metaIp4') || '',
        metaIp6: url.searchParams.get('metaIp6') || '',
        cfDomain:url.searchParams.get('cf')      || '',
        echDomain:url.searchParams.get('ech')    || 'cloudflare-ech.com'
    };

    try {
        const result = await resolveDNS(domain, type, config);
        return json(result);
    } catch (err) {
        return json({ error: err.message }, 500);
    }
}

async function resolveDNS(domain, type, config) {
    domain = domain.toLowerCase().replace(/\.$/, '');

    const isTwitter = TWITTER_DOMAINS.some(d => domain === d || domain.endsWith("." + d));
    const isMeta = META_DOMAINS.some(d => domain === d || domain.endsWith("." + d));

    if (isTwitter || isMeta) {
        if (type === 'AAAA') return { domain, type, answers: [], ech: null };
        if (type === 'HTTPS') {
            const ech = isTwitter ? await fetchRealEch(config.echDomain) : META_ECH_CONFIG;
            return { domain, type, answers: [], ech: ech || null };
        }
        let ipList = [];
        if (isTwitter && config.ip4) ipList = parseIpList(config.ip4);
        else if (isMeta && config.metaIp4) ipList = parseIpList(config.metaIp4);
        else if (isTwitter && config.cfDomain) {
            const resolved = await resolveDomainToIp(config.cfDomain);
            if (resolved.length > 0) ipList = resolved;
        } else ipList = isTwitter ? [DEFAULT_TWITTER_IP] : [DEFAULT_META_IP];
        return { domain, type, answers: ipList, ech: null };
    }

    const dnsType = type === 'HTTPS' ? 65 : (type === 'AAAA' ? 28 : 1);
    const data = await queryUpstreamDNS(domain, dnsType);
    if (!data) return { domain, type, error: '上游查询失败' };

    let answers = [];
    let ech = null;
    if (data.Answer) {
        if (type === 'HTTPS') {
            const rec = data.Answer.find(r => r.type === 65);
            if (rec) {
                const parsed = parseHttpsRecord(rec.data);
                if (parsed && parsed.ech) ech = parsed.ech;
            }
        } else {
            answers = data.Answer.filter(r => r.type === dnsType).map(r => r.data);
        }
    }

    const owner = await detectOwner(domain);
    if (!ech && type === 'HTTPS') {
        if (owner === 'META') ech = META_ECH_CONFIG;
        else if (owner === 'CF') ech = await fetchRealEch(config.echDomain);
    }

    if (type === 'A' && config.ip4) answers = parseIpList(config.ip4);
    else if (type === 'AAAA' && config.ip6) answers = parseIpList(config.ip6);
    else if (type === 'A' && config.metaIp4 && owner === 'META') answers = parseIpList(config.metaIp4);
    else if (type === 'AAAA' && config.metaIp6 && owner === 'META') answers = parseIpList(config.metaIp6);
    else if (config.cfDomain) {
        const resolved = await resolveDomainToIp(config.cfDomain, dnsType);
        if (resolved.length > 0) answers = resolved;
    }

    return { domain, type, answers, ech: ech || null };
}

// ========== 工具函数 ==========
function parseIpList(raw) {
    if (!raw) return [];
    raw = raw.trim();
    if (raw.startsWith('[') && raw.endsWith(']')) {
        try {
            const arr = JSON.parse(raw);
            if (Array.isArray(arr)) return arr.map(String).filter(s => s);
        } catch {}
    }
    return raw.split(',').map(s => s.trim()).filter(s => s);
}

async function resolveDomainToIp(domain, type = 1) {
    const data = await queryUpstreamDNS(domain, type);
    if (data && data.Answer) {
        return data.Answer.filter(r => r.type === type).map(r => r.data);
    }
    return [];
}

async function queryUpstreamDNS(name, type) {
    const params = `?name=${encodeURIComponent(name)}&type=${type}`;
    const urls = [UPSTREAM_JSON_GOOGLE + params, UPSTREAM_JSON_ALI + params];
    const promises = urls.map(url =>
        fetch(url, { headers: { 'Accept': 'application/dns-json' } })
            .then(res => res.ok ? res.json() : Promise.reject())
    );
    try {
        return await Promise.any(promises);
    } catch {
        try {
            const res = await fetch(urls[0], { headers: { 'Accept': 'application/dns-json' } });
            if (res.ok) return res.json();
        } catch {}
        return null;
    }
}

async function fetchRealEch(echDomain) {
    const cacheKey = `ech:${echDomain}`;
    const cached = cacheMap.get(cacheKey);
    if (cached && Date.now() < cached.expire) return cached.value;

    try {
        const data = await queryUpstreamDNS(echDomain, 65);
        if (data && data.Answer) {
            const rec = data.Answer.find(r => r.type === 65);
            if (rec) {
                const parsed = parseHttpsRecord(rec.data);
                if (parsed && parsed.ech) {
                    cacheMap.set(cacheKey, { value: parsed.ech, expire: Date.now() + 600_000 });
                    return parsed.ech;
                }
            }
        }
    } catch {}
    return null;
}

function parseHttpsRecord(dataStr) {
    const parts = dataStr.split(/\s+/);
    if (parts.length < 3) return null;
    const result = {};
    for (let i = 2; i < parts.length; i++) {
        const [k, v] = parts[i].split('=');
        if (k === 'ech') result.ech = v;
        else if (k === 'alpn') result.alpn = v;
    }
    return result;
}

async function detectOwner(domain) {
    const cacheKey = `owner:${domain}`;
    const cached = cacheMap.get(cacheKey);
    if (cached && Date.now() < cached.expire) return cached.value;

    try {
        const data = await queryUpstreamDNS(domain, 1);
        if (data && data.Answer) {
            for (const rec of data.Answer) {
                if (rec.type === 1) {
                    const ip = rec.data;
                    if (isIpInCidrs(ip, getCompiledMeta())) {
                        cacheMap.set(cacheKey, { value: 'META', expire: Date.now() + CACHE_TTL });
                        return 'META';
                    }
                    if (isIpInCidrs(ip, getCompiledCF())) {
                        cacheMap.set(cacheKey, { value: 'CF', expire: Date.now() + CACHE_TTL });
                        return 'CF';
                    }
                }
            }
        }
    } catch {}
    cacheMap.set(cacheKey, { value: null, expire: Date.now() + 60_000 });
    return null;
}

// ========== 二进制 DNS 转发、构建、解析工具 ==========
async function forwardQuery(body) {
    const reqInit = {
        method: 'POST',
        headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' },
        body
    };
    const pGoogle = fetch(UPSTREAM_DNS_GOOGLE, reqInit).then(res => res.ok ? res : Promise.reject());
    const pAli = fetch(UPSTREAM_DNS_ALI, reqInit).then(res => res.ok ? res : Promise.reject());
    try {
        return await Promise.any([pGoogle, pAli]);
    } catch {
        return fetch(UPSTREAM_DNS_GOOGLE, reqInit);
    }
}

function dnsResponse(buffer) {
    return new Response(buffer, {
        headers: { 'Content-Type': 'application/dns-message', 'Access-Control-Allow-Origin': '*' }
    });
}

function createMultiAnsResponse(id, qn, qt, rds, ttl = 3600) {
    const encodedName = encodeDnsName(qn);
    const questionLen = 12 + encodedName.length + 4;
    const pointer = 0xC000 | 12;
    let totalLen = questionLen;
    for (const r of rds) totalLen += 2 + 2 + 2 + 4 + 2 + r.length;

    const buf = new Uint8Array(totalLen);
    const v = new DataView(buf.buffer);
    v.setUint16(0, id);
    v.setUint16(2, 0x8180);
    v.setUint16(4, 1);
    v.setUint16(6, rds.length);
    v.setUint16(8, 0);
    v.setUint16(10, 0);

    let offset = 12;
    buf.set(encodedName, offset); offset += encodedName.length;
    v.setUint16(offset, qt); offset += 2;
    v.setUint16(offset, 1);  offset += 2;

    for (const r of rds) {
        v.setUint16(offset, pointer); offset += 2;
        v.setUint16(offset, qt); offset += 2;
        v.setUint16(offset, 1); offset += 2;
        v.setUint32(offset, ttl); offset += 4;
        v.setUint16(offset, r.length); offset += 2;
        buf.set(r, offset); offset += r.length;
    }
    return buf.buffer;
}

function packHttpsParams(priority, target, params) {
    const targetBuf = target === "." ? new Uint8Array([0]) : encodeDnsName(target);
    const paramBufs = params.map(p => encodeSvcParam(p.key, p.val)).filter(b => b);
    paramBufs.sort((a, b) => new DataView(a.buffer).getUint16(0) - new DataView(b.buffer).getUint16(0));
    let totalLen = 2 + targetBuf.length;
    for (const b of paramBufs) totalLen += b.length;
    const res = new Uint8Array(totalLen);
    const v = new DataView(res.buffer);
    v.setUint16(0, priority);
    res.set(targetBuf, 2);
    let offset = 2 + targetBuf.length;
    for (const b of paramBufs) { res.set(b, offset); offset += b.length; }
    return res;
}

function encodeSvcParam(key, value) {
    const ids = { 'alpn': 1, 'ech': 5 };
    const id = ids[key];
    if (!id) return null;
    let valBuf;
    if (key === 'alpn') {
        const parts = value.split(',');
        valBuf = new Uint8Array(parts.reduce((a, b) => a + b.length + 1, 0));
        let o = 0;
        for (const p of parts) {
            valBuf[o++] = p.length;
            for (let i = 0; i < p.length; i++) valBuf[o++] = p.charCodeAt(i);
        }
    } else {
        const s = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
        valBuf = new Uint8Array(s.length);
        for (let i = 0; i < s.length; i++) valBuf[i] = s.charCodeAt(i);
    }
    const res = new Uint8Array(4 + valBuf.length);
    const v = new DataView(res.buffer);
    v.setUint16(0, id);
    v.setUint16(2, valBuf.length);
    res.set(valBuf, 4);
    return res;
}

function encodeDnsName(domain) {
    const parts = domain.split('.');
    const buf = new Uint8Array(domain.length + 2);
    let offset = 0;
    for (const part of parts) {
        buf[offset++] = part.length;
        for (let i = 0; i < part.length; i++) buf[offset++] = part.charCodeAt(i);
    }
    buf[offset++] = 0;
    return buf.slice(0, offset);
}

function parseDnsPacket(buf) {
    const v = new DataView(buf);
    if (buf.byteLength < 12) return null;
    let offset = 12;
    const labels = [];
    while (offset < buf.byteLength) {
        const len = v.getUint8(offset);
        if (len === 0) { offset++; break; }
        if ((len & 0xC0) === 0xC0) { offset += 2; break; }
        offset++;
        labels.push(new TextDecoder().decode(buf.slice(offset, offset + len)));
        offset += len;
    }
    return {
        id: v.getUint16(0),
        questions: [{ name: labels.join('.'), type: v.getUint16(offset) }]
    };
}

function extractIpsFromPacket(buffer) {
    const ips = [];
    const view = new DataView(buffer);
    if (buffer.byteLength < 12) return [];
    const ancount = view.getUint16(6);
    const totalRecords = ancount + view.getUint16(8) + view.getUint16(10);
    let offset = 12;
    try {
        for (let i = 0; i < view.getUint16(4); i++) {
            while (view.getUint8(offset) !== 0) {
                if ((view.getUint8(offset) & 0xC0) === 0xC0) { offset += 1; break; }
                offset += view.getUint8(offset) + 1;
            }
            offset += 5;
        }
        for (let i = 0; i < totalRecords; i++) {
            while (view.getUint8(offset) !== 0) {
                if ((view.getUint8(offset) & 0xC0) === 0xC0) { offset += 1; break; }
                offset += view.getUint8(offset) + 1;
            }
            offset += 1;
            const type = view.getUint16(offset); offset += 8;
            const rdlen = view.getUint16(offset); offset += 2;
            if (type === 1 && rdlen === 4) {
                ips.push(Array.from(new Uint8Array(buffer.slice(offset, offset + 4))).join('.'));
            } else if (type === 28 && rdlen === 16) {
                const raw = new Uint8Array(buffer.slice(offset, offset + 16));
                ips.push(formatIPv6(raw));
            }
            offset += rdlen;
        }
    } catch (e) {}
    return ips;
}

function formatIPv6(bytes) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
        parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    }
    let longestStart = -1, longestLen = 0;
    let currentStart = -1, currentLen = 0;
    for (let i = 0; i < parts.length; i++) {
        if (parts[i] === '0') {
            if (currentStart === -1) currentStart = i;
            currentLen++;
            if (currentLen > longestLen) { longestLen = currentLen; longestStart = currentStart; }
        } else {
            currentStart = -1; currentLen = 0;
        }
    }
    if (longestLen > 1) {
        parts.splice(longestStart, longestLen, '');
        if (longestStart === 0) parts.unshift('');
        if (longestStart + longestLen === 8) parts.push('');
    }
    return parts.join(':').replace(/:{3,}/, '::');
}

// ========== CIDR 工具 ==========
function compileCidrs(cidrList) {
    const v4 = [], v6 = [];
    for (const cidr of cidrList) {
        try {
            const [ip, bitsStr] = cidr.split('/');
            const bits = parseInt(bitsStr, 10);
            if (ip.includes(':')) {
                const mask = ~( (1n << (128n - BigInt(bits))) - 1n );
                const ipBn = ipv6ToBigInt(ip);
                v6.push({ start: ipBn & mask, end: (ipBn & mask) | ( (1n << (128n - BigInt(bits))) - 1n ) });
            } else {
                const mask = ~((1 << (32 - bits)) - 1);
                const ipNum = ipToLong(ip);
                v4.push({ start: (ipNum & mask) >>> 0, end: ((ipNum & mask) | ((1 << (32 - bits)) - 1)) >>> 0 });
            }
        } catch (e) {}
    }
    return { v4, v6 };
}

function isIpInCidrs(ip, compiled) {
    if (ip.includes(':')) {
        try {
            const ipBn = ipv6ToBigInt(ip);
            return compiled.v6.some(r => ipBn >= r.start && ipBn <= r.end);
        } catch {}
    } else {
        try {
            const ipNum = ipToLong(ip);
            return compiled.v4.some(r => ipNum >= r.start && ipNum <= r.end);
        } catch {}
    }
    return false;
}

function ipToLong(ip) {
    return ip.split('.').reduce((a, b) => (a << 8) + parseInt(b, 10), 0) >>> 0;
}
function ipv6ToBigInt(ip) {
    let p = ip.split(':');
    if (ip.includes('::')) {
        const [f, s] = ip.split('::');
        const fP = f ? f.split(':') : [];
        const sP = s ? s.split(':') : [];
        p = [...fP, ...Array(8 - fP.length - sP.length).fill('0'), ...sP];
    }
    return p.reduce((a, b) => (a << 16n) + BigInt(parseInt(b || '0', 16)), 0n);
}

function ipToBytes(ip) {
    return new Uint8Array(ip.split('.').map(Number));
}
function ipv6ToBytes(ip) {
    let p = ip.split(':');
    if (ip.includes('::')) {
        const [l, r] = ip.split('::');
        const lp = l ? l.split(':') : [];
        const rp = r ? r.split(':') : [];
        p = [...lp, ...Array(8 - lp.length - rp.length).fill('0'), ...rp];
    }
    const b = new Uint8Array(16);
    p.forEach((v, i) => {
        const val = parseInt(v, 16) || 0;
        b[i * 2] = val >> 8;
        b[i * 2 + 1] = val & 0xFF;
    });
    return b;
}
function bytesToIp(bytes) {
    return Array.from(bytes).join('.');
}

async function getOwnerFromCache(name) {
    if (cacheMap.has(name)) {
        const item = cacheMap.get(name);
        if (Date.now() < item.expire) return item.val;
        cacheMap.delete(name);
    }
    return null;
}

function setOwnerCache(name, owner, ctx) {
    cacheMap.set(name, { val: owner, expire: Date.now() + CACHE_TTL });
      // 可选：使用 Cache API
}

async function activeProbeOwner(domain, ctx) {
    try {
        const data = await queryUpstreamDNS(domain, 1);
        if (data && data.Answer) {
            for (const rec of data.Answer) {
                if (rec.type === 1) {
                    const ip = rec.data;
                    if (isIpInCidrs(ip, getCompiledMeta())) {
                        setOwnerCache(domain, 'META', ctx);
                        return { owner: 'META', ips: data.Answer.filter(r => r.type === 1).map(r => r.data) };
                    }
                    if (isIpInCidrs(ip, getCompiledCF())) {
                        setOwnerCache(domain, 'CF', ctx);
                        return { owner: 'CF', ips: data.Answer.filter(r => r.type === 1).map(r => r.data) };
                    }
                }
            }
        }
    } catch {}
    return null;
}

async function fetchCleanEchRdata(domain, ctx) {
    // 与 fetchRealEch 类似，但返回打包后的 bytes
    let data = null;
    const cacheKey = `ech:packed:${domain}`;
    const cached = cacheMap.get(cacheKey);
    if (cached && Date.now() < cached.expire) return cached.value;

    try {
        const res = await queryUpstreamDNS(domain, 65);
        if (res && res.Answer) {
            const ans = res.Answer.find(r => r.type === 65);
            if (ans && !ans.data.startsWith('\\#')) {
                const parts = ans.data.split(/\s+/);
                if (parts.length >= 3) {
                    const params = [];
                    for (let i = 2; i < parts.length; i++) {
                        const [k, v] = parts[i].split('=');
                        if (k === 'alpn' || k === 'ech') params.push({ key: k, val: v });
                    }
                    const packed = packHttpsParams(parseInt(parts[0]) || 0, parts[1], params);
                    cacheMap.set(cacheKey, { value: packed, expire: Date.now() + 600_000 });
                    return packed;
                }
            }
        }
    } catch {}
    return null;
}

async function fetchReplacementIps(domain, type, ctx) {
    const cacheKey = `replacement:${domain}:${type}`;
    const cached = cacheMap.get(cacheKey);
    if (cached && Date.now() < cached.expire) return cached.value;

    try {
        const data = await queryUpstreamDNS(domain, type);
        if (data && data.Answer) {
            const ips = data.Answer.filter(r => r.type === type).map(r => r.data);
            if (ips.length > 0) {
                const result = ips.map(ip => type === 1 ? ipToBytes(ip) : ipv6ToBytes(ip));
                cacheMap.set(cacheKey, { value: result, expire: Date.now() + 600_000 });
                return result;
            }
        }
    } catch {}
    return null;
}
// ========== 前端页面 ==========
function getHtml() {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ECH DNS 查询</title>
    <style>
        :root {
            --bg: #0f172a;
            --card: #1e293b;
            --text: #e2e8f0;
            --accent: #38bdf8;
            --border: #334155;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background: var(--bg);
            color: var(--text);
            font-family: system-ui, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            background: var(--card);
            border-radius: 16px;
            padding: 2rem;
            width: 100%;
            max-width: 550px;
            box-shadow: 0 8px 30px rgba(0,0,0,0.4);
        }
        h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
        .subtitle { color: #94a3b8; font-size: 0.85rem; margin-bottom: 1.5rem; }
        label { font-size: 0.9rem; display: block; margin-bottom: 0.5rem; }
        input, select, button {
            width: 100%;
            padding: 0.75rem 1rem;
            margin-bottom: 1rem;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 0.95rem;
        }
        button {
            background: var(--accent);
            color: #0f172a;
            font-weight: bold;
            border: none;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        button:disabled { opacity: 0.6; cursor: not-allowed; }
        .result-box {
            background: var(--bg);
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
            word-break: break-all;
            font-family: monospace;
            font-size: 0.9rem;
            min-height: 60px;
            border: 1px solid var(--border);
            white-space: pre-wrap;
        }
        .loading { color: var(--accent); }
        .error { color: #f87171; }
        .advanced-toggle {
            margin: 1rem 0;
            color: var(--accent);
            cursor: pointer;
            font-size: 0.9rem;
            user-select: none;
        }
        .advanced-toggle:hover { text-decoration: underline; }
        .advanced-fields {
            display: none;
            margin-bottom: 1rem;
        }
        .advanced-fields.show { display: block; }
        .advanced-fields input { margin-bottom: 0.75rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 ECH DNS 查询</h1>
        <p class="subtitle">自动注入 ECH，支持自定义优选 IP</p>
        <div>
            <label for="domain">域名</label>
            <input type="text" id="domain" placeholder="例如 twitter.com" value="twitter.com">
        </div>
        <div>
            <label for="type">记录类型</label>
            <select id="type">
                <option value="A">A (IPv4)</option>
                <option value="AAAA">AAAA (IPv6)</option>
                <option value="HTTPS">HTTPS (ECH)</option>
            </select>
        </div>
        <div class="advanced-toggle" onclick="toggleAdvanced()">⚙️ 高级选项 ▾</div>
        <div id="advancedFields" class="advanced-fields">
            <label for="ip4">IPv4 替换 (ip4)</label>
            <input type="text" id="ip4" placeholder="1.2.3.4, 5.6.7.8">
            <label for="ip6">IPv6 替换 (ip6)</label>
            <input type="text" id="ip6" placeholder="::1, ::2">
            <label for="metaIp4">Meta IPv4 (metaIp4)</label>
            <input type="text" id="metaIp4" placeholder="157.240.1.1">
            <label for="metaIp6">Meta IPv6 (metaIp6)</label>
            <input type="text" id="metaIp6" placeholder="2a03:2880:...">
            <label for="cfDomain">CF 解析域名 (cf)</label>
            <input type="text" id="cfDomain" placeholder="example.com">
            <label for="echDomain">ECH 域名 (ech)</label>
            <input type="text" id="echDomain" placeholder="cloudflare-ech.com">
        </div>
        <button id="queryBtn" onclick="doQuery()">查询</button>
        <div id="result" class="result-box"></div>
    </div>
    <script>
        function toggleAdvanced() {
            document.getElementById('advancedFields').classList.toggle('show');
        }
        async function doQuery() {
            const domain = document.getElementById('domain').value.trim();
            const type = document.getElementById('type').value;
            const btn = document.getElementById('queryBtn');
            const resultDiv = document.getElementById('result');
            if (!domain) { resultDiv.innerHTML = '<span class="error">请输入域名</span>'; return; }
            const params = new URLSearchParams();
            params.set('domain', domain);
            params.set('type', type);
            const ip4 = document.getElementById('ip4').value.trim();
            const ip6 = document.getElementById('ip6').value.trim();
            const metaIp4 = document.getElementById('metaIp4').value.trim();
            const metaIp6 = document.getElementById('metaIp6').value.trim();
            const cfDomain = document.getElementById('cfDomain').value.trim();
            const echDomain = document.getElementById('echDomain').value.trim();
            if (ip4) params.set('ip4', ip4);
            if (ip6) params.set('ip6', ip6);
            if (metaIp4) params.set('metaIp4', metaIp4);
            if (metaIp6) params.set('metaIp6', metaIp6);
            if (cfDomain) params.set('cf', cfDomain);
            if (echDomain) params.set('ech', echDomain);
            btn.disabled = true;
            resultDiv.innerHTML = '<span class="loading">查询中…</span>';
            try {
                const res = await fetch('/api/query?' + params.toString());
                const data = await res.json();
                if (data.error) resultDiv.innerHTML = '<span class="error">错误：' + data.error + '</span>';
                else resultDiv.textContent = JSON.stringify(data, null, 2);
            } catch (err) {
                resultDiv.innerHTML = '<span class="error">网络错误：' + err.message + '</span>';
            } finally { btn.disabled = false; }
        }
    </script>
</body>
</html>`;
}

// 兼容 JSON 响应
function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
}