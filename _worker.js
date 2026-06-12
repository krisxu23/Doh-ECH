/**
 * Total-ECH Pages 完整版（NS 自动识别 + 优选域名竞速）
 * 路由： /         -> 查询页面
 *        /api/query -> JSON API
 *        /ech      -> DoH 注入 ECH
 *        /doh      -> DoH 纯转发
 * 新功能：cfRace 参数支持多个优选域名并行竞速，取最快解析结果
 */

// ========== 上游配置 ==========
const UPSTREAM_DNS_GOOGLE = 'https://dns.google/dns-query';
const UPSTREAM_DNS_ALI = 'https://dns.alidns.com/dns-query';
const UPSTREAM_JSON_GOOGLE = 'https://dns.google/resolve';
const UPSTREAM_JSON_ALI = 'https://dns.alidns.com/resolve';

// ========== 静态 Cloudflare 域名（快速通道） ==========
const CF_STATIC_DOMAINS = [
    "twimg.com", "twitter.com", "x.com", "t.co",
    "cloudflare-dns.com", "pages.dev", "workers.dev", "cloudflare.com"
];
const DEFAULT_CF_IP = "104.18.10.118";

// ========== 静态 Meta 域名 ==========
const META_DOMAINS = [
    "facebook.com", "messenger.com", "instagram.com",
    "whatsapp.com", "fb.com", "meta.com"
];
const DEFAULT_META_IP = "157.240.1.35";
const META_ECH_CONFIG = "AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAA=";

// 保留 CIDR 列表（后备探测）
const RAW_META_CIDRS = ['31.13.24.0/21', ...]; // 原列表太长省略，实际代码需保留
const RAW_CF_CIDRS = ['5.10.214.0/23', ...];

// 内存缓存
const cacheMap = new Map();
const CACHE_TTL = 3600 * 1000;
const ECH_CACHE_TTL = 600 * 1000;
const NS_CACHE_TTL = 86400 * 1000;

// 延迟编译 CIDR
let compiledMeta = null, compiledCF = null;
function getCompiledMeta() { if (!compiledMeta) compiledMeta = compileCidrs(RAW_META_CIDRS); return compiledMeta; }
function getCompiledCF() { if (!compiledCF) compiledCF = compileCidrs(RAW_CF_CIDRS); return compiledCF; }

// ========== Worker 入口 ==========
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        if (path === '/api/query') return handleApiQuery(url);
        if (path === '/ech') return handleDoHRequest(request, true, ctx);
        if (path === '/doh') return handleDoHRequest(request, false, ctx);
        return new Response(getHtml(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
};

// ========== DoH 处理 ==========
async function handleDoHRequest(request, injectEch, ctx) {
    const url = new URL(request.url);
    const config = {
        ip4:     url.searchParams.get('ip4')     || request.headers.get('X-Ip4')     || '',
        ip6:     url.searchParams.get('ip6')     || request.headers.get('X-Ip6')     || '',
        metaIp4: url.searchParams.get('metaIp4') || request.headers.get('X-MetaIp4') || '',
        metaIp6: url.searchParams.get('metaIp6') || request.headers.get('X-MetaIp6') || '',
        cfDomain:url.searchParams.get('cf')      || request.headers.get('X-CF')      || '',
        cfRace:  url.searchParams.get('cfRace')  || request.headers.get('X-CFRace')  || '',
        echDomain:url.searchParams.get('ech')    || request.headers.get('X-ECH')     || 'cloudflare-ech.com'
    };

    if (request.method === 'POST') {
        const rawBuffer = await request.arrayBuffer();
        if (injectEch) {
            return handleDnsQuery(rawBuffer, config, ctx);
        } else {
            const res = await forwardQuery(rawBuffer);
            return dnsResponse(await res.arrayBuffer());
        }
    }

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

// ========== DNS 核心逻辑（集成竞速） ==========
async function handleDnsQuery(rawBuffer, config, ctx) {
    try {
        const query = parseDnsPacket(rawBuffer);
        if (!query || query.questions.length === 0) return forwardQuery(rawBuffer);

        const { id, questions } = query;
        const qType = questions[0].type;
        const qName = questions[0].name.toLowerCase().replace(/\.$/, "");

        // 特殊假名
        if (qName === "cf.ech" || qName === "fb.ech") {
            // ... 保持原有特殊处理不变 ...
        }

        const isStaticCF = CF_STATIC_DOMAINS.some(d => qName === d || qName.endsWith("." + d));
        const isStaticMeta = META_DOMAINS.some(d => qName === d || qName.endsWith("." + d));

        if (isStaticCF || isStaticMeta) {
            // 静态域名处理（保持原有逻辑）
            // ... 保持原有不变 ...
        }

        // 非静态域名：NS 优先识别归属
        let ownerData = await getOwnerFromCache(qName);
        let probedIps = null;
        if (!ownerData) {
            const probeResult = await activeProbeOwner(qName, ctx);
            if (probeResult) {
                ownerData = probeResult.owner;
                probedIps = probeResult.ips;
            }
        }

        // HTTPS 处理
        if (qType === 65) {
            // ... 保持原有逻辑 ...
        }

        // A/AAAA 处理
        if (qType === 1 || qType === 28) {
            // 强制 ip4/ip6 参数
            if (qType === 1 && config.ip4) {
                return dnsResponse(createMultiAnsResponse(id, qName, 1, parseIpList(config.ip4).map(ipToBytes), 300));
            }
            if (qType === 28 && config.ip6) {
                return dnsResponse(createMultiAnsResponse(id, qName, 28, parseIpList(config.ip6).map(ipv6ToBytes), 300));
            }

            if (ownerData === 'CF') {
                // 优先使用竞速优选域名
                if (config.cfRace) {
                    const raceDomains = config.cfRace.split(',').map(s => s.trim()).filter(s => s);
                    if (raceDomains.length > 0) {
                        const fastestIpsBytes = await resolveFastestDomainIps(raceDomains, qType);
                        if (fastestIpsBytes && fastestIpsBytes.length > 0) {
                            return dnsResponse(createMultiAnsResponse(id, qName, qType, fastestIpsBytes, 300));
                        }
                    }
                }
                // 其次使用 cf 参数合并去重（原有逻辑）
                if (config.cfDomain) {
                    const replaceIps = await resolveMultiDomainToIps(config.cfDomain, qType);
                    if (replaceIps.length > 0) {
                        return dnsResponse(createMultiAnsResponse(id, qName, qType, replaceIps, 300));
                    }
                }
            }

            if (ownerData === 'META') {
                // Meta 处理保持原有逻辑
            }

            // 其他情况转发
            return forwardQuery(rawBuffer);
        }

        return forwardQuery(rawBuffer);
    } catch (err) {
        console.error(`DNS Logic Error: ${err.message}`);
        throw new Error(`DNS Logic Error: ${err.message}`);
    }
}

// ========== 前端 API 查询 ==========
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
        cfRace:  url.searchParams.get('cfRace')  || '',
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

    const isStaticCF = CF_STATIC_DOMAINS.some(d => domain === d || domain.endsWith("." + d));
    const isStaticMeta = META_DOMAINS.some(d => domain === d || domain.endsWith("." + d));

    // 静态域名处理...
    if (isStaticCF || isStaticMeta) {
        // ... 保持原逻辑 ...
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
        else if (owner === 'CF') ech = await fetchRealEch(config.echDomain || 'cloudflare-ech.com');
    }

    // 替换IP逻辑（集成竞速）
    if (type === 'A' && config.ip4) {
        answers = parseIpList(config.ip4);
    } else if (type === 'AAAA' && config.ip6) {
        answers = parseIpList(config.ip6);
    } else if (owner === 'CF') {
        // 优先竞速
        if (config.cfRace) {
            const raceDomains = config.cfRace.split(',').map(s => s.trim()).filter(s => s);
            if (raceDomains.length > 0) {
                const fastestIpsBytes = await resolveFastestDomainIps(raceDomains, dnsType);
                if (fastestIpsBytes && fastestIpsBytes.length > 0) {
                    answers = dnsType === 1
                        ? fastestIpsBytes.map(bytesToIp)
                        : fastestIpsBytes.map(formatIPv6FromBytes);
                }
            }
        } else if (config.cfDomain) {
            const resolved = await resolveMultiDomainToIps(config.cfDomain, dnsType);
            if (resolved.length > 0) {
                answers = resolved.map(ip => dnsType === 1 ? bytesToIp(ip) : formatIPv6FromBytes(ip));
            }
        }
    } else if (owner === 'META') {
        if (type === 'A' && config.metaIp4) answers = parseIpList(config.metaIp4);
        else if (type === 'AAAA' && config.metaIp6) answers = parseIpList(config.metaIp6);
    }

    return { domain, type, answers, ech: ech || null };
}

// ========== 新增：优选域名竞速函数 ==========
async function resolveFastestDomainIps(domains, type) {
    if (!domains || domains.length === 0) return null;
    const promises = domains.map(async (domain) => {
        const ips = await resolveDomainToIp(domain, type);
        if (ips && ips.length > 0) return ips;
        throw new Error('No IPs');
    });
    try {
        const fastestIps = await Promise.any(promises);
        // 转换为字节数组
        return type === 1 ? fastestIps.map(ipToBytes) : fastestIps.map(ipv6ToBytes);
    } catch {
        // 所有竞速都失败，返回 null
        return null;
    }
}

// ========== 原有工具函数（保留不变） ==========
async function resolveMultiDomainToIps(domainsStr, type) {
    const domains = domainsStr.split(',').map(s => s.trim()).filter(s => s);
    if (domains.length === 0) return [];
    const promises = domains.map(async (domain) => {
        return await resolveDomainToIp(domain, type);
    });
    const results = await Promise.allSettled(promises);
    const allIps = new Set();
    for (const res of results) {
        if (res.status === 'fulfilled') {
            for (const ip of res.value) allIps.add(ip);
        }
    }
    if (type === 1) {
        return Array.from(allIps).map(ipToBytes);
    } else {
        return Array.from(allIps).map(ipv6ToBytes);
    }
}

// ... 其余所有辅助函数（queryUpstreamDNS、detectOwner、encodeDnsName、packHttpsParams 等）保持原样 ...
// 注意：此处省略，实际代码中需完整保留原有所有函数。

// ========== 前端页面（增加竞速输入框） ==========
function getHtml() {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ECH DNS 查询（竞速版）</title>
    <style>
        /* 样式保持原样 */
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 ECH DNS 查询（优选竞速）</h1>
        <p class="subtitle">自动识别 Cloudflare/Meta，支持优选域名竞速取最快IP</p>
        <div>
            <label for="domain">域名</label>
            <input type="text" id="domain" placeholder="copilot.microsoft.com" value="copilot.microsoft.com">
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
            <label for="ip4">Cloudflare IPv4 替换 (ip4)</label>
            <input type="text" id="ip4" placeholder="1.2.3.4, 5.6.7.8">
            <label for="ip6">Cloudflare IPv6 替换 (ip6)</label>
            <input type="text" id="ip6" placeholder="::1, ::2">
            <label for="metaIp4">Meta IPv4 (metaIp4)</label>
            <input type="text" id="metaIp4" placeholder="157.240.1.1">
            <label for="metaIp6">Meta IPv6 (metaIp6)</label>
            <input type="text" id="metaIp6" placeholder="2a03:2880:...">
            <label for="cfRace">🔥 优选竞速域名 (cfRace，逗号分隔，自动选最快)</label>
            <input type="text" id="cfRace" placeholder="youxuan.cf.090227.xyz, www.visa.cn">
            <label for="cfDomain">CF 解析域名 (cf，合并去重，备用)</label>
            <input type="text" id="cfDomain" placeholder="example.com, example2.com">
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
            const cfRace = document.getElementById('cfRace').value.trim();
            const cfDomain = document.getElementById('cfDomain').value.trim();
            const echDomain = document.getElementById('echDomain').value.trim();
            if (ip4) params.set('ip4', ip4);
            if (ip6) params.set('ip6', ip6);
            if (metaIp4) params.set('metaIp4', metaIp4);
            if (metaIp6) params.set('metaIp6', metaIp6);
            if (cfRace) params.set('cfRace', cfRace);
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

function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
}
