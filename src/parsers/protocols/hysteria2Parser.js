import { parseServerInfo, parseUrlParams, createTlsConfig, parseMaybeNumber, parseHopInterval, parseArray, parseBool } from '../../utils.js';

// Official URIs put the hop list in the authority (`host:20000-50000`). parseInt keeps only the first number.
function authorityHopPorts(portText) {
    if (!portText) return undefined;
    let text = String(portText).trim();
    // A fragment can sit on the authority when the link has no query string.
    const hashIndex = text.indexOf('#');
    if (hashIndex !== -1) text = text.slice(0, hashIndex);
    text = text.replace(/\/+$/, '');
    try {
        text = decodeURIComponent(text);
    } catch {
        // Keep the raw port text when it is not valid percent-encoding.
    }
    if (!/[,-]/.test(text)) return undefined;
    // `host:23200,47000-50000` puts the primary listen port first. Clients ignore
    // that port once a hop list is set, so it must not be repeated there.
    const comma = text.indexOf(',');
    if (comma !== -1) {
        const first = text.slice(0, comma).trim();
        const rest = text.slice(comma + 1).trim();
        if (/^\d+$/.test(first) && rest) return rest;
    }
    return text;
}

export function parseHysteria2(url) {
    const { addressPart, params, name } = parseUrlParams(url);
    let host;
    let port;
    let portText;
    let password = null;

    if (addressPart.includes('@')) {
        const [uuid, serverInfo] = addressPart.split('@');
        const parsed = parseServerInfo(serverInfo);
        host = parsed.host;
        port = parsed.port;
        portText = parsed.portText;
        password = decodeURIComponent(uuid);
    } else {
        const parsed = parseServerInfo(addressPart);
        host = parsed.host;
        port = parsed.port;
        portText = parsed.portText;
        password = params.auth;
    }

    // Hysteria2 requires TLS by protocol design
    if (!params.security) params.security = 'tls';
    const tls = createTlsConfig(params);
    const obfs = {};
    if (params['obfs-password']) {
        obfs.type = params.obfs;
        obfs.password = params['obfs-password'];
    }

    const hopInterval = parseHopInterval(params['hop-interval'] ?? params['hop_interval']);

    return {
        tag: name,
        type: 'hysteria2',
        server: host,
        server_port: port,
        password: password,
        tls,
        obfs: Object.keys(obfs).length > 0 ? obfs : undefined,
        auth: params.auth,
        recv_window_conn: params.recv_window_conn,
        up: params.up ?? (params.upmbps ? parseMaybeNumber(params.upmbps) : undefined),
        down: params.down ?? (params.downmbps ? parseMaybeNumber(params.downmbps) : undefined),
        ports: params.mport || params.ports || authorityHopPorts(portText),
        hop_interval: hopInterval,
        alpn: parseArray(params.alpn),
        fast_open: parseBool(params['fast-open'])
    };
}
