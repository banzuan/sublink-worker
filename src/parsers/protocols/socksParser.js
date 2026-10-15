import { parseBool } from '../../utils.js';

function decodeComponent(value) {
    if (!value) return '';
    try {
        return decodeURIComponent(value);
    } catch {
        return value;
    }
}

export function parseSocks(url) {
    let parsedUrl;
    try {
        parsedUrl = new URL(url);
    } catch {
        return undefined;
    }

    const scheme = parsedUrl.protocol.replace(':', '').toLowerCase();
    if (scheme !== 'socks' && scheme !== 'socks5') {
        return undefined;
    }

    const server = parsedUrl.hostname.startsWith('[') && parsedUrl.hostname.endsWith(']')
        ? parsedUrl.hostname.slice(1, -1)
        : parsedUrl.hostname;
    if (!server) return undefined;

    const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : 1080;
    const username = decodeComponent(parsedUrl.username);
    const password = decodeComponent(parsedUrl.password);
    const displayServer = server.includes(':') ? `[${server}]` : server;
    const tag = decodeComponent(parsedUrl.hash.slice(1)) || `SOCKS ${displayServer}:${port}`;
    const udp = parseBool(parsedUrl.searchParams.get('udp'));

    return {
        tag,
        type: 'socks',
        server,
        server_port: port,
        version: '5',
        ...(username ? { username } : {}),
        ...(password ? { password } : {}),
        ...(udp !== undefined ? { udp } : {})
    };
}
