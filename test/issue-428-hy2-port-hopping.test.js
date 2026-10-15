import { describe, it, expect } from 'vitest';
import { parseHysteria2 } from '../src/parsers/protocols/hysteria2Parser.js';
import { convertYamlProxyToObject } from '../src/parsers/convertYamlProxyToObject.js';
import { convertSurgeProxyToObject } from '../src/parsers/convertSurgeProxyToObject.js';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';
import { ClashConfigBuilder } from '../src/builders/ClashConfigBuilder.js';
import { SurgeConfigBuilder } from '../src/builders/SurgeConfigBuilder.js';

describe('issue #428: hysteria2 port hopping', () => {
    it('parses mport alias from share links', () => {
        const proxy = parseHysteria2('hysteria2://pass@example.com:443?mport=20000-30000&hop_interval=30&sni=example.com#hop');
        expect(proxy.ports).toBe('20000-30000');
        expect(proxy.hop_interval).toBe(30);
    });

    it('still parses the canonical ports param', () => {
        const proxy = parseHysteria2('hysteria2://pass@example.com:443?ports=20000-30000&hop-interval=15#hop');
        expect(proxy.ports).toBe('20000-30000');
        expect(proxy.hop_interval).toBe(15);
    });

    it('parses mport alias from Clash YAML proxies', () => {
        const proxy = convertYamlProxyToObject({
            name: 'hop',
            type: 'hysteria2',
            server: 'example.com',
            port: 443,
            password: 'pass',
            mport: '20000-30000',
            'hop-interval': 30
        });
        expect(proxy.ports).toBe('20000-30000');
        expect(proxy.hop_interval).toBe(30);
    });

    it('emits sing-box hysteria2 fields that sing-box accepts', () => {
        const converted = SingboxConfigBuilder.prototype.convertProxy({
            tag: 'hop',
            type: 'hysteria2',
            server: 'example.com',
            server_port: 443,
            password: 'pass',
            ports: '20000-30000',
            hop_interval: 30,
            up: 100,
            down: 200,
            auth: 'x',
            recv_window_conn: 1000,
            fast_open: true,
            tls: { enabled: true, server_name: 'example.com' }
        });

        expect(converted.server_ports).toEqual(['20000:30000']);
        expect(converted.hop_interval).toBe('30s');
        expect(converted.up_mbps).toBe(100);
        expect(converted.down_mbps).toBe(200);
        expect(converted).not.toHaveProperty('ports');
        expect(converted).not.toHaveProperty('up');
        expect(converted).not.toHaveProperty('down');
        expect(converted).not.toHaveProperty('auth');
        expect(converted).not.toHaveProperty('recv_window_conn');
        expect(converted).not.toHaveProperty('fast_open');
    });

    it('converts comma-separated port ranges for sing-box', () => {
        const converted = SingboxConfigBuilder.prototype.convertProxy({
            tag: 'hop',
            type: 'hysteria2',
            server: 'example.com',
            server_port: 443,
            ports: '20000-30000, 40000-50000'
        });
        expect(converted.server_ports).toEqual(['20000:30000', '40000:50000']);
    });

    it('reads a hop list from the official URI authority', () => {
        const proxy = parseHysteria2('hysteria2://pass@example.com:20000-50000/?sni=example.com#hop');
        expect(proxy.server).toBe('example.com');
        expect(proxy.server_port).toBe(20000);
        expect(proxy.ports).toBe('20000-50000');
    });

    it('reads mixed ports from the authority, including percent-encoded commas', () => {
        const proxy = parseHysteria2('hysteria2://pass@example.com:123%2C5000-6000/?insecure=1#hop');
        expect(proxy.server_port).toBe(123);
        expect(proxy.ports).toBe('123,5000-6000');
    });

    it('reads an IPv6 authority hop range', () => {
        const proxy = parseHysteria2('hysteria2://pass@[2001:db8::1]:20000-50000/#hop');
        expect(proxy.server).toBe('2001:db8::1');
        expect(proxy.server_port).toBe(20000);
        expect(proxy.ports).toBe('20000-50000');
    });

    it('does not invent hop ports for a single authority port', () => {
        const proxy = parseHysteria2('hysteria2://pass@example.com:443#hop');
        expect(proxy.server_port).toBe(443);
        expect(proxy.ports).toBeUndefined();
    });

    it('lets an explicit mport query override the authority hop list', () => {
        const proxy = parseHysteria2('hysteria2://pass@example.com:20000-50000?mport=40000-41000#hop');
        expect(proxy.ports).toBe('40000-41000');
    });

    it('parses a duration hop interval and ignores a random range', () => {
        const duration = parseHysteria2('hysteria2://pass@example.com:443?ports=20000-30000&hop-interval=30s#hop');
        expect(duration.hop_interval).toBe(30);

        const random = parseHysteria2('hysteria2://pass@example.com:443?ports=20000-30000&hop-interval=15-30#hop');
        expect(random.hop_interval).toBeUndefined();
    });

    it('parses a duration hop interval from Clash YAML', () => {
        const proxy = convertYamlProxyToObject({
            name: 'hop',
            type: 'hysteria2',
            server: 'example.com',
            port: 443,
            password: 'pass',
            ports: '20000-30000',
            'hop-interval': '30s'
        });
        expect(proxy.hop_interval).toBe(30);
    });

    it('writes Surge port-hopping and reads it back', () => {
        const line = SurgeConfigBuilder.prototype.convertProxy({
            tag: 'hop',
            type: 'hysteria2',
            server: 'example.com',
            server_port: 443,
            password: 'pass',
            ports: '123,5000-6000',
            hop_interval: 30,
            tls: { enabled: true, server_name: 'example.com' }
        });
        expect(line).toContain('port-hopping=123;5000-6000');
        expect(line).toContain('port-hopping-interval=30');

        const proxy = convertSurgeProxyToObject(line);
        expect(proxy.ports).toBe('123,5000-6000');
        expect(proxy.hop_interval).toBe(30);
        expect(proxy.server_port).toBe(443);
    });

    it('keeps Clash hysteria2 port hopping fields as-is', () => {
        const converted = ClashConfigBuilder.prototype.convertProxy({
            tag: 'hop',
            type: 'hysteria2',
            server: 'example.com',
            server_port: 443,
            password: 'pass',
            ports: '20000-30000',
            hop_interval: 30,
            tls: { enabled: true, server_name: 'example.com' }
        });

        expect(converted.ports).toBe('20000-30000');
        expect(converted['hop-interval']).toBe(30);
    });
});
