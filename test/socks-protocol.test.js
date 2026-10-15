import { describe, expect, it } from 'vitest';
import { parseSocks } from '../src/parsers/protocols/socksParser.js';
import { ProxyParser } from '../src/parsers/ProxyParser.js';
import { convertYamlProxyToObject } from '../src/parsers/convertYamlProxyToObject.js';
import { convertSurgeProxyToObject } from '../src/parsers/convertSurgeProxyToObject.js';
import { ClashConfigBuilder } from '../src/builders/ClashConfigBuilder.js';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';
import { SurgeConfigBuilder } from '../src/builders/SurgeConfigBuilder.js';

describe('socks share links', () => {
    it('parses socks5 userinfo, udp, and the fragment name', () => {
        const proxy = parseSocks('socks5://user:p%3Aass@1.2.3.4:1080?udp=1#home%20socks');
        expect(proxy).toEqual({
            tag: 'home socks',
            type: 'socks',
            server: '1.2.3.4',
            server_port: 1080,
            version: '5',
            username: 'user',
            password: 'p:ass',
            udp: true
        });
    });

    it('accepts socks:// without credentials and defaults the port to 1080', () => {
        const proxy = parseSocks('socks://example.com#plain');
        expect(proxy.server).toBe('example.com');
        expect(proxy.server_port).toBe(1080);
        expect(proxy.username).toBeUndefined();
        expect(proxy.password).toBeUndefined();
        expect(proxy.udp).toBeUndefined();
    });

    it('parses an IPv6 authority', () => {
        const proxy = parseSocks('socks5://[2001:db8::1]:1080#v6');
        expect(proxy.server).toBe('2001:db8::1');
        expect(proxy.server_port).toBe(1080);
        expect(proxy.tag).toBe('v6');
    });

    it('registers both schemes', async () => {
        const fromSocks = await ProxyParser.parse('SOCKS://example.com:1080#a');
        const fromSocks5 = await ProxyParser.parse('socks5://example.com:1080#b');
        expect(fromSocks.type).toBe('socks');
        expect(fromSocks5.type).toBe('socks');
    });

    it('writes Clash, sing-box, and Surge fields', () => {
        const proxy = parseSocks('socks5://user:secret@example.com:1080?udp=0#node');

        expect(ClashConfigBuilder.prototype.convertProxy(proxy)).toMatchObject({
            name: 'node',
            type: 'socks5',
            server: 'example.com',
            port: 1080,
            username: 'user',
            password: 'secret',
            udp: false
        });

        const singbox = SingboxConfigBuilder.prototype.convertProxy(proxy);
        expect(singbox.type).toBe('socks');
        expect(singbox.version).toBe('5');
        expect(singbox.username).toBe('user');
        expect(singbox.password).toBe('secret');
        expect(singbox.udp).toBeUndefined();

        const surge = SurgeConfigBuilder.prototype.convertProxy(proxy);
        expect(surge).toBe('node = socks5, example.com, 1080, username=user, password=secret');
    });

    it('reads Clash YAML and Surge socks5 nodes', () => {
        const yamlProxy = convertYamlProxyToObject({
            name: 'yaml-socks',
            type: 'socks5',
            server: 'example.com',
            port: 1080,
            username: 'user',
            password: 'secret',
            udp: true
        });
        expect(yamlProxy).toMatchObject({
            tag: 'yaml-socks',
            type: 'socks',
            version: '5',
            username: 'user',
            udp: true
        });

        const surgeProxy = convertSurgeProxyToObject('surge-socks = socks5, example.com, 1080, username=user, password=secret');
        expect(surgeProxy).toMatchObject({
            tag: 'surge-socks',
            type: 'socks',
            server_port: 1080,
            username: 'user',
            password: 'secret',
            version: '5'
        });
    });
});
