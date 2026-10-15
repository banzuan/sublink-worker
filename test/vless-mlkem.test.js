import { describe, expect, it } from 'vitest';
import { parseVless } from '../src/parsers/protocols/vlessParser.js';
import { convertYamlProxyToObject } from '../src/parsers/convertYamlProxyToObject.js';
import { ClashConfigBuilder } from '../src/builders/ClashConfigBuilder.js';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';

const REALITY_LINK = 'vless://580ef251-af2b-49f4-aea4-56a8a8f7a391@1.2.3.4:443?encryption=none&security=reality&type=tcp&sni=example.com&fp=chrome&pbk=testpublickey&sid=testsid';

describe('vless support-x25519mlkem768', () => {
    it('keeps the hint when the share link sets it true', () => {
        const proxy = parseVless(`${REALITY_LINK}&support-x25519mlkem768=true#mlkem`);
        expect(proxy.tls.reality.support_x25519mlkem768).toBe(true);
        expect(proxy.tls.reality.public_key).toBe('testpublickey');
    });

    it('drops the hint when it is absent or false', () => {
        expect(parseVless(`${REALITY_LINK}#plain`).tls.reality.support_x25519mlkem768).toBeUndefined();
        expect(parseVless(`${REALITY_LINK}&support-x25519mlkem768=false#off`).tls.reality.support_x25519mlkem768).toBeUndefined();
        expect(parseVless(`${REALITY_LINK}&support-x25519mlkem768=0#off`).tls.reality.support_x25519mlkem768).toBeUndefined();
    });

    it('emits the hint only on Clash reality-opts', () => {
        const proxy = parseVless(`${REALITY_LINK}&support-x25519mlkem768=1#mlkem`);
        const clash = ClashConfigBuilder.prototype.convertProxy(proxy);
        expect(clash['reality-opts']['support-x25519mlkem768']).toBe(true);
        expect(clash['reality-opts']['public-key']).toBe('testpublickey');

        const singbox = SingboxConfigBuilder.prototype.convertProxy(proxy);
        expect(singbox.tls.reality.support_x25519mlkem768).toBeUndefined();
        expect(singbox.tls.reality.public_key).toBe('testpublickey');
        expect(proxy.tls.reality.support_x25519mlkem768).toBe(true);
    });

    it('omits the Clash field when the hint is off', () => {
        const clash = ClashConfigBuilder.prototype.convertProxy(parseVless(`${REALITY_LINK}#plain`));
        expect(clash['reality-opts']).not.toHaveProperty('support-x25519mlkem768');
    });

    it('keeps the hint from Clash YAML', () => {
        const enabled = convertYamlProxyToObject({
            name: 'mlkem',
            type: 'vless',
            server: '1.2.3.4',
            port: 443,
            uuid: '580ef251-af2b-49f4-aea4-56a8a8f7a391',
            tls: true,
            'reality-opts': {
                'public-key': 'testpublickey',
                'short-id': 'testsid',
                'support-x25519mlkem768': true
            }
        });
        expect(enabled.tls.reality.support_x25519mlkem768).toBe(true);

        const disabled = convertYamlProxyToObject({
            name: 'plain',
            type: 'vless',
            server: '1.2.3.4',
            port: 443,
            uuid: '580ef251-af2b-49f4-aea4-56a8a8f7a391',
            tls: true,
            'reality-opts': {
                'public-key': 'testpublickey',
                'short-id': 'testsid',
                'support-x25519mlkem768': false
            }
        });
        expect(disabled.tls.reality.support_x25519mlkem768).toBeUndefined();
    });
});
