import { basicAuthorization } from './basicAuthorization.js';

function decode(header: string): string {
  expect(header.startsWith('Basic ')).toBe(true);
  return Buffer.from(header.slice('Basic '.length), 'base64').toString('utf-8');
}

describe('basicAuthorization', () => {
  // The decoded value is what the server sees before it decodes each half.
  // Each half must decode to the original with a form decoder (RFC 6749
  // Appendix B) and with decodeURIComponent (Keycard zones).
  it.each([
    { name: 'the RFC 6749 Appendix B input', id: 'c', secret: ' %&+£€', decoded: 'c:%20%25%26%2B%C2%A3%E2%82%AC' },
    { name: 'letters, digits and *-._', id: 'client-1', secret: 'Secret_2.*', decoded: 'client-1:Secret_2.*' },
    { name: "~ and !'()", id: 'c', secret: "a~!'()b", decoded: "c:a~!'()b" },
    { name: 'a colon in the client ID', id: 'ua:client', secret: 'shh', decoded: 'ua%3Aclient:shh' },
    { name: 'base64 characters in the secret', id: 'c', secret: 'a+b/c=', decoded: 'c:a%2Bb%2Fc%3D' },
    { name: 'a space and a percent sign', id: 'c', secret: 'a b%41', decoded: 'c:a%20b%2541' },
    { name: 'characters outside Latin-1', id: 'c', secret: 'pässwörd密码', decoded: 'c:p%C3%A4ssw%C3%B6rd%E5%AF%86%E7%A0%81' },
  ])('encodes $name', ({ id, secret, decoded }) => {
    const value = decode(basicAuthorization(id, secret));

    expect(value).toBe(decoded);
    const halves = value.split(':');
    expect(halves).toHaveLength(2);
    expect(halves.map((half) => new URLSearchParams(`v=${half}`).get('v'))).toEqual([id, secret]);
    expect(halves.map((half) => decodeURIComponent(half))).toEqual([id, secret]);
  });
});
