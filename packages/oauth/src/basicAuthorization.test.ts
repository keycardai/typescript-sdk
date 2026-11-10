import { basicAuthorization } from './basicAuthorization.js';

function decode(header: string): string {
  expect(header.startsWith('Basic ')).toBe(true);
  return Buffer.from(header.slice('Basic '.length), 'base64').toString('utf-8');
}

describe('basicAuthorization', () => {
  // The decoded value is what the server sees before it percent-decodes each half.
  it.each([
    { name: 'unreserved characters', id: 'client-1', secret: 'Secret_2.~', decoded: 'client-1:Secret_2.~' },
    { name: 'a colon in the client ID', id: 'ua:client', secret: 'shh', decoded: 'ua%3Aclient:shh' },
    { name: 'base64 characters in the secret', id: 'c', secret: 'a+b/c=', decoded: 'c:a%2Bb%2Fc%3D' },
    { name: 'a space and a percent sign', id: 'c', secret: 'a b%41', decoded: 'c:a%20b%2541' },
    { name: 'characters outside Latin-1', id: 'c', secret: 'pässwörd密码', decoded: 'c:p%C3%A4ssw%C3%B6rd%E5%AF%86%E7%A0%81' },
  ])('percent-encodes $name', ({ id, secret, decoded }) => {
    const value = decode(basicAuthorization(id, secret));

    expect(value).toBe(decoded);
    const [encodedId, encodedSecret] = value.split(':');
    expect([decodeURIComponent(encodedId), decodeURIComponent(encodedSecret)]).toEqual([id, secret]);
    expect([
      new URLSearchParams(`v=${encodedId}`).get('v'),
      new URLSearchParams(`v=${encodedSecret}`).get('v'),
    ]).toEqual([id, secret]);
  });
});
