import {sign, verify} from '../dist/src/index.js';
import {describe, it} from 'node:test';
import {ok, rejects} from 'node:assert/strict';

describe('signature', () => {
  it('should sign and verify a message', async () => {
    const message = 'Hello World!';
    const signature = 'secret_key';
    const signedMessage = await sign(message, signature);
    const verified = await verify(signedMessage, signature);
    ok(verified);
  });

  it('should return false if the key is invalid', async () => {
    const message = 'Hello World!';
    const signature = 'secret_key';
    const signedMessage = await sign(message, signature);
    const verified = await verify(signedMessage, 'invalid_key');
    ok(!verified);
  });

  it('should return false if the message is invalid', async () => {
    const message = 'Hello World!';
    const signature = 'secret_key';
    const signedMessage = await sign(message, signature);
    const tamparedMessage = signedMessage.split('').reverse().join('');
    const verified = await verify(tamparedMessage, signature);
    ok(!verified);
  });
});
