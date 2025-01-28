<script setup>
import { ref, onMounted } from 'vue';
import {
  verifyP256Point,
  base64urlToBuffer,
  parseAttestationObject,
  parsePublicKeyHex,
  parsePayloadHex,
  parseSignatureHex,
} from './utils.js';
import {
  Secp256r1,
  EcdsaP256,
  WebAuthnP256,
  Params,
} from './zkProgram.js';
import { ec } from 'elliptic';

const generateRandomChallenge = () => {
  const challenge = new Uint8Array(32);
  window.crypto.getRandomValues(challenge);
  return challenge;
};

const toBase64 = (buffer) =>
  btoa(String.fromCharCode(...new Uint8Array(buffer)));

  const registerUser = async () => {
  const publicKey = {
    rp: {
      name: 'raidas',
    },
    user: {
      id: Uint8Array.from('raidas', (c) => c.charCodeAt(0)),
      name: 'raidas_name',
      displayName: 'raidsa_display',
    },
    pubKeyCredParams: [
      {
        type: 'public-key',
        alg: -7,
      },
    ],
    attestation: 'direct',
    timeout: 60000,
    challenge: generateRandomChallenge(),
  };

  const credential = await navigator.credentials.create({ publicKey });
  console.log(credential);

  // parse objects
  const publicKeyHex = parsePublicKeyHex(credential.response.attestationObject);
  console.log(publicKeyHex);
};

const askForAnyKey = async () => {
  const publicKey = {
    challenge: generateRandomChallenge(),
    allowCredentials: [
      {
        type: 'public-key',
        id: base64urlToBuffer('KSA7G0BCX9LkRNUHLYlFuQ'),
        transports: [],
      },
    ],
    userVerification: 'preferred',
  };
  const assertion = await navigator.credentials.get({ publicKey });

  if (assertion) {
    console.log(assertion);
    const payloadHex = await parsePayloadHex(
      assertion.response.clientDataJSON,
      assertion.response.authenticatorData
    );
    console.log(payloadHex);
    const singatureHex = await parseSignatureHex(
      toBase64(assertion.response.signature)
    );
    console.log(singatureHex);

    await verify_elliptic(
      '0x040cdb8e9fb984e9f75e4e8df69475cc7ff0d4d2f88c16d31ea861a2b562d62ebb82538ff6baeab63e6e62cad57e6cec3007db70901d66de253e964bae6293e7e9',
      payloadHex,
      singatureHex
    );
  }
};

const verify_o1js = async (
  publicKeyHex,
  payloadHex,
  signatureHex
) => {
  // parse hex values
  const publicKey_ = Secp256r1.fromHex(publicKeyHex);
  const payload_ = Secp256r1.Scalar.from(payloadHex);
  const signature_ = EcdsaP256.fromHex(signatureHex);

  // run zk program
  await WebAuthnP256.compile();
  const isvalid = await WebAuthnP256.verifySignature({
    publicKey: publicKey_,
    payload: payload_,
    signature: signature_,
  });

  console.log('signature is valid: ', isvalid.proof.publicOutput.toBoolean());
  return isvalid.proof.publicOutput.toBoolean();
};

const verify_crypto = async (publicKeyHex, payloadHex, signatureHex) => {
  // Remove '0x' prefix if present
  publicKeyHex = publicKeyHex.replace('0x', '');
  payloadHex = payloadHex.replace('0x', '');
  signatureHex = signatureHex.replace('0x', '');

  // Convert hex strings to Uint8Array
  const publicKeyBytes = new Uint8Array(
    publicKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
  );
  const payloadBytes = new Uint8Array(
    payloadHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
  );
  const signatureBytes = new Uint8Array(
    signatureHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
  );

  // Import the public key
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    publicKeyBytes,
    {
      name: 'ECDSA',
      namedCurve: 'P-256' // Adjust if using a different curve
    },
    true,
    ['verify']
  );

  // Verify the signature
  const isValid = await crypto.subtle.verify(
    {
      name: 'ECDSA',
      hash: 'SHA-256'
    },
    cryptoKey,
    signatureBytes,
    payloadBytes
  );
  console.log('signature is valid:', isValid)
  return isValid;
};

const verify_elliptic = (publicKeyHex, payloadHex, signatureHex) => {

  const hexToUint8Array = (hex) => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  };

  const ec_ = new ec('p256');

  // Remove '0x' prefix if present
  publicKeyHex = publicKeyHex.replace('0x', '');
  payloadHex = payloadHex.replace('0x', '');
  signatureHex = signatureHex.replace('0x', '');

  // Convert hex strings to buffers
  const publicKeyBytes = hexToUint8Array(publicKeyHex);
  const payloadBytes = hexToUint8Array(payloadHex);
  const signatureBytes = hexToUint8Array(signatureHex);

  // Import the public key
  const publicKey = ec_.keyFromPublic(publicKeyBytes, 'hex');

  // Split the signature into r and s components
  const r = signatureBytes.slice(0, 32); // First 32 bytes
  const s = signatureBytes.slice(32, 64); // Next 32 bytes

  // Verify the signature
  const isValid = publicKey.verify(payloadBytes, { r, s });
  console.log('signature is valid:', isValid);
  return isValid;
};

</script>

<template>
  <button @click="registerUser">register</button>
  <button @click="askForAnyKey">authenticate</button>
</template>

<style scoped></style>