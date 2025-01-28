import { decodeFirstSync } from 'cbor-web';

// Helper function to decode base64url to Uint8Array
export const base64urlToBuffer = (base64url) => {
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
};

// Helper function to encode Uint8Array to base64url
export const bufferToBase64url = (buffer) => {
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

/*
  Parse public key from credentials.response.attestationObject
*/
export const parseAttestationObject = (attestationObject) => {
  // Decode the base64url to get the raw bytes
  // const attestationBuffer = base64urlToBuffer(attestationObject);

  // Decode the CBOR
  const attestationCbor = decodeFirstSync(attestationObject);

  // Get the authData from the attestation
  const { authData } = attestationCbor;

  // The public key starts after:
  // 32 bytes of RP ID hash
  // 1 byte of flags
  // 4 bytes of signature counter
  // 16 bytes of AAGUID
  // 2 bytes of credential ID length (L)
  // L bytes of credential ID
  let position = 32 + 1 + 4;

  // Skip AAGUID
  position += 16;

  // Get credential ID length
  const credentialIdLength = (authData[position] << 8) | authData[position + 1];
  position += 2;

  // Skip credential ID
  position += credentialIdLength;

  // The rest is the CBOR-encoded public key
  const publicKeyCose = authData.slice(position);
  const publicKeyObject = decodeFirstSync(publicKeyCose);

  // COSE key to JWK conversion
  // For ES256 (ECDSA with P-256 curve)
  const x = publicKeyObject.get(-2); // X coordinate
  const y = publicKeyObject.get(-3); // Y coordinate

  return {
    kty: 'EC',
    crv: 'P-256',
    x: bufferToBase64url(x),
    y: bufferToBase64url(y),
    ext: true,
  };
};

/*
  Parse the public key stored inside the attestationObject of credential:
*/
export const parsePublicKeyHex = (attestationObject) => {
  // Parse points
  const pk = parseAttestationObject(attestationObject);
  const xBuffer = base64urlToBuffer(pk.x);
  const yBuffer = base64urlToBuffer(pk.y);

  // Ensure both x and y are 32 bytes as expected for P-256
  if (xBuffer.length !== 32 || yBuffer.length !== 32) {
    throw new Error('Invalid x or y length for P-256 curve.');
  }

  // Create the uncompressed point buffer
  const uncompressedPoint = new Uint8Array([0x04, ...xBuffer, ...yBuffer]);
  const uncompressedPointHex = Array.from(uncompressedPoint)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  const publicKeyHex = '0x' + uncompressedPointHex;

  return publicKeyHex;
};

/*
  Read the signed payload into hex payload = hash(concat(authenticatorData, hashedClientDataJSON)):
*/
export const parsePayloadHex = async (clientDataJSON, authenticatorData) => {
  if (!crypto.subtle) {
    throw new Error('Web Crypto API is not supported in this browser.');
  }

  // const clientDataJSONBuffer = new TextEncoder().encode(clientDataJSON);
  const hashedClientDataJSON = await crypto.subtle.digest(
    'SHA-256',
    clientDataJSON
  );
  // const authenticatorDataBuffer = base64urlToBuffer(authenticatorData);
  console.log(authenticatorData);

  // concatenate
  const payload = new Uint8Array(
    authenticatorData.byteLength + hashedClientDataJSON.byteLength
  );
  payload.set(new Uint8Array(authenticatorData), 0);
  payload.set(
    new Uint8Array(hashedClientDataJSON),
    authenticatorData.byteLength
  );

  const hashedPayload = await crypto.subtle.digest('SHA-256', payload);
  const payloadHex =
    '0x' +
    Array.from(new Uint8Array(hashedPayload))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

  return payloadHex;
};

/*
  Parse signature stored inside the assertion response:
*/
export const parseSignatureHex = (signature) => {
  const readAsn1IntegerSequence = (input) => {
    if (input[0] !== 0x30) throw new Error('Input is not an ASN.1 sequence');
    const seqLength = input[1];
    const elements = [];

    let current = input.slice(2, 2 + seqLength);
    while (current.length > 0) {
      const tag = current[0];
      if (tag !== 0x02)
        throw new Error('Expected ASN.1 sequence element to be an INTEGER');

      const elLength = current[1];
      elements.push(current.slice(2, 2 + elLength));
      current = current.slice(2 + elLength);
    }
    return elements;
  };

  const convertEcdsaAsn1Signature = (input) => {
    const elements = readAsn1IntegerSequence(input);
    if (elements.length !== 2)
      throw new Error('Expected 2 ASN.1 sequence elements');
    let [r, s] = elements;

    // Each component should be 32 bytes for P-256
    const targetLength = 32;

    // Handle leading zeros properly
    r = r[0] === 0 ? r.slice(1) : r;
    s = s[0] === 0 ? s.slice(1) : s;

    // Pad if shorter than 32 bytes
    if (r.length < targetLength) {
      r = new Uint8Array([
        ...new Uint8Array(targetLength - r.length).fill(0),
        ...r,
      ]);
    }
    if (s.length < targetLength) {
      s = new Uint8Array([
        ...new Uint8Array(targetLength - s.length).fill(0),
        ...s,
      ]);
    }

    // Verify final lengths
    if (r.length !== targetLength || s.length !== targetLength) {
      throw new Error(
        `Invalid R or S length. Expected ${targetLength} bytes each`
      );
    }

    return new Uint8Array([...r, ...s]);
  };

  const signatureBuffer = base64urlToBuffer(signature);
  const signature_ = convertEcdsaAsn1Signature(signatureBuffer);
  const signatureHex =
    '0x' +
    Array.from(signature_)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

  return signatureHex;
};

/*
  Verify P-256 coordinates
*/
export const verifyP256Point = (x, y) => {
  // P-256 curve parameters
  const p = BigInt(
    '0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'
  ); // Prime modulus
  const a = BigInt(
    '0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC'
  ); // Curve coefficient a
  const b = BigInt(
    '0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B'
  ); // Curve coefficient b

  // Convert base64url to BigInt
  const xBuf = base64urlToBuffer(x);
  const yBuf = base64urlToBuffer(y);

  // Check lengths
  if (xBuf.length !== 32 || yBuf.length !== 32) {
    return false;
  }

  // Convert to BigInt
  const xInt = BigInt(
    '0x' +
      Array.from(xBuf)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
  );
  const yInt = BigInt(
    '0x' +
      Array.from(yBuf)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
  );

  // Verify point satisfies curve equation: y² = x³ + ax + b (mod p)
  const left = (yInt * yInt) % p;
  const right = (xInt * xInt * xInt + a * xInt + b) % p;

  return left === right;
};
