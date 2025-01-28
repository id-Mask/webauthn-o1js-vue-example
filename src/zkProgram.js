import {
  Struct,
  ZkProgram,
  Crypto,
  createForeignCurve,
  createEcdsa,
  Bool,
} from 'o1js';  
  
// init
export class Secp256r1 extends createForeignCurve(Crypto.CurveParams.Secp256r1) {}
export class EcdsaP256 extends createEcdsa(Secp256r1) {}

export class Params extends Struct({
  publicKey: Secp256r1,
  payload: Secp256r1.Scalar,
  signature: EcdsaP256,
}) {}

export const WebAuthnP256 = ZkProgram({
  name: 'webauthn-p256',
  publicInput: Params,
  publicOutput: Bool,
  methods: {
    verifySignature: {
      privateInputs: [],
      async method(params) {
        const { publicKey, payload, signature } = params;
        /*
          Use verify for a byte array of the unhashed payload.
          Use verifySignedHash for a hashed payload (parsed and supplied as scalar).
          https://github.com/o1-labs/o1js/blob/6ebbc23710f6de023fea6d83dc93c5a914c571f2/src/lib/provable/crypto/foreign-ecdsa.ts#L81-L102
        */
        const isValid = signature.verifySignedHash(payload, publicKey);
        return { publicOutput: isValid };
      },
    },
  },
});
