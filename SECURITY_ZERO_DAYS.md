# Zero-days encontrados en Session Desktop 1.18.3 (recepción de mensajes remotos)

**Base:** `dev` @ `b4f92b3` (v1.18.3) · **Método:** análisis estático dirigido al *message pipeline* +
PoCs ejecutables · **Estado:** los 4 están corregidos en esta rama.

> Nota de actualización: ZD-4 se encontró en la tercera pasada (barrido de regex con `recheck` +
> revisión de la ruta de comunidades SOGS v4).

Todo lo que hay aquí es alcanzable **por un tercero cualquiera de la red Session**, sin interacción del
usuario y **sin que acepte la solicitud de mensaje**: los mensajes de desconocidos se descifran y se
procesan (solo no se descargan los adjuntos ni se aprueba la conversación). No dependen de ninguna
librería de terceros ni de una versión vulnerable de una dependencia: son fallos del propio código.

> Aviso de honestidad, igual que en `SECURITY_AUDIT.md`: no he podido compilar ni ejecutar la app en
> este entorno (faltan `node_modules`, los submódulos y `protobuf/compiled.js`). Las PoCs reproducen
> la lógica y el SQL **exactos** del cliente (copiados literalmente de `ts/node/sql.ts`), no el binario
> completo. Las correcciones están verificadas por sintaxis (`typescript.transpileModule`) y revisión,
> no por `tsc --noEmit` ni por la suite de tests. Antes de publicar nada, valida en un build real.

---

## ZD-1 · Resolución de reacciones y citas *cross-conversation* (autorización)

**Severidad:** Media-Alta (integridad; mutación de mensajes de conversaciones ajenas)
**Componentes:** `ts/util/reactions.ts` (`getMessageByReaction`), `ts/receiver/queuedJob.ts`
(`pushQuotedMessageToStoreIfNeeded`), `ts/state/ducks/conversations.ts` (`lookupQuoteInStore`)
**PoC:** `security-poc/01_cross_conversation_reaction_quote.mjs` (reproduce el fallo y el arreglo)

### El fallo

El sobre (envelope) autentica **quién** envía la reacción, pero no **a qué mensaje apunta**. Ese
"a qué" viene del protobuf remoto:

```ts
// ts/receiver/dataMessage.ts
const addedToMessage = await Reactions.handleMessageReaction({
  reaction: rawDataMessage.reaction,          // <-- remoto, sin autenticar
  sender: msgModel.get('source'),             //    autenticado (autor del envelope)
  you: isUsFromCache(msgModel.get('source')),
});
```

y se resolvía así:

```ts
// ts/util/reactions.ts (v1.18.3)
const collection = await Data.getMessagesBySentAt(originalMessageId);   // SELECT ... WHERE sent_at = ?
originalMessage = collection.find(item => item.get('sent_at') === id && item.get('source') === author);
```

`getMessagesBySentAt` **no filtra por `conversationId`**, y `getMessagesBySenderAndSentAt` (usada por
las citas) tampoco: `SELECT json FROM messages WHERE source = $source AND sent_at = $timestamp`.

Resultado: una reacción recibida en la conversación con Mallory se aplica a un mensaje de la
conversación con Alice, si Mallory acierta `(author, sent_at)` de ese mensaje.

Esto no es teórico: `sent_at` y el autor de los mensajes de **cualquier miembro de un grupo o
comunidad** son visibles para el resto de miembros (todos reciben los mismos `sent_at`), y el pubkey
`05…` de una persona es público por diseño. Es decir, **cualquier miembro de un grupo del que
participe Alice puede fabricar reacciones que se aplicarán a los mensajes de Alice en las
conversaciones privadas de la víctima con ella**, y una reacción a un mensaje *nuestro* dispara además
una notificación (`throttledNotify`).

En el caso de las **citas** el efecto es de *lectura cross-contexto*: el cliente resuelve el mensaje
citado por `(author, sent_at)` y renderiza su texto/adjuntos dentro del mensaje del atacante, es decir,
el atacante puede hacer que la víctima vea contenido de otra conversación dentro de su chat. El
`quote` que se envía hoy solo lleva `{timestamp, author}` (`MessageModel.getQuotedMessage()`), así que
**no** hay exfiltración automática del cuerpo citado: el riesgo es de integridad / ingeniería social
(hacer creer a la víctima que alguien dijo algo en otro contexto). Verificado, no lo inflo.

Prueba de que la intención del código era la contraria: `MessageModel.getQuotedMessageAuthorIsUs()`
**sí** resuelve la cita con `Data.getMessagesByConvoIdAndSentAt([{ convoId, sentAt }])`. El propio repo
tiene la versión correcta en otro sitio.

### PoC

```
$ node --experimental-sqlite security-poc/01_cross_conversation_reaction_quote.mjs
=== VULNERABLE (v1.18.3) ===
[reaction] received in conversation 0533333333… resolved to: [ '0511111111… "the safe code is 4321"' ]
[quote]    received in conversation 0533333333… resolved to: [ '0511111111… "the safe code is 4321"' ]
=== FIXED ===
[reaction] same attack, lookup scoped to the receiving conversation: no target found -> reaction dropped ✔
```

Mensaje que envía el atacante (1:1, sin que la víctima haya aceptado nada), en protobuf:

```proto
Content {
  dataMessage {
    reaction { emoji: "🔥" action: REACT id: <sent_at de un mensaje de Alice> author: "<pubkey de Alice>" }
    sigTimestamp: <sent_at del envelope>          // debe coincidir, o omitirse (ver ZD-2)
  }
}
```

### Corrección

* `getMessageByReaction(reaction, { conversationId, openGroupConversationId })`: el mensaje objetivo
  se busca **solo dentro de la conversación** en la que llegó la reacción
  (`item.get('conversationId') === conversationId`). Si no se pasa conversación, **se rechaza** la
  reacción (antes se hacía la búsqueda global por defecto).
* `handleMessageReaction` acepta y propaga `conversationId`; actualizados los 4 puntos de llamada
  (`dataMessage.ts` = entrante, `conversation.ts` ×3 = saliente local, `sogsV3SendReaction.ts` usa la
  rama de comunidad, ya acotada por `serverId`).
* `pushQuotedMessageToStoreIfNeeded(quote, conversationId)`: filtra el resultado de SQL por
  `conversationId` y rechaza citas sin conversación o sin id válido.
* `lookupQuoteInStore({ timestamp, conversationId, ... })`: el match en redux también exige
  `propsForMessage.convoId === conversationId`; `removeQuotedMessageProps` pasa el `convoId` del
  mensaje que cambia (antes podía borrar la cita equivocada si dos conversaciones compartían timestamp).

---

## ZD-2 · *Pinning* permanente de una conversación con un `sent_at` futuro (DoS remoto persistente)

**Severidad:** Media-Alta (DoS persistente y silencioso, cero interacción, sobrevive reinicios)
**Componentes:** `ts/receiver/common.ts` (`shouldProcessContentMessage`), efecto en
`ts/receiver/dataMessage.ts` / `ts/receiver/queuedJob.ts` (`setActiveAt`)
**PoC:** `security-poc/02_future_timestamp_pin.mjs`

### El fallo

```ts
// v1.18.3
if (!sentAtMs || !longOrNumberToNumber(sigTimestampMs)) {
  return true;                       // "legacy client" -> se procesa sin comprobar NADA
}
...
return envelopeTimestamp === contentTimestamp;
```

Nunca se acota `sent_at` **por arriba**: el emisor lo elige libremente, y si omite `sigTimestamp` del
protobuf ni siquiera se compara con el del contenido. Después:

```ts
conversation.setActiveAt(Math.max(conversation.getActiveAt() || 0, sent_at));
if (!activeAt || sent_at > activeAt) { conversation.setLastMessage(...) }
```

con `active_at` **persistido en SQLite**. Un único mensaje fechado en 2077 deja la conversación:

* clavada arriba en el panel izquierdo para siempre,
* sin actualizar el preview del último mensaje para **todos** los mensajes reales posteriores
  (el usuario ve "hi" del atacante y no ve nada de lo que le escriben de verdad),
* y no se arregla reiniciando la app; solo borrando la conversación.

Además descoloca los temporizadores de mensajes efímeros, que se calculan a partir de `sent_at`.

### PoC

```
$ node --experimental-sqlite security-poc/02_future_timestamp_pin.mjs
=== VULNERABLE (v1.18.3) ===
1) attacker message dated +50y: stored, last message updated
2) real message from the same contact, 1 min later: stored, last message NOT updated
   conversation active_at now: 2076-10-11T21:57:59.485Z
   last message shown to the victim: "hi"
=== FIXED ===
1) attacker message dated +50y: dropped (sent_at too far in the future)
2) real message from the same contact, 1 min later: stored, last message updated
   last message shown to the victim: "are you there?"
```

### Corrección

`shouldProcessContentMessage()` rechaza cualquier mensaje con `sent_at > NetworkTime.now() + 24h`
(`MAX_FUTURE_MESSAGE_SKEW_MS`). Se aplica a mensajes de swarm **y** de comunidad (el `posted` del
servidor tampoco es de fiar). Se deja 1 día de margen por desfase de reloj; ajustable.

*Riesgo residual:* sigue permitido "envenenar" hasta +24h. Si se quiere cerrar del todo, hay que
clampear `active_at` (no confiar en `sent_at` remoto para ordenar) — cambio mayor, anotado en el audit.

---

## ZD-3 · Replay de `OFFER` de llamada por un `Math.max()` mal usado

**Severidad:** Media (spam/DoS de llamadas entrantes por replay; sin límite de tasa entrante)
**Componente:** `ts/receiver/callMessage.ts`
**PoC:** `security-poc/03_call_offer_replay.mjs`

```ts
// v1.18.3
if (Math.max(envelope.sentAtMs - NetworkTime.now()) > TTL_DEFAULT.CALL_MESSAGE) { drop }
```

`Math.max()` con **un solo argumento** es la función identidad: el chequeo solo descarta ofertas
fechadas en el futuro, nunca las viejas. La intención obvia era `Math.abs(...)`. Cualquier usuario
puede reenviar una `OFFER` antigua (o un snode malicioso reinjectarla) y hacer sonar el teléfono de la
víctima con una llamada obsoleta, repetidamente.

```
$ node security-poc/03_call_offer_replay.mjs
offer                              | v1.18.3  | fixed
stale offer (now - 6h)             | RINGS    | drop
stale offer (now - 30d)            | RINGS    | drop
```

**Corrección:** `Math.abs(envelope.sentAtMs - NetworkTime.now()) > TTL_DEFAULT.CALL_MESSAGE`.

---

## ZD-4 · Suplantación de remitente en comunidades: la firma Ed25519 se valida por entrada pero se atribuye por `data` (bypass de autenticación)

**Severidad:** Alta (rompe la única garantía criptográfica frente al servidor de comunidad)
**Componentes:** `ts/session/apis/open_group_api/sogsv3/sogsApiV3.ts:146` (`filterOutMessagesInvalidSignature`),
`ts/webworker/workers/node/util/util.worker.ts:94` (`verifyAllSignatures`)
**PoC:** `security-poc/04_sogs_signature_dealias.mjs` (criptografía real, Ed25519, no simulada)

### El fallo

En las comunidades (SOGS v3/v4) el servidor **no es de confianza**: por eso cada mensaje viene con una
firma Ed25519 sobre el blob `data`, y el cliente comprueba esa firma antes de atribuir el mensaje a
`session_id`. El problema es **cómo** se empareja la validación con el mensaje:

```ts
// util.worker.ts — devuelve los PAYLOADS validados, no las entradas
if (valid) {
  checked.push(unchecked.base64EncodedData);   // ← solo el string base64
}

// sogsApiV3.ts — re-asocia por igualdad de string, con .find()
const signaturesValidMessages = compact(
  (signatureValidEncodedData || []).map(validData =>
    messagesFilteredBlindedIds.find(m => m.data === validData)   // ← primera entrada con ese data
  )
);
```

`verifyAllSignatures` valida el par `(session_id, data, signature)` de **cada entrada**, pero devuelve el
`data`. El llamador busca **la primera** entrada del lote cuyo `data` coincida. Si dos entradas del
mismo lote comparten `data` (mismo blob, distinto `session_id`), la firma válida del atacante "admite"
la entrada del otro remitente, cuya firma es inválida y **nunca se vuelve a comprobar**.

El blob `data` en SOGS es cifrado **simétrico** con la clave derivada de la pubkey del servidor: es
público para todos los miembros y para el servidor. Cualquiera puede copiar el blob exacto.

### PoC

Escenario: respuesta de poll con el mismo `data` dos veces (la primera entrada con `session_id` de la
víctima y firma basura; la segunda con la firma real del atacante sobre ese mismo blob):

```
$ node security-poc/04_sogs_signature_dealias.mjs
--- estado inicial ---
victim  : 15cb1fd242d7b9…
attacker: 15e8f003f23f1e…
data (mismo blob en las 2 entradas): VGhpcyBtZXNzYWdlIGlzIGVu…
firma de la entrada 1 (atribuida a la víctima) es válida? false

=== CLIENTE SIN PARCHEAR ===
entradas que pasan el filtro de firma: [ '15cb1fd242d7b9… (seqno 101)' ]
=> el mensaje se procesa y se guarda como enviado por: LA VÍCTIMA  <-- SUPLANTACIÓN
   (source/senderIdentity del SogsDecodedEnvelope = 15cb1fd242d7b9…)

=== CLIENTE PARCHEADO ===
entradas que pasan el filtro de firma: [ '15e8f003f23f1e… (seqno 102)' ]
=> el mensaje se atribuye a: el atacante (correcto)

--- variante B: dos entradas legítimas, mismo blob ---
sin parchear, entradas devueltas: [ '15cb1fd242d7b9…', '15cb1fd242d7b9…' ]
parcheado, entradas devueltas: [ '15cb1fd242d7b9…', '15e8f003f23f1e…' ]
```

Impacto: el mensaje se procesa con `source`/`senderIdentity` = el remitente elegido por quien controla
la respuesta, así que aparece en la UI como **escrito por esa persona**, y todas las decisiones
posteriores (menciones, `isUs`, respuestas, reacciones de esa conversación) usan esa identidad falsa.
En la variante B el efecto secundario es el inverso: el mensaje legítimo del atacante **desaparece**
silenciosamente (supresión).

### Precondición, dicha sin adornos

Para controlar `session_id` de una entrada ajena hace falta controlar la respuesta del servidor
(servidor de comunidad malicioso/comprometido, MITM sobre un servidor que se sirve en claro, o una
implementación de SOGS que acepte el `public_key` que el cliente envía en el POST — el cliente **sí**
envía `public_key` en `toJson()`). No es una inyección desde una cuenta normal contra un servidor
honesto: en ese caso el servidor deriva `session_id` de la clave autenticada. Pero el objetivo exacto
de esta comprobación de firma es proteger al usuario **de su propio servidor**, y tal como está escrita
no lo hace: el servidor puede firmar un blob con su propia cuenta y presentarlo como de cualquier
miembro (administradores incluidos), y el cliente lo acepta.

### Corrección

`verifyAllSignatures` devuelve ahora los **índices** de las entradas validadas (`Array<number>`), y
`filterOutMessagesInvalidSignature` atribuye **por índice**, con una comprobación extra de que el
payload que se atribuye es exactamente el que se validó (defensa en profundidad). También se ignoran
entradas sin `data`/`signature`/`sender` en vez de mandarlas al verificador.

---

## Qué NO he encontrado (para acotar expectativas)

Barrido automatizado de los 101 literales regex de `ts/**/*.{ts,tsx}` con `recheck@4`: los candidatos
que marca (p. ej. `MessageBodyHighlight`, ```` ``` ````-fences de `MessageBody.tsx`, el `OUTER_WHITESPACE_REGEX`
de `ts/session/utils/String.ts`) **no son explotables**: los dos primeros solo se aplican a texto local
que el usuario escribe en el compositor, y en `String.ts`, `loggerTimed.ts` y `privacy.ts` los prefijos
son literales de un solo carácter, así que recheck produce un falso positivo (no hay ambigüedad de
partición). Sin ReDoS remoto.

He revisado los sumideros clásicos y **no** he encontrado un RCE ni un XSS explotable:

* `dangerouslySetInnerHTML` solo en `SessionHtmlRenderer`, con DOMPurify + `ALLOWED_TAGS`/`ALLOWED_ATTR`.
* Sin `eval` / `new Function` / `vm` en todo el árbol.
* SQL parametrizado en todo `ts/node/sql.ts` salvo el `PRAGMA rekey` (corregido en el audit anterior).
* Las reacciones usan el `sender` autenticado del envelope, **no** `reaction.author`, para el "quién"
  (el bug ZD-1 es el "a qué", no el "quién").
* Los mensajes de configuración (`configurationMessage`) no se procesan desde contenido de terceros:
  van por el namespace propio del usuario y por `configMessage.ts`.
* `memberSessionIds` / `messageHashes` de protobuf se decodifican como arrays vacíos con protobufjs,
  así que el `TypeError` que "arreglé" en el audit anterior **no era alcanzable** por red (queda como
  defensa en profundidad).

El vector más grave que queda abierto sigue siendo arquitectónico, no un bug puntual: `SEC-01` del
audit (renderer con `nodeIntegration:true` + `contextIsolation:false`), que convierte cualquier XSS
futuro en ejecución de código en el sistema.

---

## Ficheros tocados por estos arreglos

```
ts/util/reactions.ts                        (ZD-1)
ts/receiver/dataMessage.ts                  (ZD-1)
ts/receiver/queuedJob.ts                    (ZD-1)
ts/models/conversation.ts                   (ZD-1, call sites)
ts/state/ducks/conversations.ts             (ZD-1)
ts/receiver/common.ts                       (ZD-2)
ts/receiver/callMessage.ts                  (ZD-3)
ts/session/apis/open_group_api/sogsv3/sogsApiV3.ts        (ZD-4)
ts/webworker/workers/node/util/util.worker.ts             (ZD-4)
security-poc/01_cross_conversation_reaction_quote.mjs
security-poc/02_future_timestamp_pin.mjs
security-poc/03_call_offer_replay.mjs
security-poc/04_sogs_signature_dealias.mjs
```

Verificación recomendada en un build funcional:

```sh
pnpm install && git submodule update --init --recursive && pnpm build:protobuf
pnpm tsc --noEmit && pnpm test
# y añadir tests de receptor con: reacción cross-conversation, quote cross-conversation,
# mensaje con sent_at=+50y, OFFER de hace 30 días.
```
