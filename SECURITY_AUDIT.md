# Auditoría de seguridad — Session Desktop (`session-desktop`, v1.18.3)

**Alcance:** todo el código JavaScript/TypeScript del repositorio (`ts/**`, `preload.js`, `about_preload.js`,
`password_preload.js`, `build/*`, `package.json`), ~156 000 líneas / 989 ficheros `.ts(x)`.
**Fecha:** 2026-10-24. **Base:** `dev` @ `b4f92b3`.

---

## 0. Veredicto honesto sobre el «0 riesgos»

**No es posible garantizar «0 riesgos»** en una aplicación de este tamaño, y cualquier informe que lo
prometa está mintiendo. Lo que sí se ha hecho aquí:

* Revisión manual dirigida de **todas las superficies de ataque reales** de un cliente de mensajería
  de escritorio: modelo de proceso de Electron, manejadores IPC del proceso principal, protocolos
  personalizados, actualizador automático, empaquetado (AppImage/deb/NSIS), manejo de adjuntos
  (descarga, descifrado, escritura en disco), parseo de mensajes remotos (protobuf), grupos v2,
  comunidades/SOGS, file server v2, onion v4, previsualización de enlaces, base de datos SQLCipher,
  contraseñas y bloqueo, registro de logs y redacción de datos sensibles.
* **13 hallazgos corregidos en código** en esta sesión (ver §2), incluidos 3 de severidad alta.
* **1 riesgo crítico arquitectónico que no se puede corregir sin un refactor grande** y que debe
  planificarse (SEC‑01). Mientras exista, la superficie de impacto de cualquier inyección en el
  renderer es ejecución de código arbitrario.
* Una lista explícita de lo que **no** cubre esta auditoría (§6) y de las comprobaciones que salieron
  limpias (§5), para que no se confunda «revisado y correcto» con «no revisado».

Conclusión: el código está, en general, **por encima de la media** en higiene de seguridad
(saneado de HTML con DOMPurify, validación de `attachmentCount`, ventanas/webviews bloqueadas,
permisos denegados por defecto, `linkify` endurecido, onion v4 con AES‑GCM autenticado). Los
problemas serios están en la **arquitectura de proceso de Electron** y en el **empaquetado /
actualización**, no en la criptografía del protocolo (que además vive en `libsession`, un binario
nativo fuera de este repositorio).

---

## 1. Resumen de hallazgos

| ID | Severidad | Título | Estado |
|----|-----------|--------|--------|
| SEC‑01 | **Crítica** (arquitectura) | Renderer sin aislamiento: `nodeIntegration:true` + `contextIsolation:false` en las 3 ventanas | **Abierto** (plan de migración §4) |
| SEC‑02 | **Alta** | AppImage elimina `chrome-sandbox` y arranca con `--no-sandbox` ⇒ sandbox del SO desactivada | **Corregido** |
| SEC‑03 | **Alta** | `verifyUpdateCodeSignature: false` ⇒ auto‑update de Windows sin verificar la firma del instalador | **Corregido** |
| SEC‑04 | **Alta** | Handler `file://`: confusión de prefijo de directorio + excepción no capturada | **Corregido** |
| SEC‑05 | **Alta** | Inyección en el `PRAGMA rekey` de SQLCipher (frase de contraseña interpolada, validación solo en el renderer) | **Corregido** |
| SEC‑06 | Media | Descarga de adjuntos sin límite de tamaño ⇒ agotamiento de memoria/DoS remoto | **Corregido** |
| SEC‑07 | Media | SSRF / sondeo de red local vía previsualización de enlaces | **Corregido** |
| SEC‑08 | Media | Verificación de digest de adjunto truncable a 1 byte | **Corregido** |
| SEC‑09 | Media | Hash de contraseña con comparación no constante; sin límite de intentos al desbloquear | **Parcial** (comparación corregida; falta *rate limiting*) |
| SEC‑10 | Media | DoS por `memberSessionIds` ausente en cambios de miembro de grupo v2 | **Corregido** |
| SEC‑11 | Baja | El renderer puede inyectar una versión arbitraria en el actualizador | **Corregido** |
| SEC‑12 | Baja | `removeDefaultServerPk()` borraba el parámetro equivocado del fragmento de URL | **Corregido** |
| SEC‑13 | Baja/Info | `__qa_action` exfiltra el mnemónico a `LOCAL_DEVNET_SEEDER_URL` (solo builds no empaquetadas) | Abierto (aceptado, documentado) |
| SEC‑14 | Info | La redacción de logs no cubre mnemónico/frases; `export-logs` vuelca todo | Abierto (recomendación) |

---

## 1-bis. Zero-days del pipeline de mensajes remotos (2ª y 3ª pasada)

En una segunda pasada centrada exclusivamente en la recepción de mensajes remotos se han encontrado
tres fallos explotables **por cualquier usuario de la red, sin interacción y sin aceptar la solicitud
de mensaje**. Están documentados con PoC ejecutable en [`SECURITY_ZERO_DAYS.md`](./SECURITY_ZERO_DAYS.md):

| ID | Severidad | Título | Estado |
|----|-----------|--------|--------|
| ZD-1 | Media-Alta | Reacciones y citas resuelven el mensaje objetivo por `(sent_at, author)` **en toda la base de datos**, sin acotar a la conversación ⇒ mutación/renderizado de mensajes de conversaciones ajenas | Corregido |
| ZD-2 | Media-Alta | `sent_at` sin cota superior (+ bypass del chequeo `sigTimestamp` si "legacy") ⇒ *pinning* persistente de una conversación para siempre (DoS silencioso que sobrevive reinicios) | Corregido |
| ZD-3 | Media | `Math.max()` con un argumento donde se quería `Math.abs()` en `callMessage.ts` ⇒ replay de `OFFER`s de llamada antiguas | Corregido |
| ZD-4 | Alta | `verifyAllSignatures` devuelve el payload y el llamador re-asocia con `.find(m => m.data === validData)`: con dos entradas que comparten `data`, la firma de uno "admite" el mensaje del otro ⇒ **suplantación de remitente en comunidades**, la firma del mensaje no protege del servidor | Corregido |

PoCs: `security-poc/01_cross_conversation_reaction_quote.mjs`,
`security-poc/02_future_timestamp_pin.mjs`, `security-poc/03_call_offer_replay.mjs`,
`security-poc/04_sogs_signature_dealias.mjs`.

---

## 2. Hallazgos detallados y correcciones aplicadas

### SEC‑01 — Renderer sin aislamiento (CRÍTICO, arquitectura) — ABIERTO

`ts/mains/main_node.ts:329‑336` (ventana principal), `:675‑680` (ventana de contraseña),
`:734‑738` (ventana «acerca de»):

```ts
webPreferences: {
  nodeIntegration: true,
  enableRemoteModule: true,
  nodeIntegrationInWorker: true,
  contextIsolation: false,
  // sandbox: true,
  ...
}
```

**Por qué es crítico.** El renderer tiene acceso directo a `require`, al sistema de ficheros, a
`child_process`, a la base de datos y a la clave SQLCipher que está en memoria del proceso Node. Con
`contextIsolation:false`, cualquier ejecución de JavaScript en el renderer (XSS/DOM‑clobbering,
una dependencia npm comprometida que se ejecute en el renderer — hay tres dependencias cargadas
desde tarballs de GitHub: `emoji-mart`, `react-contexify`, `@emoji-mart/*`, además de `sharp` y
`libsession_util_nodejs` —, o una extensión de depuración) escala inmediatamente a **ejecución de
código en el sistema operativo y exfiltración de toda la historia de mensajes y de la frase semilla**.

Se revisaron específicamente los sumideros de XSS (`dangerouslySetInnerHTML`, `innerHTML`,
`document.write`, `eval`, `new Function`): **no hay ninguno con datos remotos sin sanear**
(`SessionHtmlRenderer` usa DOMPurify con lista blanca de etiquetas/atributos; `CompositionInput`
usa `contentEditable="plaintext-only"` y sólo reinyecta HTML de borradores propios;
`MessageBody` construye elementos React). Es decir, hoy no hay una cadena de explotación conocida
en el código de la app, pero **la barrera que impide que un fallo de XSS se convierta en RCE no
existe**. Toda la seguridad de la aplicación depende de que nunca aparezca un XSS.

**Mitigaciones intermedias** (bajo coste, sin refactor completo):
1. `sandbox: true` en las tres ventanas (compatible con `nodeIntegration:true` *solo* si antes se
   migra a preload; ver punto 2).
2. Migrar progresivamente a `contextIsolation:true` + `contextBridge` en `preload.js`: es el
   cambio grande. Se puede hacer por fases: primero la ventana «acerca de» y la de contraseña
   (que casi no usan Node), después la principal.
3. Mientras tanto: añadir una CSP estricta (`default-src 'none'; script-src 'self'; connect-src 'none'`)
   a `background.html` para reducir la superficie de inyección, y quitar `enableRemoteModule`
   (ya no existe en Electron ≥ 14: es configuración muerta y engañosa).
4. Auditar/`npm audit`+pin de las dependencias servidas desde GitHub releases.

---

### SEC‑02 — AppImage sin sandbox del sistema operativo (ALTA) — CORREGIDO

* `build/afterPackHook.js` borraba `chrome-sandbox` del paquete AppImage («we explicitly disable it»).
* `build/launcher-script.sh` añadía `--no-sandbox` cuando `unprivileged_userns_clone == 0`.

Resultado: en el artefacto Linux principal, el renderer se ejecutaba **siempre** sin sandbox de
Chromium (namespace/seccomp). Combinado con SEC‑01, un XSS pasa de «leer la app» a «comprometer la
máquina». Además, el script pasaba un argumento vacío `""` en el caso normal (bug de *quoting*).

**Corrección.** `build/afterPackHook.js` ya no elimina `chrome-sandbox`; `build/launcher-script.sh`
usa un array de argumentos y sólo añade `--no-sandbox` como último recurso cuando el kernel indica
que no hay user namespaces.

> Nota: las instalaciones `.deb`/NSIS nunca estuvieron afectadas por este punto.

---

### SEC‑03 — Actualizaciones de Windows sin verificación de firma (ALTA) — CORREGIDO

`package.json:270`: `"verifyUpdateCodeSignature": false` dentro de `build.win`.
Con eso, `electron-updater` sólo comprueba el SHA‑512 publicado en `latest.yml` y **no** verifica que
el instalador descargado esté firmado por `Session Technology Stiftung` (`publisherName`).
Un actor capaz de servir metadatos de actualización (proxy corporativo con CA instalada, DNS/BGP
secuestrado sobre TLS corporativo, cuenta/CI comprometida) obtiene **ejecución de código** en todas
las instalaciones Windows. Se corrige a `true`: es la opción por defecto de electron-builder y el
publicador ya está configurado.

**Acción de verificación en CI:** el pipeline de release debe firmar con el certificado de
`Session Technology Stiftung`, o los usuarios Windows verán fallar la actualización (fail‑closed,
que es el comportamiento deseado).

---

### SEC‑04 — Traversal / excepción en el protocolo `file:` (ALTA) — CORREGIDO

`ts/node/protocol_filter.ts` (versión anterior):

* `properCasing.startsWith(userDataPath)` → `~/.config/Session-evil` **pasa** el filtro si
  `userDataPath` es `~/.config/Session`. La comprobación debe ser de frontera de directorio.
* `decodeURIComponent(targetUrl)` sin `try/catch`: una URL con un `%` suelto lanza `URIError`
  dentro del handler del protocolo del proceso principal (excepción no capturada ⇒ posible crash /
  estado inconsistente).
* El esquema se eliminaba cortando un número fijo de caracteres (`slice(7|8)`), lo que convierte
  cualquier esquema en una ruta (`http://host/x` → `//host/x`).

**Corrección.** Se valida el esquema `file://`, se captura el error de decodificación, se resuelven
symlinks con `realpathSync` dentro de `try/catch` y se comprueba la pertenencia con
`isPathInside()` (comparación por segmento, con `path.sep`, case‑insensitive en Windows).

---

### SEC‑05 — Inyección en `PRAGMA rekey` de SQLCipher (ALTA) — CORREGIDO

`ts/node/sql.ts:169` (antes): `assertGlobalInstance().pragma(\`rekey = ${value}\`)` con
`value = '${password}'`. La API `pragma()` no admite *bind parameters*, así que la frase se concatena
en el SQL.

La única validación de la frase vivía en el **renderer** (`ts/util/passwordUtils.ts`,
`validatePassword()`), y el manejador IPC `set-password` (`ts/mains/main_node.ts`) la llamaba **sin
validar**. Cualquier compromiso del renderer (o cualquier futura ruta que llame al IPC sin pasar por
el formulario) podía:
* cerrar la cadena y ejecutar un `PRAGMA key='...'` distinto (cifrar la base con una clave
  desconocida ⇒ **pérdida total de datos**), o
* romper la sentencia y dejar la base en un estado inconsistente.

**Corrección (defensa en profundidad, dos capas):**
1. `ts/util/passwordUtils.ts`: lista blanca estricta (letras, dígitos y símbolos seguros; se rechazan
   `'`, `"`, `\`, saltos de línea y caracteres de control) y comparación de hash en tiempo constante
   (`crypto.timingSafeEqual`).
2. `ts/node/sql.ts`: nuevo `assertSafeSQLKeyPassword()` que **lanza** si la frase contiene algo
   inseguro, ejecutado en el proceso principal justo antes del `rekey`.
3. `ts/mains/main_node.ts` (`set-password`): valida con `PasswordUtil.validatePassword()` antes de
   tocar la base.

---

### SEC‑06 — Descarga de adjuntos sin límite de tamaño (MEDIA) — CORREGIDO

* `ts/receiver/attachments.ts` aceptaba el campo `size` de un mensaje remoto sin comprobarlo
  (`downloadAttachmentFs`).
* `ts/session/apis/file_server_api/FileServerApi.ts` y
  `ts/session/apis/open_group_api/sogsv3/sogsV3FetchFile.ts` devolvían el cuerpo completo sin cota.

`MAX_ATTACHMENT_FILESIZE_BYTES` (10 MB) sólo se aplicaba **al enviar**. Un contacto (o una comunidad,
que no requiere aceptar invitación) podía declarar/publicar un fichero de varios GB: el cliente lo
descargaba **íntegro en memoria** (`bodyBinary`), provocando *OOM*/cierre de la app — DoS remoto
trivial y repetible.

**Corrección.** Se rechaza antes de descargar si `size` declarado > 10 MB y se rechaza después
de descargar cualquier cuerpo > `MAX + 1 MB` (con log explícito). Mismo límite para SOGS.
*(Pendiente de mejora futura: streaming con corte en el propio `node-fetch` — `size:` — para no
llegar a bufferizar nunca el exceso.)*

---

### SEC‑07 — SSRF / sondeo de red local vía previsualizaciones (MEDIA) — CORREGIDO

`ts/util/linkPreviews.ts` → `isLinkSafeToPreview()` sólo exigía `https:` y «no sneaky».
`https://127.0.0.1:8443`, `https://10.0.0.5`, `https://169.254.169.254` (metadatos cloud),
`https://[::1]`, `https://algo.internal`… pasaban el filtro y el cliente hace la petición **desde
el equipo del usuario** (`node-fetch` en el renderer con Node), con `redirect: manual` pero
siguiendo redirecciones `https`.

Un contacto puede enviar un mensaje con un enlace así; si el usuario lo pega en el compositor (o
pega cualquier texto que lo contenga) el cliente sondea su red local y el atacante infiere
servicios abiertos por el tiempo de respuesta/éxito del preview. También permite alcanzar endpoints
de metadatos en el *host* (no en la VM, pero sí servicios locales que escuchan en TLS).

**Corrección.** `isLocalOrPrivateHostname()` bloquea loopback, RFC1918, CGNAT, link‑local
(`169.254/16`), multicast/reservado, IPv6 ULA/link‑local/`::ffff:`, `localhost`, `*.local`,
`*.internal`, `*.lan`, `*.home.arpa`, `*.onion` y nombres de una sola etiqueta. Se apoya en la
normalización WHATWG de `URL` (p. ej. `https://2130706433` → `127.0.0.1`).

---

### SEC‑08 — Digest de adjunto truncable (MEDIA) — CORREGIDO

`ts/util/crypto/attachmentsEncrypter.ts`: `verifyDigest()` iteraba `for (i < theirDigest.byteLength)`
sin comprobar longitudes. Un `digest` de 1 byte reducía la comprobación a 8 bits; uno mayor que 32
leía fuera de rango (`undefined ^ x`). La integridad real la da el HMAC‑SHA256 previo, por lo que no
era explotable *per se*, pero es un fallo real de la verificación.

**Corrección.** Se exige `a.byteLength === b.byteLength` (32) antes de comparar.

---

### SEC‑09 — Contraseñas: comparación y fuerza bruta (MEDIA) — PARCIAL

`ts/util/passwordUtils.ts` (antes): `sha512(phrase) === hash` (comparación no constante) y KDF de una
sola pasada SHA‑512 sin sal. Además, `password-window-login` y `password-recovery-phrase`
(`ts/mains/main_node.ts`) **no tienen límite de intentos ni back‑off**.

Corregido: comparación en tiempo constante con `crypto.timingSafeEqual` y validación endurecida.
Pendiente (recomendado): *rate limiting* exponencial en el proceso principal para ambos IPC, y
migración del hash a `scrypt`/`argon2` (el hash sólo se usa para confirmar la contraseña actual antes
de cambiarla; el cifrado real lo hace SQLCipher, así que la prioridad es media).

---

### SEC‑10 — DoS en cambios de miembro de grupo v2 (MEDIA) — CORREGIDO

`ts/receiver/groupv2/handleGroupV2Message.ts:321`:
`change.memberSessionIds.filter(...)` lanzaba `TypeError` si el campo venía ausente en el protobuf
remoto (rechazo no capturado en el pipeline de mensajes), y la comprobación posterior
`if (!filteredMemberChange)` era código muerto (un array siempre es *truthy*), de modo que una lista
vacía generaba un mensaje de sistema «miembro añadido/eliminado» sin miembros.

**Corrección.** `(change.memberSessionIds || []).filter(...)` + `length === 0` → *return*.

---

### SEC‑11 — Versión de release controlada por el renderer (BAJA) — CORREGIDO

`ipc.on('set-release-from-file-server')` aceptaba cualquier `releaseVersion` no vacía y la pasaba a
`semver.gt()` en el actualizador (que lanza con valores inválidos, dejando el updater en error
permanente hasta reinicio). **Corrección:** validación con `semver.parse()` y del tipo en el proceso
principal, normalizando el valor.

---

### SEC‑12 — `removeDefaultServerPk()` borraba el parámetro equivocado (BAJA) — CORREGIDO

`ts/session/url/index.ts`: al detectar la clave del file server por defecto, borraba
`queryParamEncryptionKey` (`e`) en lugar de `queryParamServerEd25519Pubkey` (`p`). Efecto: se
mantenía en la URL la clave del servidor por defecto y se eliminaba (de nuevo) la `profileKey`.
No es explotable, es un bug funcional con impacto en privacidad/compatibilidad. **Corregido.**

---

### SEC‑13 — `__qa_action` exfiltra el mnemónico (BAJA/INFO, aceptado)

`ts/mains/main_node.ts` (`ipcMain.on('__qa_action')`) envía la frase semilla a
`process.env.LOCAL_DEVNET_SEEDER_URL` vía `shell.openExternal`. Está protegido por
`if (app.isPackaged) return;`, así que **no afecta a builds de producción**, pero:
* cualquier build de desarrollo/CI empaquetada sin `app.isPackaged` (p. ej. `electron .` con
  `NODE_ENV=production`) lo permite;
* combinado con SEC‑01, cualquier XSS en un build de desarrollo filtra la semilla.

Recomendación: eliminar por completo del árbol de producción (moverlo a un módulo de test cargado
condicionalmente con `isTestIntegration()`).

---

### SEC‑14 — Redacción de logs (INFO)

`ts/util/privacy.ts` (`redactAll`) redacta rutas, IDs de sesión (05/03/15/25), IPs de snodes y URLs,
pero **no** frases semilla ni contenido de mensajes. `export-logs` empaqueta todos los `.log`
rotados y la base de datos de depuración en un `.txt` que el usuario comparte a mano. No es una
vulnerabilidad (requiere acción del usuario), pero conviene: (a) redactar secuencias de 12/13/24/25
palabras BIP‑39, (b) mostrar un aviso explícito antes de exportar.

---

## 3. Observaciones menores (sin cambio de código)

1. `enableRemoteModule: true` y `nativeWindowOpen: true` ya no existen en Electron 40: son opciones
   muertas que dan una falsa sensación de configuración. Eliminarlas.
2. `snodeHttpsAgent = new https.Agent({ rejectUnauthorized: false })` (`ts/session/apis/snode_api/onions.ts:699`)
   es correcto **en contexto**: el payload va cifrado con AES‑GCM usando una clave simétrica derivada
   de la petición (que el servidor no conoce en claro fuera del propio cifrado), por lo que un MITM
   del TLS hacia el snode no puede forjar la respuesta. Conviene documentarlo en el código para que
   nadie lo «arregle» ni lo copie a otro sitio. Lo mismo para el `rejectUnauthorized:false` de
   `SeedNodeAPI` en modo testnet (`ca` fijado por código en producción).
3. `getUnpaddedAttachment()` considera «padding» cualquier byte más allá del tamaño declarado sin
   comprobar que sean ceros. No es explotable (el padding es local y el MAC ya está verificado),
   pero es frágil.
4. `parseFileServerUrl()` acepta cualquier host y esquema `http:`. Los mensajes pueden apuntar el
   cliente a un file server arbitrario; se mitiga porque la descarga va por onion v4 (la conexión la
   hace el service node, no el usuario) y el contenido va cifrado/autenticado con la clave del
   mensaje. Documentarlo como decisión de diseño.
5. `ts/node/config/base_config.ts` escribe el JSON de configuración sin escritura atómica ni
   `fsync`; un corte de luz puede corromper `config.json`. Además permite que otro proceso local
   sustituya el fichero. Impacto bajo, pero una escritura `tmp` + `rename` es trivial.
6. `README.md` documenta la verificación GPG de releases; esto **no** protege al usuario final de un
   auto‑update manipulado (SEC‑03 lo hacía). Mantener ambos: firma del instalador + hashes firmados.

---

## 4. Plan priorizado recomendado

| Prioridad | Acción | Esfuerzo |
|-----------|--------|----------|
| P0 | Verificar en CI que el instalador Windows se firma con `Session Technology Stiftung` (SEC‑03) y sacar un release con la corrección | Bajo |
| P0 | Revisar el artefacto AppImage generado: `chrome-sandbox` presente y con permisos correctos (SEC‑02) | Bajo |
| P1 | **SEC‑01 por fases**: (a) CSP estricta en `background.html`, (b) migrar ventanas «about»/«password» a `contextIsolation:true` + `contextBridge`, (c) migrar la ventana principal y habilitar `sandbox:true` | Alto |
| P1 | Streaming con límite en las descargas (`node-fetch` `size`/abort por bytes) en vez de comprobar después (SEC‑06) | Medio |
| P2 | *Rate limiting* + back‑off en `password-window-login` y `password-recovery-phrase`; migrar el hash a `scrypt` (SEC‑09) | Bajo |
| P2 | Eliminar `__qa_action` del build de producción (SEC‑13); redactar semillas en logs (SEC‑14) | Bajo |
| P2 | `npm audit`/`pnpm audit` en CI + fijado por hash de las dependencias servidas desde GitHub releases (emoji‑mart, react‑contexify, sharp, libsession) | Bajo |
| P3 | Fuzzing del parser de protobuf y del pipeline de `receiver/` (el punto donde entra todo lo remoto) | Medio |
| P3 | Pentest dinámico sobre el binario empaquetado (por un tercero) | Alto |

---

## 5. Comprobaciones que salieron limpias (revisadas explícitamente)

* **Sin `eval` / `new Function` / `vm`** en todo el árbol.
* **Sin SQL dinámico peligroso**: todas las consultas de `ts/node/sql.ts`, `database_utility.ts` y
  migraciones usan parámetros (`$id`, `?`) o nombres de tabla/columna provenientes de constantes del
  módulo. El único punto de concatenación era el `PRAGMA rekey` (SEC‑05, ya corregido).
* **Renderizado de HTML de mensajes**: React escapa por defecto; lo único que usa
  `dangerouslySetInnerHTML` pasa por DOMPurify con `ALLOWED_TAGS`/`ALLOWED_ATTR` explícitos.
* **Apertura de enlaces**: `MessageBody` exige `/^(http|https):/i` + `isLinkSneaky`; `will-navigate`
  se cancela siempre y sólo se delega a `shell.openExternal` para `http(s)`. Ventanas nuevas y
  `webview` bloqueados globalmente (`web-contents-created` → `will-attach-webview` +
  `setWindowOpenHandler({action:'deny'})`).
* **Permisos**: `setPermissionRequestHandler` deniega por defecto (`geolocation`, `midiSysex`,
  `openExternal`, `pointerLock`), `media` sólo si el usuario lo activó.
* **Validación de mensajes entrantes**: `cleanIncomingDataMessage()` limita a 32 adjuntos, valida
  flags y normaliza adjuntos; el poller limita tamaños por namespace (`maxSizeMap`).
* **Criptografía**: AES‑CBC+HMAC‑SHA256 para adjuntos clásicos con comparación constante del MAC;
  `crypto_secretstream_xchacha20poly1305` para cifrado local en reposo; claves de 32 bytes desde
  `libsodium`/`crypto.randomBytes` (nunca `Math.random`);
  `crypto_sign_verify_detached` sobre los mensajes de grupo v2 (invite, info‑change, member‑change)
  con la clave del grupo.
* **Onion v4**: respuesta cifrada con clave simétrica derivada de la petición (AES‑GCM) ⇒
  autenticidad implícita; `allow401s` desactivado en las rutas sensibles.
* **Ficheros en disco**: los nombres de adjuntos se generan localmente (32 bytes aleatorios en hex),
  nunca a partir del nombre enviado por el remoto; el nombre del remoto se sanea
  (`replaceUnicodeV2`) y sólo se usa para mostrar.

---

## 6. Fuera de alcance / no auditado

* `ts/localization/**` y `dynamic_assets/**` (submódulos vacíos en este checkout) y las traducciones
  generadas.
* `libsession_util_nodejs` (binario nativo), `@signalapp/sqlcipher` (binding nativo), `sharp`,
  `libsodium-wrappers-sumo`: son **código de terceros** con superficie de memoria (`wasm`/nativo).
  Se asume que están parcheados por sus mantenedores; si un atacante controla una imagen/adjunto, la
  exposición a fallos de memoria de `sharp`/`libvips` es real y sólo el sandbox del SO (SEC‑02)
  la contiene.
* El backend de Session (oxen‑core / SOGS / file server / backend «Pro») y la app móvil.
* Sin pruebas dinámicas: **no** se ha compilado ni ejecutado la app (faltan `node_modules` y los
  submódulos en este entorno). Las correcciones se han verificado a nivel de sintaxis
  (`typescript.transpileModule`, `bash -n`, `node --check`) y de revisión manual; **no** con
  `tsc --noEmit` completo ni con la batería de tests.

---

## 7. Cómo verificar las correcciones localmente

```sh
pnpm install            # dependencias
git submodule update --init --recursive   # ts/localization + dynamic_assets
pnpm build:protobuf
pnpm tsc --noEmit       # comprobación de tipos de todo el árbol
pnpm test               # tests unitarios
pnpm build              # build completo
```

Comprobaciones puntuales de los arreglos:

* **SEC‑02**: `pnpm build-release` y luego `ls -l release/linux-unpacked/chrome-sandbox`
  (debe existir) y `strings release/*.AppImage | grep -- --no-sandbox` (sólo en el script).
* **SEC‑03**: firmar y publicar en un canal de pruebas; la actualización debe fallar si el
  instalador no está firmado por el publicador configurado.
* **SEC‑04**: desde la consola del renderer de desarrollo,
  `fetch('file:///%E0%A4%A').catch(e => console.log(e))` no debe tumbar el proceso principal, y
  `file:///home/<otro-usuario>/x` debe denegarse.
* **SEC‑05**: intentar fijar la contraseña `a'b` o `a"b` por IPC: debe devolver error de validación y
  la base debe seguir abriéndose con la contraseña anterior.
* **SEC‑06/07/08/10**: cubiertos por tests del receptor (añadir casos con `size` gigante,
  `memberSessionIds` ausente, digest de 1 byte y enlaces a `https://127.0.0.1`).
