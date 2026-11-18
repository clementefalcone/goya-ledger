# Goya LexChain

**Motor de contratos legales on-chain.**

Define un flujo legal. LexChain lo ejecuta con firma electrónica, identidad verificada, timestamp cualificado, y archivo regulatorio — automáticamente, en cualquier jurisdicción.

---

## El problema

Firmar un contrato legalmente válido hoy requiere 5 piezas que no se hablan entre sí:

1. Redacción (Word/PDF)
2. Identidad (notario, verificación presencial)
3. Firma (DocuSign, plataformas propietarias)
4. Timestamp (autoridad de sellado)
5. Archivo (gestión documental, 7-15 años)

Cada pieza es manual, costosa, y específica de un país. Un contrato chileno no sirve en UAE sin re-hacer todo.

## La solución

LexChain unifica las 5 piezas en una API. El desarrollador define el flujo legal en YAML. LexChain ejecuta cada paso on-chain, con toda la criptografía y compliance que la ley exige.

```
Developer → define flujo YAML → POST /api/v1/lexchain/deploy
Usuario   → firma en la app   → POST /api/v1/lexchain/{id}/advance
LexChain  → verifica identidad, firma, timestampea, archiva → automático
```

El usuario nunca ve LexChain. Ve un botón "Firmar". Debajo, LexChain garantiza que ese clic cumple la ley.

---

## Cómo funciona

### 1. Define el contrato

```yaml
# compraventa.lexchain.yaml
contract:
  name: "Compraventa Inmueble"
  jurisdiction: chile
  governing_law: "Ley 19.799, Código Civil Art. 1801"
  retention: 10 years

parties:
  vendedor:
    identity: rut
    proofing_level: high
  comprador:
    identity: rut
    proofing_level: high
  notario:
    identity: rut
    proofing_level: high
    role: notary

documents:
  escritura:
    title: "Escritura de compraventa"
    hash: sha256

stages:
  - name: borrador
    parties: [vendedor, comprador]
    signature: simple
    actions:
      - notarize: escritura
    next: revision

  - name: revision
    parties: [vendedor, comprador, notario]
    timeout: 5 days
    next: firma | cancelado

  - name: firma
    parties: [vendedor, comprador]
    signature:
      level: advanced
      algorithm: ml-dsa-65
      biometric: [fingerprint, government_id]
    actions:
      - sign: { document: escritura, format: cades-t }
      - timestamp: rfc3161
      - credential: { to: vendedor, type: "TransferProof" }
      - credential: { to: comprador, type: "OwnershipProof" }
    next: notarizacion

  - name: notarizacion
    parties: [notario]
    signature:
      level: advanced
      biometric: [fingerprint]
    actions:
      - sign: { document: escritura, format: pades }
      - archive: { document: escritura, retention: 10 years }
      - transfer: { asset: escritura, from: vendedor, to: comprador }
    next: completado

  - name: cancelado
    terminal: true

  - name: completado
    terminal: true
```

### 2. Despliega

```bash
curl -X POST https://goya-node.fly.dev/api/v1/lexchain/deploy \
  -H "Authorization: Bearer $TOKEN" \
  -F "contract=@compraventa.lexchain.yaml"

# Response:
# { "contract_id": "lex_a1b2c3", "status": "deployed", "current_stage": "borrador" }
```

### 3. Los usuarios interactúan

```bash
# Vendedor firma el borrador
curl -X POST https://goya-node.fly.dev/api/v1/lexchain/lex_a1b2c3/advance \
  -H "Content-Type: application/json" \
  -d '{
    "party": "did:goya:vendedor123",
    "signature": "ed25519_hex...",
    "public_key": "pubkey_hex..."
  }'

# LexChain automáticamente:
# 1. Verifica que el DID tiene RUT válido (identity proofing level: high)
# 2. Verifica la firma Ed25519
# 3. Notariza el documento (proof of existence)
# 4. Avanza al stage "revision"
```

### 4. LexChain ejecuta las reglas

Cada `advance` pasa por el pipeline:

```
Request
  │
  ├─ ¿El party está en el stage actual?          → 403 si no
  ├─ ¿Tiene identity proofing del nivel requerido? → 403 si no
  ├─ ¿La firma cumple el level requerido?          → 400 si no
  │   ├─ simple: Ed25519 ✓
  │   ├─ advanced: ML-DSA-65 + biométrico ✓
  │   └─ seal: ML-DSA-65 + legal entity ✓
  ├─ ¿Timeout del stage expiró?                    → auto-avanza
  ├─ ¿Todos los parties requeridos firmaron?        → ejecuta actions
  │   ├─ notarize → on-chain proof of existence
  │   ├─ sign → CAdES/XAdES/PAdES según format
  │   ├─ timestamp → RFC 3161 token
  │   ├─ credential → SD-JWT VC o mdoc emitido
  │   ├─ archive → audit store con retention
  │   └─ transfer → ownership transfer on-chain
  └─ Avanza al next stage
```

---

## Poder notarial UAE

```yaml
contract:
  name: "General Power of Attorney"
  jurisdiction: uae
  governing_law: "Federal Decree-Law 46/2021"
  retention: 15 years

parties:
  principal:
    identity: emirates_id
    proofing_level: substantial
  agent:
    identity: emirates_id
    proofing_level: substantial
  witnesses:
    identity: emirates_id
    proofing_level: low
    count: 2

documents:
  poa:
    title: "General Power of Attorney"

stages:
  - name: granting
    parties: [principal]
    signature:
      level: advanced
      algorithm: ml-dsa-65
      biometric: [fingerprint, facial]
    actions:
      - sign: { document: poa, format: xades }
      - timestamp: rfc3161
    next: witnessing

  - name: witnessing
    parties: [witnesses]
    require: "count(signed) >= 2"
    signature: simple
    actions:
      - sign: { document: poa, format: cades }
    next: active

  - name: active
    timeout_from: granting.completed
    timeout: 1 year
    on_timeout: expired
    revocable_by: [principal]
    on_revoke: revoked

  - name: revoked
    actions:
      - archive: { document: poa, retention: 15 years }
      - notify: { to: agent, message: "Power of Attorney revoked" }
    terminal: true

  - name: expired
    actions:
      - archive: { document: poa, retention: 15 years }
    terminal: true
```

## Licitación pública Chile

```yaml
contract:
  name: "Licitación Pública"
  jurisdiction: chile
  governing_law: "Ley 19.886 de Compras Públicas"
  retention: 10 years

parties:
  entidad:
    identity: rut
    proofing_level: high
    role: government
  oferentes:
    identity: rut
    proofing_level: high
    count: 1..100

documents:
  bases:
    title: "Bases de licitación"
  ofertas:
    per_party: oferentes
    sealed: true
  evaluacion:
    title: "Acta de evaluación"

stages:
  - name: publicacion
    parties: [entidad]
    signature:
      level: advanced
      biometric: [fingerprint]
    actions:
      - notarize: bases
      - timestamp: rfc3161
    timeout: 30 days
    next: recepcion

  - name: recepcion
    parties: [oferentes]
    signature:
      level: advanced
      biometric: [fingerprint]
    actions:
      - sign: { document: oferta, format: cades-t }
      - seal: oferta
    on_timeout: apertura

  - name: apertura
    parties: [entidad]
    actions:
      - unseal: each oferta
      - verify: each oferta
    next: evaluacion_stage

  - name: evaluacion_stage
    parties: [entidad]
    timeout: 15 days
    signature:
      level: advanced
      biometric: [fingerprint]
    actions:
      - sign: { document: evaluacion, format: pades }
      - timestamp: rfc3161
      - credential: { to: ganador, type: "AdjudicacionCredential" }
    next: adjudicada

  - name: adjudicada
    actions:
      - notify: { to: each oferentes, message: "Resultado disponible" }
      - archive: { document: bases, retention: 10 years }
      - archive: { document: evaluacion, retention: 10 years }
      - archive: { document: each ofertas, retention: 10 years }
    terminal: true
```

## Credencial verificable EU

```yaml
contract:
  name: "EU Person Identification Data"
  jurisdiction: eu
  governing_law: "eIDAS 2.0, ARF 1.4"

parties:
  issuer:
    identity: eu_national_id
    proofing_level: high
    role: qtsp
  holder:
    identity: eu_national_id
    proofing_level: substantial

credentials:
  pid:
    type: "eu.europa.ec.eudi.pid.1"
    format: [sd_jwt, mdoc]
    claims: [given_name, family_name, birth_date, nationality, age_over_18]
    selective_disclosure: true
    expiry: 1 year

stages:
  - name: proofing
    parties: [holder]
    actions:
      - verify_identity: { party: holder, level: substantial }
    next: issuance

  - name: issuance
    parties: [issuer]
    signature:
      level: seal
      algorithm: ml-dsa-65
    actions:
      - credential: { definition: pid, to: holder }
    next: active

  - name: active
    on_present:
      - verify: pid
      - check_status: pid
    revocable_by: [issuer]
    on_revoke: revoked
    on_timeout: expired

  - name: revoked
    actions:
      - revoke: pid
    terminal: true

  - name: expired
    terminal: true
```

---

## Qué hace LexChain que no hace nadie

| Tú haces | LexChain hace automáticamente |
|----------|-------------------------------|
| Defines parties con `identity: rut` | Valida RUT (módulo 11) antes de dejar firmar |
| Pones `jurisdiction: uae` | Aplica retención 15 años, acepta Emirates ID |
| Pones `signature: advanced` | Exige ML-DSA-65 + biométrico, rechaza Ed25519 |
| Pones `format: cades-t` | Genera CAdES-BES + timestamp token, DER-encoded |
| Pones `credential: { type: "PID" }` | Emite SD-JWT VC con selective disclosure |
| Pones `timeout: 5 days` | Auto-avanza o cancela cuando expira |
| Pones `sealed: true` | Cifra ofertas hasta que el stage de apertura las libere |
| Pones `archive: { retention: 10 years }` | Almacena en audit store con hash chain tamper-evident |

**El desarrollador define el QUÉ. LexChain resuelve el CÓMO.**

---

## Arquitectura técnica

```
                          ┌─────────────────────┐
  compraventa.yaml  ────► │   YAML Parser        │
                          │   (serde_yaml)        │
                          └──────────┬────────────┘
                                     │
                          ┌──────────▼────────────┐
                          │   Contract Validator   │
                          │   - Stage graph valid  │
                          │   - Jurisdiction rules │
                          │   - Party types check  │
                          └──────────┬────────────┘
                                     │
                          ┌──────────▼────────────┐
                          │   ContractDefinition   │
                          │   (Rust struct)         │
                          │   Stored on-chain      │
                          └──────────┬────────────┘
                                     │
                     POST /advance   │
                    ─────────────►   │
                          ┌──────────▼────────────┐
                          │   Stage Machine        │
                          │   - Validate party     │
                          │   - Check signature    │
                          │   - Execute actions    │
                          │   - Advance stage      │
                          └──────────┬────────────┘
                                     │
                          ┌──────────▼────────────┐
                          │   Goya Modules         │
                          │   (already exist)      │
                          │                        │
                          │   SigningProvider       │
                          │   TsaProvider          │
                          │   sd_jwt / mdoc        │
                          │   AuditStore           │
                          │   RaStore              │
                          │   BlockStore           │
                          └────────────────────────┘
```

**No hay VM. No hay bytecode. No hay compilación.**

YAML → struct Rust → validación de reglas → llamadas directas a módulos existentes.

Es un **orquestador declarativo**, no un lenguaje de programación.

---

## API (implementada)

Desplegar y firmar se replican por la cadena; cada nodo vuelve a verificar. En la cadena solo viajan los DIDs de las partes, las firmas y una huella sellada del texto (`payload_commitment` = hash de sal + texto). El texto y su sal quedan en el nodo donde se desplegó el contrato.

### POST /api/v1/lexchain/deploy

Body: `{ "type", "parties": [{ "role", "did", "signature_level" }], "payload", "require_notarization"?, "deadline_secs"?, "webhook_url"? }`, o `{ "template", "parties": { rol: did }, "payload" }`. Cualquiera puede proponer un contrato; nadie queda obligado hasta firmar. Respuesta: el contrato completo con `payload_salt` (guárdalo para probar el texto más adelante).

### POST /api/v1/lexchain/{id}/sign

Body: `{ "did", "public_key", "signature", "biometric_evidence"? }`. La firma es sobre `fes:{did}:{content_hash}` (o `fea:{did}:{content_hash}:{bio_hash}` en nivel avanzado). La autoriza la firma de la parte con la clave registrada de su DID; no hace falta certificado de organización.

### GET /api/v1/lexchain/{id}

Sin parámetros devuelve la vista pública (sin texto). Una parte obtiene el texto completo con `?did=…&issued_at=…&signature=…`, firmando `lexchain:read:{id}:{issued_at}` con su DID (vigencia de 300 s).

### GET /api/v1/lexchain · GET /api/v1/lexchain/templates

Lista de contratos (vista pública) y plantillas disponibles.

---

## Diferenciación

| | DocuSign | Ethereum | Hyperledger | **Goya LexChain** |
|---|---|---|---|---|
| Firma legal | ✅ Básica | ❌ | ❌ | ✅ **FES/FEA/Seal** |
| Multi-jurisdicción | Parcial | ❌ | ❌ | ✅ **Chile/EU/UAE** |
| Post-quantum | ❌ | ❌ | ❌ | ✅ **ML-DSA-65** |
| On-chain immutable | ❌ | ✅ | ✅ | ✅ |
| Identity verification | ❌ | ❌ | Parcial | ✅ **RUT/Emirates ID/EU** |
| Qualified timestamp | ❌ | Bloque | ❌ | ✅ **RFC 3161** |
| Selective disclosure | ❌ | ❌ | ❌ | ✅ **SD-JWT/mdoc** |
| Contratos declarativos | ❌ | Solidity | Chaincode | ✅ **YAML** |
| Precio | $25+/mes | Gas fees | Gratis pero complejo | **Gratis (open source)** |

---

## Roadmap

### Fase 1 — Core engine (6 semanas)

- YAML parser + `ContractDefinition` struct
- Stage machine evaluator
- Validators: jurisdiction rules, party types, signature levels
- API: deploy, advance, status, list
- 3 contract templates: compraventa, poder notarial, credencial

### Fase 2 — Templates + SDK (4 semanas)

- 10 contract templates (contratos más comunes por jurisdicción)
- JavaScript/TypeScript SDK para integración frontend
- Webhook notifications por stage change
- Dashboard web para visualizar contratos activos

### Fase 3 — Marketplace (4 semanas)

- Template marketplace — abogados publican plantillas de contratos
- Versioning de contratos (v1, v2 con migración)
- Multi-party approval flows
- Integración con wallets (EUDI Wallet, UAE Pass)

**MVP funcional: 6 semanas.**

---

## Mercado

| Vertical | Caso de uso | Tamaño |
|----------|------------|--------|
| **Notarías digitales** | Compraventa, poderes, mandatos | 4,200 notarías en Chile |
| **Gobierno** | Licitaciones, permisos, certificados | $380B compras públicas LATAM |
| **Legal tech** | Contratos laborales, NDAs, SLAs | $28B global (2025) |
| **Salud** | Consentimiento informado, recetas | Regulado en toda jurisdicción |
| **Comercio exterior** | Cartas de crédito, BL, certificados de origen | $32T comercio global |
| **Real estate** | Compraventa, arriendos, hipotecas | Mayor asset class mundial |

---

*"Define el contrato. LexChain hace el resto."*
