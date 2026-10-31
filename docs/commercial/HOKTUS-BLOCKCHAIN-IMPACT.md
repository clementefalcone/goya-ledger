# Impacto de rust-bc en Hoktus

> **Hoktus** es una plataforma SaaS que automatiza la gestión de personal, optimizando procesos clave como contratación, validación de documentos y antecedentes, además de la coordinación en tiempo real.

---

## Donde encaja naturalmente

### 1. Validación de documentos y antecedentes

El problema central de Hoktus aquí es **confianza**: ¿este certificado es auténtico? ¿estos antecedentes fueron alterados?

rust-bc resuelve esto con:

- **Credenciales verificables** (`POST /credentials/issue`, `POST /credentials/{id}/verify`) — un empleador emite una credencial, cualquier tercero la verifica criptográficamente sin contactar al emisor.
- **Identidad DID** (`POST /identity/create`) — cada trabajador, empresa y entidad validadora tiene una identidad descentralizada. No depende de un servidor central para verificar quién firmó qué.
- **Inmutabilidad** — un documento validado y registrado on-chain no puede ser alterado retroactivamente. Auditoría perfecta.

**Caso concreto:** una universidad emite un título como credencial verificable → Hoktus lo verifica en milisegundos sin llamar a la universidad → el resultado queda registrado con timestamp inmutable.

### 2. Trazabilidad del proceso de contratación

Cada paso del pipeline (postulación → verificación → contrato → onboarding) se registra como transacción:

- Quién aprobó qué, cuándo, con qué evidencia
- Cadena de custodia documental completa
- Útil para auditorías laborales, fiscalización y compliance

El **gateway pipeline** (endorse → order → commit) garantiza que cada acción pasa por validación de política antes de registrarse.

### 3. Datos sensibles entre organizaciones

Hoktus coordina entre empresas, trabajadores y entidades externas. Las **private data collections** permiten:

- Antecedentes penales visibles solo para la empresa contratante y el servicio de verificación
- Datos médicos compartidos solo entre el trabajador y salud ocupacional
- Cada organización ve solo lo que su política de acceso permite

```bash
POST /private-data/collections
{ "name": "antecedentes-penales", "member_org_ids": ["hoktus", "registro-civil"] }
```

### 4. Firmas post-cuánticas (ML-DSA-65)

Contratos laborales y validaciones de antecedentes son documentos de largo plazo. Con `SIGNING_ALGORITHM=ml-dsa-65`, las firmas resisten ataques cuánticos futuros — relevante para registros que deben ser verificables por décadas.

---

## Donde NO agrega valor

- **Coordinación en tiempo real** — la blockchain no reemplaza WebSockets o sistemas de mensajería. La latencia de consenso (orden de segundos) no sirve para chat o notificaciones instantáneas.
- **CRUD operativo diario** — listas de turnos, asignaciones, dashboards. Eso es PostgreSQL/Redis, no blockchain. Poner operaciones frecuentes y mutables on-chain es sobreingeniería.
- **Lógica de negocio SaaS** — pricing, billing, permisos de usuario. Nada de esto necesita descentralización.

---

## Modelo de integración realista

```
┌─────────────────────────────────────┐
│           Hoktus SaaS               │
│  (PostgreSQL, Redis, API REST)      │
│                                     │
│  Contratación ─── Turnos ─── RRHH  │
└──────────┬──────────────────────────┘
           │ Solo eventos de alto valor
           ▼
┌─────────────────────────────────────┐
│           rust-bc network           │
│                                     │
│  • Registro de credenciales         │
│  • Verificación de antecedentes     │
│  • Firmas de contratos              │
│  • Auditoría de procesos críticos   │
│  • Private data entre orgs          │
└─────────────────────────────────────┘
```

Hoktus sigue siendo el sistema operativo. rust-bc actúa como **capa de confianza y auditoría** para los momentos donde la integridad, la verificabilidad y la privacidad inter-organizacional importan.

---

## Resumen ejecutivo

| Área Hoktus | Impacto blockchain | Nivel |
|---|---|---|
| Validación de documentos | Credenciales verificables, verificación sin intermediario | **Alto** |
| Antecedentes | Private data collections, trazabilidad inmutable | **Alto** |
| Contratos laborales | Firmas PQC, registro auditable | **Medio-Alto** |
| Compliance / auditoría | Cadena de evidencia inmutable | **Alto** |
| Coordinación tiempo real | Ninguno — usar infraestructura convencional | **Nulo** |
| Gestión operativa diaria | Ninguno — overhead innecesario | **Nulo** |

---

La blockchain no reemplaza el SaaS. Lo complementa en los puntos donde la confianza entre partes, la verificabilidad a largo plazo y la privacidad compartida son el problema real.
