# Cerulean Ledger y la Ley 21.663 de Ciberseguridad

## Su organización ya debe cumplir. Nosotros le ayudamos.

La **Ley 21.663 — Ley Marco de Ciberseguridad e Infraestructura Crítica de la Información** entró en vigencia en 2024 y aplica a todas las organizaciones que operan servicios esenciales o infraestructura crítica en Chile. Las multas por incumplimiento van desde 5.000 hasta 40.000 UTM.

Cerulean Ledger no es solo compatible con la ley — **fue diseñado para superarla**.

---

## Qué exige la ley y cómo respondemos

### 1. Integridad de la información

**Lo que dice la ley:** Los datos críticos no deben poder ser alterados sin detección. Se exigen mecanismos que garanticen la integridad de registros y comunicaciones.

**Lo que entregamos:** Cada registro en Cerulean Ledger queda sellado criptográficamente. Cualquier alteración — por mínima que sea — es detectable de forma inmediata y automática. No depende de políticas internas ni de buena voluntad: la integridad está garantizada por diseño matemático.

**Resultado para su organización:** Ante una auditoría o incidente, usted puede demostrar que sus registros no han sido alterados desde su creación. Sin discusión posible.

---

### 2. Confidencialidad y control de acceso

**Lo que dice la ley:** Solo personas y sistemas autorizados deben acceder a información sensible. Se requieren mecanismos robustos de autenticación y control de acceso.

**Lo que entregamos:** Cerulean opera con un modelo de "denegación por defecto" — nadie accede a nada a menos que esté explícitamente autorizado. Cada organización participante tiene su propio espacio aislado y solo ve la información que le corresponde. La autenticación se realiza mediante certificados digitales, no contraseñas.

**Resultado para su organización:** Cumplimiento inmediato del principio de mínimo privilegio. Separación de datos entre organizaciones sin configuración compleja.

---

### 3. Trazabilidad y auditoría

**Lo que dice la ley:** Toda acción relevante debe quedar registrada de forma auditable. Se debe poder reconstruir qué ocurrió, quién lo hizo, y cuándo.

**Lo que entregamos:** Cada operación en Cerulean Ledger queda firmada digitalmente con la identidad del autor, con fecha y hora, y vinculada a un registro permanente e inalterable. Un auditor externo puede verificar cualquier operación sin necesidad de acceder al sistema completo.

**Resultado para su organización:** Trail de auditoría completo, verificable por terceros, disponible en tiempo real. Cumple con los requisitos de la ANCI y de cualquier auditor externo.

---

### 4. Criptografía de estado del arte

**Lo que dice la ley:** Se deben utilizar estándares criptográficos reconocidos y actualizados. La seguridad debe reflejar el "estado del arte" de la industria.

**Lo que entregamos:** Cerulean Ledger implementa los estándares más recientes del NIST (Instituto Nacional de Estándares de EE.UU.):

- **ML-DSA-65** (FIPS 204, 2024) — firmas digitales de nueva generación
- **SHA3-256** (FIPS 202) — algoritmo de hash de última generación
- **ML-KEM-768** (FIPS 203) — intercambio de claves resistente a computación cuántica (TLS híbrido, opt-in)

Estos son los mismos estándares que están adoptando el Departamento de Defensa de EE.UU. y la Unión Europea para proteger infraestructura crítica.

**Resultado para su organización:** No solo cumple con el estándar actual — ya está protegido contra las amenazas de la próxima década. Cuando la computación cuántica sea una realidad, sus registros seguirán siendo seguros.

---

### 5. Continuidad operacional

**Lo que dice la ley:** Los servicios esenciales deben garantizar continuidad ante fallas, ataques o desastres. Se exigen planes de recuperación y mecanismos de resiliencia.

**Lo que entregamos:** Hoy la red tiene un nodo que escribe y nodos réplica que guardan una copia completa de la cadena. Si el nodo que escribe cae, los registros siguen disponibles y verificables en las réplicas, pero no se aceptan registros nuevos hasta que vuelve. El consenso BFT con 4 validadores ya está implementado y probado: con un validador caído, los otros 3 siguen aceptando registros y el que vuelve se pone al día solo. Su activación en producción está pendiente. Los datos se persisten en almacenamiento duradero con recuperación automática tras reinicio. El sistema soporta apagados controlados sin pérdida de información.

**Resultado para su organización:** Sus registros no se pierden si falla un servidor. Con el consenso BFT activo, además seguirán aceptándose registros nuevos aunque falle un validador.

---

### 6. Gestión de riesgos y detección de amenazas

**Lo que dice la ley:** Se deben implementar mecanismos de detección, prevención y respuesta ante incidentes de ciberseguridad.

**Lo que entregamos:** Cerulean incluye detección automática de comportamiento malicioso: si un participante intenta manipular el sistema, es detectado y aislado automáticamente. Límites de velocidad protegen contra ataques de saturación. Eventos de seguridad se emiten en tiempo real para integración con sus sistemas de monitoreo (SIEM).

**Resultado para su organización:** Detección proactiva de amenazas integrada en la plataforma, lista para conectar con su CSIRT o SOC interno.

---

### 7. Gobernanza de seguridad

**Lo que dice la ley:** Las organizaciones deben establecer estructuras de gobernanza para la ciberseguridad, con roles, responsabilidades y procedimientos claros.

**Lo que entregamos:** Cerulean incluye un sistema de gobernanza integrado donde las decisiones se toman mediante votación verificable entre los participantes autorizados. Cada cambio de política queda registrado, votado y auditable. No hay decisiones unilaterales opacas.

**Resultado para su organización:** Gobernanza de seguridad auditable y transparente, demostrable ante el regulador.

---

## Lo que la ley no exige pero nosotros sí entregamos

| Capacidad | Beneficio |
|---|---|
| **Protección post-cuántica** | Sus registros de hoy seguirán siendo seguros cuando existan computadores cuánticos capaces de romper la criptografía convencional |
| **Verificación desde dispositivos móviles** | Un auditor o regulador puede verificar registros desde su teléfono, sin instalar nada pesado |
| **Interoperabilidad multi-organización** | Varias instituciones comparten una verdad común sin que ninguna pueda alterarla unilateralmente |
| **Ejecución de reglas automatizadas** | Lógica de negocio que se ejecuta automáticamente y de forma verificable (contratos inteligentes) |

---

## Modelo de implementación

### Fase 1 — Piloto (4-6 semanas)

- Despliegue en su infraestructura o en nube privada
- Integración con un proceso crítico de su organización
- Capacitación del equipo operacional
- Informe de cumplimiento inicial

### Fase 2 — Producción (2-4 semanas adicionales)

- Conexión con sistemas existentes (ERP, SIEM, bases de datos)
- Configuración de políticas de acceso y retención
- Documentación de gobernanza para el regulador
- Monitoreo y alertas en producción

### Fase 3 — Certificación (según necesidad)

- Acompañamiento para auditoría externa
- Preparación de evidencia para la ANCI
- Ruta hacia certificación FIPS 140-3 (si se requiere para mercado internacional)

---

## Preguntas frecuentes

**"¿Necesito reemplazar mis sistemas actuales?"**
No. Cerulean se integra con su infraestructura existente mediante APIs estándar. No reemplaza su ERP o su base de datos — agrega una capa de integridad y verificabilidad sobre ellos.

**"¿Quién controla los datos?"**
Usted. Cerulean se despliega en su propia infraestructura o en una nube que usted controle. No hay dependencia de terceros ni de plataformas públicas.

**"¿Qué pasa si la ley cambia o se agregan requisitos?"**
La plataforma es configurable y extensible. Los algoritmos criptográficos, las políticas de acceso y las reglas de negocio se pueden actualizar sin reemplazar el sistema.

**"¿Es esto una blockchain?"**
Técnicamente sí, pero lo relevante es que es una plataforma de registros digitales verificables, inmutables y auditables. La tecnología subyacente es un medio, no un fin.

**"¿Cuánto cuesta?"**
Depende del alcance. Ofrecemos desde pilotos acotados hasta despliegues multi-organización. Contáctenos para una evaluación sin costo de su caso particular.

---

## Resumen

| Requisito Ley 21.663 | Cerulean Ledger | Estado |
|---|---|---|
| Integridad de registros | Inmutabilidad criptográfica por diseño | Cumple |
| Confidencialidad | Aislamiento por organización, acceso denegado por defecto | Cumple |
| Trazabilidad | Firma digital + timestamp en cada operación | Cumple |
| Criptografía actualizada | NIST FIPS 204/202/203 (estándares 2024) | Excede |
| Continuidad operacional | Réplicas completas de la cadena; consenso BFT de 4 validadores probado, activación pendiente | Parcial |
| Detección de amenazas | Detección automática de manipulación + rate limiting | Cumple |
| Gobernanza | Votación verificable y auditable entre participantes | Cumple |
| Protección post-cuántica | ML-DSA-65 (firmas) + ML-KEM-768 (TLS híbrido opt-in) | Excede (no exigido) |

**Cerulean Ledger no es una solución buscando un problema. Es la respuesta técnica a lo que la ley ya exige — y a lo que va a exigir mañana.**

---

*Documento preparado por el equipo Cerulean Ledger. Para consultas: contacto comercial disponible bajo solicitud.*
