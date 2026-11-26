Asunto: Comentarios al Documento de Política — Modernización del Mercado Financiero

Santiago, [fecha]

Comisión para el Mercado Financiero
Dirección de Desarrollo de Mercado
desarrollofinanciero@cmfchile.cl

Ref.: Documento de Política "Modernización del Mercado Financiero" (versión 25/08/2026)

Estimada Comisión:

En atención a la invitación formulada por la CMF para recibir comentarios sobre las propuestas contenidas en el Documento de Política sobre Modernización del Mercado Financiero, presentamos las siguientes observaciones técnicas en relación con un conjunto de iniciativas donde consideramos que la experiencia adquirida en el desarrollo de infraestructura de registro distribuido puede resultar pertinente para el análisis que la Comisión se encuentra realizando.

Las observaciones que se presentan a continuación se refieren a las iniciativas (iv), (v), (vi) del Capítulo III, y a las Propuestas 6, 20 y 24 del Capítulo IV, en las cuales identificamos puntos de convergencia entre los objetivos planteados por la Comisión y las capacidades técnicas que hemos desarrollado en el marco del proyecto Goya Ledger, una plataforma de registro distribuido de origen chileno orientada al mercado financiero regulado.

---

**1. Sobre la Mesa Técnica sobre Tokenización de Activos (Iniciativa iv)**

El documento señala correctamente que el trabajo de esta mesa debería incluir el análisis de la equivalencia jurídica de los registros distribuidos, la interoperabilidad con la infraestructura financiera existente, el uso de contratos inteligentes, los estándares de ciberseguridad y la realización de espacios de experimentación.

Al respecto, consideramos pertinente señalar que varios de estos aspectos ya cuentan con implementaciones funcionales que podrían servir como referencia técnica para el trabajo de la mesa:

- **Equivalencia jurídica del registro**: Goya Ledger implementa un marco de firma electrónica que distingue entre Firma Electrónica Simple (FES) y Firma Electrónica Avanzada (FEA), en conformidad con la Ley 19.799 y en alineación con el Reglamento eIDAS de la Unión Europea. Las firmas se ejecutan mediante Ed25519 (FES) y ML-DSA-65 (FEA, estándar post-cuántico FIPS 204), lo que permite asociar validez probatoria diferenciada a cada tipo de registro según su nivel de firma.

- **Interoperabilidad con infraestructura financiera**: La plataforma implementa los estándares OID4VCI y OID4VP en su versión 1.0 Final, lo que permite la emisión y presentación de credenciales verificables interoperables con la European Digital Identity Wallet (EUDIW). Esto incluye soporte para formatos SD-JWT VC y mdoc (ISO 18013-5), mecanismos de Pushed Authorization Request (PAR) con PKCE, y un nonce endpoint separado conforme a la especificación vigente.

- **Contratos inteligentes**: La plataforma incluye un motor de ejecución de contratos basado en EVM (revm), un ciclo de vida de chaincode (install → approve → commit → simulate) y un motor de contratos legales (LexChain) que orquesta la suscripción con firma electrónica y estampado de tiempo RFC 3161.

- **Ciberseguridad**: Se han incorporado los tres estándares post-cuánticos publicados por NIST (ML-KEM-768 para encapsulación de claves, ML-DSA-65 para firmas digitales, y SLH-DSA para firmas basadas en hash), junto con un módulo criptográfico orientado a FIPS 140. La capa de transporte utiliza un híbrido X25519+ML-KEM-768 para protección ante la amenaza de harvest-now-decrypt-later.

Consideramos que la existencia de estas implementaciones podría contribuir a que el trabajo de la mesa técnica se desarrolle sobre la base de evidencia práctica, complementando el análisis regulatorio con la experiencia de operar un sistema que ya enfrenta los desafíos técnicos que la iniciativa busca abordar.

---

**2. Sobre la Eliminación de Títulos Físicos en Emisiones Desmaterializadas (Iniciativa v)**

El documento plantea consolidar la desmaterialización de los valores, eliminando la necesidad de emitir o mantener títulos físicos cuando la propiedad ya se acredita mediante anotaciones en cuenta.

En este contexto, un registro distribuido con consenso BFT (Byzantine Fault Tolerant) ofrece una alternativa técnica para representar la propiedad de instrumentos desmaterializados con garantías formales de integridad: cada anotación es inmutable, ordenada por consenso, y verificable de forma independiente por cualquier participante autorizado. La operación del registro puede distribuirse entre múltiples validadores independientes, reduciendo la dependencia de un único punto de control a medida que se incorporan operadores independientes.

Goya Ledger implementa este modelo mediante un protocolo de consenso basado en HotStuff con Delegated Proof of Stake, verificado formalmente en Lean 4 para la propiedad de no-bifurcación (no_fork). El sistema de credenciales verificables (SD-JWT VC con divulgación selectiva) permite representar la titularidad con la granularidad que requiere la interacción entre emisores, depositarios y reguladores.

---

**3. Sobre la Automatización de Modificaciones en Líneas de Bonos (Iniciativa vi)**

La iniciativa busca simplificar y digitalizar el registro de modificaciones estandarizadas en líneas de bonos, reduciendo tiempos de tramitación y cargas administrativas.

El motor LexChain de Goya Ledger fue diseñado precisamente para este tipo de operaciones: la creación, modificación y suscripción de instrumentos contractuales con firma electrónica, estampado de tiempo y registro en blockchain. El flujo contempla la orquestación de firmas FES o FEA según el nivel requerido, la generación de sellos de tiempo RFC 3161 por una autoridad TSA, y el registro inmutable del evento contractual. Este tipo de automatización podría adaptarse al ciclo de vida de modificaciones en líneas de bonos, donde la estandarización del instrumento permite definir reglas programáticas para su procesamiento.

---

**4. Sobre Transferencias Electrónicas Simplificadas para EMT y Microempresarios (Propuesta 6)**

La propuesta busca impulsar esquemas de transferencias simplificadas basados en identificadores únicos que permitan realizar pagos de forma más simple, rápida y segura.

Un sistema de identidad descentralizada basado en Identificadores Descentralizados (DID) ofrece una alternativa técnica para este propósito. En Goya Ledger, cada participante obtiene un identificador en el formato `did:goya:{derivación}`, generado de manera determinista a partir de su clave pública. Este identificador es verificable criptográficamente, no depende de un registro centralizado, y permite asociar credenciales verificables (como la habilitación para operar en un determinado esquema de pagos) sin exponer datos personales innecesarios, gracias al mecanismo de divulgación selectiva de SD-JWT.

Esta arquitectura podría resultar compatible con los objetivos de interoperabilidad entre proveedores de servicios de pago y de inclusión financiera que la propuesta plantea.

---

**5. Sobre el Reconocimiento de Equivalencia Regulatoria Bancaria ante la Unión Europea (Propuesta 20)**

La propuesta busca promover el reconocimiento de equivalencia de la normativa prudencial chilena por parte de las autoridades europeas, facilitando que las entidades financieras de esa jurisdicción puedan invertir en instrumentos chilenos bajo condiciones regulatorias equivalentes.

En esta línea, consideramos relevante señalar que la interoperabilidad técnica con los estándares europeos constituye un complemento necesario al reconocimiento regulatorio. Goya Ledger ha sido diseñado para operar bajo los estándares que la Unión Europea está adoptando en el marco de eIDAS 2.0 y la Architecture and Reference Framework (ARF) de la EUDIW. La plataforma ha superado un conjunto de 62 pruebas de conformidad que verifican la compatibilidad con las especificaciones OID4VCI 1.0 Final, OID4VP 1.0 Final, SD-JWT VC, y los requisitos del Reglamento de Implementación CIR 2025/848 para el registro de Relying Parties.

Adicionalmente, el proyecto cuenta con una entidad legal constituida en Estonia, lo que permite la notificación como Prestador de Servicios de Confianza (TSP) ante el Registro Estonio de Actividad Económica (RIA), bajo el marco del Reglamento eIDAS. Esta experiencia práctica podría aportar antecedentes al análisis que la CMF desarrolle sobre los requisitos técnicos que faciliten el reconocimiento de equivalencia.

---

**6. Sobre el Fortalecimiento de la Infraestructura de Colaterales Financieros (Propuesta 24)**

La propuesta plantea modernizar el régimen aplicable a las garantías financieras para asegurar su ejecución oportuna y eficaz, particularmente en escenarios de insolvencia.

Un mecanismo de escrow programático sobre registro distribuido ofrece una vía para implementar la ejecución automática de garantías bajo condiciones predefinidas, con certeza jurídica respaldada por el registro inmutable de cada operación. Goya Ledger implementa un ciclo de vida de escrow (lock → release para operaciones salientes; verify proof → mint para operaciones entrantes) con verificación de pruebas Merkle, lo que permite demostrar la existencia y el estado de una garantía sin requerir la intervención de un tercero de confianza adicional.

Este tipo de infraestructura podría resultar pertinente para el tratamiento de colaterales financieros en contextos donde la velocidad de ejecución y la reducción del riesgo de contraparte constituyen prioridades, como señala la propuesta.

---

**Observación general**

El Documento de Política señala que la modernización del mercado financiero "deja de ser únicamente una agenda de perfeccionamiento regulatorio y pasa a constituir una condición necesaria para mantener la competitividad del mercado chileno" (Sección II, p. 5). Coincidimos con este diagnóstico y consideramos que la incorporación de tecnologías de registro distribuido, identidad descentralizada y criptografía post-cuántica no constituye un ejercicio especulativo, sino una necesidad que varias jurisdicciones ya están abordando mediante marcos regulatorios concretos — como MiCA y eIDAS 2.0 en la Unión Europea.

La existencia de una implementación funcional de origen chileno, con alineación a estos estándares internacionales y con un marco de firma electrónica compatible con la Ley 19.799, puede constituir un insumo útil para el trabajo técnico que la Comisión tiene previsto desarrollar en torno a estas propuestas.

Quedamos a disposición de la Comisión para aportar información técnica adicional, facilitar acceso a la plataforma para su evaluación, o participar en las instancias de diálogo técnico que se establezcan en el contexto de estas iniciativas.

Atentamente,

[Nombre]
[Cargo]
[Contacto]
