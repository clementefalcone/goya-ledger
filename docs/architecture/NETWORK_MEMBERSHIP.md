# Membresía de red P2P

**Regla:** un nodo entra a la lista de peers solo si prueba, con una firma de su llave de validador, que controla la dirección que anuncia.

## Anuncios firmados

El mensaje `Version` lleva `signer` (llave pública en hex), `signed_at` (segundos UNIX) y `signature`. La firma cubre el mensaje `p2p:version:{network_id}:{p2p_address}:{signed_at}`. Un nodo admite la dirección anunciada solo si se cumplen las cuatro condiciones:

1. La llave está en `TRUSTED_BLOCK_SIGNERS`, o es la del propio nodo.
2. La firma es válida para ese `network_id` y esa dirección.
3. `signed_at` difiere menos de 300 s del reloj local.
4. La dirección es enrutable, es decir, no vacía y distinta de `0.0.0.0`.

Por cada vía de entrada a la lista:

- **Conexión entrante:** se admite la dirección declarada en el `Version`.
- **Conexión saliente (`connect_to_peer`):** además, la dirección declarada por el peer debe ser exactamente la que se marcó.
- **`Peers` y descubrimiento:** las listas que reportan otros nodos ya no se insertan. Se intenta conectar a cada dirección y solo entra la que supere el handshake firmado.

Un nodo sin `TRUSTED_BLOCK_SIGNERS` no admite a nadie más. Un `Version` sin firma o de una llave desconocida igual puede pedir bloques y enviar mensajes firmados, pero no entra a la lista de peers.

Cada validador debe definir `P2P_EXTERNAL_ADDRESS` con la dirección por la que los demás lo marcan.

## Certificate Pinning TLS

El pinning de certificados añade una segunda línea de defensa sobre la validación CA habitual: aunque un certificado esté firmado por una CA de confianza, solo se aceptan los nodos cuyo certificado coincida con un fingerprint conocido.

### Variable de entorno

| Variable | Obligatoria | Descripción |
|----------|-------------|-------------|
| `TLS_PINNED_CERTS` | No | Lista de fingerprints SHA-256 (hex) separados por coma. Si está ausente o vacía, el pinning está **desactivado** y se acepta cualquier cert válido. |

### Comportamiento

- **Sin `TLS_PINNED_CERTS`** (o vacío): solo se valida la cadena CA (comportamiento TLS/mTLS habitual).
- **Con `TLS_PINNED_CERTS`**: tras la validación CA, se comprueba que el fingerprint SHA-256 del cert de extremo (`end-entity`) esté en la lista. Si no coincide, el handshake se rechaza.
- El pinning aplica tanto a conexiones salientes (cert del servidor, vía `PinningServerCertVerifier`) como a mTLS entrante (cert del cliente, vía `PinningClientCertVerifier`).
- `TLS_VERIFY_PEER=false` desactiva toda verificación, incluido el pinning — solo para desarrollo.

### Calcular un fingerprint

El fingerprint es el SHA-256 de los bytes DER del certificado (no del PEM, sino del DER subyacente):

```bash
# A partir de un archivo PEM
openssl x509 -in peer.pem -outform DER | openssl dgst -sha256 -hex | awk '{print $2}'
```

El resultado es una cadena de 64 caracteres hexadecimales, por ejemplo:

```
a3f1c2e4b5d6789012345678901234567890abcdef1234567890abcdef123456
```

### Ejemplo de despliegue

```bash
# Pinning de dos nodos conocidos (fingerprints de ejemplo)
export TLS_PINNED_CERTS="a3f1c2e4b5d6789012345678901234567890abcdef1234567890abcdef123456,\
b7e8d9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7"

# Combinado con mTLS
export TLS_MUTUAL=true
export TLS_CA_CERT_PATH=/etc/bc/ca.pem
export TLS_CERT_PATH=/etc/bc/node.pem
export TLS_KEY_PATH=/etc/bc/node.key
export TLS_PINNED_CERTS="a3f1c2e4b5d6789012345678901234567890abcdef1234567890abcdef123456"
```

### Añadir un nuevo nodo

1. Obtener el PEM del cert del nuevo nodo.
2. Calcular su fingerprint con el comando anterior.
3. Añadir el fingerprint a `TLS_PINNED_CERTS` en todos los nodos existentes.
4. Reiniciar los nodos para que recojan la nueva lista.

> **Nota:** durante una rotación de certificados, incluir temporalmente tanto el fingerprint antiguo como el nuevo para evitar interrupciones del servicio.
