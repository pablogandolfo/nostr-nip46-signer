# Modelo de amenazas --- Nostr Remote Signer

**Clasificación:** documento técnico de seguridad\
**Sistema:** Nostr Remote Signer MVP\
**Alcance:** aplicación Go, vault en memoria, transporte NIP-46/NIP-44,
interfaz HTTP y contenedor Docker\
**Estado:** modelo inicial; requiere revisión y validación técnica
independiente

## 1. Objetivo

Este documento identifica los activos críticos, límites de confianza,
amenazas, controles y riesgos residuales del MVP de Remote Signer. Se
utiliza para orientar decisiones de diseño y priorizar medidas de
mitigación antes de una eventual puesta en producción.

El modelo no constituye una certificación de seguridad ni acredita que
todas las mitigaciones estén implementadas o probadas.

## 2. Alcance y supuestos

Se consideran:

-   Proceso Go que mantiene el vault de claves.
-   API HTTP y panel web administrativo.
-   Sesiones y autorización NIP-46.
-   Cifrado de mensajes NIP-44.
-   Conexiones WebSocket salientes a relays Nostr.
-   Imagen Docker basada en Alpine Linux.
-   Sistema operativo host, runtime de contenedores y red.

Supuestos de diseño:

-   El servicio no necesita persistir claves privadas para el
    funcionamiento del MVP.
-   Los relays son infraestructura externa y no se consideran
    confiables.
-   El operador controla el host y la configuración de despliegue.
-   La interfaz web es una herramienta administrativa, no un mecanismo
    de autenticación.
-   Las operaciones de firma deben limitarse a comandos y eventos
    expresamente autorizados.

## 3. Activos y objetivos de seguridad

  -----------------------------------------------------------------------
  Activo                  Impacto de compromiso   Objetivo
  ----------------------- ----------------------- -----------------------
  Clave privada           Suplantación permanente Confidencialidad y
  (`nsec`/secreto)        de identidad y firma    control de acceso
                          fraudulenta             

  Clave pública (`npub`)  Correlación e           Exposición controlada
                          identificación de la    
                          identidad               

  Secreto de              Vinculación no          Confidencialidad y uso
  emparejamiento          autorizada de clientes  único/controlado

  Sesiones autorizadas    Ejecución de comandos   Integridad y revocación
                          no aprobados            

  Solicitudes y           Manipulación o          Autenticidad e
  respuestas NIP-46       repetición de           integridad
                          operaciones             

  URI bunker              Acceso o intento de     Distribución controlada
                          emparejamiento no       
                          autorizado              

  Configuración y relays  Redirección o           Integridad y
                          degradación del         disponibilidad
                          servicio                

  API administrativa      Sustitución de          Autenticación y
                          identidad o abuso de    autorización
                          recursos                

  Logs y volcados         Exposición accidental   Minimización y
                          de secretos             confidencialidad
  -----------------------------------------------------------------------

## 4. Límites de confianza y superficies de ataque

1.  **Navegador → API HTTP:** datos no confiables, riesgo de CSRF, XSS,
    abuso de endpoints y solicitudes automatizadas.
2.  **API → vault:** frontera de acceso al material criptográfico;
    requiere sincronización, validación y ciclo de vida seguro.
3.  **Signer → relay:** red externa no confiable; los eventos recibidos
    deben validarse criptográficamente y semánticamente.
4.  **Cliente NIP-46 → signer:** el cifrado no sustituye la
    autenticación, autorización ni validación de comandos.
5.  **Contenedor → host:** el aislamiento del contenedor depende del
    kernel, runtime, configuración y privilegios del host.
6.  **Proceso → memoria del sistema operativo:** GC, swap, core dumps,
    depuradores y volcados pueden afectar la confidencialidad de
    secretos.

## 5. Amenazas y mitigaciones

### 5.1 Exposición de claves privadas

**Amenaza:** un atacante obtiene la clave privada desde archivos, bases
de datos, logs, variables de entorno, volcados o memoria del proceso.

**Impacto:** compromiso de la identidad Nostr y capacidad de producir
firmas fraudulentas.

**Controles de diseño:**

-   Mantener el secreto en el vault residente en memoria.
-   Evitar persistencia intencional en archivos y bases de datos.
-   No registrar claves, `nsec`, secretos de pairing, URI bunker ni
    payloads sensibles.
-   Evitar devolver material secreto a la interfaz web.
-   Limitar las funciones que pueden operar sobre el secreto.
-   Cerrar el vault durante el apagado controlado.

**Riesgo residual y precisión técnica:**

La memoria RAM no constituye una garantía absoluta contra análisis
forense. Go utiliza garbage collection y puede crear copias de datos;
las cadenas son inmutables; el sistema operativo puede utilizar swap; y
un proceso privilegiado puede inspeccionar memoria o generar core dumps.
La llamada a una rutina de limpieza tampoco garantiza por sí sola que
todas las copias hayan sido sobrescritas.

**Medidas adicionales recomendadas:**

-   Deshabilitar core dumps cuando la plataforma lo permita.
-   Evaluar swap cifrado o deshabilitado según la política del host.
-   Restringir `ptrace`, depuración y acceso al proceso.
-   Minimizar copias y duración de vida de secretos.
-   Evaluar bibliotecas y primitivas que permitan manejo de buffers
    controlados y borrado explícito.
-   Considerar aislamiento mediante usuario dedicado, límites de
    recursos y controles MAC del sistema operativo.

### 5.2 Fuerza bruta y abuso de endpoints

**Amenaza:** un atacante automatiza solicitudes de importación,
generación de identidades o recuperación de URI bunker.

**Impacto:** agotamiento de CPU/memoria, abuso de recursos y aumento de
oportunidades de ataque contra operaciones administrativas.

**Control previsto:** rate limiting en memoria, con exclusión mutua
(`sync.Mutex`) para proteger el estado compartido.

Política de referencia del MVP:

  Endpoint                             Umbral    Ventana
  -------------------------- ---------------- ----------
  `POST /api/key/import`        5 solicitudes   1 minuto
  `POST /api/key/generate`      5 solicitudes   1 minuto
  `GET /api/bunker`            10 solicitudes   1 minuto
  `GET /api/status`            30 solicitudes   1 minuto

La clave del contador combina IP, método y ruta. Al superar el umbral,
el middleware devuelve HTTP `429 Too Many Requests` y un encabezado
`Retry-After`.

**Riesgo residual:**

-   Los límites en memoria se reinician al reiniciar el proceso.
-   El control por IP puede eludirse mediante múltiples IP o redes
    distribuidas.
-   Usuarios detrás de NAT pueden compartir el mismo límite.
-   Un mapa limitado reduce crecimiento indefinido, pero debe diseñarse
    cuidadosamente para resistir agotamiento de entradas.
-   Un mutex global puede convertirse en punto de contención bajo carga.

**Medidas adicionales recomendadas:** autenticación administrativa,
límites en proxy perimetral, cuotas globales, métricas, alertas y
pruebas de carga/concurrencia.

### 5.3 XSS y manipulación del DOM

**Amenaza:** datos no confiables se insertan en el DOM como HTML
ejecutable.

**Impacto:** ejecución de JavaScript en el origen del panel y posible
abuso de las funciones administrativas disponibles.

**Controles previstos:**

-   Utilizar `textContent` para mensajes y valores textuales recibidos
    del servidor.
-   Evitar `innerHTML` y evaluación dinámica de código.
-   Mantener la interfaz en JavaScript nativo y reducir dependencias.
-   Aplicar Content Security Policy.

**Riesgo residual:** la CSP solicitada permite `'unsafe-inline'` para
scripts y estilos. Esto reduce su eficacia frente a determinados
escenarios XSS. Además, `textContent` no protege por sí solo frente a
CSRF, robo de sesión o abuso de endpoints.

**Medidas adicionales recomendadas:** mover scripts y estilos a archivos
externos, eliminar `'unsafe-inline'`, aplicar nonces o hashes cuando
proceda y validar estrictamente el contenido de entrada.

### 5.4 Clickjacking y contenido MIME

**Amenaza:** el panel se incorpora en un frame malicioso o el navegador
interpreta contenido con un tipo MIME distinto del esperado.

**Controles previstos:**

``` http
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
Referrer-Policy: no-referrer
```

**Riesgo residual:** la política CSP debe revisarse conforme a los
recursos reales de la aplicación. Para una política moderna y más
estricta se recomienda incorporar `frame-ancestors 'none'`, además de
eliminar las excepciones inline.

### 5.5 CSRF y acceso administrativo no autorizado

**Amenaza:** un sitio externo induce al navegador de un operador a
realizar solicitudes administrativas, o un tercero accede directamente a
los endpoints.

**Impacto:** importación o sustitución de identidad, generación de
claves y obtención de URI bunker.

**Estado:** el rate limiting y las cabeceras de seguridad no
proporcionan autenticación ni protección CSRF completa.

**Controles requeridos antes de producción:**

-   Autenticación administrativa explícita.
-   Token CSRF y validación de origen.
-   Cookies seguras si se utiliza autenticación basada en sesión
    (`HttpOnly`, `Secure`, `SameSite`).
-   Restricción de escucha a loopback o red administrativa.
-   TLS cuando exista acceso remoto.
-   Autorización específica para cada operación.

### 5.6 Ataques al protocolo NIP-46/NIP-44

**Amenaza:** cliente no autorizado, mensaje manipulado, repetición de
solicitud, comando fuera de política o evento construido para inducir
una firma no deseada.

**Impacto:** acceso no autorizado a operaciones criptográficas o firma
de eventos maliciosos.

**Controles requeridos:**

-   Validar la identidad del cliente y el secreto de pairing.
-   Derivar claves de conversación de acuerdo con la especificación
    NIP-44 y las claves correctas.
-   Validar estructura, tipo, tamaño, destinatario y contenido de cada
    mensaje.
-   Mantener una lista permitida de comandos.
-   Aplicar autorización granular por sesión.
-   Validar kind, tags, challenge, expiración y demás condiciones del
    flujo de autenticación objetivo.
-   Rechazar comandos desconocidos y eventos fuera de la política.
-   Gestionar expiración, revocación y cierre de sesiones.
-   No firmar automáticamente por el solo hecho de que un mensaje esté
    cifrado.

**Riesgo residual:** la interoperabilidad debe verificarse contra
clientes reales y vectores de prueba oficiales. La restricción a
`kind 22242` debe comprobarse frente al flujo de autenticación concreto;
no debe considerarse universal para cualquier cliente Nostr.

### 5.7 Relays maliciosos o no disponibles

**Amenaza:** relay que entrega eventos inválidos, duplicados o
retrasados, interrumpe conexiones o intenta degradar el servicio.

**Controles requeridos:**

-   Validación local de firmas y contenido.
-   Timeouts, límites de tamaño y control de concurrencia.
-   Reconexión con backoff.
-   Detección de duplicados y gestión de eventos fuera de orden.
-   Configuración explícita de relays confiables operacionalmente, sin
    delegarles la autorización.
-   No incluir secretos en filtros, logs o mensajes de diagnóstico.

### 5.8 Compromiso del contenedor o del host

**Amenaza:** explotación de dependencias, escalada de privilegios,
acceso al filesystem o compromiso del kernel/runtime.

**Controles defensivos previstos para Docker/Alpine:**

-   Imagen de ejecución mínima basada en Alpine Linux.
-   Usuario no privilegiado.
-   Filesystem de solo lectura.
-   `--cap-drop ALL`.
-   `no-new-privileges`.
-   Límites de memoria, CPU y procesos.
-   Sin montaje de volúmenes para claves.
-   Publicación del puerto únicamente en loopback del host.
-   Dependencias y certificados controlados.

**Riesgo residual:** Alpine reduce el tamaño de la imagen y la
superficie de paquetes, pero no es una frontera de seguridad por sí
sola. La seguridad depende también del kernel, runtime, configuración,
actualización de paquetes y cadena de suministro.

**Medidas adicionales recomendadas:** escaneo de imágenes, fijación de
versiones y digests, SBOM, firma de imágenes, actualizaciones periódicas
y ejecución de pruebas en el entorno de despliegue.

## 6. Matriz resumida de riesgos

  -----------------------------------------------------------------------
  Amenaza           Probabilidad      Impacto           Prioridad
                    inicial                             
  ----------------- ----------------- ----------------- -----------------
  Exposición de     Media             Crítico           Muy alta
  clave privada                                         

  Acceso            Alta si se expone Crítico           Muy alta
  administrativo no sin autenticación                   
  autorizado                                            

  Abuso de          Media             Alto              Alta
  endpoints /                                           
  fuerza bruta                                          

  Solicitudes       Media             Crítico           Muy alta
  NIP-46 no                                             
  autorizadas                                           

  XSS en panel      Media             Alto              Alta

  CSRF              Media             Alto              Alta

  Relay no          Media             Medio/alto        Alta
  disponible o                                          
  malicioso                                             

  Compromiso del    Baja/media        Crítico           Alta
  contenedor/host                                       

  Agotamiento del   Media             Medio             Media
  rate limiter                                          
  -----------------------------------------------------------------------

Las valoraciones son cualitativas y preliminares; deben ajustarse con
evidencia de pruebas, exposición real y análisis del entorno.

## 7. Requisitos de verificación

Antes de considerar el MVP apto para un entorno productivo:

-   [ ] Confirmar que ninguna clave privada aparece en logs, respuestas
    HTTP o archivos.
-   [ ] Revisar el ciclo de vida de las claves y la concurrencia del
    vault.
-   [ ] Ejecutar `go test -race ./...`.
-   [ ] Ejecutar análisis estático y escaneo de dependencias.
-   [ ] Verificar rate limiting, límites globales y comportamiento bajo
    carga.
-   [ ] Probar las cabeceras HTTP en respuestas 2xx, 4xx y 5xx.
-   [ ] Probar CSRF, XSS y autenticación administrativa.
-   [ ] Verificar NIP-44 con vectores oficiales y NIP-46 con clientes
    interoperables.
-   [ ] Verificar que las operaciones de firma requieren autorización
    válida.
-   [ ] Inspeccionar configuración Docker, usuario, capacidades y
    filesystem.
-   [ ] Revisar logs, core dumps, swap y permisos del host.
-   [ ] Documentar resultados, incidencias y aceptación de riesgos
    residuales.

## 8. Conclusión

El diseño del MVP adopta una estrategia de defensa en profundidad:
minimización de persistencia de secretos, criptografía nativa del
protocolo Nostr, validación de solicitudes, limitación de tráfico,
endurecimiento HTTP y ejecución contenerizada con privilegios reducidos.

Estos controles reducen superficies de ataque, pero no eliminan el
riesgo. La custodia en RAM no garantiza ausencia de rastros físicos, el
rate limiting no sustituye autenticación y Alpine no aísla por sí solo
un proceso frente a un host comprometido. La aprobación para producción
requiere completar los controles pendientes y obtener evidencia
reproducible de pruebas técnicas y de seguridad.
