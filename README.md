# LZ-ADaudit

LZ-ADaudit es un script PowerShell para auditoria de Active Directory orientado a ejecucion en Domain Controller (DC) o desde remote shell no interactiva (por ejemplo, EDR).

Diseno operativo:
- Script unico (`AdAudit.ps1`), sin base de datos y sin UI local.
- Salida estructurada priorizada para pipelines (`JSON`, `NDJSON`, `CSV`).
- Compatible con ejecucion silenciosa (`-quiet`) y logs en archivo.

Release actual:
- `tool_name`: `LZ-ADaudit`
- `tool_version`: `v1.0.0`
- `schema_version`: `1.0`
- `release_date`: `2026-04-12`

Nota de versionado:
- Este repositorio se publica como herramienta nueva desde `v1.0.0`.
- No requiere heredar numeracion historica `5.x/6.x`.

## Que incluye v1.0.0

- Contrato de salida estable para pipelines (`execution.json`, `summary.json`, `findings.ndjson`, `findings.csv`).
- Modo `incident-response` para entornos post-compromiso.
- Correlacion de eventos de seguridad para trazabilidad (`4720`, `4728`, `4732`, `4756`).
- Soporte de baseline diff entre ejecuciones para comparar evolucion de riesgo.

## Respuesta rapida: trazabilidad de creacion de cuentas

Pregunta frecuente: "Esto ya incluye quien creo un usuario/grupo?"

Respuesta corta:
- Si, en modo incident response ahora hay correlacion nativa de Security Event Log para IDs `4720`, `4728`, `4732` y `4756`.
- Si detecta objetos nuevos por fecha (`whenCreated`) con `-recentchanges`.
- Tambien exporta inventarios con columna `WhenCreated` (`inventory/users.csv`, `inventory/groups.csv`).

Salida IR relacionada:
- `evidence/security_events.json`
- `evidence/security_events.csv`

Nota:
- La trazabilidad depende de retencion del log `Security` y de permisos de lectura sobre ese log.

## Requisitos

Minimos:
- Windows PowerShell `5+`
- Modulo `ActiveDirectory` (RSAT)

Opcionales:
- Modulo `GroupPolicy` (mejora checks y evidencia GPO)
- Modulo `DSInternals` (password quality, capacidades opcionales)

Recomendado:
- Ejecutar como administrador local en DC.

## Ejecucion rapida

Ejemplo baseline de auditoria:

```powershell
powershell -ExecutionPolicy Bypass -File .\AdAudit.ps1 -profile standard -quiet -outputPath C:\AuditOut
```

Preflight solamente:

```powershell
powershell -ExecutionPolicy Bypass -File .\AdAudit.ps1 -preflight -outputPath C:\AuditOut
```

Auditoria con inventario y evidencia:

```powershell
powershell -ExecutionPolicy Bypass -File .\AdAudit.ps1 -profile evidence -inventory -evidence -quiet -outputPath C:\AuditOut
```

Modo incident response (alias rapido):

```powershell
powershell -ExecutionPolicy Bypass -File .\AdAudit.ps1 -incidentresponse -quiet -outputPath C:\AuditOut
```

Tambien puedes usar:
- `-incident-response`
- `-incident-respones` (alias tolerante para typo operativo)

Comparacion contra ejecucion previa:

```powershell
powershell -ExecutionPolicy Bypass -File .\AdAudit.ps1 -profile standard -baseline C:\AuditOut-Previo -outputPath C:\AuditOut-Nuevo
```

`-baseline` acepta:
- Ruta de carpeta de salida previa (busca `findings.csv` o `findings.ndjson`).
- Ruta directa a `findings.csv`.
- Ruta directa a `findings.ndjson`.

## Perfiles

Perfiles actuales:
- `light`: rapido y bajo impacto.
- `standard`: cobertura equilibrada por defecto.
- `deep`: incluye mas modulos y tambien `-ntds`.
- `evidence`: cobertura amplia con orientacion a evidencia, sin `-ntds` por defecto.
- `incident-response`: perfil enfocado a post-incidente, incluye correlacion de eventos de seguridad y activa modo de evidencia/inventario.
- `inventory-only`: inventario base, menor carga.

Regla importante:
- `deep` ya incluye `ntds`.
- Si usas `evidence` y quieres dump de NTDS, agrega `-ntds` manualmente.

## Diferencia entre ejecutar con `-ntds` y sin `-ntds`

Sin `-ntds`:
- Evalua postura de seguridad AD (ACL, GPO, LDAP, cuentas, trusts, LAPS, ADCS, etc).
- Permite detectar usuarios/grupos recientes (`-recentchanges`) y cambios de inventario.
- Menor riesgo operativo y menor sensibilidad de datos.

Con `-ntds`:
- Ejecuta `ntdsutil` para generar copia de `ntds.dit` y artefactos asociados en salida.
- Aporta valor forense alto para analisis de credenciales post-compromiso.
- Incrementa sensibilidad, riesgo y requisitos de manejo seguro de evidencia.

Recomendacion IR:
- Primera corrida: sin `-ntds` (triage rapido).
- Segunda corrida: con `-ntds` solo si hay aprobacion y cadena de custodia clara.
- Si usas `-incidentresponse`, ya incluye `securityevents` para mapear actor/miembro/grupo en cambios recientes.

## Estructura de salida

Salida estructurada principal (segun modo):

```text
<outputPath>\
  execution.json
  preflight.json
  summary.json
  findings.ndjson
  findings.csv
  adaudit.nessus                 (si no usas -noNessus)
  logs\
    console.log
    debug.log
  inventory\                     (si inventory mode activo)
    users.csv
    groups.csv
    computers.csv
    dcs.csv
    trusts.csv
    gpos.csv
    privileged_accounts.csv
    service_accounts.csv
    adcs_templates.csv
  evidence\                      (si inventory mode activo)
    password_policy.json
    trusts.json
    gpo.json
    laps.json
    domain.json
    ldap.json
    acl.json
    adcs.json
    security_events.json
    security_events.csv
  diff\                          (si usas -baseline)
    diff-summary.json
    findings-added.csv
    findings-removed.csv
    findings-changed.csv
    inventory-*-added.csv
    inventory-*-removed.csv
```

Nota:
- Ademas de estos archivos estructurados, algunos modulos legacy siguen dejando artefactos `.txt/.html` para compatibilidad.

## Modos de consola y logging

Control de salida:
- `-quiet`: silencia consola (se mantienen logs en archivo).
- `-logLevel normal|verbose|debug`: controla verbosidad de consola.

Logs:
- `logs/console.log`: salida operativa.
- `logs/debug.log`: salida detallada con timestamp.

## Estados de finding

Estados normalizados soportados:
- `passed`
- `failed`
- `warning`
- `not_applicable`
- `not_evaluated`
- `partial`
- `error`

Severidad soportada:
- `informational`, `low`, `medium`, `high`, `critical`

## Codigos de salida

Comportamiento actual:
- `0`: ejecucion completa sin findings accionables.
- `1`: ejecucion completa con findings.
- `2`: ejecucion parcial (modulos fallidos o timeout/partial).
- `3`: fallo de preflight en modo `-preflight` o error de prerequisito critico (ej. modulo AD faltante al arrancar).
- `4`: error fatal al preparar salida (ej. no se puede crear directorio de output).
- `5`: parametros/seleccion invalida (ej. ejecutar sin checks/modos).

## Modulos principales disponibles

Por switch:
- `-hostdetails`
- `-domainaudit`
- `-trusts`
- `-accounts`
- `-passwordpolicy`
- `-ntds`
- `-oldboxes`
- `-gpo`
- `-ouperms`
- `-laps`
- `-authpolsilos`
- `-insecurednszone`
- `-recentchanges`
- `-spn`
- `-asrep`
- `-acl`
- `-adcs`
- `-ldapsecurity`
- `-securityevents`
- `-all`

Control adicional:
- `-select <lista>`
- `-exclude <lista>`
- `-moduleTimeoutSeconds <n>`
- `-outputPath <ruta>`
- `-baseline <ruta>`
- `-inventory`
- `-evidence`
- `-preflight`
- `-noNessus`
- `-incidentresponse` (alias: `-incident-response`, `-incident-respones`)

## Roadmap sugerido (alineado a IR)

Siguiente mejora recomendada para IR:
- Ampliar correlacion a mas IDs (`4726`, `4738`, `4740`, `4767`) y agrupar por cadena de ataque.
- Marcar explicitamente grupos de alta sensibilidad (Domain Admins, Enterprise Admins, Administrators, etc.) con prioridad extra.

## Uso responsable

Esta herramienta maneja datos sensibles de AD. Si habilitas `-ntds`:
- Define cadena de custodia.
- Restringe acceso a carpeta de salida.
- Protege y elimina evidencia segun politica de IR/forense.
