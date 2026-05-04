```
  ██╗     ███████╗      █████╗ ██████╗  █████╗ ██╗   ██╗██████╗ ██╗████████╗
  ██║     ╚══███╔╝     ██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
  ██║       ███╔╝      ███████║██║  ██║███████║██║   ██║██║  ██║██║   ██║
  ██║      ███╔╝       ██╔══██║██║  ██║██╔══██║██║   ██║██║  ██║██║   ██║
  ███████╗███████╗     ██║  ██║██████╔╝██║  ██║╚██████╔╝██████╔╝██║   ██║
  ╚══════╝╚══════╝     ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
```

**Active Directory Security Assessment** | Lazarus Security Framework

| Componente | Versión |
|---|---|
| `AdAudit.ps1` | `v1.4.1` |
| `report` (Python package) | `v1.6.0` |

---

Herramienta de auditoría de Active Directory diseñada para ejecución en Domain Controller o desde shell remota no interactiva (EDR, RDP, WinRM). Script único, sin dependencias externas obligatorias, salida estructurada lista para pipelines y generación automática de informes HTML + XLSX.

## Componentes

| Archivo | Descripción |
|---|---|
| `AdAudit.ps1` | Motor de auditoría PowerShell — recopila evidencia, genera findings |
| `report_generator.py` | Generador de informes — consume salida de AdAudit, produce HTML + XLSX |

## Requisitos

**Mínimos:**
- PowerShell 5.0+
- Módulo `ActiveDirectory` (RSAT)
- Ejecutar como Administrador en un DC (o cuenta con derechos de lectura AD)

**Opcionales:**
- Módulo `GroupPolicy` — mejora checks GPO y exportación
- Módulo `DSInternals` — análisis de calidad de contraseñas (`-ntds`)
- Python 3.8+ con `openpyxl` — para `report_generator.py`

## Ejecución rápida

```powershell
# Auditoría estándar
powershell -ExecutionPolicy Bypass -File .\AdAudit.ps1 -profile standard -outputPath C:\AuditOut

# Deep con todos los módulos
powershell -ExecutionPolicy Bypass -File .\AdAudit.ps1 -profile deep -inventory -evidence -outputPath C:\AuditOut

# Incident Response (post-compromiso)
powershell -ExecutionPolicy Bypass -File .\AdAudit.ps1 -incidentresponse -outputPath C:\AuditOut

# Módulos individuales
powershell -ExecutionPolicy Bypass -File .\AdAudit.ps1 -kerbdelegation -dcsync -hosthardening -outputPath C:\AuditOut
```

```bash
# Generar informe HTML + XLSX (detecta carpeta automáticamente)
python report_generator.py

# Especificar carpeta
python report_generator.py -f C:\AuditOut\20260413_120000
```

## Perfiles

| Perfil | Módulos incluidos |
|---|---|
| `light` | hostdetails, accounts, passwordpolicy, ldapsecurity |
| `standard` | + domainaudit, trusts, oldboxes, gpo, laps, dns, recentchanges, spn, asrep, **kerbdelegation**, **hosthardening** |
| `deep` | + ouperms, authpolsilos, **dcsync**, acl, adcs, ntds |
| `evidence` | deep sin ntds |
| `incident-response` | evidence + securityevents |
| `inventory-only` | hostdetails, domainaudit, accounts, oldboxes |

## Módulos disponibles

| Switch | Descripción | Severidad máx. |
|---|---|---|
| `-hostdetails` | Info del host, OS, dominio | INFO |
| `-domainaudit` | Nivel funcional, SMB, Kerberos, FSMO, DCs | HIGH |
| `-trusts` | Trusts de dominio/forest | MEDIUM |
| `-accounts` | Inactivos, bloqueados, privilegiados, protectedusers | HIGH |
| `-passwordpolicy` | Política de contraseñas (default + FGPP) | MEDIUM |
| `-ntds` | Dump de NTDS.dit via ntdsutil | CRITICAL |
| `-oldboxes` | Sistemas operativos EOL en el dominio | HIGH |
| `-gpo` | Exportación GPO, scan SYSVOL por credenciales | CRITICAL |
| `-ouperms` | Permisos no estándar en OUs | HIGH |
| `-laps` | Estado LAPS (legacy + Windows LAPS) | HIGH |
| `-authpolsilos` | Políticas de autenticación y silos | MEDIUM |
| `-insecurednszone` | Zonas DNS con actualizaciones inseguras | MEDIUM |
| `-recentchanges` | Usuarios y grupos creados en los últimos 30 días | MEDIUM |
| `-spn` | Cuentas Kerberoasteables de alto valor | HIGH |
| `-asrep` | Cuentas sin pre-autenticación Kerberos (AS-REP) | HIGH |
| `-kerbdelegation` | **[NUEVO]** Delegación Kerberos sin restricción (excl. DCs) | CRITICAL |
| `-dcsync` | **[NUEVO]** Cuentas con derechos DCSync (DS-Replication-Get-Changes-All) | CRITICAL |
| `-hosthardening` | **[NUEVO]** WDigest, LSA Protection (RunAsPPL), Credential Guard | HIGH |
| `-acl` | Permisos ACL peligrosos en objetos AD | HIGH |
| `-adcs` | Vulnerabilidades ADCS (ESC1-4, ESC8) | CRITICAL |
| `-ldapsecurity` | Firma LDAP, LDAPS, channel binding, null sessions | HIGH |
| `-securityevents` | Correlación de eventos de seguridad (4720/4728/4732/4756) | HIGH |

## Estructura de salida

```
<outputPath>\
  execution.json          metadata de ejecución, módulos, tiempos
  preflight.json          resultado de checks de prerequisitos
  summary.json            resumen de findings por severidad/categoría
  findings.ndjson         findings en formato NDJSON (un objeto por línea)
  findings.csv            mismo contenido en CSV para Excel/SIEM
  adaudit.nessus          XML Nessus (omitir con -noNessus)
  logs\
    console.log
    debug.log
  inventory\              (activado con -inventory)
    users.csv
    groups.csv
    computers.csv
    dcs.csv
    trusts.csv
    gpos.csv
    privileged_accounts.csv
    service_accounts.csv
    adcs_templates.csv
  evidence\               (activado con -evidence)
    domain.json
    password_policy.json
    ldap.json
    laps.json
    gpo.json
    acl.json
    adcs.json
    trusts.json
    security_events.json
    security_events.csv
```

Los módulos también generan archivos `.txt` de evidencia bruta en la raíz de salida (`ASREP.txt`, `UnconstrainedDelegation.txt`, `DCSyncRights.txt`, `HostHardening.txt`, etc.) que `report_generator.py` consume automáticamente.

## Informe generado (`report_generator.py`)

El generador produce dos archivos en la carpeta de auditoría:

- `report.html` — informe interactivo con gráficos, plan de remediación priorizado, tabla de findings sortable, controles positivos detectados
- `report.xlsx` — workbook Excel con 21 hojas: Summary, Findings, inventarios, políticas, evidencia LDAP/LAPS/GPO/ADCS, plan de remediación

Características del informe:
- Auto-detección de la carpeta de auditoría más reciente
- Gráficos SVG inline con botón "Copy as PNG" para reportes
- Pasos de remediación detallados por check_id con comandos PowerShell
- Referencias MITRE ATT&CK y CIS Benchmark por hallazgo
- CSS de impresión incluido (`Ctrl+P`)

## Codigos de salida

| Código | Significado |
|---|---|
| `0` | Ejecución completa sin findings accionables |
| `1` | Ejecución completa con findings |
| `2` | Ejecución parcial (módulos fallidos o timeout) |
| `3` | Fallo de preflight o prerequisito crítico ausente |
| `4` | Error fatal preparando directorio de salida |
| `5` | Parámetros inválidos o ningún módulo seleccionado |

## Opciones de control

```powershell
-profile <light|standard|deep|evidence|incident-response|inventory-only>
-select <lista>          # ej: -select "spn,asrep,kerbdelegation"
-exclude <lista>         # ej: -exclude "ntds,securityevents"
-outputPath <ruta>
-quiet                   # silencia consola, mantiene logs
-logLevel <normal|verbose|debug>
-noNessus                # omite adaudit.nessus
-inventory               # exporta CSVs de inventario
-evidence                # exporta JSONs de evidencia estructurada
-preflight               # solo checks de prerequisitos, sin auditoría
-moduleTimeoutSeconds <n>
-installdeps             # instala DSInternals si no está presente
```

## Nuevos checks v1.4.0

### RBCD, Constrained Delegation y Shadow Credentials (`-kerbdelegation`)
El módulo ahora detecta también:
- **Constrained Delegation con protocol transition** (`TrustedToAuthForDelegation = True`) — vector clásico S4U2Self con coerced auth (PetitPotam, etc.)
- **RBCD anómalo** (`msDS-AllowedToActOnBehalfOfOtherIdentity` populado en cuentas no esperadas) — vector KrbRelayUp / abuse 2024-2025
- **Shadow Credentials** (`msDS-KeyCredentialLink` populado en cuentas no administradas) — persistencia post-compromiso vía PKINIT

### ADCS LDAP-native (ESC1-15, `-adcs`)
Reescrito para leer plantillas vía `Get-ADObject` sobre `CN=Certificate Templates,...` (independiente del idioma del SO). Cobertura ampliada:
- ESC1-4, ESC8 (existentes, mejorados)
- **ESC9** (`CT_FLAG_NO_SECURITY_EXTENSION`)
- **ESC10** (weak certificate mapping, CVE-2022-34691)
- **ESC13** (OID group link abuse vía `msDS-OIDToGroupLink`)
- **ESC14** (altSecID mapping abuse)
- **ESC15 / EKUwu** (CVE-2024-49019, V1 templates con EKU client auth)

### NoPAC, PKINIT enforcement, krbtgt enctype (`-hosthardening`)
- Verifica patches NoPAC (KB5008102/5008380): `KrbtgtFullPacSignature`, `PacRequestorEnforcement`
- Valida `StrongCertificateBindingEnforcement = 2` (PKINIT full enforce, febrero 2025)
- Valida `krbtgt msDS-SupportedEncryptionTypes` AES-only

### AdminSDHolder + Configuration NC (`-dcsync`)
DCSync rights se auditan también en:
- `CN=AdminSDHolder,CN=System,DC=...` (vector típico de persistencia)
- `CN=Configuration,DC=...` (replicación particionada)

## Nuevos checks v1.3.0

### Unconstrained Kerberos Delegation (`-kerbdelegation`)
Detecta usuarios y equipos con `TrustedForDelegation = True`, excluyendo automáticamente los Domain Controllers legítimos. Un atacante que compromete un host con delegación sin restricción puede capturar TGTs de cualquier usuario que se autentique — incluyendo Domain Admins.

### DCSync Rights (`-dcsync`)
Audita la ACL del objeto raíz del dominio buscando el ACE `DS-Replication-Get-Changes-All` (GUID `1131f6ad-...`) en cuentas no pertenecientes a los grupos legítimos (DCs, Domain Admins, Enterprise Admins, SYSTEM). Una cuenta con este derecho puede volcar todos los hashes del dominio sin tocar el DC físicamente.

### Host Hardening (`-hosthardening`)
Verifica en el DC local:
- **WDigest** `UseLogonCredential` — si está en `1`, las credenciales en texto plano se cachean en LSASS (Mimikatz las extrae directamente)
- **LSA Protection** `RunAsPPL` — si está ausente o en `0`, LSASS no está protegido como proceso PPL
- **Credential Guard / VBS** — informacional

## Uso responsable

Esta herramienta genera evidencia sensible de Active Directory. Aplica las siguientes medidas:

- Restringe el acceso a la carpeta de salida (`icacls` o ACL NTFS)
- Si usas `-ntds`, define cadena de custodia antes de ejecutar
- Elimina la evidencia según la política de retención de tu organización
- No ejecutes en producción sin autorización explícita

## Changelog

| Versión | Fecha | Cambios principales |
|---|---|---|
| v1.0.0 | 12/04/2026 | Release inicial — contrato de salida estable, perfiles, incident-response |
| v1.3.0 | 13/04/2026 | kerbdelegation, dcsync, hosthardening — nuevos módulos y DB de remediación |
| v1.4.0 | 27/04/2026 | Bug-fixes críticos (ACL filter, NTDS custody), ADCS LDAP-native (ESC9-15), RBCD/Constrained/ShadowCreds, NoPAC/PKINIT, performance (single-pass ACL, paginación, cacheo, CIM paralelo), idempotencia, $profile→$auditProfile, manifest de stems |
| v1.4.1 | 27/04/2026 | Resiliencia para producción: ningún fallo individual aborta el run. Imports no-fatales (salvo AD), `Get-Variables` resiliente, helper `Invoke-Safe`, top-level trap, try/finally que garantiza ejecución de `Export-AllFindings`, try/catch per-iteration en módulos nuevos, `errors.log` dedicado, `errors_captured` en `execution.json` |
