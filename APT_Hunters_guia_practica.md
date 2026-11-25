# Guía práctica: iniciar en Threat Hunting / APT Hunting

## Objetivo
Aprender a formular hipótesis, buscar evidencia en logs y tráfico, confirmar hallazgos y convertir la búsqueda manual en una detección reutilizable. Trabaja únicamente en sistemas propios o con autorización escrita.

## Qué necesitas
- Fundamentos de Linux y Windows: procesos, servicios, tareas programadas, registro y memoria.
- Redes: TCP/IP, DNS, HTTP/HTTPS y conexiones persistentes.
- Telemetría: Sysmon, Windows Event Logs, `auditd`, syslog, proxy y DNS.
- Scripting básico: Python o Bash.
- Herramientas: Elastic/Wazuh, Wireshark/Zeek, Sigma, YARA y Volatility.

## Ciclo de trabajo

1. **Hipótesis**: define qué comportamiento sospechas y qué ataque puede explicarlo.
2. **Datos**: identifica qué fuente de telemetría debería registrar ese comportamiento.
3. **Búsqueda**: ejecuta consultas y filtra ruido conocido.
4. **Verificación**: relaciona proceso, usuario, padre, red, horario y persistencia.
5. **Respuesta**: confirma, descarta o escala el hallazgo.
6. **Automatización**: transforma el patrón establecido en una regla Sigma, YARA o un job periódico.

Ejemplo:

> Hipótesis: Office abre PowerShell codificado para establecer persistencia.

Busca en Sysmon eventos 1 (creación de procesos):

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id = 1
}
```

## Laboratorio mínimo

- 1 VM Windows con Sysmon.
- 1 VM Linux con Elastic Security o Wazuh.
- Una red aislada sin acceso a sistemas reales.
- Atomic Red Team para emular técnicas de manera controlada.

Documenta para cada ejercicio:
- Técnica ATT&CK.
- Hipótesis.
- Fuente utilizada.
- Consulta realizada.
- Evidencia esperada.
- Evidencia obtenida.
- Baseline legítimo.
- Regla final y forma de validar falsos positivos.

## Plan de 12 semanas

| Semanas | Objetivo | Entregable |
|---|---|---|
| 1-3 | Redes, Linux, Windows y lectura de logs | Un informe de qué procesos, servicios y conexiones son normales |
| 4-6 | Montar Sysmon y Elastic/Wazuh | Panel con eventos de procesos, red y autenticación |
| 7-9 | Practicar 5 técnicas ATT&CK | Una ficha por técnica con hipótesis, consulta y evidencia |
| 10-12 | Automatizar hallazgos | Reglas Sigma/YARA y casos de prueba |

Empezar con estas técnicas:

1. T1059.001 — PowerShell.
2. T1053.005 — Tarea programada en Windows.
3. T1547.001 — Registro de inicio.
4. T1059.004 — Shell Unix.
5. T1071 — C2 mediante protocolos comunes.

## Comandos esenciales

### Linux

```bash
# Árbol de procesos
ps -eo pid,ppid,user,cmd --forest

# Conexiones y procesos propietarios
ss -tunap

# Inicios de sesión
last -a

# Logs de un servicio
journalctl -u nginx --since "1 hour ago"

# Archivos modificados recientemente
find / -mtime -1 -type f 2>/dev/null

# Captura de tráfico
sudo tcpdump -i eth0 -w captura.pcap

# Buscar indicadores codificados
grep -iE "-enc|base64|frombase64" /var/log/* 2>/dev/null
```

### Windows

```powershell
# Procesos creados por Sysmon
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id = 1
}

# Conexiones de red registradas por Sysmon
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id = 3
}

# Tareas programadas
Get-ScheduledTask | Where-Object State -ne 'Disabled'

# Conexiones activas
Get-NetTCPConnection | Where-Object State -eq 'Established'
```

## Plantilla de hipótesis

```text
Técnica ATT&CK:
Hipótesis:
Fuente de datos:
Consulta o filtro:
Evidencia que confirmaría:
Ruido legítimo esperado:
Cómo descartar falsos positivos:
Acción de respuesta:
Cómo automatizar:
Cómo validar la detección:
```

## Lectura de hallazgos

No concluyas únicamente por una coincidencia de palabra o hash. Relaciona al menos:

- Qué proceso se creó.
- Quién lo ejecutó.
- Qué padre lo lanzó.
- Qué línea de comandos recibió.
- Qué red destino abrió.
- Qué usuario inició sesión.
- Qué persistió posteriormente.
- Qué cambio creó en disco o registro.

## Plataformas de práctica

- Blue Team Labs Online
- Hack The Box — Blue Team / Sherlocks
- CyberDefenders
- MITRE ATT&CK Evaluations
- Laboratorio propio con Atomic Red Team

## Primer reto

Simula PowerShell desde un proceso Office o una herramienta de ofimática de prueba. Crea la actividad únicamente en tu laboratorio y responde:

1. ¿Qué evento de Sysmon registra el proceso hijo?
2. ¿Qué padre aparece?
3. ¿Qué argumentos contiene?
4. ¿Se registra una conexión saliente?
5. ¿Qué consulta puede detectar el patrón sin producir demasiado ruido?
6. ¿Qué regla Sigma podrías escribir con el resultado?

## Criterio de finalización

Habrás completado la introducción cuando puedas presentar:
- 5 hipótesis documentadas.
- 5 búsquedas reproducibles.
- 3 hallazgos clasificados como verdaderos o falsos positivos.
- 2 reglas Sigma o YARA probadas.
- 1 informe de amenaza con evidencia y recomendación de respuesta.
