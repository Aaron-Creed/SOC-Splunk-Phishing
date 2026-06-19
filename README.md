# 🛡️ SOC Investigation Lab: Phishing Triaging & SIEM Correlation with Splunk

## 📝 Introducción
Este repositorio contiene la documentación y el análisis técnico de incidentes gestionados en un entorno simulado de Centro de Operaciones de Seguridad (SOC) de TryHackMe. El objetivo principal de la investigación fue realizar el triaje de alertas de correo electrónico entrante en una cola de incidentes, investigar los Indicadores de Compromiso (IOCs) mediante herramientas externas de reputación y correlacionar la telemetría utilizando **Splunk** para determinar el impacto real en los endpoints de la organización.

---

## Habilidades y Herramientas Demostradas
* **SIEM:** Splunk (Búsqueda, filtrado y correlación cruzada de eventos de red y correo).
* **Análisis de Logs:** Interpretación de estructuras JSON provenientes de fuentes de correo y firewalls.
* **Investigación de Amenazas:** Uso de VirusTotal y Cisco Talos Intelligence; identificación de tácticas de ingeniería social (*Typosquatting*).
* **Gestión de Alertas:** Clasificación técnica de incidentes (Falsos Positivos frente a Verdaderos Positivos).

---

## Caso 1: Análisis de Falso Positivo (Plataforma HR)

### Alerta Inicial
La cola de alertas detectó un evento relacionado con un enlace externo sospechoso entrante.

* **ID de Alerta:** 8814
* **Regla:** Inbound Email Containing Suspicious External Link
* **Gravedad:** Medium
* **Remitente:** `onboarding@hrconnex.thm`
* **Destinatario:** `j.garcia@thetrydaily.thm`

![Cola de Alertas - Caso 1](Caso1_Cola.png)

### Investigación y Análisis de Logs
Al inspeccionar los registros indexados en Splunk para el dominio `hrconnex.thm`, se localizó el flujo de correos asociados. Durante el análisis, se interceptó un correo interno enviado por un miembro del equipo (`h.harris@thetrydaily.thm`) informando a soporte que una nueva contratación no había recibido sus accesos desde el dominio externo en cuestión. En dicho mensaje se aclara explícitamente que `hrconnex.thm` corresponde al proveedor externo oficial de Recursos Humanos de la empresa para la gestión de onboarding y trámites de contratación.

Además, la auditoría del panel lateral en Splunk confirmó que el campo `datasource` presentaba un valor de `1` (únicamente registros de tipo `email`), validando la ausencia completa de logs en el Firewall de la compañía, lo que demuestra que no existieron conexiones web salientes ni interacciones anómalas por parte de los usuarios.

### Conclusión y Cierre
* **Veredicto:** **Falso Positivo (False Positive)**
* **Justificación:** El dominio analizado es legítimo y pertenece al flujo operativo de la organización. La alerta fue disparada por firmas genéricas automatizadas del gateway de correo. No representa ningún peligro.
* **Recomendación:** Agregar el dominio `hrconnex.thm` a la lista blanca (*whitelist*) del gateway de correo institucional para mitigar futuras falsas alarmas recurrentes.

---

## Caso 2: Phishing de Amazon - Verdadero Positivo Mitigado

### Alerta Inicial
El sistema detectó una alerta de correo electrónico simulando de forma urgente un problema con la entrega de un paquete.

* **ID de Alerta:** 8815
* **Regla:** Inbound Email Containing Suspicious External Link
* **Remitente:** `urgents@amazon.biz`
* **Destinatario:** `h.harris@thetrydaily.thm`
* **Enlace Identificado:** `http://bit.ly/3sHkX3da12340`

![Cola de Alertas - Caso 2](Caso2_Inicio.png)

### Investigación de Amenazas (IOCs)
Se analizó el contenido y los metadatos del correo entrante, detectando indicadores claros de suplantación de identidad utilizando un dominio falso (`amazon.biz`) y un enlace acortado para enmascarar el destino original.

![Log de Correo de Phishing](Caso2_Correo.png)

Para complementar la investigación, se consultaron plataformas de inteligencia de amenazas. El análisis en **VirusTotal** y **Cisco Talos** proporcionó información sobre la infraestructura del dominio, mapeando las direcciones IP relacionadas:

![Análisis de Reputación - VirusTotal](Caso2_VirusTotal1.png)
![Análisis de Reputación - Cisco Talos](Caso2_Talos.png)

### 📊 Correlación y Análisis del Impacto en Splunk
Se realizó una búsqueda en el SIEM aislando el identificador único del acortador web (`3sHkX3da12340`). Los resultados mostraron una línea de tiempo clara en la que se confirma el impacto de la ingeniería social:
1.  **16:30:34** - El correo fraudulento es depositado en la bandeja del usuario.
2.  **16:31:48** - El usuario ejecuta la acción de clic en el link malicioso.

![Línea de Tiempo del Incidente](Caso2_Interaccion.png)

Al auditar los detalles técnicos de los eventos extendidos, se identificó un segundo registro proveniente de una fuente de datos distinta, clasificando un evento de **`datasource: firewall`**. La telemetría demostró que el tráfico web saliente originado desde el endpoint comprometido (**IP de Origen: `10.20.2.17`**) hacia la IP externa `67.199.248.11` fue interceptado e interrumpido de forma automática por los controles perimetrales de la organización:

* **Acción:** `blocked`
* **Regla Activada:** `Blocked Websites`

![Detalles del Bloqueo en el Firewall](Caso2_Interaccion2.png)

### Conclusión y Cierre
* **Veredicto:** **Verdadero Positivo (True Positive) - Mitigado**
* **Justificación:** El correo constituyó un ataque real de suplantación de identidad y phishing. A pesar de que el empleado interactuó con la amenaza, el incidente fue contenido de inmediato en el perímetro gracias a las políticas del Firewall, impidiendo el compromiso del host o la exfiltración de credenciales.
* **Recomendación:** Mantener el bloqueo permanente del remitente y del dominio malicioso, y coordinar una sesión breve de concientización sobre Phishing e Ingeniería Social para el usuario afectado.
