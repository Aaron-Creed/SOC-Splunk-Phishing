# 🛡️ SOC Investigation Lab: Phishing Triaging & SIEM Correlation with Splunk

## 📝 Introducción
Este repositorio contiene la documentación y el análisis técnico de dos alertas gestionadas en un entorno simulado de Centro de Operaciones de Seguridad (SOC). El objetivo principal de este laboratorio fue realizar el triaje de alertas de correo electrónico entrante, investigar los Indicadores de Compromiso (IOCs) y correlacionar la telemetría en **Splunk** para determinar el impacto real en los endpoints de la organización.

---

## 🛠️ Habilidades y Herramientas Demostradas
*   **SIEM:** Splunk (Búsqueda, filtrado y correlación de eventos).
*   **Análisis de Logs:** Interpretación de estructuras JSON provenientes de fuentes de correo y firewall.
*   **Investigación de Amenazas:** Análisis de reputación de dominios, tácticas de ingeniería social y técnicas de *typosquatting*.
*   **Clasificación de Incidentes:** Determinación de Falsos Positivos (FP) y Verdaderos Positivos (TP).

---

## 🔍 Caso 1: Análisis de Falso Positivo (Plataforma HR)

### 🚨 Alerta Inicial
*   **ID de Alerta:** 8814
*   **Clasificación:** Medium - Phishing
*   **Asunto:** `Action Required: Finalize Your Onboarding Profile`
*   **Remitente:** `onboarding@hrconnex.thm`
*   **Destinatario:** `j.garcia@thetrydaily.thm`

### 🕵️‍♂️ Investigación y Análisis de Logs
Al revisar la cola de alertas, se identificó un correo dirigido a un empleado de la empresa que contenía un enlace hacia el dominio `hrconnex.thm`. 

Se procedió a realizar una búsqueda exhaustiva en Splunk utilizando el IOC (`hrconnex.thm`). Durante la inspección del panel lateral de campos interesantes (**Interesting Fields**), se determinó que el campo `datasource` tenía un valor de `1`, correspondiendo únicamente a registros de tipo `email`. Esto confirmó matemáticamente la **ausencia de logs de firewall**, lo que significa que el usuario nunca interactuó ni hizo clic en el enlace.

![Panel de Splunk - Caso 1](TU_RUTA_DE_IMAGEN/026558b5-70e4-47f4-bdf5-087dfc8a5502.png)

Posteriormente, se localizó un correo interno legítimo enviado por el equipo de TI/Operaciones (`h.harris@thetrydaily.thm`) donde se mencionaba explícitamente que `hrconnex.thm` corresponde al proveedor externo oficial de Recursos Humanos de la organización para la gestión de trámites de nuevas contrataciones.

### 🛑 Conclusión y Cierre
*   **Veredicto:** **Falso Positivo (False Positive)**
*   **Justificación:** La alerta se disparó debido a una clasificación errónea de los filtros de correo automáticos ante un enlace externo. La investigación demostró que el dominio es legítimo, pertenece al flujo del negocio y no existió interacción anómala de red.
*   **Acciones Recomendadas:** Coordinar con el equipo de ingeniería de correo para agregar el dominio `hrconnex.thm` a la lista de remitentes permitidos (*whitelist*), evitando futuras interrupciones operativas.

---

## 🎯 Caso 2: Phishing de Amazon - Verdadero Positivo Mitigado

### 🚨 Alerta Inicial
*   **Clasificación:** Alta - Phishing / Suplantación de Identidad
*   **Remitente:** `urgents@amazon.biz`
*   **Destinatario:** `h.harris@thetrydaily.thm`
*   **Enlace Malicioso:** `http://bit.ly/3sHkX3da12340`

### 🕵️‍♂️ Investigación y Análisis de Logs
Al analizar el correo, se identificaron múltiples indicadores de ingeniería social: uso de un dominio no oficial (`.biz`) simulando una marca reconocida (*Typosquatting*) y el uso de un acortador de URL público (`bit.ly`) para ocultar el destino final.

Para medir el impacto, se realizó una búsqueda en Splunk aislando el identificador único del acortador (`3sHkX3da12340`). A diferencia del caso anterior, el panel de campos interesantes reflejó la presencia de múltiples fuentes de datos, confirmando un registro de **`datasource: firewall`**.

![Correlación de Eventos - Caso 2](TU_RUTA_DE_IMAGEN/Interaccion con el correo Caso2.png)

La línea de tiempo correlacionada demostró lo siguiente:
1.  **16:30:34** - El correo ingresa a la bandeja de entrada del usuario.
2.  **16:31:48** - El usuario interactúa con el vector de ataque y hace clic en el enlace.

Al abrir los detalles del evento del firewall, se validó que la conexión web (`web-browsing`) originada desde la IP interna del host afectado **`10.20.2.17`** hacia la IP de destino externo `67.199.248.11` fue interceptada de manera inmediata.

![Detalles del Bloqueo del Firewall](TU_RUTA_DE_IMAGEN/Detalles de la interaccion Caso2.png)

### 🛑 Conclusión y Cierre
*   **Veredicto:** **Verdadero Positivo (True Positive) - Mitigado**
*   **Justificación:** El correo representaba una amenaza real de suplantación de identidad y el usuario llegó a ejecutar la acción de clic. Sin embargo, el incidente fue completamente mitigado en el perímetro gracias a la regla de seguridad del Firewall (`Rule: Blocked Websites`), la cual aplicó una acción de **`Action: blocked`**, impidiendo que el host fuera comprometido.
*   **Acciones Recomendadas:** Notificar al usuario sobre el evento para reforzar la concientización en Phishing y proceder al bloqueo preventivo del remitente en la pasarela de correo.
