# 🛡️ SOC Investigation Lab: Phishing Triaging & SIEM Correlation with Splunk

## 📝 Introducción
Este repositorio contiene la documentación y el análisis técnico de incidentes gestionados en un entorno simulado de Centro de Operaciones de Seguridad (SOC) de TryHackMe. El objetivo principal de la investigación fue realizar el triaje de alertas de correo electrónico entrante en una cola de incidentes, investigar los Indicadores de Compromiso (IOCs) y correlacionar la telemetría utilizando **Splunk** para determinar el impacto real en los endpoints de la organización.

---

## 🛠️ Habilidades y Herramientas Demostradas
*   **SIEM:** Splunk (Búsqueda, filtrado y correlación cruzada de eventos).
*   **Análisis de Logs:** Interpretación de estructuras JSON provenientes de fuentes de correo y firewalls.
*   **Investigación de Amenazas:** Identificación de tácticas de ingeniería social y técnicas de suplantación de identidad (*Typosquatting*).
*   **Gestión de Alertas:** Clasificación técnica de incidentes (Falsos Positivos frente a Verdaderos Positivos).

---

## 🔍 Caso 1: Análisis de Falso Positivo (Plataforma HR)

### 🚨 Alerta Inicial
La cola de alertas detectó un evento relacionado con un enlace externo sospechoso entrante.

*   **ID de Alerta:** 8814
*   **Regla:** Inbound Email Containing Suspicious External Link
*   **Gravedad:** Medium
*   **Remitente:** `onboarding@hrconnex.thm`
*   **Destinatario:** `j.garcia@thetrydaily.thm`

![Cola de Alertas - Caso 1](Caso N° 1.png)

### 🕵️‍♂️ Investigación y Análisis de Logs
Al inspeccionar los registros indexados en Splunk para el dominio `hrconnex.thm`, localizamos el correo electrónico original que gatilló el evento:

![Log del Correo Recibido](Caso%201%20327.png)

Al contrastar la actividad, se descubrió un segundo registro crucial dentro del flujo interno. Un analista de la organización (`h.harris@thetrydaily.thm`) envió una notificación al equipo de TI explicando de manera explícita que `hrconnex.thm` es un socio externo legítimo de recursos humanos para la gestión del alta y papeleo de nuevas contrataciones:

![Log de Correo Interno Confirmando Legitimidad](Caso%201%20333.png)

Además, al analizar el comportamiento general mediante las búsquedas cruzadas de Splunk, se determinó que los eventos indexados mantenían un único origen perimetral de tipo correo, validando la falta de interacciones web asociadas hacia el exterior.

### 🛑 Conclusión y Cierre
*   **Veredicto:** **Falso Positivo (False Positive)**
*   **Justificación:** El dominio analizado corresponde a una plataforma legítima necesaria para la operación del negocio. El incidente se generó debido a una firma genérica de los filtros automatizados del correo. No existió ninguna actividad maliciosa ni peligro asociado.
*   **Recomendación:** Agregar el dominio `hrconnex.thm` a la lista blanca (*whitelist*) del gateway de correo institucional para prevenir alertas recurrentes.

---

## 🎯 Caso 2: Phishing de Amazon - Verdadero Positivo Mitigado

### 🚨 Alerta Inicial
El sistema detectó una segunda alerta de correo simulando una notificación urgente de entrega de paquetes.

*   **ID de Alerta:** 8815
*   **Regla:** Inbound Email Containing Suspicious External Link
*   **Remitente:** `urgents@amazon.biz`
*   **Destinatario:** `h.harris@thetrydaily.thm`
*   **Enlace Identificado:** `http://bit.ly/3sHkX3da12340`

![Cola de Alertas - Caso 2](Caso%20N%C2%B0%202.png)

### 🕵️‍♂️ Investigación y Análisis de Logs
Se examinó la estructura del correo electrónico malicioso entrante. Se identificaron de inmediato tácticas evidentes de ingeniería social basadas en la urgencia y el uso de un dominio no oficial para suplantar una marca reconocida (`amazon.biz`):

![Log de Correo de Phishing](Correo%20Caso2.png)

Para rastrear el impacto y descubrir si el destinatario interactuó con la amenaza, se realizó una consulta en Splunk aislando el código único del acortador web. A diferencia del primer escenario, la búsqueda de red arrojó eventos correlacionados donde se detectó actividad de tráfico web originada por el host afectado hacia el exterior apenas un minuto después de la llegada del correo:

![Línea de Tiempo y Correlación de Eventos](Captura de pantalla 2026-06-19 114853.png)

Al auditar los campos extendidos del evento de red, localizamos el registro generado por el **Firewall** de la empresa. El evento demostró que el dispositivo interceptó la navegación del endpoint comprometido (**IP de Origen: `10.20.2.17`**) denegando el acceso de forma contundente gracias a las reglas preestablecidas para categorías Web prohibidas:

*   **Acción:** `blocked`
*   **Regla Activada:** `Blocked Websites`
*   **IP de Destino:** `67.199.248.11` (Servidor del enlace acortado)

![Detalles Técnicos del Bloqueo en Firewall](Captura de pantalla 2026-06-19 114838.png)

### 🛑 Conclusión y Cierre
*   **Veredicto:** **Verdadero Positivo (True Positive) - Mitigado**
*   **Justificación:** El correo constituyó una campaña real de ingeniería social encaminada a la suplantación de identidad. Aunque el empleado ejecutó la acción de clicar el link malicioso, las políticas perimetrales del Firewall neutralizaron el vector de ataque antes de que el endpoint estableciera comunicación con el servidor del atacante. El sistema quedó completamente fuera de peligro.
*   **Recomendación:** Bloquear de forma permanente el dominio remitente `.biz` e iniciar un proceso breve de concientización y formación en técnicas de Phishing para el usuario afectado.
