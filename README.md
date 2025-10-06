# 🔒 Sistema de Anonimización de Datos

## 📘 Descripción General

Este sistema permite **detectar, evaluar y anonimizar información personal (PII)** contenida en archivos de datos (CSV, XLSX, JSON, etc.).  
Fue desarrollado con **FastAPI** y **Pandas**, priorizando la **integridad contextual** y la **privacidad de los datos**.

Su objetivo es proteger la identidad de las personas **sin perder el valor analítico del dataset**, aplicando distintas estrategias de anonimización según el nivel de riesgo detectado.

---

## ⚙️ Flujo del Sistema

```mermaid
graph LR
A[Cargar dataset] --> B[Detección de PII]
B --> C[Evaluación de riesgo]
C --> D[Aplicación de estrategias]
D --> E[Generación de reporte]
E --> F[Archivo anonimizado]
