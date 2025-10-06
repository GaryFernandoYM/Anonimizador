import re
import pandas as pd
from typing import Dict, Set
from app.config import COMMON_PII_COLUMN_NAMES, REGEX_PATTERNS

# 🔍 Patrones adicionales para Perú y texto libre
DNI_PE_RE = re.compile(r"\b\d{8}\b")          # DNI de 8 dígitos
RUC_PE_RE = re.compile(r"\b\d{11}\b")         # RUC de 11 dígitos
DATE_RE = re.compile(r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})\b")
ADDRESS_HINT_RE = re.compile(r"\b(av\.|jr\.|calle|urbanización|mz|lt|avda|avenida|pasaje|pje|barrio|sector|urb\.?)", re.IGNORECASE)
NAME_HINT_RE = re.compile(r"^[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+(\s[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+)+$")

def detect_pii_columns(df: pd.DataFrame) -> Set[str]:
    """
    Detecta columnas que contienen posibles datos personales (PII)
    mediante heurísticas de nombres y patrones de contenido.
    """
    detected = set()
    lower_cols = {c: c.lower() for c in df.columns}

    # 🔹 Detección por nombre de columna
    for original, low in lower_cols.items():
        for key in COMMON_PII_COLUMN_NAMES:
            if key in low:  # incluye coincidencias parciales
                detected.add(original)
                break

    # 🔹 Detección por contenido (valores)
    sample = df.head(300)  # analizamos primeras filas
    for col in df.columns:
        try:
            series = sample[col].astype(str).fillna("")
        except Exception:
            continue

        text = " ".join(series.tolist())

        # Correos, teléfonos, DNI, RUC
        if any(re.search(p, text) for p in REGEX_PATTERNS.values()):
            detected.add(col)
            continue
        if DNI_PE_RE.search(text) or RUC_PE_RE.search(text):
            detected.add(col)
            continue
        # Fechas
        if DATE_RE.search(text):
            detected.add(col)
            continue
        # Direcciones
        if ADDRESS_HINT_RE.search(text):
            detected.add(col)
            continue
        # Si parecen nombres propios (solo letras y espacios, mayúscula inicial)
        matches = series[series.str.match(NAME_HINT_RE, na=False)]
        if len(matches) > 0.5 * len(series):  # más del 50% parecen nombres
            detected.add(col)
            continue

    return detected


def count_hits(df: pd.DataFrame, col: str) -> int:
    """
    Cuenta el número de ocurrencias de patrones sensibles en una columna.
    """
    try:
        series = df[col].astype(str).fillna("")
    except Exception:
        return 0

    text = " ".join(series.tolist())
    hits = 0

    # 🔸 Patrones base (email, phone, etc.)
    for pattern in REGEX_PATTERNS.values():
        hits += len(re.findall(pattern, text))

    # 🔸 PII adicionales
    hits += len(re.findall(DNI_PE_RE, text))
    hits += len(re.findall(RUC_PE_RE, text))
    hits += len(re.findall(DATE_RE, text))
    hits += len(re.findall(ADDRESS_HINT_RE, text))

    return hits