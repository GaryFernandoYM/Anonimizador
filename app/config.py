# app/config.py
from __future__ import annotations

from pathlib import Path
import os
import re
import unicodedata
from typing import Dict, Set, Tuple, Optional

# ============================================================
# RUTAS PRINCIPALES
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUTS_DIR = BASE_DIR / "outputs"

DATA_DIR.mkdir(parents=True, exist_ok=True)
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# ENTORNO / SEGURIDAD
# ============================================================

ENVIRONMENT: str = os.getenv("APP_ENV", "dev")  # dev | prod | test
APP_SALT: str = os.getenv("APP_SALT", "pepper")

# Valida que la SALT tenga un mínimo de entropía (simple heurística)
if len(APP_SALT) < 6 and ENVIRONMENT != "test":
    # No lanzamos excepción para no romper dev, pero lo registramos
    # (si usas logging, cámbialo por un warning)
    print("[config] ⚠️ APP_SALT muy corta; considera usar 16+ caracteres en producción.")

# Límite de tamaño de archivo (MB) y filas de muestreo
MAX_FILE_MB: int = int(os.getenv("MAX_FILE_MB", "50"))
MAX_SAMPLE_ROWS: int = int(os.getenv("MAX_SAMPLE_ROWS", "500"))

# Tipos de archivo permitidos
ALLOWED_EXTENSIONS: Set[str] = {"csv", "tsv", "txt", "xlsx", "xlsm", "xls", "parquet", "jsonl", "json"}

# ============================================================
# NORMALIZACIÓN DE NOMBRES DE COLUMNA
# ============================================================

# Permitimos letras, números, guion bajo; preservamos tildes comunes
VALID_COLNAME_CHARS = re.compile(r"[^A-Za-z0-9_áéíóúüñÁÉÍÓÚÜÑ]+")

def strip_accents(s: str) -> str:
    """Quita acentos manteniendo legibilidad, ej.: 'ubicación' -> 'ubicacion'."""
    return "".join(
        c for c in unicodedata.normalize("NFD", s) if unicodedata.category(c) != "Mn"
    )

def normalize_colname(name: str) -> str:
    """
    Normaliza un nombre de columna:
      - trim
      - minúsculas
      - quita acentos
      - reemplaza espacios y separadores por _
      - colapsa __
    """
    s = str(name or "").strip().lower()
    s = strip_accents(s)
    s = re.sub(r"[ \t\-/\.]+", "_", s)
    s = VALID_COLNAME_CHARS.sub("_", s)
    s = re.sub(r"_{2,}", "_", s).strip("_")
    return s

# Sinónimos -> canónicos (aplicado después de normalize_colname)
COLUMN_SYNONYMS: Dict[str, str] = {
    # Identidad
    "full_name": "name",
    "nombres": "nombre",
    "apellidos": "apellido",
    "persona": "name",
    "productor": "name",
    "responsable": "name",
    "encargado": "name",
    "autor": "name",
    # Documentos
    "doc": "documento",
    "documento_identidad": "documento",
    # Contacto
    "e_mail": "email",
    "correo": "email",
    "tlf": "telefono",
    "telf": "telefono",
    "movil": "telefono",
    "movil_": "telefono",
    "movil1": "telefono",
    # Ubicación
    "direccion": "address",
    "domicilio": "address",
    "ubicacion": "location",
    "ubicacion_": "location",
    "ubicacion_gps": "location",
    "barrio": "zona",
    # Fechas
    "fecha_nacimiento": "dob",
    "nacimiento": "dob",
    "fec_nac": "dob",
    "f_nac": "dob",
    "fch": "fecha",
    # Geo
    "coordenada": "coordenadas",
    "coordenadas": "coordenadas",
    # Económicos
    "importe": "monto",
    "ingreso": "monto",
    # Atributos sensibles
    "sexo": "gender",
    "genero": "gender",
    "race_ethnicity": "race_ethnicity",
    "nivel_educativo_padres": "parental_level_of_education",
}

def canonical_colname(name: str) -> str:
    n = normalize_colname(name)
    return COLUMN_SYNONYMS.get(n, n)

# ============================================================
# CLASIFICACIÓN DE COLUMNAS (por nombre)
# ============================================================

# PII directos (identificadores personales o contacto)
COMMON_PII_COLUMN_NAMES: Set[str] = {
    # Identidad
    "nombre", "name", "apellido", "apellidos",
    # Documentos y números identificatorios
    "dni", "documento", "ruc", "pasaporte", "passport", "cedula", "ssn", "nif", "nie",
    # Contacto
    "telefono", "phone", "celular", "email", "e_mail",
    # Domicilio
    "address", "domicilio", "direccion",
}

# Atributos SENSIBLES (no identifican por sí solos, pero son sensibles)
SENSITIVE_ATTRIBUTES: Set[str] = {
    "gender", "sexo", "genero",
    "race", "ethnicity", "race_ethnicity",
    "religion", "orientacion_sexual", "discapacidad",
    "parental_level_of_education",
}

# Quasi-identificadores (pueden reidentificar combinados)
QUASI_IDENTIFIER_NAMES: Set[str] = {
    "dob", "birthday", "fecha",
    "departamento", "provincia", "distrito", "ubigeo",
    "latitud", "longitud", "location", "coordenadas",
    "zona", "barrio", "address",
    "valor", "monto", "salario", "precio", "costo",
    "age", "edad", "ocupacion", "profesion",
}

# ============================================================
# PATRONES REGEX (robustos)
# ============================================================

REGEX_PATTERNS: Dict[str, str] = {
    # Email (suficientemente estricto sin llegar al RFC completo)
    "email": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    # Teléfono internacional con separadores comunes
    "phone": r"\b(?:\+?\d{1,3}[\s\-\.]?)?(?:\(?\d{2,4}\)?[\s\-\.]?)?\d{3,4}[\s\-\.]?\d{3,4}\b",
    # DNI Perú (8), RUC Perú (11)
    "dni_pe": r"\b\d{8}\b",
    "ruc_pe": r"\b\d{11}\b",
    # Fechas comunes: dd/mm/yyyy, yyyy-mm-dd, etc.
    "date": r"\b(?:\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2})\b",
    # Coordenadas decimales (lat/long)
    "geo_coord": r"\b[-+]?\d{1,3}\.\d{3,}\b",
    # IPs
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    "ipv6": r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b",
    # Tarjetas (16 dígitos con separadores)—validar luego con Luhn
    "cc_like": r"\b(?:\d[ -]*?){13,19}\b",
    # IBAN (muy general)
    "iban": r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
}

# Compilados para performance
REGEX_COMPILED = {k: re.compile(v) for k, v in REGEX_PATTERNS.items()}

# ============================================================
# DETECCIÓN DE TIPOS Y RIESGO (heurística)
# ============================================================

# Peso de riesgo por categoría (0-100)
RISK_WEIGHTS: Dict[str, int] = {
    "pii_strict": 90,
    "pii_contact": 80,
    "document_id": 85,
    "quasi_identifier": 60,
    "sensitive_attribute": 70,
    "generic": 20,
}

# Estrategias sugeridas por categoría
SUGGESTED_STRATEGIES: Dict[str, str] = {
    "pii_strict": "mask",
    "pii_contact": "mask",
    "document_id": "hash",
    "quasi_identifier": "generalize_geo",   # o generalize_date si aplica
    "sensitive_attribute": "drop",           # o mask, según política
    "generic": "mask",
}

def luhn_check(num: str) -> bool:
    """Valida Luhn para tarjetas."""
    digits = [int(c) for c in re.sub(r"\D", "", num)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = (len(digits) - 2) % 2
    for i, d in enumerate(digits[:-1]):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    checksum += digits[-1]
    return checksum % 10 == 0

def is_allowed_filetype(filename: str) -> bool:
    ext = (filename or "").lower().rsplit(".", 1)[-1]
    return ext in ALLOWED_EXTENSIONS

def file_size_ok(filepath: Path) -> bool:
    try:
        return (filepath.stat().st_size / (1024 * 1024)) <= MAX_FILE_MB
    except FileNotFoundError:
        return False

def categorize_by_name(colname: str) -> Tuple[str, int]:
    """
    Clasifica una columna por su nombre normalizado en:
      - pii_strict, pii_contact, document_id, sensitive_attribute, quasi_identifier, generic
    y devuelve (categoria, riesgo_base).
    """
    c = canonical_colname(colname)

    # Documentos / IDs
    if c in {"dni", "documento", "ruc", "pasaporte", "passport", "cedula", "ssn", "nif", "nie"}:
        return "document_id", RISK_WEIGHTS["document_id"]

    # Contacto directo
    if c in {"telefono", "phone", "celular", "email", "e_mail"}:
        return "pii_contact", RISK_WEIGHTS["pii_contact"]

    # Identidad directa
    if c in {"nombre", "name", "apellido", "apellidos"}:
        return "pii_strict", RISK_WEIGHTS["pii_strict"]

    # Atributos sensibles
    if c in SENSITIVE_ATTRIBUTES:
        return "sensitive_attribute", RISK_WEIGHTS["sensitive_attribute"]

    # Quasi-identificadores
    if c in QUASI_IDENTIFIER_NAMES:
        return "quasi_identifier", RISK_WEIGHTS["quasi_identifier"]

    return "generic", RISK_WEIGHTS["generic"]

def content_based_hints(text_sample: str) -> Optional[Tuple[str, int]]:
    """
    Heurística por contenido: intenta detectar PII en el texto.
    Retorna (categoria, riesgo_extra) o None.
    """
    s = str(text_sample or "")
    if not s:
        return None

    # Email
    if REGEX_COMPILED["email"].search(s):
        return ("pii_contact", 20)
    # Phone
    if REGEX_COMPILED["phone"].search(s):
        return ("pii_contact", 20)
    # Documentos Perú
    if REGEX_COMPILED["dni_pe"].search(s) or REGEX_COMPILED["ruc_pe"].search(s):
        return ("document_id", 30)
    # Fechas
    if REGEX_COMPILED["date"].search(s):
        return ("quasi_identifier", 10)
    # Coordenadas
    if REGEX_COMPILED["geo_coord"].search(s):
        return ("quasi_identifier", 15)
    # IPs
    if REGEX_COMPILED["ipv4"].search(s) or REGEX_COMPILED["ipv6"].search(s):
        return ("quasi_identifier", 15)
    # Tarjetas (con Luhn)
    m = REGEX_COMPILED["cc_like"].search(s)
    if m and luhn_check(m.group()):
        return ("document_id", 40)
    # IBAN (muy general)
    if REGEX_COMPILED["iban"].search(s):
        return ("document_id", 30)

    return None

def merge_risk(base: Tuple[str, int], hint: Optional[Tuple[str, int]]) -> Tuple[str, int]:
    """
    Combina categoría base por nombre con pista por contenido.
    La categoría más alta (según el riesgo) prevalece y se suma un bonus limitado.
    """
    if not hint:
        return base
    cat_base, risk_base = base
    cat_hint, bonus = hint
    # Si hint sugiere una categoría más fuerte:
    if RISK_WEIGHTS.get(cat_hint, 0) > RISK_WEIGHTS.get(cat_base, 0):
        return (cat_hint, min(100, RISK_WEIGHTS[cat_hint] + bonus))
    return (cat_base, min(100, risk_base + bonus))

def suggested_strategy_for_category(category: str) -> str:
    return SUGGESTED_STRATEGIES.get(category, "mask")

# ============================================================
# EJEMPLOS DE USO (para tus servicios)
# ============================================================
# from app.config import (
#     canonical_colname, categorize_by_name, content_based_hints,
#     merge_risk, suggested_strategy_for_category
# )
#
# col = canonical_colname("Parental Level of Education")
# base_cat, base_risk = categorize_by_name(col)
# hint = content_based_hints("Bachelor's degree")  # puede devolver sensitive_attribute
# final_cat, final_risk = merge_risk((base_cat, base_risk), hint)
# strategy = suggested_strategy_for_category(final_cat)