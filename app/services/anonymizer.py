import os
import re
import hmac
import hashlib
import pandas as pd
from typing import Dict, Any, Tuple
from datetime import datetime

# ---------------------------
# Patrones y utilidades
# ---------------------------
EMAIL_RE = re.compile(r"([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
# Teléfonos variados (acepta +, (), espacios, guiones); no es perfecto pero cubre casos comunes
PHONE_INLINE_RE = re.compile(r"(?:\+?\d[\d\-\s().]{6,}\d)")
DIGIT_RE = re.compile(r"\d")
DNI_PE_RE = re.compile(r"\b\d{8}\b")
RUC_PE_RE = re.compile(r"\b\d{11}\b")

DEFAULT_SALT = os.getenv("APP_SALT", "pepper")  # Usa variable de entorno para producción

def _to_str(v) -> str:
    if pd.isna(v):
        return ""
    return str(v).strip()

def _mask_text(s: str, keep_start: int = 1, keep_end: int = 1, mask_char: str = "*") -> str:
    if not s:
        return s
    if len(s) <= keep_start + keep_end:
        return mask_char * len(s)
    return s[:keep_start] + (mask_char * (len(s) - keep_start - keep_end)) + s[-keep_end:]

def _mask_email(s: str) -> str:
    if not s or "@" not in s:
        return _mask_text(s, 1, 1)
    return EMAIL_RE.sub(lambda m: m.group(1) + "***" + m.group(2), s)

def _mask_phone_digits(s: str, tail_keep: int = 2) -> str:
    if not s:
        return s
    digits = [c for c in s if c.isdigit()]
    if not digits:
        return s
    masked = "".join("*" if c.isdigit() else c for c in s)
    tail = "".join(digits[-tail_keep:]) if tail_keep > 0 else ""
    return masked + (f" ({tail})" if tail else "")

def _hash_value(s: str, salt: str = DEFAULT_SALT, length: int = 16) -> str:
    # sha256(salt + s)
    h = hashlib.sha256((salt + s).encode()).hexdigest()
    return h[:length]

def _hmac_pseudonym(s: str, salt: str = DEFAULT_SALT, prefix: str = "ID_") -> str:
    # seudónimo determinista y no reversible
    digest = hmac.new(salt.encode(), s.encode(), hashlib.sha256).hexdigest()[:10]
    return f"{prefix}{digest}"

def _generalize_date_value(s: str, granularity: str = "year_month") -> str:
    # granularity: "year" | "year_month"
    if not s:
        return s
    # usar pandas para parseo robusto
    dt = pd.to_datetime(s, errors="coerce", dayfirst=True, infer_datetime_format=True)
    if pd.isna(dt):
        return s
    if granularity == "year":
        return f"{dt.year}"
    # default year_month
    return f"{dt.year}-{dt.month:02d}"

def _generalize_geo_value(s: str, levels: int = 2) -> str:
    # elimina precisión (número/calle), conserva últimos niveles (ej. "Distrito, Provincia")
    if not s:
        return s
    s2 = DIGIT_RE.sub("", s).strip()
    parts = [p.strip() for p in s2.split(",") if p.strip()]
    if not parts:
        return s
    return ", ".join(parts[-abs(levels):]) if levels > 0 else parts[-1]

def _bucket_numeric_value(s: str, size: float = 10.0) -> str:
    # bucketiza números (p. ej., 23 -> 20-29 si size=10)
    try:
        x = float(s)
    except Exception:
        return s
    if size <= 0:
        return s
    import math
    lo = math.floor(x / size) * size
    hi = lo + size - 1
    if size.is_integer():
        lo_i, hi_i = int(lo), int(hi)
        return f"{lo_i}-{hi_i}"
    return f"{lo:.2f}-{hi:.2f}"

def _bucket_age_value(s: str, bins: Tuple[int, ...] = (0, 12, 18, 30, 45, 60, 75, 200)) -> str:
    # clasifica edad en rangos
    try:
        age = float(s)
    except Exception:
        return s
    for i in range(len(bins) - 1):
        if bins[i] <= age < bins[i + 1]:
            return f"{int(bins[i])}-{int(bins[i+1]-1)}"
    return s

def _redact_free_text(s: str) -> str:
    # redacción (censura) de PII incrustada en texto libre
    if not s:
        return s
    out = s
    out = EMAIL_RE.sub(lambda m: m.group(1) + "***" + m.group(2), out)
    out = PHONE_INLINE_RE.sub(lambda m: _mask_phone_digits(m.group(0), tail_keep=0), out)
    out = DNI_PE_RE.sub(lambda m: _mask_text(m.group(0), keep_start=0, keep_end=0), out)
    out = RUC_PE_RE.sub(lambda m: _mask_text(m.group(0), keep_start=0, keep_end=0), out)
    return out

# ---------------------------
# Parser de estrategias
# ---------------------------
def _parse_strategy(strategy: str) -> Tuple[str, Dict[str, Any]]:
    """
    Acepta formatos:
      - "mask"
      - "mask:keep_start=2,keep_end=2,char=#"
      - "generalize_date:granularity=year"
      - "generalize_geo:levels=2"
      - "bucket_numeric:size=5"
      - "bucket_age"  (usa bins por defecto)
      - "hash:length=24"
      - "pseudonym:prefix=USR_"
      - "drop"
      - "redact_text" (para texto libre)
    """
    if not strategy:
        return "mask", {}
    if ":" not in strategy:
        return strategy.strip(), {}
    name, raw = strategy.split(":", 1)
    params: Dict[str, Any] = {}
    for kv in raw.split(","):
        kv = kv.strip()
        if not kv or "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        k = k.strip()
        v = v.strip()
        # convertir a tipos básicos
        if v.isdigit():
            params[k] = int(v)
        else:
            try:
                params[k] = float(v)
            except Exception:
                if v.lower() in ("true", "false"):
                    params[k] = (v.lower() == "true")
                else:
                    params[k] = v
    return name.strip(), params

# ---------------------------
# Aplicadores columnares
# ---------------------------
def apply_strategy(series: pd.Series, strategy: str) -> pd.Series:
    name, params = _parse_strategy(strategy)
    s = series.astype("string")  # pandas StringDtype (maneja <NA>)
    # Normalización a string y trimming
    s = s.map(_to_str)

    if name == "drop":
        return pd.Series(["[REMOVIDO]"] * len(s), index=s.index, dtype="string")

    if name == "mask":
        keep_start = int(params.get("keep_start", 1))
        keep_end = int(params.get("keep_end", 1))
        char = str(params.get("char", "*"))
        # Heurística: si parece email o contiene '@', usar máscara de email; si contiene muchos dígitos, máscara de teléfono
        return s.map(
            lambda v: _mask_email(v) if "@" in v
            else _mask_phone_digits(v) if sum(ch.isdigit() for ch in v) >= 6
            else _mask_text(v, keep_start=keep_start, keep_end=keep_end, mask_char=char)
        )

    if name == "hash":
        salt = str(params.get("salt", DEFAULT_SALT))
        length = int(params.get("length", 16))
        return s.map(lambda v: _hash_value(v, salt=salt, length=length))

    if name == "pseudonym":
        salt = str(params.get("salt", DEFAULT_SALT))
        prefix = str(params.get("prefix", "ID_"))
        return s.map(lambda v: _hmac_pseudonym(v, salt=salt, prefix=prefix))

    if name == "generalize_date":
        gran = str(params.get("granularity", "year_month"))  # "year" | "year_month"
        return s.map(lambda v: _generalize_date_value(v, granularity=gran))

    if name == "generalize_geo":
        levels = int(params.get("levels", 2))
        return s.map(lambda v: _generalize_geo_value(v, levels=levels))

    if name == "bucket_numeric":
        size = float(params.get("size", 10.0))
        return s.map(lambda v: _bucket_numeric_value(v, size=size))

    if name == "bucket_age":
        # se permite bins personalizados como "bins=0|18|30|45|60|200"
        bins_raw = params.get("bins")
        if bins_raw:
            try:
                bins = tuple(int(x) for x in str(bins_raw).split("|"))
            except Exception:
                bins = (0, 12, 18, 30, 45, 60, 75, 200)
        else:
            bins = (0, 12, 18, 30, 45, 60, 75, 200)
        return s.map(lambda v: _bucket_age_value(v, bins=bins))

    if name == "redact_text":
        # Ideal para columnas de texto libre con PII
        return s.map(_redact_free_text)

    # fallback: máscara genérica
    return s.map(lambda v: _mask_text(v))

# ---------------------------
# API principal
# ---------------------------
def anonymize_df(df: pd.DataFrame, plan: Dict[str, str]) -> pd.DataFrame:
    """
    Aplica el plan de anonimización por columna.
    - plan: dict { columna: estrategia }
    - soporta estrategias con parámetros (ver _parse_strategy)
    """
    out = df.copy()
    for col, strat in plan.items():
        if col in out.columns:
            out[col] = apply_strategy(out[col], strat)
    return out