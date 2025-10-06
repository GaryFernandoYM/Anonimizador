from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Tuple
from typing import Annotated
from pydantic import BaseModel, Field, field_validator, ConfigDict
import re

# --------------------------------------------------------------------
# Estrategias soportadas (nombre base). Algunas admiten parámetros.
# p.ej.: "mask", "hash:length=24", "generalize_date:granularity=year"
# --------------------------------------------------------------------
StrategyName = Literal[
    "mask",
    "hash",
    "drop",
    "pseudonym",
    "generalize_date",
    "generalize_geo",
    "bucket_numeric",
    "bucket_age",
    "redact_text",
]

# Permite "name" o "name:k=v,..." (k y v sin coma)
_STRATEGY_PATTERN = re.compile(
    r"^(?P<name>[a-z_]+)(?::(?P<params>(?:[A-Za-z_]+\s*=\s*[^,=]+)(?:\s*,\s*[A-Za-z_]+\s*=\s*[^,=]+)*))?$"
)

# Lista no vacía
NonEmptyList = Annotated[List[str], Field(min_length=1)]


class ColumnPlan(BaseModel):
    """
    Representa la estrategia a aplicar a una columna específica.
    strategy: cadena validada tipo "mask" o "mask:keep_start=2,keep_end=2"
    """
    column: str = Field(..., min_length=1)
    strategy: str = Field(..., min_length=2, description="Estrategia, e.g. 'mask' o 'hash:length=24'")

    model_config = ConfigDict(extra="forbid")

    @field_validator("strategy")
    @classmethod
    def validate_strategy(cls, v: str) -> str:
        m = _STRATEGY_PATTERN.match(v.strip())
        if not m:
            raise ValueError(
                "Formato de estrategia inválido. Usa 'name' o 'name:k=v,k2=v2'."
            )

        name = m.group("name")
        # nombre base debe ser uno de los soportados
        allowed: Tuple[str, ...] = (
            "mask",
            "hash",
            "drop",
            "pseudonym",
            "generalize_date",
            "generalize_geo",
            "bucket_numeric",
            "bucket_age",
            "redact_text",
        )
        if name not in allowed:
            raise ValueError(f"Estrategia no soportada: '{name}'")

        # Validación ligera de parámetros (opcional)
        params = m.group("params")
        if params:
            for kv in params.split(","):
                if "=" not in kv:
                    raise ValueError("Cada parámetro debe ser 'k=v'")
                k, val = [x.strip() for x in kv.split("=", 1)]
                if not k:
                    raise ValueError("Clave de parámetro vacía")
                # Reglas simples por estrategia (opcionales y suaves)
                if name == "hash" and k == "length":
                    if not val.isdigit() or not (8 <= int(val) <= 64):
                        raise ValueError("hash:length debe estar entre 8 y 64")
                if name == "generalize_date" and k == "granularity":
                    if val not in ("year", "year_month"):
                        raise ValueError("generalize_date:granularity debe ser 'year' o 'year_month'")
                if name == "generalize_geo" and k == "levels":
                    try:
                        lv = int(val)
                        if lv <= 0:
                            raise ValueError
                    except Exception:
                        raise ValueError("generalize_geo:levels debe ser entero > 0")
                if name == "bucket_numeric" and k == "size":
                    try:
                        sz = float(val)
                        if sz <= 0:
                            raise ValueError
                    except Exception:
                        raise ValueError("bucket_numeric:size debe ser numérico > 0")
        return v


class AnonymizeRequest(BaseModel):
    """
    Petición de anonimización: columnas seleccionadas + mapa de estrategias.
    Se permiten dos formas de plan:
      - 'plans': lista de ColumnPlan (recomendado)
      - 'strategies': dict[str, str] (retro-compatibilidad)
    """
    selected_columns: NonEmptyList
    # Retro-compat: {"col": "mask", "dni": "hash:length=24", ...}
    strategies: Optional[Dict[str, str]] = Field(default=None)
    # Forma robusta y validada: lista de planes por columna
    plans: Optional[List[ColumnPlan]] = Field(
        default=None,
        description="Lista de plan por columna; domina sobre 'strategies' si ambos se envían."
    )
    sample_rows: int = Field(default=10, ge=1, le=1000)

    model_config = ConfigDict(extra="forbid")

    @field_validator("strategies")
    @classmethod
    def validate_strategies(cls, v: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        if v is None:
            return v
        # Validar cada estrategia con el mismo patrón de ColumnPlan
        for col, strat in v.items():
            if not col or not isinstance(col, str):
                raise ValueError("Las claves de 'strategies' deben ser nombres de columna válidos.")
            if not isinstance(strat, str) or not strat.strip():
                raise ValueError(f"Estrategia inválida para columna '{col}'.")
            ColumnPlan(column=col, strategy=strat)  # reutiliza validación
        return v

    def effective_plan(self) -> Dict[str, str]:
        """
        Retorna un dict col->estrategia consolidado, priorizando 'plans' sobre 'strategies'.
        Solo incluye columnas presentes en selected_columns (por seguridad).
        """
        plan: Dict[str, str] = {}
        if self.plans:
            for item in self.plans:
                if item.column in self.selected_columns:
                    plan[item.column] = item.strategy
        elif self.strategies:
            for col, strat in self.strategies.items():
                if col in self.selected_columns:
                    plan[col] = strat
        return plan


class Report(BaseModel):
    detected_pii_columns: List[str] = Field(default_factory=list)
    column_risk: Dict[str, int] = Field(default_factory=dict)
    global_score: int = Field(0, ge=0, le=100)
    notes: Optional[str] = None

    model_config = ConfigDict(extra="forbid")


class PreviewResponse(BaseModel):
    columns: List[str]
    head: List[Dict[str, Any]]

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------
# Modelos adicionales útiles para tu API/Front
# ---------------------------------------------
class UploadResponse(BaseModel):
    filename: str
    columns: List[str]
    head: List[Dict[str, Any]]

    model_config = ConfigDict(extra="forbid")


class AnalyzeResponse(BaseModel):
    filename: str
    columns: List[str]
    detected_pii_columns: List[str] = Field(default_factory=list)
    # Sugerencias automáticas (columna -> estrategia sugerida)
    suggestions: Dict[str, str] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")


class AnonymizeResponse(BaseModel):
    report_url: str

    model_config = ConfigDict(extra="forbid")