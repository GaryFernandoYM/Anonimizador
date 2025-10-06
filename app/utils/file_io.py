import pandas as pd
from pathlib import Path
from typing import Tuple

def load_dataset(path: Path) -> pd.DataFrame:
    if path.suffix.lower() in [".csv"]:
        return pd.read_csv(path, encoding="utf-8", low_memory=False)
    if path.suffix.lower() in [".xlsx", ".xlsm", ".xls"]:
        return pd.read_excel(path)
    raise ValueError("Formato no soportado. Usa CSV o XLSX.")

def save_dataset(df, path: Path):
    if path.suffix.lower() == ".csv":
        df.to_csv(path, index=False, encoding="utf-8")
    elif path.suffix.lower() in [".xlsx", ".xlsm", ".xls"]:
        df.to_excel(path, index=False)
    else:
        df.to_csv(path.with_suffix(".csv"), index=False, encoding="utf-8")  # fallback

def safe_filename(original: str) -> str:
    # simplón: reemplaza espacios y caracteres raros
    return "".join(c if c.isalnum() or c in (".", "_", "-") else "_" for c in original)