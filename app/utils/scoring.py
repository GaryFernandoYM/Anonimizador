from typing import Dict, List

def risk_score_by_column(pii_hits: Dict[str, int]) -> Dict[str, int]:
    """
    Convierte #detecciones por columna a escala 0-100 (heurística simple).
    """
    out = {}
    for col, hits in pii_hits.items():
        if hits == 0:
            out[col] = 0
        elif hits < 10:
            out[col] = 30
        elif hits < 100:
            out[col] = 60
        else:
            out[col] = 85
    return out

def global_risk_score(column_scores: Dict[str, int]) -> int:
    if not column_scores:
        return 0
    return int(sum(column_scores.values()) / len(column_scores))