from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import pandas as pd
from datetime import datetime
import json

from app.config import DATA_DIR, OUTPUTS_DIR
from app.schemas import AnonymizeRequest, Report
from app.utils.file_io import load_dataset, save_dataset, safe_filename
from app.services.detectors import detect_pii_columns, count_hits
from app.services.anonymizer import anonymize_df
from app.utils.scoring import risk_score_by_column, global_risk_score

app = FastAPI(title="Anonimizador FastAPI (Robusto)")

# Static & templates
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "title": "Inicio", "year": datetime.now().year}
    )

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    fname = safe_filename(file.filename)
    dest = DATA_DIR / fname
    with open(dest, "wb") as f:
        f.write(await file.read())

    df = load_dataset(dest)
    head_records = df.head(10).to_dict(orient="records")
    return JSONResponse({
        "filename": fname,
        "columns": list(df.columns),
        "head": head_records
    })

def _suggest_strategy(col: str) -> str:
    lc = col.lower()
    if any(k in lc for k in ["mail", "correo", "@", "email", "e-mail"]):
        return "mask"
    if any(k in lc for k in ["tel", "cel", "phone", "movil", "móvil"]):
        return "mask:keep_start=0,keep_end=0"
    if "dni" in lc:
        return "hash:length=24"
    if "ruc" in lc:
        return "pseudonym:prefix=RUC_"
    if any(k in lc for k in ["fecha", "nacimiento", "dob", "date", "fec_"]):
        return "generalize_date:granularity=year"
    if any(k in lc for k in ["direccion", "address", "domicilio", "ubicacion", "ubigeo", "ubicación"]):
        return "generalize_geo:levels=2"
    if any(k in lc for k in ["monto", "ingreso", "salario", "precio", "valor", "importe"]):
        return "bucket_numeric:size=100"
    if "edad" in lc:
        return "bucket_age"
    # Texto libre potencialmente sensible
    if any(k in lc for k in ["observacion", "observación", "nota", "comentario", "descripcion", "descripción"]):
        return "redact_text"
    return "mask"

@app.post("/api/analyze")
async def analyze(filename: str = None):
    """
    Analiza un archivo previamente subido (guardado en /data) y devuelve:
      - columnas
      - columnas con PII detectada
      - sugerencias de estrategia por columna
    Enviar filename como query param o en el body (form/json).
    """
    if not filename:
        return JSONResponse({"error": "Falta 'filename' en query/body."}, status_code=400)

    src = DATA_DIR / filename
    if not src.exists():
        return JSONResponse({"error": "Archivo no encontrado."}, status_code=404)

    df = load_dataset(src)
    detected = list(detect_pii_columns(df))
    suggestions = {c: _suggest_strategy(c) for c in df.columns}

    return JSONResponse({
        "filename": filename,
        "columns": list(df.columns),
        "detected_pii_columns": sorted(detected),
        "suggestions": suggestions
    })

@app.post("/anonymize/{filename}")
async def anonymize(filename: str, req: AnonymizeRequest):
    """
    Aplica el plan de anonimización recibido en 'req.strategies' y genera:
      - archivo anonimizado en /outputs
      - JSON de reporte en /outputs/<base>_report.json
      - URL de reporte HTML
    """
    src = DATA_DIR / filename
    if not src.exists():
        return JSONResponse({"error": "Archivo no encontrado."}, status_code=404)

    df = load_dataset(src)

    # Detección PII previa (para reporte)
    detected = detect_pii_columns(df)
    pii_hits = {col: count_hits(df, col) for col in df.columns if col in detected}
    per_col_score = risk_score_by_column(pii_hits)
    gscore = global_risk_score(per_col_score)

    # Aplicar plan
    plan = req.strategies or {}
    out_df = anonymize_df(df, plan)

    out_name = Path(filename).stem + "_anon" + Path(filename).suffix
    out_path = OUTPUTS_DIR / out_name
    save_dataset(out_df, out_path)

    # Persistir reporte JSON
    report_json = {
        "original_filename": filename,
        "output_filename": out_name,
        "detected_pii_columns": sorted(list(detected)),
        "column_risk": per_col_score,
        "global_score": gscore,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "plan": plan
    }
    (OUTPUTS_DIR / f"{Path(filename).stem}_report.json").write_text(
        json.dumps(report_json, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    return JSONResponse({"report_url": f"/report/{out_name}"})

@app.get("/report/{output_name}", response_class=HTMLResponse)
def report_view(request: Request, output_name: str):
    """
    Renderiza el reporte HTML y muestra una previsualización (primeras filas)
    del archivo anonimizado antes de descargar.
    """
    out_path = OUTPUTS_DIR / output_name
    if not out_path.exists():
        return RedirectResponse(url="/")

    # Intentar cargar el JSON asociado (si se generó en /anonymize)
    base = Path(output_name).stem.replace("_anon", "")
    json_path = OUTPUTS_DIR / f"{base}_report.json"

    if json_path.exists():
        with open(json_path, "r", encoding="utf-8") as f:
            js = json.load(f)
        report = Report(
            detected_pii_columns=js.get("detected_pii_columns", []),
            column_risk=js.get("column_risk", {}),
            global_score=js.get("global_score", 0),
            notes=f"Archivo original: {js.get('original_filename')} • Plan aplicado: {js.get('plan')}"
        )
    else:
        report = Report(
            detected_pii_columns=[],
            column_risk={},
            global_score=5,
            notes="No se halló el JSON de reporte; mostrando versión básica."
        )

    # Cargar el archivo anonimizado y preparar previsualización
    try:
        from app.utils.file_io import load_dataset
        df_preview = load_dataset(out_path)
        preview_columns = list(df_preview.columns)
        preview_rows = df_preview.head(20).to_dict(orient="records")  # Muestra hasta 20 filas
    except Exception:
        preview_columns, preview_rows = [], []

    return templates.TemplateResponse(
        "report.html",
        {
            "request": request,
            "title": "Reporte",
            "report": report,
            "output_name": output_name,
            "preview_columns": preview_columns,
            "preview_rows": preview_rows,
            "year": datetime.now().year
        }
    )

@app.get("/download/{output_name}")
def download(output_name: str):
    """
    Descarga el archivo anonimizado desde /outputs.
    """
    path = OUTPUTS_DIR / output_name
    if not path.exists():
        return JSONResponse({"error": "Archivo no encontrado."}, status_code=404)
    media = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" if path.suffix.lower() in [".xlsx"] else "text/csv"
    return FileResponse(path, filename=output_name, media_type=media)