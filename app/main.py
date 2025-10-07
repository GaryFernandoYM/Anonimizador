# app/main.py
from fastapi import FastAPI, UploadFile, File, Request, HTTPException
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
from datetime import datetime
import pandas as pd
import json
import traceback

from app.config import (
    DATA_DIR, OUTPUTS_DIR,
    is_allowed_filetype, file_size_ok, MAX_FILE_MB
)
from app.schemas import AnonymizeRequest, Report
from app.utils.file_io import load_dataset, save_dataset, safe_filename
from app.services.detectors import detect_pii_columns, count_hits
from app.services.anonymizer import anonymize_df
from app.utils.scoring import risk_score_by_column, global_risk_score

app = FastAPI(title="Anonimizador FastAPI (Robusto)")

# Static & templates
BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "title": "Inicio", "year": datetime.now().year}
    )

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    try:
        # 1) Validar extensión
        if not is_allowed_filetype(file.filename):
            raise HTTPException(status_code=400, detail="Tipo de archivo no permitido")

        # 2) Guardar temporalmente
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        dest = DATA_DIR / safe_filename(file.filename)
        with dest.open("wb") as f:
            f.write(await file.read())

        # 3) Validar tamaño
        if not file_size_ok(dest):
            dest.unlink(missing_ok=True)
            raise HTTPException(status_code=400, detail=f"Archivo > {MAX_FILE_MB} MB")

        # 4) Leer muestra
        ext = dest.suffix.lower()
        if ext in [".csv", ".tsv", ".txt"]:
            sep = "\t" if ext == ".tsv" else ","
            df = pd.read_csv(dest, sep=sep, nrows=500)
        elif ext in [".xlsx", ".xlsm", ".xls"]:
            df = pd.read_excel(dest, nrows=500)
        elif ext == ".parquet":
            df = pd.read_parquet(dest)
        elif ext in [".jsonl", ".json"]:
            try:
                df = pd.read_json(dest, lines=True)
            except ValueError:
                df = pd.read_json(dest)
        else:
            raise HTTPException(status_code=400, detail="Extensión no soportada")

        cols = [str(c) for c in df.columns.tolist()]
        head = df.head(10).fillna("").astype(str).to_dict(orient="records")
        return JSONResponse({"filename": dest.name, "columns": cols, "head": head})

    except HTTPException:
        raise
    except Exception as e:
        print("ERROR /upload:", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Error interno al procesar el archivo")

# --- sugeridor muy simple para no romper el front ---
def _suggest_strategy(col_name: str) -> str:
    lc = str(col_name).lower()
    if any(k in lc for k in ["mail", "correo", "email"]):
        return "mask"
    if any(k in lc for k in ["tel", "phone", "cel"]):
        return "mask"
    if any(k in lc for k in ["dni", "documento", "ruc", "passport", "pasaporte"]):
        return "hash:length=16"
    if any(k in lc for k in ["fecha", "date", "nacimiento", "dob"]):
        return "generalize_date:granularity=year"
    if any(k in lc for k in ["lat", "long", "coord", "ubicacion", "address", "direccion"]):
        return "generalize_geo:levels=2"
    return ""  # ignorar por defecto

@app.post("/api/analyze")
async def analyze(filename: str | None = None):
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
    src = DATA_DIR / filename
    if not src.exists():
        return JSONResponse({"error": "Archivo no encontrado."}, status_code=404)

    df = load_dataset(src)

    # Métricas PII previas
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

    # Guardar reporte JSON
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
        json.dumps(report_json, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    return JSONResponse({"report_url": f"/report/{out_name}"})

@app.get("/report/{output_name}", response_class=HTMLResponse)
def report_view(request: Request, output_name: str):
    out_path = OUTPUTS_DIR / output_name
    if not out_path.exists():
        return RedirectResponse(url="/")

    base = Path(output_name).stem.replace("_anon", "")
    json_path = OUTPUTS_DIR / f"{base}_report.json"

    if json_path.exists():
        js = json.loads(json_path.read_text(encoding="utf-8"))
        report = Report(
            detected_pii_columns=js.get("detected_pii_columns", []),
            column_risk=js.get("column_risk", {}),
            global_score=js.get("global_score", 0),
            notes=f"Archivo original: {js.get('original_filename')} • Plan aplicado: {js.get('plan')}"
        )
    else:
        report = Report(detected_pii_columns=[], column_risk={}, global_score=5,
                        notes="No se halló el JSON de reporte; mostrando versión básica.")

    try:
        df_preview = load_dataset(out_path)
        preview_columns = list(df_preview.columns)
        preview_rows = df_preview.head(20).to_dict(orient="records")
    except Exception:
        preview_columns, preview_rows = [], []

    return templates.TemplateResponse(
        "report.html",
        {"request": request, "title": "Reporte", "report": report,
         "output_name": output_name, "preview_columns": preview_columns,
         "preview_rows": preview_rows, "year": datetime.now().year}
    )

@app.get("/download/{output_name}")
def download(output_name: str):
    path = OUTPUTS_DIR / output_name
    if not path.exists():
        return JSONResponse({"error": "Archivo no encontrado."}, status_code=404)
    media = ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
             if path.suffix.lower() == ".xlsx" else "text/csv")
    return FileResponse(path, filename=output_name, media_type=media)
