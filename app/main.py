from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import Request

from app.core.config import ROOT_DIR, get_settings
from app.core.models import AnalyzeRequest, CaseUpdateRequest
from app.services.analysis import analyze_indicators, list_analyses, load_analysis
from app.services.exporter import export_case_excel, export_excel
from app.services.storage import get_case, init_db, list_cases, update_case


settings = get_settings()
app = FastAPI(title=settings.app_name)
app.mount("/static", StaticFiles(directory=ROOT_DIR / "app" / "static"), name="static")
templates = Jinja2Templates(directory=ROOT_DIR / "app" / "templates")
init_db()


@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"app_name": settings.app_name})


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "openai": bool(settings.openai_api_key),
        "virustotal": bool(settings.virustotal_api_key),
        "malwarebazaar": bool(settings.malwarebazaar_api_key),
        "abuseipdb": bool(settings.abuseipdb_api_key),
        "urlscan": bool(settings.urlscan_api_key),
        "otx": bool(settings.otx_api_key),
    }


@app.get("/api/analyses")
async def analyses():
    return list_analyses()


@app.get("/api/cases")
async def cases():
    return list_cases()


@app.get("/api/cases/{case_id}")
async def case_detail(case_id: str):
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@app.patch("/api/cases/{case_id}")
async def case_update(case_id: str, payload: CaseUpdateRequest):
    case = update_case(
        case_id,
        status=payload.status,
        notes=payload.notes,
        tasks=[task.model_dump() for task in payload.tasks],
    )
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@app.get("/api/cases/{case_id}/excel")
async def download_case_excel(case_id: str):
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    path = export_case_excel(case, language="en")
    return FileResponse(
        path,
        filename=path.name,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.post("/api/analyze")
async def analyze(payload: AnalyzeRequest):
    return await analyze_indicators(
        indicators=payload.indicators,
        company_name=payload.company_name,
        context=payload.context,
        use_openai=payload.use_openai,
        language=payload.language,
    )


@app.get("/api/analyses/{analysis_id}")
async def get_analysis(analysis_id: str):
    try:
        return load_analysis(analysis_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Analysis not found") from exc


@app.get("/api/analyses/{analysis_id}/excel")
async def download_excel(analysis_id: str):
    try:
        analysis = load_analysis(analysis_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Analysis not found") from exc
    path = export_excel(analysis)
    return FileResponse(
        path,
        filename=path.name,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
