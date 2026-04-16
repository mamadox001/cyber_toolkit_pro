# =============================================================================
# CyberToolkit Pro — Web Dashboard (FastAPI)
# =============================================================================
# REST API backend + embedded web UI for tool browsing, execution, and
# result viewing. Lightweight alternative to CLI for visual workflows.
#
# Start: python main.py dashboard
# Access: http://127.0.0.1:8443
# =============================================================================

import sys
import os
import json
import threading
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.loader import load_all
from core.registry import get_registry
from core.executor import execute
from core.pipeline import run_profile, list_profiles
from core.config import Config
from core.models import ToolResult


def create_app():
    """Create and configure the FastAPI application."""
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import HTMLResponse, JSONResponse
        from fastapi.staticfiles import StaticFiles
        from pydantic import BaseModel
        from typing import Optional, Dict, Any
    except ImportError:
        print("[!] FastAPI not installed. Run: pip install fastapi uvicorn")
        return None

    app = FastAPI(
        title="CyberToolkit Pro",
        description="Professional Cybersecurity Framework — Web Dashboard",
        version="2.0.0",
    )

    # --- Request Models ---
    class RunToolRequest(BaseModel):
        tool_path: str
        args: Dict[str, Any] = {}

    class RunPipelineRequest(BaseModel):
        profile: str
        args: Dict[str, Any] = {}

    # --- API Routes ---

    @app.get("/", response_class=HTMLResponse)
    async def root():
        """Serve the dashboard UI."""
        template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
        except FileNotFoundError:
            return HTMLResponse(content="<h1>Dashboard template not found</h1>", status_code=500)

    @app.get("/api/tools")
    async def list_tools():
        """List all registered tools."""
        registry = get_registry()
        tools = {}
        for cat in registry.categories():
            tools[cat] = []
            for tool in registry.tools_in_category(cat):
                info = tool["info"]
                tools[cat].append({
                    "name": info.name if hasattr(info, "name") else info.get("name", ""),
                    "category": info.category if hasattr(info, "category") else info.get("category", ""),
                    "description": info.description if hasattr(info, "description") else info.get("description", ""),
                    "version": info.version if hasattr(info, "version") else info.get("version", ""),
                    "args": [
                        {
                            "name": a.name if hasattr(a, "name") else a.get("name", ""),
                            "description": a.description if hasattr(a, "description") else a.get("description", ""),
                            "required": a.required if hasattr(a, "required") else a.get("required", False),
                            "default": a.default if hasattr(a, "default") else a.get("default", ""),
                        }
                        for a in (info.args if hasattr(info, "args") else info.get("args", []))
                    ],
                    "path": f"{info.category if hasattr(info, 'category') else info.get('category', '')}.{info.name if hasattr(info, 'name') else info.get('name', '')}",
                })
        return {"tools": tools, "total": registry.tool_count()}

    @app.get("/api/tools/{category}")
    async def list_tools_by_category(category: str):
        """List tools in a specific category."""
        registry = get_registry()
        tools = registry.tools_in_category(category)
        if not tools:
            raise HTTPException(status_code=404, detail=f"Category '{category}' not found")
        return {"category": category, "tools": [
            {
                "name": t["info"].name if hasattr(t["info"], "name") else t["info"].get("name", ""),
                "description": t["info"].description if hasattr(t["info"], "description") else t["info"].get("description", ""),
                "path": f"{category}.{t['info'].name if hasattr(t['info'], 'name') else t['info'].get('name', '')}",
            }
            for t in tools
        ]}

    @app.post("/api/run")
    async def run_tool(request: RunToolRequest):
        """Execute a specific tool and return results."""
        registry = get_registry()
        tool = registry.get(request.tool_path)
        if not tool:
            raise HTTPException(status_code=404, detail=f"Tool '{request.tool_path}' not found")

        result = execute(tool, request.args)
        return result.to_dict()

    @app.get("/api/profiles")
    async def get_profiles():
        """List available pipeline profiles."""
        profiles = list_profiles()
        return {"profiles": profiles}

    @app.post("/api/pipeline")
    async def run_pipeline_endpoint(request: RunPipelineRequest):
        """Execute a pipeline profile."""
        results = run_profile(request.profile, request.args)
        return {
            "profile": request.profile,
            "results": [r.to_dict() for r in results],
            "total": len(results),
            "success": sum(1 for r in results if r.status == "success"),
        }

    @app.get("/api/status")
    async def status():
        """Framework status and info."""
        registry = get_registry()
        return {
            "framework": "CyberToolkit Pro",
            "version": "2.5.0",
            "tools_loaded": registry.tool_count(),
            "categories": registry.categories(),
            "timestamp": datetime.utcnow().isoformat(),
        }

    @app.get("/api/stats")
    async def dashboard_stats():
        """Get dashboard statistics from database."""
        try:
            from core.database import get_db
            return get_db().get_dashboard_stats()
        except Exception as e:
            return {"error": str(e)}

    @app.get("/api/scans")
    async def scan_history(target: str = "", tool: str = "", limit: int = 50):
        """Get scan history from database."""
        try:
            from core.database import get_db
            scans = get_db().get_scans(target=target, tool=tool, limit=limit)
            return {"scans": scans, "total": len(scans)}
        except Exception as e:
            return {"error": str(e)}

    @app.get("/api/findings")
    async def findings(scan_id: str = "", severity: str = "", limit: int = 100):
        """Get findings from database."""
        try:
            from core.database import get_db
            results = get_db().get_findings(scan_id=scan_id, severity=severity, limit=limit)
            return {"findings": results, "total": len(results)}
        except Exception as e:
            return {"error": str(e)}

    @app.get("/api/targets")
    async def targets():
        """Get all known targets."""
        try:
            from core.database import get_db
            return {"targets": get_db().get_targets()}
        except Exception as e:
            return {"error": str(e)}

    @app.get("/api/audit")
    async def audit_trail(tool: str = "", target: str = "", limit: int = 100):
        """Get audit trail entries."""
        try:
            from core.audit import get_audit
            entries = get_audit().get_entries(limit=limit, tool=tool, target=target)
            return {"entries": entries, "total": len(entries)}
        except Exception as e:
            return {"error": str(e)}

    @app.get("/api/campaigns")
    async def campaigns():
        """List all campaigns."""
        try:
            from core.campaign import CampaignManager
            return {"campaigns": CampaignManager.list_campaigns()}
        except Exception as e:
            return {"error": str(e)}

    @app.get("/api/scope")
    async def scope_status():
        """Get scope enforcement status."""
        try:
            from core.scope import get_scope
            scope = get_scope()
            return {
                "enabled": scope.enabled,
                "allowed_ips": [str(n) for n in scope.allowed_ips],
                "allowed_domains": [p.pattern for p in scope.allowed_domains],
                "excluded_ips": [str(n) for n in scope.excluded_ips],
            }
        except Exception as e:
            return {"error": str(e)}

    return app


def start_dashboard(host: str = "127.0.0.1", port: int = 8443):
    """Start the dashboard server."""
    # Load tools before starting
    load_all(quiet=True)

    app = create_app()
    if app is None:
        return

    try:
        import uvicorn
        print(f"\n  [*] CyberToolkit Pro Dashboard")
        print(f"  [*] Starting at http://{host}:{port}")
        print(f"  [*] API docs at http://{host}:{port}/docs")
        print(f"  [*] Press Ctrl+C to stop\n")
        uvicorn.run(app, host=host, port=port, log_level="warning")
    except ImportError:
        print("[!] uvicorn not installed. Run: pip install uvicorn")
    except KeyboardInterrupt:
        print("\n  [*] Dashboard stopped")


if __name__ == "__main__":
    start_dashboard()
