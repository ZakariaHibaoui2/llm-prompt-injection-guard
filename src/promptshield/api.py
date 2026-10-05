"""REST API: put PromptShield in front of any LLM endpoint."""
from __future__ import annotations

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field

from . import __version__
from .guard import PromptGuard

app = FastAPI(title="PromptShield", version=__version__, description="Prompt-injection firewall for LLM apps")
GUARD = PromptGuard()


class ScanIn(BaseModel):
    text: str = Field(max_length=50_000)
    source: Literal["user", "document"] = "user"


class SanitizeIn(BaseModel):
    text: str = Field(max_length=200_000)
    allowed_image_hosts: list[str] = []


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/scan")
def scan(body: ScanIn) -> dict:
    return GUARD.scan(body.text, body.source).as_dict()


@app.post("/sanitize")
def sanitize(body: SanitizeIn) -> dict:
    return {"text": PromptGuard.sanitize(body.text, tuple(h.lower() for h in body.allowed_image_hosts))}
