"""Optional localhost FastAPI service providing a real HTTP trust boundary.

Run with: uvicorn minivac.api:app --host 127.0.0.1 --port 8000
No client-facing clock control, claimed game state, or client verdict trusted.
"""
from fastapi import FastAPI
from pydantic import BaseModel, Field
from .server_logic import GameServer

app = FastAPI(title="MiniVAC Educational Server", version="0.1")
server = GameServer(enforce_rules=True)


class Action(BaseModel):
    player_id: str = Field(min_length=1, max_length=50)
    kind: str
    dx: float = 0.0


@app.post("/action")
def action(request: Action):
    return server.action(request.player_id, request.kind, request.dx)


@app.get("/state/{player_id}")
def state(player_id: str):
    return server.state(player_id)
