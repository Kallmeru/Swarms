"""python -m server, so running the app needs no uvicorn CLI knowledge and
picks up the PORT a platform hands it (Render, Fly, Cloud Run all set it)."""
import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "server.app:app",
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8000")),
        reload=bool(os.environ.get("SWARMS_RELOAD")),
    )
