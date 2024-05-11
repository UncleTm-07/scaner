import uvicorn
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from database import create_tables
from router import router
from service import start_scan


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_tables()
    yield


app = FastAPI(lifespan=lifespan)
app.include_router(router)

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.websocket("/scan")
async def websocket_endpoint(websocket: WebSocket):
    try:
        await websocket.accept()
        data = await websocket.receive_text()
        await start_scan(data, websocket)
        await websocket.close()
    except Exception as e:
        await websocket.send_json({"error": e, "message": "Виникла помилка!"})
        await websocket.close()


if __name__ == '__main__':
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
