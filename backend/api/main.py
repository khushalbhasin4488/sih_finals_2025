from fastapi import FastAPI

app = FastAPI(title="Log Analyzer Tool API")

@app.get("/")
async def root():
    return {"message": "Log Analyzer Tool API is running"}
