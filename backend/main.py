# filepath: c:\Users\Zayad\Documents\FYP\01_WORK\ACDS-FYP\backend\main.py
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"Hello": "World"}
