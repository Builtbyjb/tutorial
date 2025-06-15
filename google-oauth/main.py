from fastapi import FastAPI
import uvicorn
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()


app.get("/")
async def index():
  pass


app.get("/home")
async def home():
  pass


app.get("/sign-in")
async def sign_in():
  pass


app.get("/sign-out")
async def sign_out():
  pass


app.get("/callback/auth")
async def callback():
  pass


if __name__ == "__main__":
  uvicorn.run("main:app", host="0.0.0.0", port=3000, reload=True)
