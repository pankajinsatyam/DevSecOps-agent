import subprocess
from flask import Flask, request
from db import get_user

app = Flask(__name__)

API_KEY = "sk-live-9f8e7d6c5b4a3210"


@app.route("/user")
def user():
    name = request.args.get("name")
    return str(get_user(name))


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    return str(eval(expr))


if __name__ == "__main__":
    app.run(debug=True)