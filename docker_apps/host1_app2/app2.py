from flask import Flask
import requests

app = Flask(__name__)


@app.route('/')
def home():
    return requests.get("http://flask_ishan1:5000/hello").text


@app.route('/hello')
def say_hello():
    return "Hello! I am flask_ishan2"


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5001)
