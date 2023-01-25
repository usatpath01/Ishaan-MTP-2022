from flask import Flask
import requests

app = Flask(__name__)


@app.route('/flask_ishan1')
def home():
    return requests.get("http://flask_ishan:5000/hello").text


@app.route('/flask_ishan2')
def home2():
    return requests.get("http://flask_ishan2:5001/hello").text


@app.route('/hello')
def say_hello():
    return "Hello! I am flask_smrl"


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
