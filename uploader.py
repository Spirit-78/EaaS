from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
import sys
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.backends import default_backend


#cert = x509.load_pem_x509_certificate(pem_data, default_backend())
# cert.serial_number

app = Flask(__name__)

class EncService:
    def __init__(self, cert_id):
        self.key = ''
        self.cert_id = cert_id

    def write_key(self):
        with open('keys.key', 'wb') as keys_file:
            keys_file.write(self.cert_id + ":" + self.key.decode('utf-8'))

    def generate_key(self):
        self.key = Fernet.generate_key()

    def  check_cert(self):
        pass

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['certificate']
        f.save("certificates/" + secure_filename(f.filename))
        print('This is standard output', file=sys.stdout)
        return '<p>file uploaded successfully<p>'
    else:
        return '<p>something went wrong.</p>'


if __name__ == '__main__':
    app.run(debug=True)