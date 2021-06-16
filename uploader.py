from flask import Flask, render_template, request, redirect
from werkzeug.utils import secure_filename
import sys
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from Crypto.Hash import SHA
import datetime


#cert = x509.load_pem_x509_certificate(pem_data, default_backend())
# cert.serial_number

app = Flask(__name__)

class EncService:
    def __init__(self, cert_hash):
        self.key = Fernet.generate_key()
        self.cert_hash = cert_hash

    def write_key(self):
        with open('keys.key', 'wb') as keys_file:
            keys_file.write('\n' + self.cert_hash + ":" + self.key.decode('latin1'))

    def check_cert(self):
        with open('keys/keys.key', 'r') as key_file:
            for line in key_file.readlines():
                if line.split(':')[0] == self.cert_hash:
                    self.key = line.split(':')[1].encode('utf-8')
                    return
        self.write_key()


def check_date(cert):
    return cert.not_valid_before.timestamp() < datetime.datetime.now().timestamp() < cert.not_valid_after.timestamp()


@app.route('/')
def index():
    return render_template('prva_strana.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['certificate']
        f.save("certificates/" + secure_filename(f.filename))
        with open('certificates/' + secure_filename(f.filename), 'r') as file:
            data = ''.join(file.readlines()).encode('utf-8')
            cert = x509.load_pem_x509_certificate(data, default_backend())
            print(f'This is standard output {cert.signature}', file=sys.stdout)
            if not check_date(cert):
                return render_template('not_valid.html')
            handler = EncService(SHA.new(cert.signature).hexdigest())
            handler.check_cert()
        return redirect('/functions')


@app.route('/functions')
def enc_dec():
    return render_template('vtora_strana.html')


if __name__ == '__main__':
    app.run(debug=True)
