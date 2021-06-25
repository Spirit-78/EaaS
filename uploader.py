from flask import Flask, render_template, request, redirect, send_file
from werkzeug.utils import secure_filename
import sys
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from Crypto.Hash import SHA
import datetime

app = Flask(__name__)


class EncService:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cert_hash = ''
        self.doc_name = ''
        self.text = ''

    def set_cert_hash(self, cert_hash):
        self.cert_hash = cert_hash

    def set_doc_name(self, doc_name):
        self.doc_name = doc_name

    def set_text_name(self, text_name):
        self.text = text_name

    def get_doc_name(self):
        return self.doc_name

    @staticmethod
    def write_to_modified(data):
        with open('modified/client_file', 'wb') as mod_file:
            print(f"WRITING DATA: {data}", file=sys.stdout)
            mod_file.write(data)

    def process_text(self, action):
        fernet = Fernet(self.key)
        if action == 'Encrypt':
            data = fernet.encrypt(self.text.encode('utf-8'))
        else:
            data = fernet.decrypt(self.text.encode('utf-8'))
        self.write_to_modified(data)

    def write_key(self):
        with open('keys/keys.key', 'a') as keys_file:
            print('WRITING KEY: ', self.key, 'WRITING CERT_HASH: ', self.cert_hash, file=sys.stdout)
            keys_file.write('\n' + self.cert_hash + ":" + self.key.decode('latin1'))

    def check_cert(self):
        with open('keys/keys.key', 'r') as key_file:
            for line in key_file.readlines():
                if line.split(':')[0] == self.cert_hash:
                    self.key = line.split(':')[1].encode('utf-8')
                    return
        self.write_key()

    def print_details(self):
        print('KEY: ', self.key, 'CERT_HASH: ', self.cert_hash, 'DOC NAME: ', self.doc_name, file=sys.stdout)

    def encrypt_file(self):
        fernet = Fernet(self.key)
        with open(f'documents/{self.doc_name}', 'r') as file:
            enc_data = fernet.encrypt(''.join(file.readlines()).encode('utf-8'))
            print('ENCRYPTING DATA: ', enc_data, file=sys.stdout)
            self.write_to_modified(enc_data)

    def decrypt_file(self):
        fernet = Fernet(self.key)
        with open(f'documents/{self.doc_name}', 'r') as file:
            dec_data = fernet.decrypt(''.join(file.readlines()).encode('utf-8'))
            print('DECRYPTING DATA: ', dec_data, file=sys.stdout)
            self.write_to_modified(dec_data)


handler = EncService()


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
            print(f'UPLOAD FILE HEXDIGEST FROM CERT_SIGNATURE: {SHA.new(cert.signature).hexdigest()}', file=sys.stdout)
            if not check_date(cert):
                return render_template('not_valid.html')
            global handler
            handler.set_cert_hash(SHA.new(cert.signature).hexdigest())
            handler.check_cert()
        return redirect('/functions')


@app.route('/functions')
def enc_dec():
    return render_template('vtora_strana.html')


@app.route('/doc_upload', methods=['POST'])
def doc_upload():
    print(f'BUTTON CLICKED: {request.form["action"]}', file=sys.stdout)
    f = request.files['document']
    f.save("documents/" + secure_filename(f.filename))
    global handler
    handler.set_doc_name(secure_filename(f.filename))
    return redirect('/encrypt') if request.form['action'] == 'Encrypt' else redirect('/decrypt')


@app.route('/encrypt')
def encrypt():
    global handler
    handler.print_details()
    handler.encrypt_file()
    return render_template('download_file.html')


@app.route('/<path:filename>', methods=['GET', 'POST'])
def download(filename):
    print('filename: ', filename, file=sys.stdout)
    return send_file('modified/client_file', as_attachment=True)


@app.route('/decrypt')
def decrypt():
    global handler
    handler.print_details()
    handler.decrypt_file()
    return render_template('download_file.html')


@app.route('/text_input', methods=['POST'])
def text_input():
    text = request.form['text']
    print(f'INPUT TEXT: {text}', file=sys.stdout)
    global handler
    handler.set_text_name(text)
    handler.process_text(request.form['action'])
    return render_template('download_file.html')


if __name__ == '__main__':
    app.run(debug=True)
