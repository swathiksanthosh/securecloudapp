# app.py
import os
from flask import Flask, request, render_template, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import json
import binascii
from cloud_upload import upload_to_drive


from encrypt_decrypt import encrypt_data, decrypt_data
from steganography import encode_text_into_image, decode_text_from_image
from Crypto.Random import get_random_bytes

UPLOAD_FOLDER = 'uploads'
KEY_IMAGES = 'key_images'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KEY_IMAGES, exist_ok=True)

app = Flask(__name__)
app.secret_key = 'dev-secret-key'  # for flash messages; replace in real use
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

INDEX_HTML = """
<!doctype html>
<title>Secure Cloud Prototype</title>
<h2>Encrypt & Hide Key</h2>
<form method=post enctype=multipart/form-data action="{{ url_for('encrypt') }}">
  <label>File to encrypt</label><br>
  <input type=file name=file required><br><br>
  <label>Algorithm</label>
  <select name=algorithm>
    <option>AES</option>
    <option>DES</option>
    <option>RC6</option>
  </select><br><br>
  <label>Cover image (PNG recommended)</label><br>
  <input type=file name=cover_image required><br><br>
  <label>Expiry in minutes</label><br>
  <input type=number name=expiry value=60 min=1><br><br>
  <input type=submit value="Encrypt & Hide Key">
</form>

<hr>
<h2>Decrypt</h2>
<form method=post enctype=multipart/form-data action="{{ url_for('decrypt') }}">
  <label>Encrypted file</label><br>
  <input type=file name=file required><br><br>
  <label>Key image (PNG)</label><br>
  <input type=file name=key_image required><br><br>
  <input type=submit value="Decrypt">
</form>

{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul>
    {% for m in messages %}
      <li>{{m}}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
"""
@app.route('/')
def index():
    return render_template('index.html')

def gen_random_key_for_algo(algorithm: str) -> bytes:
    algo = algorithm.strip().lower()
    if algo == 'aes':
        return get_random_bytes(16)  # AES-128
    elif algo == 'des':
        return get_random_bytes(8)   # DES 8 bytes
    elif algo == 'rc6':
        return get_random_bytes(16)  # RC6 128-bit
    else:
        raise ValueError("unsupported")

@app.route('/encrypt', methods=['POST'])
def encrypt():
    f = request.files.get('file')
    cover = request.files.get('cover_image')
    algorithm = request.form.get('algorithm', 'AES')
    expiry_minutes = int(request.form.get('expiry', 60))

    if not f or not cover:
        flash("Missing file or cover image")
        return redirect(url_for('index'))

    fname = secure_filename(f.filename)
    fpath = os.path.join(UPLOAD_FOLDER, fname)
    f.save(fpath)

    cover_name = secure_filename(cover.filename)
    cover_path = os.path.join(KEY_IMAGES, cover_name)
    cover.save(cover_path)

    # generate symmetric key
    key = gen_random_key_for_algo(algorithm)
    # read file bytes
    with open(fpath, 'rb') as fh:
        plaintext = fh.read()

    # encrypt
    iv_and_ct = encrypt_data(algorithm, key, plaintext)
    enc_name = fname + '.enc'
    enc_path = os.path.join(UPLOAD_FOLDER, enc_name)
    with open(enc_path, 'wb') as eh:
        eh.write(iv_and_ct)

    expiry_time = datetime.utcnow() + timedelta(minutes=expiry_minutes)
    metadata = {
        "algorithm": algorithm,
        "key_hex": binascii.hexlify(key).decode('utf-8'),
        # store expiry in ISO UTC
        "expiry_utc": expiry_time.isoformat() + 'Z',
        "original_filename": fname,
        "enc_filename": enc_name
    }
    metadata_str = json.dumps(metadata)

    # hide metadata in cover image -> output file
    # hide metadata in cover image -> output file
    out_key_image = os.path.join(KEY_IMAGES, f"key_{fname}.png")
    encode_text_into_image(cover_path, out_key_image, metadata_str)

# Upload files to Google Drive
    try:
        cloud_link1 = upload_to_drive(enc_path)
        cloud_link2 = upload_to_drive(out_key_image)

        flash(f"Encrypted file uploaded to Google Drive: {cloud_link1}")
        flash(f"Key image uploaded to Google Drive: {cloud_link2}")
    except Exception as e:
        flash(f"Failed to upload to cloud: {e}")

    flash(f"Encrypted file: {enc_name}")
    flash(f"Key image created: {os.path.basename(out_key_image)} (contains key + expiry)")
    flash("Download the encrypted file and the key image. Use the key image to decrypt before expiry.")

    return redirect(url_for('index'))


@app.route('/decrypt', methods=['POST'])
def decrypt():
    f = request.files.get('file')
    key_img = request.files.get('key_image')
    if not f or not key_img:
        flash("Missing encrypted file or key image")
        return redirect(url_for('index'))

    enc_name = secure_filename(f.filename)
    enc_path = os.path.join(UPLOAD_FOLDER, enc_name)
    f.save(enc_path)

    key_img_name = secure_filename(key_img.filename)
    key_img_path = os.path.join(KEY_IMAGES, key_img_name)
    key_img.save(key_img_path)

    try:
        metadata_str = decode_text_from_image(key_img_path)
        metadata_str = metadata_str.strip()

        if not metadata_str or not metadata_str.startswith('{'):
            flash("Invalid key image. Please upload the correct key_<filename>.png (must be the generated PNG)")
            return redirect(url_for('index'))

        metadata = json.loads(metadata_str)
    except Exception as e:
        flash(f"Failed to extract metadata from key image: {e}")
        return redirect(url_for('index'))

    # check expiry
    expiry = metadata.get('expiry_utc')
    if expiry is None:
        flash("No expiry in metadata — aborting")
        return redirect(url_for('index'))

    # parse expiry (assume format like 2025-10-20T12:34:56.123Z)
    try:
        expiry_dt = datetime.fromisoformat(expiry.replace('Z', '+00:00'))
    except Exception:
        flash("Invalid expiry format inside key image")
        return redirect(url_for('index'))

    now = datetime.utcnow().replace(tzinfo=None)
    # convert expiry to naive UTC
    expiry_naive = expiry_dt.astimezone().replace(tzinfo=None)

    if now > expiry_naive:
        flash("Access expired — cannot decrypt.")
        return redirect(url_for('index'))

    algorithm = metadata.get('algorithm')
    key_hex = metadata.get('key_hex')
    if algorithm is None or key_hex is None:
        flash("Metadata missing algorithm/key")
        return redirect(url_for('index'))

    key = binascii.unhexlify(key_hex.encode('utf-8'))

    # read ciphertext
    with open(enc_path, 'rb') as eh:
        iv_and_ct = eh.read()

    try:
        plaintext = decrypt_data(algorithm, key, iv_and_ct)
    except Exception as e:
        flash(f"Decryption failed: {e}")
        return redirect(url_for('index'))

    # store recovered file
    orig_name = metadata.get('original_filename', 'recovered_file')
    out_path = os.path.join(UPLOAD_FOLDER, f"decrypted_{orig_name}")
    with open(out_path, 'wb') as of:
        of.write(plaintext)

    flash(f"Decryption success! Download: decrypted_{orig_name}")
    return redirect(url_for('index'))

@app.route('/downloads/<path:filename>')
def downloads(filename):
    path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(path):
        flash("File not found")
        return redirect(url_for('index'))
    return send_file(path, as_attachment=True)

if __name__ == "__main__":
    # debug mode for prototype
    app.run(host='0.0.0.0', port=5000, debug=True)
