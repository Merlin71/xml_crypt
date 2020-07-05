import pickle
import Crypto.Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from xml.etree import ElementTree
import io
import codecs


def xml_decrypt(filename, password, rounds=100, parser=None):
    hashed_password = _get_key_hash(password=password, rounds=rounds)
    with open(filename, 'r') as f_enc:
        ct_bytes = pickle.load(f_enc)
    try:
        iv = ct_bytes['iv']
        ct = ct_bytes['ciphertext']
        cipher = AES.new(hashed_password, mode=AES.MODE_CBC, iv=iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        mem_file = io.BytesIO(pt)
    except (ValueError, KeyError):
        print("Incorrect decryption")
        raise
    else:
        xml = ElementTree.parse(source=mem_file, parser=parser)
        return xml
        pass


def xml_encrypt(plaintext_filename, encrypted_filename, password, rounds=100):
    hashed_password = _get_key_hash(password=password, rounds=rounds)
    cipher = AES.new(hashed_password, mode=AES.MODE_CBC)
    with open(plaintext_filename, 'r') as f_plain:
        ct_bytes = cipher.encrypt(pad(f_plain.read(), AES.block_size))

    with open(encrypted_filename, 'w') as f_enc:
        pickle.dump({"iv": cipher.iv, "ciphertext": ct_bytes}, f_enc)


def xml_obfuscate(plaintext_filename, encrypted_filename):
    with open(plaintext_filename, 'r') as f_plain:
        pt_data = f_plain.read()

    with open(encrypted_filename, 'w') as f_enc:
        f_enc.write(codecs.decode(pt_data, 'rot-13'))


def xml_reverse_obfuscate(filename, parser=None):
    with open(filename, 'r') as f_enc:
        ct_data = f_enc.read()

    mem_file = io.StringIO(codecs.decode(ct_data, 'rot-13'))
    xml = ElementTree.parse(source=mem_file, parser=parser)
    return xml


def _get_key_hash(password, rounds):
    key = password
    for i in range(rounds):
        key = hashlib.sha256(key).digest()

    return key
