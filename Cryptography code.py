import os
import time
import tracemalloc
from Cryptodome.Cipher import ChaCha20
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import DSA
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA256
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

# PKi elements
PKIElements = {
    "revoked_serials": set(),
    "root_certificate": None,
    "intermediate_ca": {"name": "intermediate_ca"},
    "users": {},
    "next_serial_number": 1,
}

KEYS_DIR = "Keys_and_certs"
os.makedirs(KEYS_DIR, exist_ok=True)

# load all ecc private keys
def load_private_key_from_pem(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

# load all certificates
def load_cert_from_pem(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

# load all dsa private keys
def load_dsa_private_key(path):
    with open(path, "rb") as f:
        return DSA.import_key(f.read())

# load all dsa public keys
def load_dsa_public_key(path):
    with open(path, "rb") as f:
        return DSA.import_key(f.read())


def cert_fingerprint(cert):
    return cert.fingerprint(hashes.SHA256())


def clear_intermediate_ca_files():
    # Remove intermediate CA files when root CA changes
    ca_cert_path = os.path.join(KEYS_DIR, "intermediate_ca_certificate.pem")
    ca_key_path = os.path.join(KEYS_DIR, "intermediate_ca_private_key.pem")

    if os.path.exists(ca_cert_path):
        os.remove(ca_cert_path)
        print("Removed old Intermediate CA certificate")
    if os.path.exists(ca_key_path):
        os.remove(ca_key_path)
        print("Removed old Intermediate CA private key")


def clear_all_user_files():
    # Remove all user certificate files when intermediate CA changes
    print("Clearing all user certificates due to CA change")
    for filename in os.listdir(KEYS_DIR):
        if filename.startswith("U_"):
            filepath = os.path.join(KEYS_DIR, filename)
            os.remove(filepath)
    print("All user certificates removed")


def create_root_ca():
    root_cert_path = os.path.join(KEYS_DIR, "root_ca_certificate.pem")
    root_key_path = os.path.join(KEYS_DIR, "root_ca_private_key.pem")

    # Check if files exist
    if os.path.exists(root_cert_path) and os.path.exists(root_key_path):
        print("Loading existing Root CA")
        PKIElements["root_certificate"] = load_cert_from_pem(root_cert_path)
        PKIElements["root_private_key"] = load_private_key_from_pem(root_key_path)
        print("Root CA loaded from files\n")
        return False  # Existing CA loaded

    print("Creating NEW Root CA")

    root_private_key = ec.generate_private_key(ec.SECP256R1())

    root_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UOG Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "UOG Root CA"),
    ])

    now = datetime.now(timezone.utc)
    #  certificate layout
    root_certificate = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True
        )
        .sign(root_private_key, hashes.SHA256())
    )

    PKIElements["root_certificate"] = root_certificate
    PKIElements["root_private_key"] = root_private_key

    # Save Root CA private key
    with open(root_key_path, "wb") as f:
        f.write(
            root_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save Root CA certificate
    with open(root_cert_path, "wb") as f:
        f.write(root_certificate.public_bytes(serialization.Encoding.PEM))

    print("Root CA created and saved")
    print("Chain of trust broken so all certificates must be recreated \n")
    return True  


def create_intermediate_ca(force_recreate=False):
    ca_cert_path = os.path.join(KEYS_DIR, "intermediate_ca_certificate.pem")
    ca_key_path = os.path.join(KEYS_DIR, "intermediate_ca_private_key.pem")

    # remove old files
    if force_recreate:
        clear_intermediate_ca_files()

    # Check if files exist
    if os.path.exists(ca_cert_path) and os.path.exists(ca_key_path):
        print("Loading existing Intermediate CA")
        PKIElements["intermediate_ca"]["certificate"] = load_cert_from_pem(ca_cert_path)
        PKIElements["intermediate_ca"]["private_key"] = load_private_key_from_pem(ca_key_path)
        print("Intermediate CA loaded from files\n")
        return False  # Existing CA loaded

    print("Creating NEW Intermediate CA")

    ca_private_key = ec.generate_private_key(ec.SECP256R1())

    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UOG Intermediate CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "UOG Intermediate CA"),
    ])

    now = datetime.now(timezone.utc)

    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(PKIElements["root_certificate"].subject)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        )
        .sign(PKIElements["root_private_key"], hashes.SHA256())
    )

    PKIElements["intermediate_ca"]["private_key"] = ca_private_key
    PKIElements["intermediate_ca"]["certificate"] = ca_certificate

    # Save Intermediate CA private key
    with open(ca_key_path, "wb") as f:
        f.write(
            ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save Intermediate CA certificate
    with open(ca_cert_path, "wb") as f:
        f.write(ca_certificate.public_bytes(serialization.Encoding.PEM))

    print("Intermediate CA created and saved\n")
    return True  # New CA created


# RA storage for approved users
ra = {"approved_users": ["steve", "stacey", "kevin", "dave"]}


def RA(username):
    # Approves a user so the CA can issue them a certificate
    print(f"RA starting identity verification for: {username}")

    if username in ra["approved_users"]:
        print(f" RA approved: '{username}' found in authorized users")
        return True
    else:
        print(f" RA rejected: '{username}' not found in authorized users")
        return False


def ca_issue_certificate(username):
    # Check RA approval
    if username not in ra["approved_users"]:
        print(f"error: '{username}' is not approved by RA.")
        return None

    print(f"Creating certificate for '{username}'")
    # Resource Testing for whole certificate
    CertstartTime = time.time()

    # Resource Testing
    ECCstartTime = time.time()

    user_private_key = ec.generate_private_key(ec.SECP256R1())  # Generate user key pair
    user_public_key = user_private_key.public_key()

    ECCendTime = time.time()
    print("ECC key generated time:", round(ECCendTime - ECCstartTime, 5), "seconds")

    # Build subject (user identity)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UOG Users"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    # Issuer is the Intermediate CA
    issuer = PKIElements["intermediate_ca"]["certificate"].subject

    # Validity period
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(days=365)

    # Build and sign certificate with Intermediate CA private key
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(user_public_key)
        .serial_number(PKIElements["next_serial_number"])
        .not_valid_before(now)
        .not_valid_after(expiry)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(f"{username}.uog.local")
            ]),
            critical=False,
        )
        .sign(
            PKIElements["intermediate_ca"]["private_key"],
            hashes.SHA256(),
        )
    )

    # Increment serial number for next certificate
    PKIElements["next_serial_number"] += 1

    # Save user private key
    with open(f"Keys_and_certs/U_{username}_ecc_private_key.pem", "wb") as f:
        f.write(
            user_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save user certificate
    with open(f"Keys_and_certs/U_{username}_certificate.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    dssStart = time.time()
    dsa_key = DSA.generate(1024)
    dssEnd = time.time() - dssStart

    # Save DSA private key
    with open(f"Keys_and_certs/U_{username}_dsa_private_key.pem", "wb") as f:
        f.write(dsa_key.export_key())

    # Save DSA public key
    with open(f"Keys_and_certs/U_{username}_dsa_public_key.pem", "wb") as f:
        f.write(dsa_key.publickey().export_key())

    print("Time to create DSA key:", round(dssEnd, 5), "Seconds")

    # Store certificate info in PKI
    PKIElements["users"][username] = {
        "certificate": certificate,
        "ec_private_key": user_private_key,
        "dss_private": dsa_key,
        "dss_public": dsa_key.publickey(),
    }

    print(f"Certificate successfully issued for '{username}'\n")
    print(f"Certificate issued for '{username}'")
    print(f"Certificate contents: {certificate}")
    print("Certificate stored in PKI.\n")

    CertendTime = time.time() - CertstartTime
    print("Certificate generation time:", round(CertendTime, 5), "seconds")

    return certificate


def load_user(username):
    # Load an existing user's certificates and keys from files
    cert_path = os.path.join(KEYS_DIR, f"U_{username}_certificate.pem")
    ecc_key_path = os.path.join(KEYS_DIR, f"U_{username}_ecc_private_key.pem")
    dsa_private_path = os.path.join(KEYS_DIR, f"U_{username}_dsa_private_key.pem")
    dsa_public_path = os.path.join(KEYS_DIR, f"U_{username}_dsa_public_key.pem")

    # Check if all necessary files exist
    if not all(os.path.exists(p) for p in [cert_path, ecc_key_path, dsa_private_path, dsa_public_path]):
        return False

    try:
        certificate = load_cert_from_pem(cert_path)
        ec_private_key = load_private_key_from_pem(ecc_key_path)
        dss_private = load_dsa_private_key(dsa_private_path)
        dss_public = load_dsa_public_key(dsa_public_path)

        PKIElements["users"][username] = {
            "certificate": certificate,
            "ec_private_key": ec_private_key,
            "dss_private": dss_private,
            "dss_public": dss_public,
        }

        # Update serial number tracker if needed
        if certificate.serial_number >= PKIElements["next_serial_number"]:
            PKIElements["next_serial_number"] = certificate.serial_number + 1

        print(f"User '{username}' loaded from existing files")
        return True
    except Exception as e:
        print(f"Error loading user '{username}': {e}")
        return False


def register_user(username):
    # Handles full user registration
    if username in PKIElements["users"]:
        print(f"User '{username}' already exists \n")
        return

    # Try to load existing user files first
    if load_user(username):
        return

    # If no files exist, go through registration process
    RA(username)
    certificate = ca_issue_certificate(username)

    if certificate:
        print(f"User '{username}' stored with certificate.\n")


def VA(username):
    if username not in PKIElements["users"]:
        print("VA failed: User not found in PKI")
        return False

    certificate = PKIElements["users"][username]["certificate"]
    common_name = username

    print(f"VA: Validating certificate for '{common_name}'")

    # Load certificate from PEM file
    user_entry = PKIElements["users"].get(common_name)
    if user_entry is None:
        print("VA failed: User not found in PKI")
        return False

    cert_path = os.path.join(KEYS_DIR, f"U_{username}_certificate.pem")

    try:
        cert_from_file = load_cert_from_pem(cert_path)
    except Exception as e:
        print(f"VA failed: Could not load certificate PEM: {e}")
        return False

    # Compare PEM certificate with in-memory certificate
    if cert_fingerprint(cert_from_file) != cert_fingerprint(certificate):
        print("VA failed: the certificate does not match in memory certificate")
        return False

    # Validity time check
    now = datetime.now(timezone.utc)

    if now < certificate.not_valid_before_utc:
        print("VA failed: Certificate not yet valid")
        return False

    if now > certificate.not_valid_after_utc:
        print("VA failed: Certificate has expired")
        return False

    # Revocation check
    serial = str(certificate.serial_number)
    if serial in PKIElements["revoked_serials"]:
        print("VA failed: Certificate has been revoked")
        return False

    # Check issuer matches Intermediate CA
    intermediate_cert = PKIElements["intermediate_ca"].get("certificate")

    if intermediate_cert is None:
        print("VA failed: Intermediate CA certificate not available")
        return False

    if certificate.issuer != intermediate_cert.subject:
        print("VA failed: Issuer does not match Intermediate CA")
        return False

    # Verify certificate signature
    try:
        intermediate_cert.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm)
        )
    except InvalidSignature:
        print("VA failed: Certificate signature invalid")
        return False
    except Exception as e:
        print(f"VA failed: Signature verification error: {e}")
        return False

    print(f"VA success: Certificate for '{common_name}' is valid\n")
    return True


def revoke_certificate(username):
    # Revokes a user's certificate by serial number
    if username not in PKIElements["users"]:
        print("Revocation failed: user does not exist")
        return

    cert = PKIElements["users"][username]["certificate"]
    serial = str(cert.serial_number)

    PKIElements["revoked_serials"].add(serial)
    print(f"Certificate for '{username}' revoked (serial {serial})")


def sendMessage(sender, receiver, message):
    # Checks both users exist, validates their certs, and encrypts a message
    sender = sender.lower()  # removing issues with capital letters
    receiver = receiver.lower()

    if sender not in PKIElements["users"] or receiver not in PKIElements["users"]:
        print("Sender or receiver does not exist in PKI.")
        return None

    if not VA(sender) or not VA(receiver):
        print("Certificate validation failed")
        return None

    # Resource testing for memory usage
    tracemalloc.start()

    # DSS signature
    plaintext_bytes = message.encode()
    plaintext_hash = SHA256.new(plaintext_bytes)

    dsa_private = PKIElements["users"][sender]["dss_private"]
    signer = DSS.new(dsa_private, "fips-186-3")
    signature = signer.sign(plaintext_hash)

    # ECDH key agreement
    sender_priv = PKIElements["users"][sender]["ec_private_key"]
    receiver_pub = PKIElements["users"][receiver]["certificate"].public_key()
    shared_secret = sender_priv.exchange(ec.ECDH(), receiver_pub)

    chacha_key = SHA256.new(shared_secret).digest()

    # Chacha20
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=chacha_key, nonce=nonce)
    ciphertext = cipher.encrypt(message.encode())

    msg = {
        "sender": sender,
        "receiver": receiver,
        "ciphertext": ciphertext,
        "nonce": nonce,
        "signature": signature,
    }

    print("Message sent.\n")
    currentMem, peakMem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print("Current memory usage:", currentMem, "bytes")
    print("Peak memory usage:", peakMem, "bytes")

    return msg


def receiveMessage(msg):
    # Checks the signature and then decrypts the message.
    if msg is None:
        print("Message is empty, cannot receive.")
        return False

    sender = msg["sender"]
    receiver = msg["receiver"]

    if not VA(sender) or not VA(receiver):
        print("Message rejected due to certificate validation failure\n")
        return False

    tracemalloc.start()  # memory usage test

    # ECDH key agreement
    receiver_priv = PKIElements["users"][receiver]["ec_private_key"]
    sender_pub = PKIElements["users"][sender]["certificate"].public_key()
    shared_secret = receiver_priv.exchange(ec.ECDH(), sender_pub)

    chacha_key = SHA256.new(shared_secret).digest()

    # Chacha20 decryption
    cipher = ChaCha20.new(key=chacha_key, nonce=msg["nonce"])
    plaintext = cipher.decrypt(msg["ciphertext"])

    # DSS verification
    plaintext_hash = SHA256.new(plaintext)
    dsa_public = PKIElements["users"][sender]["dss_public"]
    verifier = DSS.new(dsa_public, "fips-186-3")

    try:
        verifier.verify(plaintext_hash, msg["signature"])
        print("Signature valid.")
    except ValueError:
        print("Signature invalid. Message rejected.")
        return False

    print("Decrypted message:", plaintext.decode())

    currentMem, peakMem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print("Current memory usage:", currentMem, "bytes")
    print("Peak memory usage:", peakMem, "bytes")
    return True



root_ca_is_new = create_root_ca()
intermediate_ca_is_new = create_intermediate_ca(force_recreate=root_ca_is_new)

# If either CA is new, clear all user certificates to maintain chain of trust
if root_ca_is_new or intermediate_ca_is_new:
    clear_all_user_files()
    PKIElements["users"] = {}
    PKIElements["next_serial_number"] = 1
    print("All user data cleared - certificates must be reissued\n")


# Register example users (will load from files if they exist)
register_user("steve")
register_user("stacey")
register_user("kevin")
register_user("dave")
register_user("caroline")  # test user who is not in the authorized users

revoke_certificate("steve")  # test revoked user


while True:
    print("\nCurrent Users:", list(PKIElements["users"].keys()))

    print("\nType 'quit' at any point to stop.")

    sender = input("Sender: ").strip()
    if sender.lower() == "quit":
        break

    receiver = input("Receiver: ").strip()
    if receiver.lower() == "quit":
        break

    message = input("Message: ")
    if message.lower().strip() == "quit":
        break

    msg = sendMessage(sender, receiver, message)
    receiveMessage(msg)

    print("\n Send another message?")