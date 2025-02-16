import hmac
import hashlib
import json
import base64

secret = b'nomnomshark'  # Secret key

def generate_hmac(payload: dict) -> str:
    """Generates HMAC signature for the given payload."""
    message = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    signature = hmac.new(secret, message, hashlib.sha256).digest()
    return base64.b64encode(signature).decode()

def send_payload():
    """Simulates sending a payload with an HMAC signature."""
    payload = {
        "user": "Ellen",
        "amount": 500,
        "currency": "CAD"
    }

    hmac_signature = generate_hmac(payload)
    secure_message = {
        "payload": payload,
        "hmac": hmac_signature
    }

    # Simulate saving to file (or send over a network)
    with open("message.json", "w") as f:
        json.dump(secure_message, f)

    print("Payload sent with HMAC:", secure_message)

if __name__ == "__main__":
    send_payload()
