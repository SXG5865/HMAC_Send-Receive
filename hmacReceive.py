import hmac
import hashlib
import json
import base64

secret = b'nomnomshark'  # Shared secret key

def verify_hmac(received_payload: dict, received_hmac: str) -> bool:
    """Verifies HMAC signature."""
    message = json.dumps(received_payload, separators=(',', ':')).encode('utf-8')
    expected_signature = hmac.new(secret, message, hashlib.sha256).digest()
    expected_hmac = base64.b64encode(expected_signature).decode()

    return hmac.compare_digest(received_hmac, expected_hmac)

def receive_payload():
    """Simulates receiving and verifying a payload."""
    # Simulate reading from file (or receive over a network)
    with open("message.json", "r") as f:
        secure_message = json.load(f)

    received_payload = secure_message["payload"]
    received_hmac = secure_message["hmac"]

    if verify_hmac(received_payload, received_hmac):
        print("✅ HMAC verification: SUCCESS")
        print("Received payload:", received_payload)
    else:
        print("❌ HMAC verification: FAIL")


if __name__ == "__main__":
    receive_payload()
