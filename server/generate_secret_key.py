import secrets

# Generate a secret key with 32 bytes (256 bits) of entropy
secret_key = secrets.token_hex(32)

print("Generated secret key:", secret_key)