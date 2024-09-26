import hashlib

def calculate_hash(file_path, hash_type="MD5"):
    if hash_type == "MD5":
        hasher = hashlib.md5()
    elif hash_type == "SHA-256":
        hasher = hashlib.sha256()
    else:
        raise ValueError("Unsupported hash type")

    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            hasher.update(byte_block)
    return hasher.hexdigest()

# Пример использования для файла eicar.exe
file_path = "eicar/eicar.com"
md5_hash = calculate_hash(file_path, "MD5")
sha256_hash = calculate_hash(file_path, "SHA-256")

print(f"MD5: {md5_hash}")
print(f"SHA-256: {sha256_hash}")
