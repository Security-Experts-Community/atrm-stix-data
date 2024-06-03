import hashlib
import uuid


def create_uuid_from_string(val: str) -> uuid.UUID:
    hex_string = hashlib.md5(val.encode("UTF-8")).hexdigest()  # noqa: S324
    return uuid.UUID(hex=hex_string, version=4)
