import os
import base64
from open_webui.config import PersistentConfig

JWT_PUBLIC_KEY = base64.b64decode(
    str(
        PersistentConfig(
            "JWT_PUBLIC_KEY",
            "server.jwt.public_key",
            os.getenv("JWT_PUBLIC_KEY", ""),
        )
    )
)
