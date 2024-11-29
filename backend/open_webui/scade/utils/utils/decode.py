import datetime
import typing
from typing import Optional

import jwt

from open_webui.scade.config.config import JWT_PUBLIC_KEY


def get_token_payload(token) -> typing.Dict | None:
    try:
        payload = jwt.decode(token, JWT_PUBLIC_KEY, algorithms=["RS256"])
        if payload["exp"] < int(datetime.datetime.utcnow().timestamp()):
            return None

        return payload
    except jwt.ExpiredSignatureError:
        pass
    except jwt.InvalidTokenError:
        pass


def decode_token(token: str) -> Optional[dict]:
    data = get_token_payload(token)
    if "id" not in data:
        data["id"] = data["sub"]
    return data
