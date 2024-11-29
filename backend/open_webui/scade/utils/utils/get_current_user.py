from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from open_webui.apps.webui.models.users import Users
from open_webui.constants import ERROR_MESSAGES
from open_webui.scade.utils.utils.decode import decode_token


bearer_security = HTTPBearer(auto_error=False)


def get_or_create_current_user(data):
    user = Users.get_user_by_id(data["id"])
    if user is None:
        # TODO: refactor it
        user = Users.insert_new_user(
            id=data["id"],
            name="user",
            email=f"{data['id']}@scade.pro",
            role="user",
        )
        Users.update_user_last_active_by_id(user.id)
    else:
        Users.update_user_last_active_by_id(user.id)
    return user


def get_current_user(
    request: Request,
    auth_token: HTTPAuthorizationCredentials = Depends(bearer_security),
):
    from open_webui.utils.utils import get_current_user_by_api_key

    token = None

    if auth_token is not None:
        token = auth_token.credentials

    if token is None and "token" in request.cookies:
        token = request.cookies.get("token")

    if token is None:
        raise HTTPException(status_code=403, detail="Not authenticated")

    # auth by api key
    if token.startswith("sk-"):
        if not request.state.enable_api_key:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.API_KEY_NOT_ALLOWED
            )
        return get_current_user_by_api_key(token)

    # auth by jwt token
    try:
        data = decode_token(token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    if data is not None and "id" in data:
        return get_or_create_current_user(data)
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.UNAUTHORIZED,
        )
