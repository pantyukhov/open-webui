from fastapi import (
    Request,
    Response,
)
from starlette.responses import RedirectResponse

from open_webui.env import WEBUI_SESSION_COOKIE_SAME_SITE, WEBUI_SESSION_COOKIE_SECURE
from open_webui.scade.utils.utils.decode import decode_token
from open_webui.scade.utils.utils.get_current_user import get_or_create_current_user
from open_webui.utils.misc import parse_duration
from open_webui.utils.oauth import auth_manager_config
from open_webui.utils.utils import create_token


def init_scade_urls(app):
    @app.post("/auth/frame-login")
    async def frame_login(response: Response, request: Request):
        # Assuming jwt_token is passed in the body of the request
        data = await request.json()
        jwt_token = data.get("jwt_token")

        data = decode_token(jwt_token)
        user = get_or_create_current_user(data)

        jwt_token = create_token(
            data={"id": user.id},
            expires_delta=parse_duration(auth_manager_config.JWT_EXPIRES_IN),
        )

        # Set the cookie token
        response.set_cookie(
            key="token",
            value=jwt_token,
            httponly=True,  # Ensures the cookie is not accessible via JavaScript
            samesite=WEBUI_SESSION_COOKIE_SAME_SITE,
            secure=WEBUI_SESSION_COOKIE_SECURE,
        )

        return RedirectResponse(url="/")
