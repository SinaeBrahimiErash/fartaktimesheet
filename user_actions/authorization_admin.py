from auth.jwt_bearer import decodeJWT


def chek_user_admin(token):
    payload = decodeJWT(token)
