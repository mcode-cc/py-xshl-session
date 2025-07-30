from authlib.jose import JWTClaims


class SessionClaims(JWTClaims):
    REGISTERED_CLAIMS = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti",  # Default JWT claims
                         "version", "sid", "scope", "location", "type", "trace", "_scope",  # System claims
                         "_payloads"]  # Data claims
    REQUIRED_CLAIMS = ["iss", "aud", "exp", "nbf", "iat", "jti", "sid"]

    def __init__(self, payload, header=None, options=None, params=None):
        super().__init__(payload, header, options, params)
        # Enriching options with required attributes. Used in validate
        if self.options is None and len(self.REQUIRED_CLAIMS) > 0:
            self.options = {}
        for claim in self.REQUIRED_CLAIMS:
            if claim in self.options and isinstance(self.options[claim], dict):
                self.options[claim].update({"essential": True})
            else:
                self.options[claim] = {"essential": True}

    def __setattr__(self, name: str, value) -> None:
        if name in self.REGISTERED_CLAIMS:
            super(SessionClaims, self).__setitem__(name, value)
        else:
            super().__setattr__(name, value)
