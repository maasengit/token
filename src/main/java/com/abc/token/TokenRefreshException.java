package com.abc.token;

public class TokenRefreshException extends TokenException {
    public TokenRefreshException(String token) {
        super(token);
    }
}
