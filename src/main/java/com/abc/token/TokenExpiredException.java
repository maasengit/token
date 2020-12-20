package com.abc.token;

public class TokenExpiredException extends TokenException {
    public TokenExpiredException(String token) {
        super(token);
    }
}
