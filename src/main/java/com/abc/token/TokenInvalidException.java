package com.abc.token;

public class TokenInvalidException extends TokenException {
    public TokenInvalidException(String token) {
        super(token);
    }
}
