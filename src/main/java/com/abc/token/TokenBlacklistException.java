package com.abc.token;

public class TokenBlacklistException extends TokenException {
    public TokenBlacklistException(String token) {
        super(token);
    }
}
