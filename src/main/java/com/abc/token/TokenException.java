package com.abc.token;

public class TokenException extends RuntimeException {
    private String token;
    public TokenException(String token) {
        super(token);
        this.token = token;
    }

    public String getToken() {
        return this.token;
    }
}
