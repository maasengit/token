package com.abc.token;

public enum TokenStatus {
    VALID(0), INVALID(1), EXPIRED(2), REFRESH(3);
    private Integer value;

    TokenStatus(Integer value) {
        this.value = value;
    }

    public Integer getValue() {
        return value;
    }
}
