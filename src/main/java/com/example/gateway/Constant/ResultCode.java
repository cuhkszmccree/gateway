package com.example.gateway.Constant;



public enum ResultCode implements IErrorCode {
    SUCCESS(200, "Operation Success"),
    FAILED(500, "Operation Failed"),
    VALIDATE_FAILED(404, "Verification Failed"),
    UNAUTHORIZED(401, "Not Login or token has expired"),
    FORBIDDEN(403, "Do not have relative authority");
    private long code;
    private String message;

    private ResultCode(long code, String message) {
        this.code = code;
        this.message = message;
    }

    public long getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
