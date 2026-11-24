package io.supertokens.passkeysync;

public class PasskeySyncException extends Exception {
    private final String code;
    private final int httpStatusCode;

    public PasskeySyncException(String code, String message) {
        this(code, message, 400);
    }

    public PasskeySyncException(String code, String message, int httpStatusCode) {
        super(message);
        this.code = code;
        this.httpStatusCode = httpStatusCode;
    }

    public String getCode() {
        return code;
    }

    public int getHttpStatusCode() {
        return httpStatusCode;
    }
}
