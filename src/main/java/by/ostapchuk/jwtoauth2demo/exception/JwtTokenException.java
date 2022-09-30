package by.ostapchuk.jwtoauth2demo.exception;

public class JwtTokenException extends RuntimeException {

    public JwtTokenException(final String message) {
        super(message);
    }
}
