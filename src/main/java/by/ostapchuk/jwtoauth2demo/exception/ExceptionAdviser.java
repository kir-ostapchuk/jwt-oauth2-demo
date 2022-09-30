package by.ostapchuk.jwtoauth2demo.exception;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@RestControllerAdvice
public record ExceptionAdviser() {

    @ResponseStatus(FORBIDDEN)
    @ExceptionHandler(AccessDeniedException.class)
    public void accessDeniedException() {
    }

    @ResponseStatus(BAD_REQUEST)
    @ExceptionHandler(ResourceNotFoundException.class)
    public void resourceNotFoundException() {
    }

    @ResponseStatus(UNAUTHORIZED)
    @ExceptionHandler({JwtException.class, JwtTokenException.class})
    public String jwtTokenException(final RuntimeException e) {
        return e.getMessage();
    }

    @ResponseStatus(INTERNAL_SERVER_ERROR)
    @ExceptionHandler(Throwable.class)
    public String generalException(final Throwable e) {
        return e.getMessage();
    }
}

