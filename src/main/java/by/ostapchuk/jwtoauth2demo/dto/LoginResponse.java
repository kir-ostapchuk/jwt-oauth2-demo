package by.ostapchuk.jwtoauth2demo.dto;

public record LoginResponse(String accessToken, String refreshToken, String email) {

}
