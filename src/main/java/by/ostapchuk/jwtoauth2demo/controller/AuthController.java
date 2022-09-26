package by.ostapchuk.jwtoauth2demo.controller;

import by.ostapchuk.jwtoauth2demo.dto.LoginRequest;
import by.ostapchuk.jwtoauth2demo.dto.LoginResponse;
import by.ostapchuk.jwtoauth2demo.security.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    // todo: think and read about Id Token

    private final TokenService tokenService;

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest loginRequest) {
        String accessToken = tokenService.generateAccessToken(loginRequest);
        String refreshToken = tokenService.generateRefreshToken(loginRequest);
        // save refresh token to DB
        return new LoginResponse(accessToken, refreshToken, loginRequest.email());
    }

    public void refreshToken() {
//         validate refresh token and find user
//         ?? check expiry time of access token??
//         generate new access and refresh tokens
//         update in db refresh token
    }
}
