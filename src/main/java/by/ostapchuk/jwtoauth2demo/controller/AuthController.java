package by.ostapchuk.jwtoauth2demo.controller;

import by.ostapchuk.jwtoauth2demo.dto.LoginRequest;
import by.ostapchuk.jwtoauth2demo.dto.LoginResponse;
import by.ostapchuk.jwtoauth2demo.dto.RefreshTokenRequest;
import by.ostapchuk.jwtoauth2demo.dto.RefreshTokenResponse;
import by.ostapchuk.jwtoauth2demo.security.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @PostMapping("/login")
    public LoginResponse login(@RequestBody final LoginRequest loginRequest) {
        return userService.login(loginRequest);
    }

    @PostMapping("/refresh-token")
    public RefreshTokenResponse refreshToken(@RequestBody final RefreshTokenRequest tokenRequest) {
        return userService.updateRefreshToken(tokenRequest);
    }
}
