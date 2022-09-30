package by.ostapchuk.jwtoauth2demo.security;

import by.ostapchuk.jwtoauth2demo.dto.LoginRequest;
import by.ostapchuk.jwtoauth2demo.dto.LoginResponse;
import by.ostapchuk.jwtoauth2demo.dto.RefreshTokenRequest;
import by.ostapchuk.jwtoauth2demo.dto.RefreshTokenResponse;
import by.ostapchuk.jwtoauth2demo.entity.User;
import by.ostapchuk.jwtoauth2demo.exception.JwtTokenException;
import by.ostapchuk.jwtoauth2demo.exception.ResourceNotFoundException;
import by.ostapchuk.jwtoauth2demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final TokenService tokenService;

    public LoginResponse login(final LoginRequest loginRequest) {
        final User user = validateEmailAndPassword(loginRequest);
        final String accessToken = tokenService.generateAccessToken(loginRequest.email());
        final String refreshToken = tokenService.generateRefreshToken(loginRequest.email());
        user.setRefreshToken(refreshToken);
        userRepository.save(user);
        return new LoginResponse(accessToken, refreshToken, loginRequest.email());
    }

    public RefreshTokenResponse updateRefreshToken(final RefreshTokenRequest tokenRequest) {
        final User user = userRepository.findByRefreshToken(tokenRequest.token())
                                        .filter(u -> tokenService.isValid(u.getRefreshToken()))
                                        .orElseThrow(() -> new JwtTokenException("Token invalid"));
        final String accessToken = tokenService.generateAccessToken(user.getEmail());
        final String refreshToken = tokenService.generateRefreshToken(user.getEmail());
        user.setRefreshToken(refreshToken);
        userRepository.save(user);
        return new RefreshTokenResponse(accessToken, refreshToken);
    }

    private User validateEmailAndPassword(final LoginRequest loginRequest) {
        return userRepository.findByEmail(loginRequest.email())
                             .filter(u -> passwordEncoder.matches(loginRequest.password(), u.getPassword()))
                             .orElseThrow(() -> new ResourceNotFoundException("Credentials are invalid"));
    }
}
