package by.ostapchuk.jwtoauth2demo.security;

import by.ostapchuk.jwtoauth2demo.dto.LoginRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtEncoder encoder;
    private final UserDetailsServiceImpl service;

    public String generateAccessToken(LoginRequest loginRequest) {
        return generateToken(loginRequest, 30);
    }

    public String generateRefreshToken(LoginRequest loginRequest) {
        return generateToken(loginRequest, 300);
    }

    private String generateToken(LoginRequest loginRequest, int expiryMinutes) {
        Instant now = Instant.now();
        String role = service.loadUserByUsername(loginRequest.email()).getAuthorities().stream()
                                     .map(GrantedAuthority::getAuthority)
                                     .collect(Collectors.joining(" "));
        JwtClaimsSet claims = JwtClaimsSet.builder()
                                          .issuer("self")
                                          .issuedAt(now)
                                          .expiresAt(now.plus(expiryMinutes, ChronoUnit.MINUTES))
                                          .subject(loginRequest.email())
                                          .claim("roles", role)
                                          .build();
        return this.encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

}
