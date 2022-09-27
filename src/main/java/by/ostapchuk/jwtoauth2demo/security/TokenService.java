package by.ostapchuk.jwtoauth2demo.security;

import by.ostapchuk.jwtoauth2demo.config.SecurityProperties;
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

import static by.ostapchuk.jwtoauth2demo.util.Constant.SPACE;

@Service
@RequiredArgsConstructor
public class TokenService {

    private static final String ISSUER = "self"; // todo: request url?

    private final JwtEncoder encoder;

    private final UserDetailsServiceImpl service;

    private final SecurityProperties securityProperties;

    public String generateAccessToken(final LoginRequest loginRequest) {
        return generateToken(loginRequest, securityProperties.accessTokenDuration());
    }

    public String generateRefreshToken(final LoginRequest loginRequest) {
        return generateToken(loginRequest, securityProperties.refreshTokenDuration());
    }

    private String generateToken(final LoginRequest loginRequest, final int duration) {
        final Instant now = Instant.now();
        final String claim = service.loadUserByUsername(loginRequest.email()).getAuthorities().stream()
                                    .map(GrantedAuthority::getAuthority)
                                    .collect(Collectors.joining(SPACE));
        final JwtClaimsSet claims = JwtClaimsSet.builder()
                                                .issuer(ISSUER)
                                                .issuedAt(now)
                                                .expiresAt(now.plus(duration, ChronoUnit.MINUTES))
                                                .subject(loginRequest.email())
                                                .claim(securityProperties.claim(), claim)
                                                .build();
        return this.encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

}
