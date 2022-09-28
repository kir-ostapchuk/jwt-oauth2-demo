package by.ostapchuk.jwtoauth2demo.security;

import by.ostapchuk.jwtoauth2demo.config.SecurityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.stream.Collectors;

import static by.ostapchuk.jwtoauth2demo.util.Constant.SPACE;
import static java.time.temporal.ChronoUnit.MINUTES;

@Service
@RequiredArgsConstructor
public class TokenService {

    private static final String ISSUER = "self";

    private final JwtEncoder encoder;

    private final JwtDecoder decoder;

    private final UserDetailsServiceImpl service;

    private final SecurityProperties securityProperties;

    public String generateAccessToken(final String email) {
        return generateToken(email, securityProperties.accessTokenDuration());
    }

    public String generateRefreshToken(final String email) {
        return generateToken(email, securityProperties.refreshTokenDuration());
    }

    private String generateToken(final String subject, final int duration) {
        final Instant now = Instant.now();
        final String claim = service.loadUserByUsername(subject).getAuthorities().stream()
                                    .map(GrantedAuthority::getAuthority)
                                    .collect(Collectors.joining(SPACE));
        final JwtClaimsSet claims = JwtClaimsSet.builder()
                                                .issuer(ISSUER)
                                                .issuedAt(now)
                                                .expiresAt(now.plus(duration, MINUTES))
                                                .subject(subject)
                                                .claim(securityProperties.claim(), claim)
                                                .build();
        return this.encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public boolean isValid(final String token) {
        return Optional.ofNullable(decoder.decode(token)).map(Jwt::getExpiresAt)
                       .map(it -> it.isBefore(Instant.now()))
                       .orElseThrow(() -> new RuntimeException("Refresh token expired"));
    }
}
