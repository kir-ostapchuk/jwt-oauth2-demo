package by.ostapchuk.jwtoauth2demo.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

// TODO: 9/27/22 add validation

@ConfigurationProperties(prefix = "security")
public record SecurityProperties(int bcryptRounds, int accessTokenDuration, int refreshTokenDuration, String claim,
                                 String authorityPrefix) {

}
