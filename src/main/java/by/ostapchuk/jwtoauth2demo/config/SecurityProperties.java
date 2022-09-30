package by.ostapchuk.jwtoauth2demo.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.convert.DurationUnit;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;
import java.time.Duration;

import static java.time.temporal.ChronoUnit.MINUTES;

@Validated
@ConfigurationProperties(prefix = "security")
public record SecurityProperties(
        @Positive @Min(4) @Max(31) int bcryptRounds,
        @NotNull @DurationUnit(MINUTES) Duration accessTokenDuration,
        @NotNull @DurationUnit(MINUTES) Duration refreshTokenDuration,
        @NotBlank String claim,
        @NotBlank String authorityPrefix) {

}
