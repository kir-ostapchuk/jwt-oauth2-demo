package by.ostapchuk.jwtoauth2demo.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Validated
@ConfigurationProperties(prefix = "rsa")
public record RsaKeyProperties(
        @NotNull RSAPublicKey publicKey,
        @NotNull RSAPrivateKey privateKey) {

}
