package by.ostapchuk.jwtoauth2demo;

import by.ostapchuk.jwtoauth2demo.config.RsaKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(RsaKeyProperties.class)
@SpringBootApplication
public class JwtOauth2DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtOauth2DemoApplication.class, args);
    }

}