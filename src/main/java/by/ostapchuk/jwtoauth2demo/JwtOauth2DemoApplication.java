package by.ostapchuk.jwtoauth2demo;

import by.ostapchuk.jwtoauth2demo.config.RsaKeyProperties;
import by.ostapchuk.jwtoauth2demo.config.SecurityProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

// TODO: 9/29/22 change runtime exception to custom ones

@EnableConfigurationProperties({RsaKeyProperties.class, SecurityProperties.class})
@SpringBootApplication
public class JwtOauth2DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtOauth2DemoApplication.class, args);
    }

}
