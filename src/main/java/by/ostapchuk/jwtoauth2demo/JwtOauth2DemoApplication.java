package by.ostapchuk.jwtoauth2demo;

import by.ostapchuk.jwtoauth2demo.config.RsaKeyProperties;
import by.ostapchuk.jwtoauth2demo.config.SecurityProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

// TODO: 9/27/22 fix response for 401 and 403 errors
// TODO: 9/29/22 configure cors more strictly
// TODO: 9/29/22 add validation for properties classes
// TODO: 9/29/22 think about issuer in token (probably change to actual url)
// TODO: 9/29/22 change runtime exception to custom ones

@EnableConfigurationProperties({RsaKeyProperties.class, SecurityProperties.class})
@SpringBootApplication
public class JwtOauth2DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtOauth2DemoApplication.class, args);
    }

}
