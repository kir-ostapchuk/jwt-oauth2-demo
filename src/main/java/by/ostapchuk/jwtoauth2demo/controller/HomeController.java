package by.ostapchuk.jwtoauth2demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class HomeController {

    @GetMapping
    public String home(Principal principal) {
        return "Hello, " + principal.getName();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/secure")
    public String secure() {
        return "This is secured!";
    }
}
