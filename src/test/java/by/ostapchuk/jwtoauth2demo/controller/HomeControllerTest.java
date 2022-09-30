package by.ostapchuk.jwtoauth2demo.controller;

import by.ostapchuk.jwtoauth2demo.config.SecurityConfig;
import by.ostapchuk.jwtoauth2demo.dto.LoginRequest;
import by.ostapchuk.jwtoauth2demo.dto.LoginResponse;
import by.ostapchuk.jwtoauth2demo.entity.Role;
import by.ostapchuk.jwtoauth2demo.entity.User;
import by.ostapchuk.jwtoauth2demo.repository.UserRepository;
import by.ostapchuk.jwtoauth2demo.security.TokenService;
import by.ostapchuk.jwtoauth2demo.security.UserDetailsServiceImpl;
import by.ostapchuk.jwtoauth2demo.security.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Optional;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = {AuthController.class, HomeController.class})
@Import({SecurityConfig.class, TokenService.class, UserDetailsServiceImpl.class, UserService.class})
@ActiveProfiles("test")
class HomeControllerTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockBean
    private UserRepository userRepository;

    @Test
    void rootWhenUnauthenticatedThen401() throws Exception {
        this.mvc.perform(get("/secure"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rootWhenAuthenticatedThenSaysHelloUser() throws Exception {
        User user =
                User.builder().id(1L).email("email").password(passwordEncoder.encode("password"))
                    .role(Role.ADMIN).build();
        Mockito.when(userRepository.findByEmail("email")).thenReturn(Optional.of(user));
        LoginRequest body = new LoginRequest("email", "password");
        MvcResult result = this.mvc.perform(post("/auth/login").content(asJsonString(body)).with(csrf()).contentType(
                                       MediaType.APPLICATION_JSON))
                                   .andExpect(status().isOk())
                                   .andReturn();

        LoginResponse response = asObject(result.getResponse().getContentAsString());

        this.mvc.perform(get("/")
                                 .header("Authorization", "Bearer " + response.accessToken()))
                .andExpect(content().string("Hello, email"));

        this.mvc.perform(get("/secure-admin")
                                 .header("Authorization", "Bearer " + response.accessToken()))
                .andExpect(content().string("This is for ADMINs only!"));

        this.mvc.perform(get("/secure-user")
                                 .header("Authorization", "Bearer " + response.accessToken()))
                .andExpect(status().isForbidden());
        this.mvc.perform(get("/secure-user")
                                 .header("Authorization", "Bearer " + "someTrashToken"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser
    void rootWithMockUserStatusIsOK() throws Exception {
        this.mvc.perform(get("/")).andExpect(status().isOk());
    }

    @SneakyThrows
    private String asJsonString(final Object obj) {
        return objectMapper.writeValueAsString(obj);
    }

    @SneakyThrows
    private LoginResponse asObject(final String json) {
        return objectMapper.readValue(json, LoginResponse.class);
    }

}
