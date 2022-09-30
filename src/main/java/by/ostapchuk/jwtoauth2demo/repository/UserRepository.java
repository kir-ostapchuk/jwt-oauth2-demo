package by.ostapchuk.jwtoauth2demo.repository;

import by.ostapchuk.jwtoauth2demo.entity.User;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface UserRepository extends CrudRepository<User, Long> {

    Optional<User> findByEmail(String email);

    Optional<User> findByRefreshToken(String refreshToken);
}
