package ao.samid.auth.repository;

import ao.samid.auth.entity.User;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.jpa.repository.JpaRepository;


import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
   Optional<User> findUserByUsername(String username);

    boolean existsByUsername(@NotBlank String username);

    boolean existsByEmail(@NotBlank @Email String email);

    Optional<User> findByUsername(String username);
}
