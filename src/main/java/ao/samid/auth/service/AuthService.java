package ao.samid.auth.service;

import ao.samid.auth.dto.request.UserLoginRequest;
import ao.samid.auth.dto.request.UserRegisterRequest;
import ao.samid.auth.dto.response.LoginResponse;
import ao.samid.auth.entity.Role;
import ao.samid.auth.entity.User;
import ao.samid.auth.handler.CustomException;
import ao.samid.auth.repository.RoleRepository;
import ao.samid.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;


@Service
@RequiredArgsConstructor
public class AuthService {
    private final JwtTokenService jwtTokenService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    public void register(UserRegisterRequest request){
        if(!request.getPassword().equals(request.getConfirmPassword())){
            throw CustomException
                    .builder()
                    .message("Passwords do not match")
                    .code(400)
                    .build();
        }
        if(userRepository.existsByUsername(request.getUsername())){
            throw CustomException
                    .builder()
                    .message("User with this username already exists")
                    .code(400)
                    .build();
        }
        if(userRepository.existsByEmail(request.getEmail())){
            throw CustomException
                    .builder()
                    .message("User with this email already exists")
                    .code(400)
                    .build();
        }
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        Role role = roleRepository.findByName("USER")
                .orElseThrow(() -> CustomException
                        .builder()
                        .message("Role not found")
                        .code(404)
                        .build());

        userRepository.save(
                User.builder()
                        .username(request.getUsername())
                        .email(request.getEmail())
                        .password(encodedPassword)
                        .enabled(true)
                        .roles(Set.of(role))
                        .build()
        );
    }
    public LoginResponse login(UserLoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> CustomException
                        .builder()
                        .message("Invalid credentials")
                        .code(404)
                        .build());
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw CustomException
                    .builder()
                    .message("Invalid credentials")
                    .code(401)
                    .build();
        }
        return LoginResponse.builder()
                .accessToken(jwtTokenService.generateAccessToken(user))
                .refreshToken(jwtTokenService.generateRefreshToken(user))
                .build();
    }
    public void logout() {
        // Implement logout logic if needed
        SecurityContextHolder.clearContext();
    }
    public LoginResponse refreshAccessToken(String refreshToken) {
        String username = jwtTokenService.getUsernameFromRefreshToken(refreshToken);
        if (!jwtTokenService.isValidRefreshToken(refreshToken)) {
            throw CustomException
                    .builder()
                    .message("Refresh token is expired")
                    .code(401)
                    .build();
        }
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> CustomException
                        .builder()
                        .message("User not found")
                        .code(404)
                        .build());

        return LoginResponse.builder()
                .accessToken(jwtTokenService.generateAccessToken(user))
                .refreshToken(refreshToken)
                .build();
    }

    public void checkAccessToken(String access) {

        String username = jwtTokenService.getUsernameFromAccessToken(access);
        if (!jwtTokenService.isValidAccessToken(access)) {
            throw CustomException
                    .builder()
                    .message("Access token is expired")
                    .code(401)
                    .build();
        }
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> CustomException
                        .builder()
                        .message("User not found")
                        .code(404)
                        .build());

    }
    public void isEditableUser(String token) {
        if (!jwtTokenService.isValidAccessToken(token)) {
            throw CustomException
                    .builder()
                    .message("Access token is expired")
                    .code(401)
                    .build();
        }

        String username = jwtTokenService.getUsernameFromAccessToken(token);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> CustomException
                        .builder()
                        .message("User not found")
                        .code(404)
                        .build());

        boolean hasPermission = user.getRoles().stream()
                .map(Role::getName) // Burada artıq name sahəsi alınır
                .anyMatch(role -> role.equalsIgnoreCase("ADMIN") || role.equalsIgnoreCase("EDITOR"));

        if (!hasPermission) {
            throw CustomException
                    .builder()
                    .message("Access denied. Only ADMIN or EDITOR roles allowed.")
                    .code(403)
                    .build();
        }
    }
}
