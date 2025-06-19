package ao.samid.auth.controller;

import ao.samid.auth.dto.request.UserLoginRequest;
import ao.samid.auth.dto.request.UserRegisterRequest;
import ao.samid.auth.dto.response.LoginResponse;
import ao.samid.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestBody UserRegisterRequest request) {
        authService.register(request);
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .build();
    }
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody UserLoginRequest request) {
        return ResponseEntity.
                status(HttpStatus.OK)
                .body(authService.login(request));
    }
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@RequestHeader("refresh-token") String refreshToken) {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(authService.refreshAccessToken(refreshToken));
    }

    @PostMapping("/access")
    public ResponseEntity<LoginResponse> access(@RequestHeader("access-token") String access) {
        authService.checkAccessToken(access);
        return ResponseEntity
                .status(HttpStatus.OK).build();
    }
    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        authService.logout();
        return ResponseEntity
                .status(HttpStatus.OK)
                .build();
    }
    @PostMapping("/check-permission")
    public ResponseEntity<Void> editableUser(@RequestHeader("access-token") String token) {
        authService.isEditableUser(token);
        return ResponseEntity
                .status(HttpStatus.OK)
                .build();
    }

}
