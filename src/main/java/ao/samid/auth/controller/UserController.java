package ao.samid.auth.controller;

import ao.samid.auth.dto.request.ChangePasswordRequest;
import ao.samid.auth.dto.request.UserUpdateRequest;
import ao.samid.auth.dto.response.UserResponse;
import ao.samid.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.util.List;

@RestController
@RequestMapping("/api/v1/user")
@RequiredArgsConstructor
public class UserController implements Serializable {
    private final UserService userService;

    @GetMapping("/all")
    public ResponseEntity<List<UserResponse>> getUsers() {
        return ResponseEntity.status(HttpStatus.OK).body(userService.getAllUsers());
    }
    @GetMapping("/{id}")
    public ResponseEntity<UserResponse> getUserById(@PathVariable Long id) {
        return ResponseEntity.status(HttpStatus.OK).body(userService.getUserById(id));
    }
    @PutMapping()
    public ResponseEntity<UserResponse> updateUser(UserUpdateRequest request) {
        return ResponseEntity.status(HttpStatus.OK).body(userService.updateUser(request));
    }
    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(ChangePasswordRequest request) {
        userService.changePassword(request);
        return ResponseEntity.status(HttpStatus.OK).build();
    }
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}
