package ao.samid.auth.service;

import ao.samid.auth.dto.request.ChangePasswordRequest;
import ao.samid.auth.dto.request.UserUpdateRequest;
import ao.samid.auth.dto.response.RoleResponse;
import ao.samid.auth.dto.response.UserResponse;
import ao.samid.auth.entity.Role;
import ao.samid.auth.entity.User;
import ao.samid.auth.handler.CustomException;
import ao.samid.auth.handler.UserNotFoundException;
import ao.samid.auth.repository.RoleRepository;
import ao.samid.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService  {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;


    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream().map(user -> UserResponse
                        .builder()
                        .id(user.getId())
                        .username(user.getUsername())
                        .email(user.getEmail())
                        .roles(user.getRoles().stream()
                                .map(role -> RoleResponse
                                        .builder()
                                        .id(role.getId())
                                        .name(role.getName()).build())
                                .collect(Collectors.toSet()))
                        .build())
                .toList();
        }

    public UserResponse getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow( UserNotFoundException::of);
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles().stream()
                        .map(role -> RoleResponse.builder()
                                .id(role.getId())
                                .name(role.getName())
                                .build())
                        .collect(Collectors.toSet()))
                .build();
    }
    //todo: implement get user by username
    public UserResponse getUserByUsername(String username) {
        User user = userRepository.findUserByUsername(username)
                .orElseThrow(UserNotFoundException::of);
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles().stream()
                        .map(role -> RoleResponse.builder()
                                .id(role.getId())
                                .name(role.getName())
                                .build())
                        .collect(Collectors.toSet()))
                .build();
    }
    public UserResponse updateUser(UserUpdateRequest request) {
        User user = userRepository.findById(request.getId())
                .orElseThrow(UserNotFoundException::of);
        user.setUsername(request.getUsername());
        if(passwordEncoder.matches(request.getOldPassword(), user.getPassword())){
            user.setPassword(request.getPassword());
            user.setEnabled(true);
            user.setEmail(request.getEmail());
            Role role = roleRepository.findById(request.getRoleId()).orElseThrow(()->CustomException.builder()
                    .message("Role not found")
                    .code(404)
                    .build());
            user.getRoles().add(role);
            userRepository.save(user);
        } else {
            throw CustomException.builder()
                    .message("Password is incorrect")
                    .code(400)
                    .build();
        }
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles().stream()
                        .map(role -> RoleResponse.builder()
                                .id(role.getId())
                                .name(role.getName())
                                .build())
                        .collect(Collectors.toSet()))
                .build();
    }
    public void changePassword(ChangePasswordRequest request) {
        User user = userRepository.findById(request.getUserId())
                .orElseThrow(UserNotFoundException::of);
        if (passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            userRepository.save(user);
        } else {
            throw CustomException.builder()
                    .message("Old password is incorrect")
                    .code(400)
                    .build();
        }
    }
    //todo: implement delete user
    public void deleteUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(UserNotFoundException::of);
        userRepository.delete(user);
    }
}


