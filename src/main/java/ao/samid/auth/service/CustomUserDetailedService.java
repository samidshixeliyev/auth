package ao.samid.auth.service;

import ao.samid.auth.entity.User;
import ao.samid.auth.handler.UserNotFoundException;
import ao.samid.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public  class CustomUserDetailedService implements UserDetailsService {
    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findUserByUsername(username)
                .orElseThrow(UserNotFoundException::of);
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())  //bular hamisi spring security-in contextine gore lazimdir
                .password(user.getPassword())  // case gore username email ile evezlene biler
                .authorities(user.getAuthorities())  //user yetkilerin contexte gonderirik
                .accountExpired(!user.isEnabled())
                .accountLocked(!user.isEnabled())
                .credentialsExpired(!user.isEnabled())
                .disabled(!user.isEnabled())
                .build();

    }
}
