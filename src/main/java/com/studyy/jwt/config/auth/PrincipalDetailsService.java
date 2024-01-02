package com.studyy.jwt.config.auth;

import com.studyy.jwt.Repository.UserRepository;
import com.studyy.jwt.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * http://localhost:8080/login -> 여기서 동작을 안함.
 */

@Slf4j
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        log.info("PrincipalDetailsService -> loadUserByUsername 요청");

        User userEntity = userRepository.findByUsername(username);
        return new PrincipalDetails(userEntity);
    }
}
