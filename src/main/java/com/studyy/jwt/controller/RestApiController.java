package com.studyy.jwt.controller;

import com.studyy.jwt.Repository.UserRepository;
import com.studyy.jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final BCryptPasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    @GetMapping("/home")
    public String home() {
        return "<h1>home<h1>";
    }

    @PostMapping("/token")
    public String token() {
        return "<h1>token<h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);

        return "회원가입 완료";
    }

    //user, manager, admin 접근 가능
    @GetMapping("/api/v1/user")
    public String user() {
        return "user";
    }

    //manager, admin 접근 가능
    @GetMapping("/api/v1/manager")
    public String manager() {
        return "manager";
    }

    //admin 접근 가능
    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }
}
