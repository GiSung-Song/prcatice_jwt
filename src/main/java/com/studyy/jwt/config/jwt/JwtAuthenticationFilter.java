package com.studyy.jwt.config.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.studyy.jwt.config.auth.PrincipalDetails;
import com.studyy.jwt.model.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.BufferedReader;
import java.io.IOException;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 필터가 있음
// login 요청 시 username, password post 전송 시
// UsernamePasswordAuthenticationFilter 동작을 함.
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청 시 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("JwtAuthenticationFilter 로그인 시도");

        // 1. username, password 받아서
        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                log.info("input : {}", input);
//            }

            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);

            log.info("user : {}", user);

            //토큰 생성
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService -> loadUserByUsername() 함수 호출 / username은 받고 password는 db에서 해결
            // authentication 에는 로그인한 정보가 들어가 있음.
            Authentication authentication = authenticationManager.authenticate(token);

            // authentication 객체가 session 영역에 저장됨. => 로그인이 되었다는 뜻.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            log.info("principalDetails : {}", principalDetails.getUser().getUsername());

            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

        log.info("========================================");

        // 2. 정상인지 로그인 시도 / authenticationManager로 로그인 시도를 하면
        // PrincipalDetailsService의 loadUserByUsername() 함수가 실행 됨.

        // 3. PrincipalDetails를 세션에 담고 (권한을 담기 위해)

        // 4. JWT 토큰을 만들어서 응답해주면 됨.
        return null;
    }
}
