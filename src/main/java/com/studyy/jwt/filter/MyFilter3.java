package com.studyy.jwt.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        log.info("필터3");

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // 토큰 : cos 토큰을 만들어줘야 함. ID, PW 값이 정삭적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답해줌.
        // 요청할 때 마다 header에 Authorization에 value 값으로 토큰을 가지고 옴
        // 그 때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 됨.(RSA, HS256)
        if (req.getMethod().equalsIgnoreCase("post")) {
            log.info("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            log.info("headerAuth : {}", headerAuth);

            if (headerAuth.equals("cos")) {
                chain.doFilter(req, res);
            } else {
                PrintWriter writer = res.getWriter();
                writer.println("인증안됨");
            }
        }
    }
}
