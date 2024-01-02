package com.studyy.jwt.config;

import com.studyy.jwt.filter.MyFilter1;
import com.studyy.jwt.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<MyFilter1> filter1() {
        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
        bean.addUrlPatterns("/*"); //모든 요청에서 필터 적용

        bean.setOrder(0); //우선 순위 / 낮은 번호가 제일 먼저 실행

        return bean;
    }

    @Bean
    public FilterRegistrationBean<MyFilter2> filter2() {
        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
        bean.addUrlPatterns("/*"); //모든 요청에서 필터 적용

        bean.setOrder(1); //우선 순위 / 낮은 번호가 제일 먼저 실행

        return bean;
    }
}
