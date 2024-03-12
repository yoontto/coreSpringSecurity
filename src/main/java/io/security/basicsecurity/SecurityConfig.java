package io.security.basicsecurity;

import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    @Order(0)
    public SecurityFilterChain adminSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // 스프링 시큐리티 6버전으로 넘어오면서 url 매칭은 securityMatcher으로 실행해야 함!
                .securityMatcher("/admin/**")
                .authorizeHttpRequests(req -> req
                        .anyRequest().hasRole("ADMIN"))
                .httpBasic(basic -> basic.init(http));

        return http.getOrBuild();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain userSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(req -> req
                        .anyRequest().permitAll())
                .formLogin();

        return http.getOrBuild();
    }

    @Primary
    @Bean
    public AuthenticationManagerBuilder configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        //임시 inMemory 테스트 유저 추가
        auth.inMemoryAuthentication()
                .withUser("user").password(passwordEncoder().encode("1111")).roles("USER")
                .and()
                .withUser("sys").password(passwordEncoder().encode("1111")).roles("SYS")
                .and()
                .withUser("admin").password(passwordEncoder().encode("1111")).roles("ADMIN", "SYS", "USER");

        return auth;
    }

}
