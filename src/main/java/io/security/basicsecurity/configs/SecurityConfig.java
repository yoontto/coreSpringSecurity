package io.security.basicsecurity.configs;

import jakarta.servlet.http.HttpSession;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Primary
    @Bean
    public AuthenticationManagerBuilder configureGlobal(AuthenticationManagerBuilder auth) throws Exception {

        String password = passwordEncoder().encode("1111");

        //임시 inMemory 테스트 유저 추가
        auth.inMemoryAuthentication()
                .withUser("user").password(password).roles("USER")
                .and()
                .withUser("manager").password(password).roles("MANAGER", "USER")
                .and()
                .withUser("admin").password(password).roles("ADMIN", "USER", "MANAGER");

        return auth;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        //정적 파일들 보안 필터 거치지 않게 설정
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(req -> req
                        .requestMatchers("/", "/user").permitAll()
                        .requestMatchers("/mypage").hasRole("USER")
                        .requestMatchers("/manages").hasRole("MANAGER")
                        .requestMatchers("/config").hasRole("ADMIN")
                        .anyRequest().authenticated());

        http.formLogin();

        return http.getOrBuild();
    }




}
