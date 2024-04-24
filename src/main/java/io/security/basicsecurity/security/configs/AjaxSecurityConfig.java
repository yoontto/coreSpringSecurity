package io.security.basicsecurity.security.configs;

import io.security.basicsecurity.security.filter.AjaxAuthenticationProcessingFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
//@EnableWebSecurity
@RequiredArgsConstructor
@Order(0)
public class AjaxSecurityConfig {

    //Manager 만들기 위해 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(req -> req
                        .requestMatchers("/api/**")
                        .authenticated()
                )
                //Ajax 필터를 Form인증 필터보다 우선으로 두기
                .addFilterBefore(ajaxAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.getOrBuild();
    }

    //Ajax 프로세싱 filter 등록하기 위해서 manager 설정해줌
    //강의는 구버전이라 override 가능했는데, 신버전부터는 bean 등록 직접 해줘야 함
    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AjaxAuthenticationProcessingFilter ajaxAuthenticationProcessingFilter() throws Exception {
        AjaxAuthenticationProcessingFilter ajaxAuthenticationProcessingFilter = new AjaxAuthenticationProcessingFilter();
        ajaxAuthenticationProcessingFilter.setAuthenticationManager(authenticationManager());
        return ajaxAuthenticationProcessingFilter;
    }

}
