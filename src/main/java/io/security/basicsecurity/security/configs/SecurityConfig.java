package io.security.basicsecurity.security.configs;

import io.security.basicsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.basicsecurity.security.provider.CustomAuthenticationProvider;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    //Authentication 객체에 detail값 넣어주기 위해 설정해야 해줘야 함
    private final AuthenticationDetailsSource authenticationDetailsSource;

    //savedRequest 사욯하는 인증 성공 핸들러
    private final AuthenticationSuccessHandler customAuthenticationSuccessHandler;
    
    //인증 실패 핸들러
    private final AuthenticationFailureHandler customAuthenticationFailureHandler;


    public SecurityConfig(AuthenticationDetailsSource authenticationDetailsSource, AuthenticationSuccessHandler customAuthenticationSuccessHandler, AuthenticationFailureHandler customAuthenticationFailureHandler) {
        this.authenticationDetailsSource = authenticationDetailsSource;
        this.customAuthenticationSuccessHandler = customAuthenticationSuccessHandler;
        this.customAuthenticationFailureHandler = customAuthenticationFailureHandler;
    }



    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //커스텀한 provider 자동으로 처리되도록 Bean등록
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    //커스텀한 인가 예외처리 핸들러 Bean등록
    @Bean
    public AccessDeniedHandler customAccessDeniedHandler(){
        CustomAccessDeniedHandler customAccessDeniedHandler = new CustomAccessDeniedHandler();
        customAccessDeniedHandler.setErrorPage("/denied");
        return customAccessDeniedHandler;
    }


    //정적 파일 무시하는 방법
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // ThreadLocal별로 SecurityContext 관리 어떻게 할지 정하기
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

        http
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/")
                        .loginProcessingUrl("/login_proc")
                        .failureUrl("/login")
                        .permitAll()
                        //Authentication 객체에 detail값 넣어주기 위해 설정해야 해줘야 함
                        .authenticationDetailsSource(authenticationDetailsSource)
                        //커스텀 인증 성공 핸들러
                        .successHandler(customAuthenticationSuccessHandler)
                        //커스텀 인증 실패 핸들러
                        .failureHandler(customAuthenticationFailureHandler)
                )
                .exceptionHandling(exception -> exception
                        //커스텀한 인가 예외처리 핸들러 지정
                        .accessDeniedHandler(customAccessDeniedHandler())
                )
/*
                .sessionManagement(session -> session       //동시 세션 제어 기능
                        .maximumSessions(1)                 //최대 세션 허용개수, -1이면 무제한
                        .maxSessionsPreventsLogin(true)     //true : 나중 사용자 로그인 막기, false : 처음 사용자 세션 종료
                        .expiredUrl("/login")               //세션이 만료된 경우 이동할 페이지
                )
                .sessionManagement((session) -> session     //세션 고정 공격으로부터 보호
                        .sessionFixation().changeSessionId()//새로 인증할 때마다 세션 아이디 변경

                        // 중요 :: 세션 생성 규칙 설정
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)       //필요시 생성(기본값)
                        /*
                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)            //항상 세션 생성
                        .sessionCreationPolicy(SessionCreationPolicy.NEVER)             //생성하지는 않지만, 이미 존재하면 사용
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)         //  생성하지도 않고, 존재해도 사용안함
                                                                                        //   JWT 인증 방식 사용시 statless로 설정

                )*/

                // 운영 서비스 할 때 적합한 방식은 아님
                // 즉각적이고 동적 권한 관리는 따로 지정해 줘야 함
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/user").hasRole("USER")
                        .requestMatchers("/admin/pay").hasRole("ADMIN")                     //상세 권한 허가 문구가 더 위쪽에 위치해야 함
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SYS")     // 더 포괄적인 url이 더 아래쪽으로 위치
                        // 예외처리 예제 확인할 때, 인증 안된 사용자 redirect 할 수 있도록 permitAll 처리함
                        .requestMatchers("/login", "/logout").permitAll()
                        .requestMatchers("/", "/users", "/denied").permitAll()
                )
                
        ;
        return http.getOrBuild();
    }



}
