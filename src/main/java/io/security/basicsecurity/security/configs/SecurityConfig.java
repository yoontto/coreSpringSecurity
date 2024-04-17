package io.security.basicsecurity.security.configs;

import io.security.basicsecurity.repository.UserRepository;
import io.security.basicsecurity.security.provider.CustomAuthenticationProvider;
import io.security.basicsecurity.security.service.CustomUserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //커스텀한 provider 자동으로 처리되도록 Bean등록
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // ThreadLocal별로 SecurityContext 관리 어떻게 할지 정하기
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

        http
                .formLogin(form -> form
                        .defaultSuccessUrl("/")
                        .failureUrl("/login")
                        //.loginProcessingUrl("/login_proc")
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")       //로그아웃은 POST방식으로 진행해야 함
                        .logoutSuccessUrl("/login") //성공하면 다시 login 페이지로 넘어감
                        .deleteCookies("remember-me")            //삭제할 쿠키 명 적어주기 :: remember-me 쿠키 삭제하기
                        .addLogoutHandler((request, response, authentication) -> {
                            HttpSession session = request.getSession();
                            session.invalidate();
                        })
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.sendRedirect("/login");
                        })
                )

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
                        */
                )

                // 운영 서비스 할 때 적합한 방식은 아님
                // 즉각적이고 동적 권한 관리는 따로 지정해 줘야 함
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/user").hasRole("USER")
                        .requestMatchers("/admin/pay").hasRole("ADMIN")                     //상세 권한 허가 문구가 더 위쪽에 위치해야 함
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SYS")     // 더 포괄적인 url이 더 아래쪽으로 위치
                        // 예외처리 예제 확인할 때, 인증 안된 사용자 redirect 할 수 있도록 permitAll 처리함
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/", "/users").permitAll()
                )
        ;
        return http.getOrBuild();
    }



}
