package io.security.basicsecurity;

import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .formLogin(form -> form
                        //.loginPage("/loginPage")
                        .defaultSuccessUrl("/")
                        .failureUrl("/login")
                        .usernameParameter("userId")
                        .passwordParameter("passwd")
                        .loginProcessingUrl("/login_proc")
                        .successHandler((request, response, authentication) -> {
                            //인증에 성공한 사용자 이름
                            System.out.println("authentication : " + authentication.getName());
                            response.sendRedirect("/");
                        })
                        .failureHandler((request, response, exception) -> {
                            System.out.println("exception : " + exception.getMessage());
                            response.sendRedirect("/loginPage");
                        })
                        .permitAll())
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
                )

                //csrf 필터는 default값이라서 따로 설정하지 않아도 작동함
                //disable 할때는 지정 필요
                //.csrf().disable()
                .csrf()
        ;
        return http.getOrBuild();
    }

    //UserDetailService 순환참조 에러
    //AuthenticationManagerBuilder에서 UserDetailService 참조하고 있기 때문에, 이 파일에서는 참조하면 안됨
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
