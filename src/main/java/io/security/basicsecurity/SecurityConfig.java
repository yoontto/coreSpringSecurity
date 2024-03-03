package io.security.basicsecurity;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(req -> req.anyRequest().authenticated())
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
                .rememberMe(rememberMe -> rememberMe
                        .alwaysRemember(false)              //서버 기동할때마다 항상 기능을 활성화 할 것인지?
                        .rememberMeParameter("remember")    //기본 파라미터는 remember-me
                        .tokenValiditySeconds(3600)         //default는 14일
                        .userDetailsService(userDetailsService))//필수로 설정!!
                                                                // rememberMe 기능을 수행할 때, 사용자 계정을 조회할 때 쓰는 서비스

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



        ;


        return http.getOrBuild();
    }
}
