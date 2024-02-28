package io.security.basicsecurity;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

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
                );


        return http.getOrBuild();
    }
}
