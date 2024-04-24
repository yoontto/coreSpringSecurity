package io.security.basicsecurity.security.provider;

import io.security.basicsecurity.security.service.AccountContext;
import io.security.basicsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class AjaxAuthenticationProvider implements AuthenticationProvider {

    private UserDetailsService userDetailsService;

    private PasswordEncoder passwordEncoder;

    public AjaxAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        //1. authentication에서 username, password 추출
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        //2. 추출한 username으로  UserService를 이용해 DB에서 사용자 정보 가져오기
        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);

        //패스워드 틀렸을 때 예외처리!
        if(!passwordEncoder.matches(password, accountContext.getPassword())){
            throw new BadCredentialsException("BadCredentialsException :: 잘못된 패스워드 접근!!!");
        }

        //3. 가져온 UserDetails 타입 정보로 UsernamePasswordAuthenticationToken 만들기(권한 주기)
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());

        //4. 토큰 반환
        return ajaxAuthenticationToken;
    }

    // 객체 타입 점검
    @Override
    public boolean supports(Class<?> authentication) {
        return AjaxAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
