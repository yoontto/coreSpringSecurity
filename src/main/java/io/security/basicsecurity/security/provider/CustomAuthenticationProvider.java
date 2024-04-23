package io.security.basicsecurity.security.provider;

import io.security.basicsecurity.security.common.FormWebAuthenticationDetails;
import io.security.basicsecurity.security.service.AccountContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

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
        
        //파라미터로 넣어준 secretKey 없으면 인증 불가
        FormWebAuthenticationDetails formDetails = (FormWebAuthenticationDetails) authentication.getDetails();
        String secretKey = formDetails.getSecretKey();
        if(secretKey == null || !"secret".equals(secretKey)) {
            throw new InsufficientAuthenticationException("InsufficientAuthenticationException!!");
        }

        //3. 가져온 UserDetails 타입 정보로 UsernamePasswordAuthenticationToken 만들기(권한 주기)
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                = new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());

        //4. 토큰 반환
        return usernamePasswordAuthenticationToken;
    }

    // 객체 타입 점검
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
