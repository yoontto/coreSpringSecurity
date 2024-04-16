package io.security.basicsecurity.security.service;

import io.security.basicsecurity.domain.Account;
import io.security.basicsecurity.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

//빈 등록하기!
@Service("CustomUserService")
public class CustomUserService implements UserDetailsService {

    private UserRepository userRepository;

    public CustomUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //유저 계정 조회
        Account account = userRepository.findByUsername(username);

        System.out.println("나 되고 있어!!!!!!");
        if (account == null) {
            throw new UsernameNotFoundException("UsernameNotFoundException :: " + username);
        }

        //조회한 유저의 권한 정보를 list로 만들어서 넣어준다.
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(account.getRole()));

        return new AccountContext(account, authorities);
    }
}
