package io.security.basicsecurity.service.impl;

import io.security.basicsecurity.domain.account.Account;
import io.security.basicsecurity.repository.RoleRepository;
import io.security.basicsecurity.repository.UserRepository;
import io.security.basicsecurity.service.UserService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("userservice")
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public UserServiceImpl(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Transactional
    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
