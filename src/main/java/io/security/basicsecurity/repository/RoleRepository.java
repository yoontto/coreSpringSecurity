package io.security.basicsecurity.repository;

import io.security.basicsecurity.domain.account.Account;
import io.security.basicsecurity.domain.role.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {

    public Role findById(long id);
}
