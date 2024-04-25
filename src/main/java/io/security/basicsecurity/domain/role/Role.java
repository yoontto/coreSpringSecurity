package io.security.basicsecurity.domain.role;

import io.security.basicsecurity.domain.account.Account;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import lombok.Data;

@Entity
@Data
public class Role {

    @Id
    @GeneratedValue
    private long id;

    @ManyToOne
    private Account account;

    private String role;
}
