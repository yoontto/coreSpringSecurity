package io.security.basicsecurity.domain.account;

import io.security.basicsecurity.domain.role.Role;
import jakarta.persistence.*;
import lombok.Data;

import java.util.List;


//데이터베이스에 저장할 때 쓰는 엔티티로 DTO와는 구분해서 사용해야 함
@Entity
@Data
public class Account {

    @Id
    @GeneratedValue
    private long id;
    private String username;
    private String password;
    private String email;
    private String age;

    @OneToMany(cascade = CascadeType.PERSIST)
    @JoinColumn(name = "account_id")
    private List<Role> roles;

}
