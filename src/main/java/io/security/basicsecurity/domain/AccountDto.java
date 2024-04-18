package io.security.basicsecurity.domain;

import io.security.basicsecurity.domain.role.RoleEnum;
import lombok.Data;


//사용자가 입력한 값을 받아오는 DTO
//엔티티와 구분해서 사용하기
@Data
public class AccountDto {

    private String username;
    private String password;
    private String email;
    private String age;
    private RoleEnum role;
}
