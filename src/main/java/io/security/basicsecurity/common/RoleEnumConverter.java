package io.security.basicsecurity.common;

import io.security.basicsecurity.domain.role.Role;
import io.security.basicsecurity.domain.role.RoleEnum;
import org.springframework.core.convert.converter.Converter;

import java.util.List;
import java.util.stream.Collector;
import java.util.stream.Collectors;

public class RoleEnumConverter implements Converter<String, RoleEnum> {

    @Override
    public RoleEnum convert(String role) {
        return RoleEnum.of(role);
    }

    public List<Role> convertRoleEnumsToRoles(List<RoleEnum> roleEnums) {
        return roleEnums.stream()
                .map(roleEnum -> {
                    Role role = new Role();
                    role.setRole(roleEnum.name());
                    return role;
                })
                .collect(Collectors.toList());
    }

}
