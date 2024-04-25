package io.security.basicsecurity.domain.role;

public enum RoleEnum {
    ROLE_USER,
    ROLE_ADMIN;

    //변환 로직
    public static RoleEnum of(String role) {
        if (role == null) {
            throw new IllegalArgumentException("RoleEnum is null");
        }

        for(RoleEnum re : RoleEnum.values()) {
            if (re.name().equals(role)) {
                return re;
            }
        }

        throw new IllegalArgumentException("잘못된 RoleEnum 값 입니다.");

    }
}
