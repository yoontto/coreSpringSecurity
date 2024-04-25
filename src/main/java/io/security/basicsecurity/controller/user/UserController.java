package io.security.basicsecurity.controller.user;

import io.security.basicsecurity.common.RoleEnumConverter;
import io.security.basicsecurity.domain.account.Account;
import io.security.basicsecurity.domain.account.AccountDto;
import io.security.basicsecurity.domain.role.Role;
import io.security.basicsecurity.domain.role.RoleEnum;
import io.security.basicsecurity.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.List;
import java.util.stream.Stream;

@Controller
public class UserController {

    private final UserService userService;

    private final PasswordEncoder passwordEncoder;

    public UserController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/mypage")
    public String myPage() {
        return "user/mypage";
    }

    @GetMapping("/users")
    public String createUser(Model model) {
        model.addAttribute("roleList", RoleEnum.values());

        return "user/login/register";
    }

    @PostMapping("/users")
    public String createUser(AccountDto accountDto) {

        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(accountDto, Account.class);

        account.setRoles(new RoleEnumConverter().convertRoleEnumsToRoles(accountDto.getRoles()));
        account.setPassword(passwordEncoder.encode(accountDto.getPassword()));
        userService.createUser(account);

        return "redirect:/";
    }
}
