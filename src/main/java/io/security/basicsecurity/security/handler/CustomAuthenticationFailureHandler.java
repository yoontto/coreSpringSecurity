package io.security.basicsecurity.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {



    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String errMsg = "Invalid Username or Password :: Basic";

        if(exception instanceof BadCredentialsException) {
            errMsg = "Invalid Username or Password :: Bad";
        } else if (exception instanceof InsufficientAuthenticationException) {
            errMsg = "Invalid SecretKey";
        }

        setDefaultFailureUrl("/login?error=true&exception=" + errMsg);

        super.onAuthenticationFailure(request, response, exception);
    }


}
