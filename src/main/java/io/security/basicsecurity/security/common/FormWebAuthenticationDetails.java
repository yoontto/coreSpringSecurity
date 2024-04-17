package io.security.basicsecurity.security.common;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;


@Getter
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    private String secretKey;

    //Authentication 객체 안에 Object 타입인 Detail을 생성해 추가해주는 작업
    public FormWebAuthenticationDetails(HttpServletRequest request) {
        //상속받은 클래스에서 기본 detail 만들어 줌
        super(request);

        //secretKey라는 파라미터 값 전달받고 detail에 넣어줌
        secretKey = request.getParameter("secret_key");

    }

}
