package com.jzjr.springsecurityjwtrbac.config;

import com.alibaba.fastjson.JSON;
import com.jzjr.springsecurityjwtrbac.common.AjaxResponseBody;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 身份验证失败处理类
 */
@Component
public class AjaxAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        AjaxResponseBody responseBody = new AjaxResponseBody();
        responseBody.setStatus("400");
        responseBody.setMsg("Login Failure");
        response.getWriter().write(JSON.toJSONString(responseBody));
    }
}
