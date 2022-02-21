package com.jzjr.springsecurityjwtrbac.config;

import com.alibaba.fastjson.JSON;
import com.jzjr.springsecurityjwtrbac.common.AjaxResponseBody;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 身份验证成功处理类
 */
@Component
public class AjaxAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        AjaxResponseBody responseBody = new AjaxResponseBody();
        responseBody.setStatus("200");
        responseBody.setMsg("Login Successful");
        response.getWriter().write(JSON.toJSONString(responseBody));
    }
}
