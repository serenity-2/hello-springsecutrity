package com.jzjr.springsecurityjwtrbac.config;

import com.alibaba.fastjson.JSON;
import com.jzjr.springsecurityjwtrbac.common.AjaxResponseBody;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 认证失败处理类 返回未授权
 */
@Component
public class AjaxAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        AjaxResponseBody responseBody = new AjaxResponseBody();
        responseBody.setStatus("000");
        responseBody.setMsg("Need Authorities");
        response.getWriter().write(JSON.toJSONString(response));
    }
}
