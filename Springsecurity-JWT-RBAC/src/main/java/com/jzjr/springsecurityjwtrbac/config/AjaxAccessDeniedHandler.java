package com.jzjr.springsecurityjwtrbac.config;

import com.alibaba.fastjson.JSON;
import com.jzjr.springsecurityjwtrbac.common.AjaxResponseBody;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * spring security的统一异常处理类
 */
@Component
public class AjaxAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        AjaxResponseBody responseBody = new AjaxResponseBody();
        responseBody.setStatus("300");
        responseBody.setMsg("Need Authorities");
        response.getWriter().write(JSON.toJSONString(response));
    }
}
