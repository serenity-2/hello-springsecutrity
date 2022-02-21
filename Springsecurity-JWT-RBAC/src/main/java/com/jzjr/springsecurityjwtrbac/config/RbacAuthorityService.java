package com.jzjr.springsecurityjwtrbac.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.Set;

@Component("rbacauthorityservice")
public class RbacAuthorityService {
    public boolean hasPermission(HttpServletRequest request, Authentication authentication) {
        Object userInfo = authentication.getPrincipal();
        boolean hasPmession = false;
        if (userInfo instanceof UserDetails) {
            String username = ((UserDetails) userInfo).getUsername();
            //获取资源
            Set<String> urls = new HashSet<>();
            // 这些 url 都是要登录后才能访问，且其他的 url 都不能访问！
            urls.add("/common/**");
            Set set2 = new HashSet();
            Set set3 = new HashSet();
            AntPathMatcher antPathMatcher = new AntPathMatcher();
            for (String url : urls) {
                if (antPathMatcher.match(url,request.getRequestURI())) {
                     hasPmession = true;
                     break;
                }
            }
            return hasPmession;
        } else {
            return false;
        }
    }
}
