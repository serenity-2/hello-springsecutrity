package com.example.springsecurityrole.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.stereotype.Component;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //使用内存中的 InMemoryUserDetailsManager
        auth.inMemoryAuthentication()
                //不使用 PasswordEncoder 密码编码器
                .passwordEncoder(NoOpPasswordEncoder.getInstance())
                //配置 admin 用户
                .withUser("admin").password("123456").roles("ADMIN")
                //配置 guest 用户
                .and().withUser("normal").password("000000").roles("NORMAL");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //配置请求地址的权限
        http.authorizeRequests()
                //所有用户可访问
                .antMatchers("/test/echo").permitAll()
                //需要admin角色
                .antMatchers("/test/admin").hasRole("ADMIN")
                //需要guest角色
                .antMatchers("/test/normal").access("hasRole('ROLE_NORMAL')")
                //任何请求访问的用户都需要认证
                .anyRequest().authenticated()
                .and()
                //设置form表单登录
                .formLogin()
                //所有用户可访问
                .permitAll()
                .and()
                .logout()
                .permitAll();
    }

}
