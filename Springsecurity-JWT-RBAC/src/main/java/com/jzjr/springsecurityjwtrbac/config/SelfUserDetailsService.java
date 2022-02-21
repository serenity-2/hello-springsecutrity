package com.jzjr.springsecurityjwtrbac.config;

import com.jzjr.springsecurityjwtrbac.model.SelfUserDetails;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class SelfUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SelfUserDetails userInfo = new SelfUserDetails();
        userInfo.setUsername(username);
        userInfo.setPassword(new BCryptPasswordEncoder().encode("123"));
        Set authoritiesSet = new HashSet<>();
        SimpleGrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
        authoritiesSet.add(grantedAuthority);
        userInfo.setAuthorities(authoritiesSet);
        return userInfo;
    }
}
