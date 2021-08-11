package com.haubui.sample.security;

import com.haubui.sample.client.role.domain.RoleResponse;
import com.haubui.sample.client.user.domain.UserResponse;
import com.haubui.sample.client.user.dto.UserDto;
import com.haubui.sample.client.user.service.UserClient;
import com.haubui.sample.common.exception.GeneralException;
import com.haubui.sample.common.utils.GetterUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserClient userClient;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String rawPassword = GetterUtil.getString(authentication.getCredentials());

        UserResponse user = null;
        try {
            UserDto userDto = new UserDto();
            userDto.setUsername(username);
            userDto.setPassword(rawPassword);
            user = userClient.verifyAccount(userDto);
        } catch (GeneralException e) {
            throw new BadCredentialsException(e.getMessage());
        }

        List<GrantedAuthority> authorities = new ArrayList<>();
        for (RoleResponse role : user.getRoles()) {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        }
        return new UsernamePasswordAuthenticationToken(username, rawPassword, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
