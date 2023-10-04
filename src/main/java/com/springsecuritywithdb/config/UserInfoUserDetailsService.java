package com.springsecuritywithdb.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.springsecuritywithdb.AppContext;
import com.springsecuritywithdb.AppContext.Key;
import com.springsecuritywithdb.entity.UserInfo;
import com.springsecuritywithdb.repository.UserInfoRepository;

import java.util.Optional;

@Component
public class UserInfoUserDetailsService implements UserDetailsService {

    @Autowired
    private UserInfoRepository repository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<UserInfo> userInfo = repository.findByName(username);
		userInfo.ifPresent(t -> {
			AppContext.set(Key.USER_ID, String.valueOf(t.getId()));
			AppContext.set(Key.USER_EMAIL, t.getEmail());		
		});
			return userInfo.map(UserInfoUserDetails::new)
					.orElseThrow(() -> new UsernameNotFoundException("user not found " + username));
		}
}
