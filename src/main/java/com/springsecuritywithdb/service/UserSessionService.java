package com.springsecuritywithdb.service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.springsecuritywithdb.entity.UserInfo;
import com.springsecuritywithdb.entity.UserSession;
import com.springsecuritywithdb.repository.UserSessionRepository;

@Service
public class UserSessionService {
	
	@Value("${session.max.inactivity:5}")
	private int maxInactivity;
	
	@Value("${session.max.inactivity:10}")
	private int maxValidity;
	
	private @Autowired UserSessionRepository userSessionRepository;
	
	public String saveSession(UserInfo info) {
		
		try {
			System.out.println("deleteByUserId is called..");
			userSessionRepository.deleteByUserId(info.getId());
		}catch(Exception e) {
			
		}
		UserSession session = UserSession.builder().id(UUID.randomUUID().toString()).lastAccessed(LocalDateTime.now()).loginTme(LocalDateTime.now())
				.userId(info.getId()).userName(info.getName()).build();
		return userSessionRepository.save(session).getId();
	}
	
	
	public UserSession getSession(int userId) {
		return userSessionRepository.findByUserId(userId).orElse(null);
	}
	
	public boolean validateSession(String sessionId) {
		boolean isValidated = false;
		UserSession session = userSessionRepository.findById(sessionId).orElse(null);
		if(session!=null) {
		LocalDateTime lastAccessed = session.getLastAccessed();
		LocalDateTime now = LocalDateTime.now();
		long between = ChronoUnit.MINUTES.between(lastAccessed, now);
		if(between<maxInactivity) {
			isValidated = true;
			session.setLastAccessed(now);
			userSessionRepository.save(session);
		}
		}
		return isValidated;
	}
	
	public void deleteSession(String sessionId) {
		userSessionRepository.deleteById(sessionId);		
	}

}
