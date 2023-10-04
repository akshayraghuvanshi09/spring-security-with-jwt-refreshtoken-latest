package com.springsecuritywithdb.filter;


import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.springsecuritywithdb.AppContext;
import com.springsecuritywithdb.AppContext.Key;
import com.springsecuritywithdb.config.UserInfoUserDetailsService;
import com.springsecuritywithdb.service.JwtService;
import com.springsecuritywithdb.service.UserSessionService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserInfoUserDetailsService userDetailsService;
    private @Autowired UserSessionService userSessionService;
    
    
    
    private List<String> whiteListUrl =List.of("/product-service/authenticate");
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
    	System.out.println(request.getRequestURI());    	
		return whiteListUrl.contains(request.getRequestURI());
	}
    
    

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;
        String sessionID = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            username = jwtService.extractUsername(token);
             sessionID = jwtService.extractSessionId(token);
             AppContext.set(Key.SESSION_ID, sessionID);
        }
        

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            if (jwtService.validateToken(token, userDetails) && userSessionService.validateSession(sessionID)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
