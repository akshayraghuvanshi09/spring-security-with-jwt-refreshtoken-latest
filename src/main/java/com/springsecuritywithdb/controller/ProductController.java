package com.springsecuritywithdb.controller;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.springsecuritywithdb.AppContext;
import com.springsecuritywithdb.AppContext.Key;
import com.springsecuritywithdb.dto.AuthRequest;
import com.springsecuritywithdb.dto.JwtResponse;
import com.springsecuritywithdb.dto.Product;
import com.springsecuritywithdb.dto.RefreshTokenRequest;
import com.springsecuritywithdb.entity.RefreshToken;
import com.springsecuritywithdb.entity.UserInfo;
import com.springsecuritywithdb.entity.UserSession;
import com.springsecuritywithdb.repository.RefreshTokenRepository;
import com.springsecuritywithdb.repository.UserInfoRepository;
import com.springsecuritywithdb.service.JwtService;
import com.springsecuritywithdb.service.ProductService;
import com.springsecuritywithdb.service.RefreshTokenService;
import com.springsecuritywithdb.service.UserSessionService;

@RestController
@RequestMapping("/product-service")
public class ProductController {
	@Autowired
	private UserSessionService userSessionService;

	@Autowired
	private UserInfoRepository userInfoRepository;

	@Autowired
	private RefreshTokenService refreshTokenService;

	@Autowired
	private ProductService service;

	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	@Autowired
	private JwtService jwtService;

	@Autowired
	private AuthenticationManager authenticationManager;

	@GetMapping("/welcome")
	public String welcome() {
		return "Welcome this endpoint is not secure";
	}

	@PostMapping("/addNewUser")
	public String addNewUser(@RequestBody UserInfo userInfo) {
		return service.addUser(userInfo);
	}

	@GetMapping("/all")
	@PreAuthorize("hasAuthority('ROLE_ADMIN')")
	public List<Product> getAllTheProducts() {
		return service.getProducts();
	}

	@GetMapping("/{id}")
	@PreAuthorize("hasRole('ROLE_USER')")
	public Product getProductById(@PathVariable int id) {
		return service.getProduct(id);
	}

	@PostMapping("/authenticate")
	public JwtResponse authenticateAndGetToken(@RequestBody AuthRequest authRequest) {
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
		if (authentication.isAuthenticated()) {
			Optional<UserInfo> findByName = userInfoRepository.findByName(authRequest.getUsername());
			RefreshToken refreshToken = findByName.get().getRefreshToken();
			if (refreshToken == null) {
				refreshToken = refreshTokenService.createRefreshToken(authRequest.getUsername());
			} else {
				refreshToken.setToken(UUID.randomUUID().toString());
				refreshToken.setExpiryDate(Instant.now().plusMillis(600000));
			}

			UserInfo userInfo = service.getUser(authRequest.getUsername());
			return JwtResponse.builder().accessToken(jwtService.generateToken(authRequest.getUsername(), userInfo, true))
					.token(refreshToken.getToken()).build();
		} else {
			throw new UsernameNotFoundException("invalid user request !");
		}

	}

	@PostMapping("/refreshToken")
	public JwtResponse refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
		System.out.println(refreshTokenRequest);
		return refreshTokenService.findByToken(refreshTokenRequest.getToken())

				.map(refreshTokenService::verifyExpiration).map(RefreshToken::getUserInfo).map(userInfo -> {
					String accessToken = jwtService.generateToken(userInfo.getName(), userInfo,false);
					return JwtResponse.builder().accessToken(accessToken).token(refreshTokenRequest.getToken()).build();
				}).orElseThrow(() -> new RuntimeException("Refresh token is not in database!"));
	}
	
	@GetMapping("/logout")
	public String logout() {
		System.out.println("Context Data = "+AppContext.getContextMap());
		SecurityContextHolder.getContext().setAuthentication(null);
		userSessionService.deleteSession(AppContext.get(Key.SESSION_ID));
		return "user logout successful";
	}

}
