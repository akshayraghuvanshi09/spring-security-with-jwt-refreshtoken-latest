package com.springsecuritywithdb.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.springsecuritywithdb.dto.AuthRequest;
import com.springsecuritywithdb.dto.JwtResponse;
import com.springsecuritywithdb.dto.Product;
import com.springsecuritywithdb.entity.RefreshToken;
import com.springsecuritywithdb.entity.UserInfo;
import com.springsecuritywithdb.service.JwtService;
import com.springsecuritywithdb.service.ProductService;
import com.springsecuritywithdb.service.RefreshTokenService;

@RestController
@RequestMapping("/product-service")
public class ProductController {

	@Autowired
	private RefreshTokenService refreshTokenService;

	@Autowired
	private ProductService service;

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
			RefreshToken refreshToken = refreshTokenService.createRefreshToken(authRequest.getUsername());

			return JwtResponse.builder().
					accessToken(jwtService.generateToken(authRequest.getUsername()))
					.token(refreshToken.getToken()).build();
		} else {
			throw new UsernameNotFoundException("invalid user request !");
		}

	}
	@PostMapping("/refreshToken")
	public JwtResponse refreshToken(@RequestBody RefreshToken refreshToken){
	return	refreshTokenService.findByToken(refreshToken.getToken())
		.map(refreshTokenService::verifyExpiration)
		.map(RefreshToken::getUserInfo)
		.map(userInfo->{
			String accesToken = jwtService.generateToken(userInfo.getName());
			return JwtResponse.builder()
					.accessToken(accesToken)
					.token(refreshToken.getToken())
					.build();
		}).orElseThrow(() -> new RuntimeException("Refresh token is not in the database !"));
	}

}
