package com.springsecuritywithdb.entity;

import java.time.LocalDate;
import java.time.LocalDateTime;

import org.hibernate.annotations.GenericGenerator;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserSession {
	@Id
	private String id;
	private Integer userId;
	private LocalDateTime loginTme;
	private LocalDateTime lastAccessed;
	private String userName;

}
