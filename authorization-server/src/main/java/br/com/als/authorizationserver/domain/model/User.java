package br.com.als.authorizationserver.domain.model;

import java.util.ArrayList;
import java.util.List;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class User {

	private Long id;
	private String name;
	private String email;
	private String pwd;
	private final List<Permission> permissions = new ArrayList<>();
}
