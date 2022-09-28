package br.com.als.resourceserver.domain.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Car {

	private String name;
	private String year;
	private String color;
}
