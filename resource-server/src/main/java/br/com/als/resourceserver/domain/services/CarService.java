package br.com.als.resourceserver.domain.services;

import java.util.Arrays;
import java.util.List;

import org.springframework.stereotype.Service;

import br.com.als.resourceserver.domain.model.Car;

@Service
public class CarService {

	public List<Car> getCars(){
		Car car1 = Car.builder()
				.name("Honda")
				.year("2022")
				.color("Vermelho")
				.build();
		Car car2 = Car.builder()
				.name("Hyundai")
				.year("2020")
				.color("Preto")
				.build();
		Car car3 = Car.builder()
				.name("Fiat")
				.year("2019")
				.color("Cinza")
				.build();
		
		return Arrays.asList(car1,car2,car3);
	}
}
