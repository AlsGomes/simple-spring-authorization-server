package br.com.als.resourceserver.api.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.als.resourceserver.domain.model.Car;
import br.com.als.resourceserver.domain.services.CarService;

@RestController
@RequestMapping("cars")
public class CarController {
	
	@Autowired
	private CarService carService;
	
	@GetMapping
	@PreAuthorize("hasAuthority('ROLE_CAN_READ') and hasAuthority('SCOPE_write')")	
	public ResponseEntity<?> getCars(){
		List<Car> cars = carService.getCars();
		return ResponseEntity.ok(cars);
	}
}
