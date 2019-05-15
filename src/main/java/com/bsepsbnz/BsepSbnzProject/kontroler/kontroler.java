package com.bsepsbnz.BsepSbnzProject.kontroler;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "api/pricelist")
public class kontroler {
	@RequestMapping("/asd")
	public String getA(){
		return "asd";
	}
}
