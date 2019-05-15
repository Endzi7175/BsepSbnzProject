package com.bsepsbnz.BsepSbnzProject.kontroler;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApplicationController {
    @GetMapping(value = "/books")
    public String getBooks() {
        return "books";
    }
    @GetMapping(value = "/manager")
    public String getManager(Model model) {
        return "manager";
    }
}