package com.example.demo.controller;


import com.example.demo.entity.AppUser;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = "login")
@AllArgsConstructor
public class LoginController {

  @GetMapping
  public String login(){
    return "login";
  }

  @PostMapping
  public String login(AppUser appUser){
    return "login";
  }
}
