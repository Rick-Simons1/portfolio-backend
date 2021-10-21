package com.clone.instagram.authservice.payload;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class VerifyCaptchaRequest {

    @NotBlank
    private String captchaResponse;
}
