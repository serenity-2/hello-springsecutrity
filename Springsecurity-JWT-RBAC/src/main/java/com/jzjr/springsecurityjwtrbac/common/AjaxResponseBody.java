package com.jzjr.springsecurityjwtrbac.common;

import lombok.Data;

import java.io.Serializable;

@Data
public class AjaxResponseBody implements Serializable {

    private static final long serialVersionUID = -5720919085816924836L;

    private String status;

    private String msg;

    private Object result;

    private String jwtToken;
}
