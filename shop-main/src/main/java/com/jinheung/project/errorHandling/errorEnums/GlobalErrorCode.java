package com.jinheung.project.errorHandling.errorEnums;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Getter
public enum GlobalErrorCode implements IErrorCode {
    BAD_REQUEST("bad request", 400),
    NOT_EXISTS_ORDER_EVENT("not exists order event", 400)

    ;
    private String message;
    private int status;
    @Override
    public String getMessage() {
        // TODO Auto-generated method stub
        return this.message;
    }
    @Override
    public String getCode() {
        // TODO Auto-generated method stub
        return this.toString();
    }
    @Override
    public int getStatus() {
        // TODO Auto-generated method stub
        return this.status;
    }
}
