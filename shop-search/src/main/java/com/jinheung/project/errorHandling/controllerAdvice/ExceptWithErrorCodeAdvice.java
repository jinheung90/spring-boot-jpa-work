package com.jinheung.project.errorHandling.controllerAdvice;

import com.jinheung.project.errorHandling.ErrorResponse;
import com.jinheung.project.errorHandling.customRuntimeException.RuntimeExceptionWithCode;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Objects;

@RestControllerAdvice
public class ExceptWithErrorCodeAdvice {

    // 내 커스텀 용 에러 핸들러
    @ExceptionHandler(RuntimeExceptionWithCode.class)
    public ResponseEntity<HashMap<String, String>> all(final RuntimeExceptionWithCode e) {
        return ErrorResponse.response(e.getCode().getCode(), e.getMessage(), HttpStatus.resolve(e.getCode().getStatus()));
    }


    // request 잘못 됬을 때
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Object handleMethodArgumentNotValidException(MethodArgumentNotValidException e) {
        String errorMessage = e.getBindingResult()
                .getAllErrors()
                .get(0)
                .getDefaultMessage();

        return new ResponseEntity<>(new HashMap<String, Object>() {{
            put("message", "no validations");
            put("error position", Objects.requireNonNull(e.getFieldError()).getField());
            put("CODE",  "G001");
        }}, HttpStatus.BAD_REQUEST);
    }



    @ExceptionHandler(NumberFormatException.class)
    public Object handleNumFormatException(NumberFormatException e) {
        String errorMessage = e.getLocalizedMessage();

        return new ResponseEntity<>(new HashMap<String, Object>() {{
            put("message", "no validations");
            put("detail", errorMessage);
            put("CODE",  "G001");
        }}, HttpStatus.BAD_REQUEST);
    }

}
