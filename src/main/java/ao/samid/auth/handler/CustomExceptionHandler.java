package ao.samid.auth.handler;

import io.swagger.v3.oas.annotations.Hidden;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.UUID;


@RestControllerAdvice
@Hidden
public class CustomExceptionHandler extends ResponseEntityExceptionHandler {
    @ExceptionHandler(CustomException.class)
    public ResponseEntity<Object> handleCustomException(CustomException ex,HttpServletRequest request) { //HttpServletRequest request bu userin frontdan gonderdiyi requestdir
        return ResponseEntity.status(ex.getCode())
                .body(ErrorResponse.builder()
                        .code(ex.getCode())
                        .message(ex.getMessage() + " bu ise her zaman custom exceptiondir")
                        .url(request.getRequestURI())
                        .build());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleException(Exception ex,HttpServletRequest request) {
        System.out.println("Exception occurred: " + ex.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponse.builder()
                        .code(HttpStatus.INTERNAL_SERVER_ERROR.value())
                        .message(ex.getMessage() + " \n Burada yazilan umumi exception")
                        .build());
    }
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<Object> handleUserNotFoundException(UserNotFoundException ex,HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ErrorResponse.builder()
                        .code(HttpStatus.NOT_FOUND.value())
                        .message(ex.getMessage() + " \n Bura user not found  exception hissesidir")
                        .url(request.getContextPath())
                        .build());
    }

}


