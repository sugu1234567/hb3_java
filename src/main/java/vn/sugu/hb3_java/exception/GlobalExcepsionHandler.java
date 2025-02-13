package vn.sugu.hb3_java.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestCookieException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import vn.sugu.hb3_java.dto.response.APIResponse;

@ControllerAdvice
public class GlobalExcepsionHandler {
    @ExceptionHandler(value = Exception.class)
    public ResponseEntity<APIResponse<String>> handlingRuntimeException(Exception exception) {
        APIResponse<String> apiResponse = new APIResponse<>();

        apiResponse.setCode(ErrorCode.UNCATEGORIZED_EXCEPTION.getCode());
        apiResponse.setMessage(exception.getMessage());

        return ResponseEntity.badRequest().body(apiResponse);
    }

    @ExceptionHandler(value = AppExcepsion.class)
    ResponseEntity<APIResponse> handlingAppException(AppExcepsion exception) {
        ErrorCode errorCode = exception.getErrorCode();

        APIResponse apiResponse = new APIResponse();

        apiResponse.setCode(errorCode.getCode());
        apiResponse.setMessage(errorCode.getMessage());

        return ResponseEntity.badRequest().body(apiResponse);
    }

    @ExceptionHandler(value = MethodArgumentNotValidException.class)
    ResponseEntity<APIResponse> handlingMethodArgumentNotValidException(MethodArgumentNotValidException exception) {
        String enumkey = exception.getFieldError().getDefaultMessage();
        ErrorCode errorCode = ErrorCode.valueOf(enumkey);

        APIResponse apiResponse = new APIResponse();

        apiResponse.setCode(errorCode.getCode());
        apiResponse.setMessage(errorCode.getMessage());

        return ResponseEntity.badRequest().body(apiResponse);
    }

    @ExceptionHandler(value = MissingRequestCookieException.class)
    public ResponseEntity<APIResponse> handlingMissingRequestCookieException(MissingRequestCookieException exception) {
        ErrorCode errorCode = ErrorCode.MISSING_COOKIE;

        APIResponse apiResponse = new APIResponse();
        apiResponse.setCode(errorCode.getCode());
        apiResponse.setMessage(errorCode.getMessage() + ": " + exception.getCookieName());

        return ResponseEntity.badRequest().body(apiResponse);
    }

}
