package vn.sugu.hb3_java.exception;

import lombok.Getter;

@Getter
public class AppExcepsion extends RuntimeException {

    private ErrorCode errorCode;

    public AppExcepsion(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }

}
