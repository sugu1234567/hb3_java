package vn.sugu.hb3_java.exception;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.experimental.FieldDefaults;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

@Getter
@FieldDefaults(level = AccessLevel.PRIVATE)

public enum ErrorCode {
    UNCATEGORIZED_EXCEPTION(500, "Uncategorized error", HttpStatus.INTERNAL_SERVER_ERROR),
    INVALID_KEY(400, "Uncategorized error", HttpStatus.BAD_REQUEST),
    USER_EXISTED(400, "User existed", HttpStatus.BAD_REQUEST),
    USERNAME_INVALID(400, "Username must be at least 3 characters", HttpStatus.BAD_REQUEST),
    INVALID_PASSWORD(400, "Password must be at least 8 characters", HttpStatus.BAD_REQUEST),
    LOGIN_INVALID(400, "Username or Password is incorrect", HttpStatus.BAD_REQUEST),
    LOGIN_VALID(400, "Username or Password cannot be blank", HttpStatus.BAD_REQUEST),
    PASSWORD_INVALID(400, "Password old password is incorrect", HttpStatus.BAD_REQUEST),
    USER_NOT_EXISTED(404, "User not existed", HttpStatus.NOT_FOUND),
    ROLE_NOT_EXISTED(404, "Role not existed", HttpStatus.NOT_FOUND),
    UNAUTHENTICATED(401, "Unauthenticated", HttpStatus.UNAUTHORIZED),
    UNAUTHORIZED(403, "You do not have permission", HttpStatus.FORBIDDEN),
    ACCESS_DENIED(403, "You do not have permission", HttpStatus.FORBIDDEN),
    REFRESH_TOKEN_INVALID(400, "refresh token is not valid", HttpStatus.BAD_REQUEST),
    TOKEN_INVALID(400, "token is not valid", HttpStatus.BAD_REQUEST),
    TOKEN_EXPIRATION(400, "token is expired", HttpStatus.BAD_REQUEST),
    MISSING_COOKIE(400, "Required cookie is missing", HttpStatus.BAD_REQUEST);

    ErrorCode(int code, String message, HttpStatusCode statusCode) {
        this.code = code;
        this.message = message;
        this.statusCode = statusCode;
    }

    int code;
    String message;
    HttpStatusCode statusCode;
}
