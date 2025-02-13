package vn.sugu.hb3_java.controller;

import java.text.ParseException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.JOSEException;

import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import vn.sugu.hb3_java.dto.response.APIResponse;
import vn.sugu.hb3_java.dto.request.AuthenticationRequest;
import vn.sugu.hb3_java.dto.request.ChangePasswordRequest;
import vn.sugu.hb3_java.dto.request.ForgotPasswordRequest;
import vn.sugu.hb3_java.dto.request.IntrospectRequest;
import vn.sugu.hb3_java.dto.request.LogoutRequest;
import vn.sugu.hb3_java.dto.request.ResetPasswordRequest;
import vn.sugu.hb3_java.dto.response.AuthenticationResponse;
import vn.sugu.hb3_java.dto.response.IntrospectResponse;
import vn.sugu.hb3_java.service.AuthenticationService;

@RestController
@RequestMapping("api/v1")
@RequiredArgsConstructor
@Validated
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)

public class AuthenticationController {
        AuthenticationService authenticationService;

        @PostMapping("/auth/login")
        public ResponseEntity<APIResponse<AuthenticationResponse>> authenticate(
                        @Valid @RequestBody AuthenticationRequest request) throws MethodArgumentNotValidException {
                var result = authenticationService.authenticate(request);
                return ResponseEntity.ok()
                                .headers(result.getHeaders())
                                .body(APIResponse.<AuthenticationResponse>builder()
                                                .result(result.getBody())
                                                .build());
        }

        @PostMapping("/auth/refresh-token")
        public ResponseEntity<APIResponse<AuthenticationResponse>> refreshToken(
                        @CookieValue(name = "refreshToken") String refreshToken) throws ParseException, JOSEException {

                var result = authenticationService.refreshToken(refreshToken);

                return ResponseEntity.ok()
                                .headers(result.getHeaders())
                                .body(APIResponse.<AuthenticationResponse>builder()
                                                .result(result.getBody().getResult())
                                                .build());
        }

        @PostMapping("/auth/logout")
        public ResponseEntity<APIResponse<Void>> logout(@RequestBody LogoutRequest request)
                        throws ParseException, JOSEException {

                authenticationService.logout(request);

                // Xóa refreshToken khỏi cookie
                ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", "")
                                .httpOnly(true)
                                .secure(true)
                                .sameSite("Strict")
                                .path("/")
                                .maxAge(0)
                                .build();

                return ResponseEntity.ok()
                                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                                .body(APIResponse.<Void>builder().build());
        }

        @PatchMapping("/password/change-password")
        APIResponse<?> changePassword(@RequestBody ChangePasswordRequest request) {
                authenticationService.changePassword(request);
                return APIResponse.<Void>builder()
                                .message("Password changed successfully")
                                .build();
        }

        @PostMapping("/password/forgot_password")
        APIResponse<Void> forgotPassword(@RequestBody ForgotPasswordRequest request) {
                authenticationService.sendResetPasswordEmail(request);
                return APIResponse.<Void>builder()
                                .message("Reset password email sent successfully")
                                .build();
        }

        // @GetMapping("/password/validate-reset-token/{token}")
        // APIResponse<Boolean> validateResetToken(@PathVariable String token) throws
        // ParseException, JOSEException {
        // boolean isValid = authenticationService.validateResetToken(token);
        // return APIResponse.<Boolean>builder()
        // .result(isValid)
        // .message(isValid ? "Token is valid" : "Token is invalid or expired")
        // .build();
        // }

        @PostMapping("/password/reset-password")
        APIResponse<Void> resetPassword(@RequestBody ResetPasswordRequest request)
                        throws ParseException, JOSEException {
                authenticationService.resetPassword(request);
                return APIResponse.<Void>builder()
                                .message("Password reset successfully")
                                .build();
        }

        @PostMapping("/auth/introspect")
        APIResponse<IntrospectResponse> authenticate(@RequestBody IntrospectRequest request)
                        throws ParseException, JOSEException {
                var result = authenticationService.introspect(request);
                return APIResponse.<IntrospectResponse>builder()
                                .result(result)
                                .build();
        }
}
