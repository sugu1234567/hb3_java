package vn.sugu.hb3_java.service;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.StringJoiner;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.var;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import vn.sugu.hb3_java.dto.request.AuthenticationRequest;
import vn.sugu.hb3_java.dto.request.ChangePasswordRequest;
import vn.sugu.hb3_java.dto.request.ForgotPasswordRequest;
import vn.sugu.hb3_java.dto.request.IntrospectRequest;
import vn.sugu.hb3_java.dto.request.LogoutRequest;
import vn.sugu.hb3_java.dto.request.ResetPasswordRequest;
import vn.sugu.hb3_java.dto.response.APIResponse;
import vn.sugu.hb3_java.dto.response.AuthenticationResponse;
import vn.sugu.hb3_java.dto.response.IntrospectResponse;
import vn.sugu.hb3_java.entity.User;
import vn.sugu.hb3_java.exception.AppExcepsion;
import vn.sugu.hb3_java.exception.ErrorCode;
import vn.sugu.hb3_java.repository.UserRepository;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class AuthenticationService {

    UserRepository userRepository;

    PasswordEncoder passwordEncoder;

    JavaMailSender mailSender;

    @NonFinal
    @Value("${jwt.signer.key}")
    protected String SIGNER_KEY;
    @NonFinal
    @Value("${jwt.valid-duration}")
    protected Long VALID_DURATION;
    @NonFinal
    @Value("${jwt.refreshable-duration}")
    protected Long REFRESHABLE_DURATION;

    public IntrospectResponse introspect(IntrospectRequest request)
            throws JOSEException, ParseException {
        var token = request.getToken();

        boolean isValid = true;
        try {
            verifyToken(token, false);

        } catch (AppExcepsion e) {
            isValid = false;
        }

        return IntrospectResponse.builder()
                .valid(isValid)
                .build();
    }

    public ResponseEntity<AuthenticationResponse> authenticate(AuthenticationRequest request) {
        var user = userRepository.findByName(request.getUsername())
                .orElseThrow(() -> new AppExcepsion(ErrorCode.USER_NOT_EXISTED));

        boolean authenticated = passwordEncoder.matches(request.getPassword(), user.getPassword());
        if (!authenticated)
            throw new AppExcepsion(ErrorCode.LOGIN_INVALID);

        var accessToken = createAccessToken(user);
        var refreshToken = createRefreshToken(user);

        user.setAccessToken(accessToken);
        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/")
                .maxAge(REFRESHABLE_DURATION)
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(AuthenticationResponse.builder()
                        .token(accessToken)
                        .authenticated(true)
                        .build());
    }

    private String createAccessToken(User user) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getName())
                .issuer("vn.hb3_java")
                .issueTime(new Date())
                .expirationTime(new Date(
                        Instant.now().plus(VALID_DURATION, ChronoUnit.SECONDS).toEpochMilli()))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", buildScope(user))
                .build();

        Payload payload = new Payload(jwtClaimsSet.toJSONObject());
        JWSObject jwsObject = new JWSObject(header, payload);

        try {
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes()));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private String createRefreshToken(User user) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getName())
                .issuer("vn.hb3_java")
                .issueTime(new Date())
                .expirationTime(new Date(
                        Instant.now().plus(REFRESHABLE_DURATION, ChronoUnit.SECONDS).toEpochMilli()))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", buildScope(user))
                .build();

        Payload payload = new Payload(jwtClaimsSet.toJSONObject());
        JWSObject jwsObject = new JWSObject(header, payload);

        try {
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes()));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public ResponseEntity<APIResponse<AuthenticationResponse>> refreshToken(
            @CookieValue(name = "refreshToken") String refreshToken) throws ParseException, JOSEException {

        var signedJWT = verifyToken(refreshToken, true);
        String name = signedJWT.getJWTClaimsSet().getSubject();

        User user = userRepository.findByName(name)
                .orElseThrow(() -> new AppExcepsion(ErrorCode.UNAUTHENTICATED));

        if (!user.getRefreshToken().equals(refreshToken)) {
            throw new AppExcepsion(ErrorCode.REFRESH_TOKEN_INVALID);
        }

        String newAccessToken = createAccessToken(user);
        String newRefreshToken = createRefreshToken(user);

        user.setAccessToken(newAccessToken);
        user.setRefreshToken(newRefreshToken);
        userRepository.save(user);

        ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", newRefreshToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/")
                .maxAge(REFRESHABLE_DURATION)
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(APIResponse.<AuthenticationResponse>builder()
                        .result(AuthenticationResponse.builder()
                                .token(newAccessToken)
                                .authenticated(true)
                                .build())
                        .build());
    }

    public void logout(LogoutRequest request) throws ParseException, JOSEException {
        var signedJWT = verifyToken(request.getToken(), false);
        String name = signedJWT.getJWTClaimsSet().getSubject();

        User user = userRepository.findByName(name)
                .orElseThrow(() -> new AppExcepsion(ErrorCode.USER_NOT_EXISTED));

        // Xóa refreshToken khỏi database
        user.setRefreshToken(null);
        userRepository.save(user);

        log.info("User {} logged out successfully", name);
    }

    private SignedJWT verifyToken(String token, boolean isRefresh) throws ParseException, JOSEException {
        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());
        SignedJWT signedJWT = SignedJWT.parse(token);

        String name = signedJWT.getJWTClaimsSet().getSubject();
        Date expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime();

        if (!signedJWT.verify(verifier)) {
            throw new AppExcepsion(ErrorCode.TOKEN_INVALID);
        }

        if (expiryTime.before(new Date())) {
            throw new AppExcepsion(ErrorCode.TOKEN_EXPIRATION);
        }

        if (isRefresh) {
            User user = userRepository.findByName(name)
                    .orElseThrow(() -> new AppExcepsion(ErrorCode.USER_NOT_EXISTED));

            if (user.getRefreshToken() == null || !user.getRefreshToken().equals(token)) {
                throw new AppExcepsion(ErrorCode.REFRESH_TOKEN_INVALID);
            }
        }

        return signedJWT;
    }

    public void changePassword(ChangePasswordRequest request) {
        String name = SecurityContextHolder.getContext().getAuthentication().getName();

        User user = userRepository.findByName(name)
                .orElseThrow(() -> new AppExcepsion(ErrorCode.USER_NOT_EXISTED));
        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {

            throw new AppExcepsion(ErrorCode.PASSWORD_INVALID);
        }
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        // Buộc người dùng phải đăng nhập lại
        user.setRefreshToken(null);
        userRepository.save(user);
    }

    public void sendResetPasswordEmail(ForgotPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new AppExcepsion(ErrorCode.USER_NOT_EXISTED));

        String token = createAccessToken(user);
        user.setResetPasswordToken(token);
        userRepository.save(user);

        String resetLink = "http://localhost:3000/reset-password?token=" + token;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(request.getEmail());
        message.setSubject("Reset Your Password");
        message.setText("Click vào link để đặt lại mật khẩu: " + resetLink);
        mailSender.send(message);
    }

    public void resetPassword(ResetPasswordRequest request) throws ParseException, JOSEException {
        String name = verifyToken(request.getToken(), false).getJWTClaimsSet().getSubject();
        User user = userRepository.findByName(name)
                .orElseThrow(() -> new AppExcepsion(ErrorCode.USER_NOT_EXISTED));

        if (!user.getResetPasswordToken().equals(request.getToken())) {
            throw new AppExcepsion(ErrorCode.TOKEN_INVALID);
        }
        // Lưu password mới
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        // Vô hiệu hóa token sau khi sử dụng
        user.setResetPasswordToken(null);

        userRepository.save(user);
    }

    private String buildScope(User user) {
        StringJoiner stringJoiner = new StringJoiner(" ");
        stringJoiner.add("ROLE_" + user.getRole().name());
        return stringJoiner.toString();
    }
}
