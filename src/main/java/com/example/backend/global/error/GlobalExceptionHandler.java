package com.example.backend.global.error;

import com.example.backend.global.common.ErrorResponse;
import com.example.backend.global.filter.TraceIdFilter;
import org.slf4j.MDC;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

  // 1. [기원님 로직 통합] RuntimeException 발생 시 상세 메시지 처리
  @ExceptionHandler(RuntimeException.class)
  public ResponseEntity<ErrorResponse> handleRuntime(RuntimeException e) {
    String traceId = currentTraceId();

    // 에러 메시지에 따라 팀원의 ErrorCode 매핑
    ErrorCode code = ErrorCode.INTERNAL_ERROR;
    String message = e.getMessage();

    // 기원님의 로그인/회원가입 에러 사유 분기 로직
    if ("AUTH_EMAIL_ALREADY_EXISTS".equals(message)) {
      code = ErrorCode.CONFLICT;
      message = "이미 사용 중인 이메일입니다.";
    } else if ("AUTH_INVALID_CREDENTIAL".equals(message)) {
      code = ErrorCode.UNAUTHORIZED;
      message = "이메일 또는 비밀번호가 일치하지 않습니다.";
    }

    return ResponseEntity.status(code.status())
        .header(TraceIdFilter.TRACE_ID_HEADER, traceId)
        .body(ErrorResponse.of(code, message, traceId));
  }

  // 2. [팀원 로직] 비즈니스 예외 처리
  @ExceptionHandler(BusinessException.class)
  public ResponseEntity<ErrorResponse> handleBusiness(BusinessException e) {
    ErrorCode code = e.getErrorCode();
    String traceId = currentTraceId();

    return ResponseEntity.status(code.status())
        .header(TraceIdFilter.TRACE_ID_HEADER, traceId)
        .body(ErrorResponse.of(code, e.getMessage(), traceId));
  }

  // 3. [팀원 로직] 유효성 검사 실패 (Validation)
  @ExceptionHandler({MethodArgumentNotValidException.class, BindException.class})
  public ResponseEntity<ErrorResponse> handleValidation(Exception e) {
    String traceId = currentTraceId();
    String message = ErrorCode.VALIDATION_FAILED.defaultMessage();

    if (e instanceof BindException be) {
      message =
          be.getBindingResult().getFieldErrors().stream()
              .findFirst()
              .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
              .orElse(message);
    }

    return ResponseEntity.status(ErrorCode.VALIDATION_FAILED.status())
        .header(TraceIdFilter.TRACE_ID_HEADER, traceId)
        .body(ErrorResponse.of(ErrorCode.VALIDATION_FAILED, message, traceId));
  }

  // 4. [팀원 로직] 기타 예외들
  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ResponseEntity<ErrorResponse> handleNotReadable(HttpMessageNotReadableException e) {
    String traceId = currentTraceId();
    return ResponseEntity.status(ErrorCode.INVALID_REQUEST.status())
        .header(TraceIdFilter.TRACE_ID_HEADER, traceId)
        .body(ErrorResponse.of(ErrorCode.INVALID_REQUEST, "요청 본문 형식이 올바르지 않습니다.", traceId));
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ErrorResponse> handleAny(Exception e) {
    String traceId = currentTraceId();
    return ResponseEntity.status(ErrorCode.INTERNAL_ERROR.status())
        .header(TraceIdFilter.TRACE_ID_HEADER, traceId)
        .body(
            ErrorResponse.of(
                ErrorCode.INTERNAL_ERROR, ErrorCode.INTERNAL_ERROR.defaultMessage(), traceId));
  }

  private String currentTraceId() {
    String traceId = MDC.get(TraceIdFilter.MDC_KEY);
    return (traceId == null || traceId.isBlank()) ? "no-trace" : traceId;
  }
}
