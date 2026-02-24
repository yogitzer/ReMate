package com.example.backend.controller;

import com.example.backend.audit.AuditLog;
import com.example.backend.audit.AuditLogService;
import com.example.backend.domain.receipt.ReceiptStatus;
import com.example.backend.dto.ReceiptSummaryDto;
import com.example.backend.entity.Receipt;
import com.example.backend.service.ReceiptService;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@Slf4j
@RestController
@RequestMapping("/api/receipts")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class ReceiptController {

  private final ReceiptService receiptService;
  private final AuditLogService auditLogService;

  @GetMapping
  public ResponseEntity<List<ReceiptSummaryDto>> getAllReceipts(
      @RequestParam Long workspaceId,
      @RequestParam Long userId,
      @RequestParam(defaultValue = "false") boolean isAdmin) {
    return ResponseEntity.ok(receiptService.getWorkspaceReceipts(workspaceId, userId, isAdmin));
  }

  @GetMapping("/export")
  public ResponseEntity<byte[]> exportToCsv(
      @RequestParam Long workspaceId,
      @RequestParam Long userId,
      @RequestParam(defaultValue = "false") boolean isAdmin) {
    try {
      List<ReceiptSummaryDto> dtos =
          receiptService.getWorkspaceReceipts(workspaceId, userId, isAdmin);
      byte[] out = receiptService.generateCsvFromDto(dtos);
      return ResponseEntity.ok()
          .header(HttpHeaders.CONTENT_TYPE, "text/csv; charset=UTF-8")
          .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=receipt_list.csv")
          .body(out);
    } catch (Exception e) {
      log.error("CSV 생성 실패", e);
      return ResponseEntity.internalServerError().build();
    }
  }

  @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  public ResponseEntity<?> upload(
      @RequestHeader(value = "X-IDEMPOTENCY-KEY", required = false) String idempotencyKey,
      @RequestPart("file") MultipartFile file,
      @RequestParam("workspaceId") Long workspaceId,
      @RequestParam("userId") Long userId) {

    if (file == null || file.isEmpty()) return ResponseEntity.badRequest().body("파일이 없습니다.");

    String key =
        (idempotencyKey == null || idempotencyKey.isBlank())
            ? "auto-" + UUID.randomUUID()
            : idempotencyKey;

    try {
      Receipt receipt = receiptService.uploadAndProcess(key, file, workspaceId, userId);
      return ResponseEntity.ok(receipt);
    } catch (Exception e) {
      log.error("업로드 실패", e);
      return ResponseEntity.internalServerError().body(e.getMessage());
    }
  }

  @PatchMapping("/{id}/status")
  public ResponseEntity<Receipt> updateStatus(
      @PathVariable Long id,
      @RequestParam Long workspaceId,
      @RequestParam Long userId,
      @RequestParam(defaultValue = "false") boolean isAdmin,
      @RequestParam ReceiptStatus status,
      @RequestParam(required = false, defaultValue = "관리자 요청") String reason) {
    return ResponseEntity.ok(
        receiptService.updateStatus(id, workspaceId, userId, status, reason, isAdmin));
  }

  @PutMapping("/{id}")
  public ResponseEntity<Receipt> updateReceipt(
      @PathVariable Long id,
      @RequestParam Long workspaceId,
      @RequestParam Long userId,
      @RequestParam(defaultValue = "false") boolean isAdmin,
      @RequestBody Map<String, Object> payload) {

    String storeName =
        payload.get("storeName") != null ? String.valueOf(payload.get("storeName")) : null;

    Integer totalAmount = null;
    Object amountObj = payload.get("totalAmount");
    if (amountObj instanceof Number n) {
      totalAmount = n.intValue();
    } else if (amountObj != null) {
      try {
        totalAmount = Integer.parseInt(String.valueOf(amountObj));
      } catch (Exception ignored) {
      }
    }

    LocalDateTime tradeAt = null;
    Object tradeAtObj = payload.get("tradeAt");
    if (tradeAtObj != null && !String.valueOf(tradeAtObj).isBlank()) {
      try {
        tradeAt =
            LocalDateTime.parse(
                String.valueOf(tradeAtObj),
                java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
      } catch (Exception e) {
        log.warn("날짜 파싱 실패: {}, 현재 시간으로 대체합니다.", tradeAtObj);
        tradeAt = LocalDateTime.now();
      }
    } else {
      tradeAt = LocalDateTime.now();
    }

    return ResponseEntity.ok(
        receiptService.updateReceipt(
            id, workspaceId, userId, totalAmount, storeName, tradeAt, isAdmin));
  }

  @PostMapping(value = "/upload/multiple", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  public ResponseEntity<List<Receipt>> uploadMultiple(
      @RequestPart("files") List<MultipartFile> files,
      @RequestParam("workspaceId") Long workspaceId,
      @RequestParam("userId") Long userId) {
    if (files == null || files.isEmpty()) return ResponseEntity.badRequest().build();
    List<Receipt> results = receiptService.uploadMultiple(files, workspaceId, userId);
    return ResponseEntity.ok(results);
  }

  @GetMapping("/{id}/history")
  public ResponseEntity<List<AuditLog>> getHistory(@PathVariable Long id) {
    try {
      List<AuditLog> logs = auditLogService.findAllByReceiptId(id);
      return ResponseEntity.ok(logs);
    } catch (Exception e) {
      log.error("이력 조회 실패 - receiptId: {}", id, e);
      return ResponseEntity.internalServerError().build();
    }
  }

  @GetMapping("/stats")
  public ResponseEntity<java.util.Map<String, Object>> getStats(@RequestParam Long workspaceId) {
    return ResponseEntity.ok(receiptService.getAdminStats(workspaceId));
  }

  @PostMapping("/{id}/resubmit")
  public ResponseEntity<Receipt> resubmit(
      @PathVariable Long id, @RequestParam Long workspaceId, @RequestParam Long userId) {
    log.info("영수증 재제출 요청 - receiptId: {}, userId: {}", id, userId);
    return ResponseEntity.ok(receiptService.resubmitReceipt(id, workspaceId, userId));
  }
}
