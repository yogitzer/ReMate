package com.example.backend.service;

import com.example.backend.audit.AuditAction;
import com.example.backend.audit.AuditLogService;
import com.example.backend.domain.receipt.ReceiptStatus;
import com.example.backend.domain.receipt.SystemErrorCode;
import com.example.backend.dto.ReceiptSummaryDto;
import com.example.backend.entity.Receipt;
import com.example.backend.ocr.GeminiService;
import com.example.backend.ocr.GoogleOcrClient;
import com.example.backend.repository.ReceiptRepository;
import com.example.backend.repository.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Slf4j
@Service
@RequiredArgsConstructor
public class ReceiptService {

  private final ReceiptRepository receiptRepository;
  private final UserRepository userRepository;
  private final GoogleOcrClient googleOcrClient;
  private final GeminiService geminiService;
  private final AuditLogService auditLogService;
  private final TagService tagService;

  private final String uploadDir =
      System.getProperty("user.home") + File.separator + "remate_uploads" + File.separator;

  @Transactional
  public Receipt uploadAndProcess(
      String idempotencyKey, MultipartFile file, Long workspaceId, Long userId) {
    validateFile(file);
    try {
      byte[] fileBytes = file.getBytes();
      byte[] hashBytes = MessageDigest.getInstance("MD5").digest(fileBytes);
      String fileHash = HexFormat.of().formatHex(hashBytes);

      return receiptRepository
          .findByFileHash(fileHash)
          .orElseGet(
              () ->
                  receiptRepository
                      .findByIdempotencyKey(idempotencyKey)
                      .orElseGet(
                          () -> {
                            String savedFileName = null;
                            Receipt receipt = null;
                            try {
                              savedFileName = saveFileToLocal(file);
                              receipt =
                                  receiptRepository.save(
                                      Receipt.builder()
                                          .idempotencyKey(idempotencyKey)
                                          .fileHash(fileHash)
                                          .workspaceId(workspaceId)
                                          .userId(userId)
                                          .status(ReceiptStatus.ANALYZING)
                                          .filePath(savedFileName)
                                          .build());
                              log.info(
                                  "=== [검증 1] DB 선저장 완료: ID={}, Status={}",
                                  receipt.getId(),
                                  receipt.getStatus());
                              JsonNode ocrJson = googleOcrClient.recognize(fileBytes);
                              log.info("=== [검증 2] OCR 분석 시작 (ID: {})", receipt.getId());
                              return processOcrResult(receipt, ocrJson);
                            } catch (Exception e) {
                              log.error("OCR 분석 에러", e);
                              if (receipt != null) return markAsFailed(receipt, e);
                              return saveFailedReceipt(
                                  idempotencyKey, fileHash, workspaceId, userId, savedFileName, e);
                            }
                          }));
    } catch (Exception e) {
      throw new RuntimeException("FILE_PROCESSING_FAILED", e);
    }
  }

  private Receipt processOcrResult(Receipt receipt, JsonNode ocrJson) {
    JsonNode textAnnotations = ocrJson.path("responses").get(0).path("textAnnotations");
    String fullText =
        textAnnotations.isMissingNode() ? "" : textAnnotations.get(0).path("description").asText();

    JsonNode aiResult = geminiService.getParsedReceipt(fullText);

    String storeName = aiResult.path("storeName").asText("알 수 없는 상호");
    int totalAmount = aiResult.path("totalAmount").asInt(0);
    String tradeAtStr = aiResult.path("tradeAt").asText();

    ReceiptStatus nextStatus =
        (aiResult.has("storeName") && !storeName.equals("알 수 없는 상호"))
            ? ReceiptStatus.WAITING
            : ReceiptStatus.NEED_MANUAL;

    LocalDateTime tradeAt;
    try {
      tradeAt = LocalDateTime.parse(tradeAtStr, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    } catch (Exception e) {
      tradeAt = LocalDateTime.now();
    }

    List<String> derivedTags = tagService.deriveTags(Receipt.builder().tradeAt(tradeAt).build());

    receipt.updateAfterAnalysis(
        storeName,
        totalAmount,
        tradeAt,
        fullText,
        nextStatus,
        derivedTags,
        derivedTags.contains("🌙 야간"));

    return receipt;
  }

  private Receipt markAsFailed(Receipt receipt, Exception e) {
    SystemErrorCode errorCode = SystemErrorCode.UNKNOWN_ERROR;
    if (e instanceof IOException) errorCode = SystemErrorCode.OCR_CONNECTION_FAILURE;
    else if (e.getMessage() != null && e.getMessage().contains("parse"))
      errorCode = SystemErrorCode.AI_PARSING_ERROR;
    receipt.markAsFailed(errorCode);
    return receipt;
  }

  public Receipt getReceiptSecurely(Long id, Long workspaceId, Long userId, boolean isAdmin) {
    Receipt receipt =
        receiptRepository
            .findByIdAndWorkspaceId(id, workspaceId)
            .orElseThrow(() -> new RuntimeException("RECEIPT_NOT_FOUND"));
    if (!isAdmin && !receipt.getUserId().equals(userId)) {
      throw new RuntimeException("ACCESS_DENIED");
    }
    return receipt;
  }

  @Transactional
  public Receipt updateStatus(
      Long id,
      Long workspaceId,
      Long userId,
      ReceiptStatus status,
      String reason,
      boolean isAdmin) {
    Receipt receipt = getReceiptSecurely(id, workspaceId, userId, isAdmin);
    ReceiptStatus oldStatus = receipt.getStatus();
    receipt.updateStatus(status, reason, userId);

    AuditAction action =
        (status == ReceiptStatus.APPROVED)
            ? AuditAction.APPROVE
            : (status == ReceiptStatus.REJECTED) ? AuditAction.REJECT : AuditAction.ANALYZE;
    auditLogService.record(
        action,
        "MEMBER",
        String.valueOf(userId),
        null,
        id,
        Map.of(
            "oldStatus",
            oldStatus.name(),
            "newStatus",
            status.name(),
            "reason",
            reason != null ? reason : ""));

    return receipt;
  }

  @Transactional
  public Receipt updateReceipt(
      Long id,
      Long workspaceId,
      Long userId,
      Integer totalAmount,
      String storeName,
      LocalDateTime tradeAt,
      boolean isAdmin) {
    Receipt receipt = getReceiptSecurely(id, workspaceId, userId, isAdmin);
    ReceiptStatus oldStatus = receipt.getStatus();
    receipt.updateInfo(totalAmount, storeName, tradeAt);
    List<String> updatedTags = tagService.deriveTags(receipt);
    receipt.updateTags(updatedTags);

    if (oldStatus != receipt.getStatus()) {
      auditLogService.record(
          AuditAction.ANALYZE,
          "MEMBER",
          String.valueOf(userId),
          null,
          id,
          Map.of("oldStatus", oldStatus.name(), "newStatus", receipt.getStatus().name()));
    }
    return receipt;
  }

  @Transactional
  public Receipt resubmitReceipt(Long id, Long workspaceId, Long userId) {
    Receipt receipt = getReceiptSecurely(id, workspaceId, userId, false);
    ReceiptStatus oldStatus = receipt.getStatus();
    receipt.resubmit();
    auditLogService.record(
        AuditAction.RESUBMIT,
        "MEMBER",
        String.valueOf(userId),
        null,
        id,
        Map.of("oldStatus", oldStatus.name(), "newStatus", receipt.getStatus().name()));
    return receipt;
  }

  @Transactional(readOnly = true)
  public List<ReceiptSummaryDto> getWorkspaceReceipts(
      Long workspaceId, Long currentUserId, boolean isAdmin) {
    List<Receipt> receipts = receiptRepository.findAllByWorkspaceId(workspaceId);
    return receipts.stream()
        .map(
            r -> {
              String ownerName =
                  userRepository.findById(r.getUserId()).map(u -> u.getName()).orElse("알 수 없음");
              if (isAdmin || r.getUserId().equals(currentUserId)) {
                return new ReceiptSummaryDto(
                    r.getId(),
                    r.getStoreName(),
                    r.getTotalAmount(),
                    r.getTradeAt(),
                    r.getStatus(),
                    ownerName,
                    r.getTags());
              }
              return new ReceiptSummaryDto(
                  r.getId(), r.getStoreName(), 0, r.getTradeAt(), r.getStatus(), ownerName, null);
            })
        .collect(Collectors.toList());
  }

  private String saveFileToLocal(MultipartFile file) {
    try {
      File dir = new File(uploadDir);
      if (!dir.exists() && !dir.mkdirs()) throw new IOException("디렉토리 생성 실패");
      String originalFilename = file.getOriginalFilename();
      String extension =
          (originalFilename != null && originalFilename.contains("."))
              ? originalFilename.substring(originalFilename.lastIndexOf("."))
              : "";
      String savedFileName = UUID.randomUUID() + extension;
      Files.copy(file.getInputStream(), Paths.get(uploadDir).resolve(savedFileName));
      return savedFileName;
    } catch (IOException e) {
      throw new RuntimeException("FILE_SAVE_FAILED");
    }
  }

  private void validateFile(MultipartFile file) {
    String contentType = file.getContentType();
    if (contentType == null
        || !(contentType.equals("image/jpeg") || contentType.equals("image/png"))) {
      throw new RuntimeException("FILE_TYPE_NOT_ALLOWED");
    }
    try {
      byte[] header = new byte[8];
      if (file.getInputStream().read(header) < 4) throw new RuntimeException("FILE_TOO_SMALL");
      if (isJpeg(header) || isPng(header)) return;
      throw new RuntimeException("FILE_TYPE_NOT_ALLOWED");
    } catch (IOException e) {
      throw new RuntimeException("FILE_UPLOAD_FAILED");
    }
  }

  private boolean isJpeg(byte[] h) {
    return (h[0] & 0xFF) == 0xFF && (h[1] & 0xFF) == 0xD8 && (h[2] & 0xFF) == 0xFF;
  }

  private boolean isPng(byte[] h) {
    return (h[0] & 0xFF) == 0x89
        && (h[1] & 0xFF) == 0x50
        && (h[2] & 0xFF) == 0x4E
        && (h[3] & 0xFF) == 0x47;
  }

  public byte[] generateCsvFromDto(List<ReceiptSummaryDto> receipts) {
    StringBuilder csv = new StringBuilder();
    csv.append('\ufeff').append("번호,상호명,날짜,금액\n");
    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    for (ReceiptSummaryDto r : receipts) {
      csv.append(r.getId())
          .append(",")
          .append(r.getStoreName())
          .append(",")
          .append(r.getTradeAt() != null ? r.getTradeAt().format(formatter) : "")
          .append(",")
          .append(r.getTotalAmount())
          .append("\n");
    }
    return csv.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
  }

  @Transactional
  public List<Receipt> uploadMultiple(List<MultipartFile> files, Long workspaceId, Long userId) {
    return files.stream()
        .map(
            file -> {
              try {
                return uploadAndProcess("multi-" + UUID.randomUUID(), file, workspaceId, userId);
              } catch (Exception e) {
                return null;
              }
            })
        .filter(Objects::nonNull)
        .collect(Collectors.toList());
  }

  private Receipt saveFailedReceipt(
      String key, String hash, Long workspaceId, Long userId, String path, Exception e) {
    SystemErrorCode errorCode = SystemErrorCode.UNKNOWN_ERROR;
    if (e instanceof IOException) errorCode = SystemErrorCode.OCR_CONNECTION_FAILURE;
    else if (e.getMessage() != null && e.getMessage().contains("parse"))
      errorCode = SystemErrorCode.AI_PARSING_ERROR;
    return receiptRepository.save(
        Receipt.builder()
            .idempotencyKey(key)
            .fileHash(hash)
            .workspaceId(workspaceId)
            .userId(userId)
            .status(ReceiptStatus.FAILED_SYSTEM)
            .systemErrorCode(errorCode)
            .filePath(path)
            .build());
  }

  public java.util.Map<String, Object> getAdminStats(Long workspaceId) {
    return receiptRepository.getWorkspaceStats(workspaceId);
  }
}
