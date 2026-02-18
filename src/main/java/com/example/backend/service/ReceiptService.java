package com.example.backend.service;

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
                            try {
                              String savedFileName = saveFileToLocal(file);
                              JsonNode ocrJson = googleOcrClient.recognize(fileBytes);
                              return parseAndSave(
                                  idempotencyKey,
                                  fileHash,
                                  ocrJson,
                                  workspaceId,
                                  userId,
                                  savedFileName);
                            } catch (Exception e) {
                              log.error("OCR 분석 에러", e);
                              return saveFailedReceipt(
                                  idempotencyKey, fileHash, workspaceId, userId, null, e);
                            }
                          }));
    } catch (Exception e) {
      throw new RuntimeException("FILE_PROCESSING_FAILED", e);
    }
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

    receipt.updateStatus(status, reason);
    auditLogService.logStatusChange(id, userId, oldStatus, status, reason);

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
      auditLogService.logStatusChange(id, userId, oldStatus, receipt.getStatus(), "정보 수정 및 승인 처리");
    }

    return receipt;
  }

  @Transactional
  public Receipt resubmitReceipt(Long id, Long workspaceId, Long userId) {

    Receipt receipt = getReceiptSecurely(id, workspaceId, userId, false);

    ReceiptStatus oldStatus = receipt.getStatus();

    receipt.resubmit();

    auditLogService.logStatusChange(id, userId, oldStatus, receipt.getStatus(), "사용자 재제출");

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

  private Receipt parseAndSave(
      String key,
      String fileHash,
      JsonNode ocrJson,
      Long workspaceId,
      Long userId,
      String filePath) {
    JsonNode textAnnotations = ocrJson.path("responses").get(0).path("textAnnotations");
    String fullText =
        textAnnotations.isMissingNode() ? "" : textAnnotations.get(0).path("description").asText();

    JsonNode aiResult = geminiService.getParsedReceipt(fullText);

    String storeName = aiResult.path("storeName").asText("알 수 없는 상호");
    int totalAmount = aiResult.path("totalAmount").asInt(0);
    String tradeAtStr = aiResult.path("tradeAt").asText();

    ReceiptStatus finalStatus =
        (aiResult.has("storeName") && !storeName.equals("알 수 없는 상호"))
            ? ReceiptStatus.WAITING
            : ReceiptStatus.NEED_MANUAL;

    LocalDateTime tradeAt;
    try {
      tradeAt = LocalDateTime.parse(tradeAtStr, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    } catch (Exception e) {
      tradeAt = LocalDateTime.now();
    }

    Receipt tempReceiptForTagging = Receipt.builder().tradeAt(tradeAt).build();
    List<String> derivedTags = tagService.deriveTags(tempReceiptForTagging);

    return receiptRepository.save(
        Receipt.builder()
            .idempotencyKey(key)
            .fileHash(fileHash)
            .workspaceId(workspaceId)
            .userId(userId)
            .status(finalStatus)
            .storeName(storeName)
            .totalAmount(totalAmount)
            .tradeAt(tradeAt)
            .nightTime(derivedTags.contains("🌙 야간"))
            .tags(derivedTags)
            .rawText(fullText)
            .filePath(filePath)
            .build());
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
