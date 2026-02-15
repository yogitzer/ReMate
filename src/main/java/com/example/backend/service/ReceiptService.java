package com.example.backend.service;

import com.example.backend.domain.receipt.ReceiptStatus;
import com.example.backend.entity.Receipt;
import com.example.backend.ocr.GeminiService;
import com.example.backend.ocr.GoogleOcrClient;
import com.example.backend.repository.ReceiptRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
  private final GoogleOcrClient googleOcrClient;
  private final GeminiService geminiService;

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
                              throw new RuntimeException("OCR_PROCESSING_FAILED");
                            }
                          }));
    } catch (Exception e) {
      throw new RuntimeException("FILE_PROCESSING_FAILED", e);
    }
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

    boolean isNightTime = (tradeAt.getHour() >= 23 || tradeAt.getHour() < 6);

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
            .nightTime(isNightTime)
            .rawText(fullText)
            .filePath(filePath)
            .build());
  }

  private String saveFileToLocal(MultipartFile file) {
    try {
      File dir = new File(uploadDir);
      if (!dir.exists() && !dir.mkdirs()) {
        throw new IOException("디렉토리 생성 실패");
      }

      String originalFilename = file.getOriginalFilename();
      String extension =
          (originalFilename != null && originalFilename.contains("."))
              ? originalFilename.substring(originalFilename.lastIndexOf("."))
              : "";

      String savedFileName = UUID.randomUUID() + extension;
      Path targetPath = Paths.get(uploadDir).resolve(savedFileName);
      Files.copy(file.getInputStream(), targetPath);

      return savedFileName;
    } catch (IOException e) {
      throw new RuntimeException("FILE_SAVE_FAILED");
    }
  }

  private void validateFile(MultipartFile file) {
    try {
      byte[] header = new byte[8];
      if (file.getInputStream().read(header) < 4) {
        throw new RuntimeException("FILE_TOO_SMALL");
      }

      if (isJpeg(header) || isPng(header)) {
        return;
      }
      throw new RuntimeException("INVALID_FILE_SIGNATURE");
    } catch (IOException e) {
      throw new RuntimeException("FILE_READ_ERROR");
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

  public List<Receipt> getReceipts(Long userId, boolean isAdmin) {
    if (isAdmin) {
      return receiptRepository.findAll();
    }
    return receiptRepository.findAllByUserId(userId);
  }

  public Receipt getReceiptSecurely(Long id, Long userId) {
    return receiptRepository
            .findByIdAndUserId(id, userId)
            .orElseThrow(() -> new RuntimeException("RECEIPT_NOT_FOUND"));
  }

  public byte[] generateCsv(List<Receipt> receipts) {
    StringBuilder csv = new StringBuilder();
    csv.append('\ufeff');
    csv.append("번호,상호명,날짜,금액\n");
    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    for (Receipt r : receipts) {
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
  public Receipt updateStatus(Long id, Long userId, ReceiptStatus status) {
    Receipt receipt = getReceiptSecurely(id, userId);
    receipt.updateStatus(status);
    return receipt;
  }

  @Transactional
  public Receipt updateReceipt(
      Long id, Long userId, Integer totalAmount, String storeName, LocalDateTime tradeAt) {
    Receipt receipt = getReceiptSecurely(id, userId);
    receipt.updateInfo(totalAmount, storeName, tradeAt);
    return receipt;
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
}
