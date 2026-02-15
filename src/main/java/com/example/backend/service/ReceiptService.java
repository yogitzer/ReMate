package com.example.backend.service;

import com.example.backend.domain.receipt.ReceiptStatus;
import com.example.backend.entity.Receipt;
import com.example.backend.ocr.GoogleOcrClient;
import com.example.backend.ocr.ReceiptParser;
import com.example.backend.repository.ReceiptRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
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
                              log.error("OCR 분석 중 에러: ", e);
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

    String storeName = ReceiptParser.extractStoreName(fullText);
    int totalAmount = ReceiptParser.extractTotalAmount(fullText);
    String tradeDate = ReceiptParser.extractTradeDate(fullText);

    Receipt receipt =
        Receipt.builder()
            .idempotencyKey(key)
            .fileHash(fileHash)
            .workspaceId(workspaceId)
            .userId(userId)
            .status(ReceiptStatus.ANALYZING)
            .storeName(storeName)
            .totalAmount(totalAmount)
            .tradeDate(tradeDate)
            .rawText(ocrJson.toString())
            .filePath(filePath)
            .build();

    return receiptRepository.save(receipt);
  }

  private String saveFileToLocal(MultipartFile file) {
    try {
      String uploadDir = "C:/receipt_uploads/";
      File dir = new File(uploadDir);
      if (!dir.exists()) dir.mkdirs();

      String originalFilename = file.getOriginalFilename();
      String extension = "";
      if (originalFilename != null && originalFilename.contains(".")) {
        extension = originalFilename.substring(originalFilename.lastIndexOf("."));
      }

      String savedFileName = UUID.randomUUID().toString() + extension;
      Path targetPath = Paths.get(uploadDir + savedFileName);
      Files.copy(file.getInputStream(), targetPath);

      return savedFileName;
    } catch (IOException e) {
      log.error("파일 저장 실패: ", e);
      throw new RuntimeException("FILE_SAVE_FAILED");
    }
  }

  private void validateFile(MultipartFile file) {
    String contentType = file.getContentType();
    if (contentType == null
        || (!contentType.equals("image/jpeg")
            && !contentType.equals("image/png")
            && !contentType.equals("application/pdf"))) {
      throw new RuntimeException("FILE_TYPE_NOT_ALLOWED");
    }
  }

  public List<Receipt> getAllReceipts() {
    return receiptRepository.findAll();
  }

  public byte[] generateCsv(List<Receipt> receipts) {
    StringBuilder csv = new StringBuilder();
    csv.append('\ufeff');
    csv.append("번호,상호명,날짜,금액\n");

    for (Receipt r : receipts) {
      csv.append(r.getId())
          .append(",")
          .append(r.getStoreName())
          .append(",")
          .append(r.getTradeDate())
          .append(",")
          .append(r.getTotalAmount())
          .append("\n");
    }
    return csv.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
  }

  @Transactional
  public Receipt updateStatus(Long id, ReceiptStatus status) {
    Receipt receipt =
        receiptRepository.findById(id).orElseThrow(() -> new RuntimeException("RECEIPT_NOT_FOUND"));
    receipt.updateStatus(status);
    return receipt;
  }

  @Transactional
  public Receipt updateReceipt(Long id, Integer totalAmount, String storeName, String tradeDate) {
    Receipt receipt =
        receiptRepository.findById(id).orElseThrow(() -> new RuntimeException("RECEIPT_NOT_FOUND"));
    receipt.updateInfo(totalAmount, storeName, tradeDate);
    return receipt;
  }

  @Transactional
  public List<Receipt> uploadMultiple(List<MultipartFile> files, Long workspaceId, Long userId) {
    return files.stream()
        .map(
            file -> {
              try {
                String tempKey = "multi-" + UUID.randomUUID();
                return uploadAndProcess(tempKey, file, workspaceId, userId);
              } catch (Exception e) {
                log.error("파일 업로드 중 개별 실패: {}", file.getOriginalFilename(), e);
                return null;
              }
            })
        .filter(Objects::nonNull)
        .collect(Collectors.toList());
  }
}
