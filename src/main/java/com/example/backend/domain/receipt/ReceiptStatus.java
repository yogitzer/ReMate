package com.example.backend.domain.receipt;

public enum ReceiptStatus {
  UPLOADED,
  ANALYZING,
  WAITING,
  NEED_MANUAL,
  APPROVED,
  REJECTED,
  FAILED_SYSTEM,
  EXPIRED
}
