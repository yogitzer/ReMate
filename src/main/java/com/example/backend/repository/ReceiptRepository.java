package com.example.backend.repository;

import com.example.backend.entity.Receipt;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ReceiptRepository extends JpaRepository<Receipt, Long> {
  Optional<Receipt> findByIdempotencyKey(String idempotencyKey);

  Optional<Receipt> findByFileHash(String fileHash);

  List<Receipt> findAllByUserId(Long userId);

  Optional<Receipt> findByIdAndUserId(Long id, Long userId);
}
