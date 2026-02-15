package com.example.backend.ocr;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ReceiptParser {

  public static int extractTotalAmount(String text) {
    // 쉼표와 공백 제거
    String cleanedText = text.replace(",", "").replace(" ", "");

    // 1. 우선순위: 특정 키워드(합계 등) 바로 뒤에 오는 숫자
    Pattern p1 =
        Pattern.compile(
            "(?:합계|결제금액|승인금액|총금액|받을금액|영수금액|TOTAL|AMOUNT)[:\\s]*(\\d{3,8})",
            Pattern.CASE_INSENSITIVE);
    Matcher m1 = p1.matcher(cleanedText);

    int maxAmount = 0;
    while (m1.find()) {
      int current = Integer.parseInt(m1.group(1));
      if (current > maxAmount) maxAmount = current;
    }

    // 2. 키워드로 못 찾았을 때만 실행: 1,000원 ~ 500,000원 사이의 숫자 중 '원'이 붙어있거나 가장 그럴싸한 값
    if (maxAmount == 0) {
      // 사업자번호(10자리)나 전화번호처럼 너무 긴 숫자는 제외하기 위해 {3,7}로 제한
      Pattern p2 = Pattern.compile("(\\d{3,7})(?:원|\\b)");
      Matcher m2 = p2.matcher(cleanedText);
      while (m2.find()) {
        int current = Integer.parseInt(m2.group(1));
        // 일반적인 식대/마트 범위인 1,000원 ~ 1,000,000원 사이만 후보로 채택
        if (current >= 1000 && current <= 1000000 && current > maxAmount) {
          maxAmount = current;
        }
      }
    }
    return maxAmount;
  }

  public static String extractTradeDate(String text) {
    Pattern p =
        Pattern.compile(
            "(20\\d{2})[\\./\\-\\s](0[1-9]|1[0-2])[\\./\\-\\s](0[1-9]|[12][0-9]|3[01])");
    Matcher m = p.matcher(text);
    if (m.find()) return String.format("%s-%s-%s", m.group(1), m.group(2), m.group(3));
    return "";
  }

  public static String extractStoreName(String text) {
    String[] lines = text.split("\n");
    for (int i = 0; i < Math.min(lines.length, 10); i++) {
      String line = lines[i].trim();
      // 숫자, 특수문자, 제외키워드 포함 시 패스
      if (line.length() < 2 || line.matches("^[0-9\\-\\s/\\.:]+$")) continue;
      if (line.matches(".*(고객용|영수증|매출|전표|카드|번호|전화|주소|가맹|신고|포상금|금융|협회|Smartro|결제|승인|사업자).*"))
        continue;

      // 상호명에 포함된 불필요한 숫자/기호 제거 (예: 23 군자농협 -> 군자농협)
      return line.replaceAll("^[0-9\\s]+", "") // 앞쪽 숫자 제거
          .replace("상호:", "")
          .replace("상호", "")
          .trim();
    }
    return "알 수 없는 상호";
  }
}
