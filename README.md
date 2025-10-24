## ✅ Passkey 인증 시스템 실험 및 백엔드 구현

### 📌 개요

FIDO2 기반의 비밀번호 없는 인증 시스템인 **Passkey 인증 방식**을 실습 및 구현하였습니다. 이는 기존 반찬 프로젝트의 2차 인증 시스템을 발전시키기 위한 실험으로, 실제 서비스에는 도입하지 못했지만 **완성도 높은 백엔드 구현과 테스트 환경 구성**을 완료하였습니다.

---

### 👨‍💻 담당 역할

- **FIDO2/Passkey 인증 원리 학습** (PublicKeyCredential, Challenge-Response, Client Data 등)
- **WebAuthn 프로토콜 흐름 분석 및 백엔드 구조 설계**
- **Spring Boot 기반 Passkey 등록/인증 API 구현**
- **Base64url/JSON 처리 및 오류 디버깅**
- **Redis TTL 기반 Challenge 유효시간 관리**
- **Yubico Java 라이브러리 적용 및 테스트 코드 작성**

---

### 🛠 기술 스택

`Java 17`, `Spring Boot 3`, `Spring Security`, `Redis`, `WebAuthn`, `Yubico Java Library`, `Base64Url`, `JWT`, `Postman`

---

### 🚀 구현 내용 요약

| 기능 구분 | 설명 |
| --- | --- |
| **1. Passkey 등록** | 클라이언트에서 생성한 PublicKeyCredential을 서버에서 파싱·검증하고, 등록 정보를 DB에 저장 |
| **2. Challenge 발급** | 인증/등록 과정에서 Redis를 통해 TTL 기반 일회용 Challenge를 발급하고 검증 |
| **3. Passkey 인증** | 클라이언트 서명값(Signature)을 서버에서 공용키 기반으로 검증하여 로그인 처리 |
| **4. 보안 고려** | Challenge 재사용 방지, Base64url 인코딩/디코딩, JWT 기반 인증 토큰 발급 |
| **5. 실습 환경** | WebAuthn 데모 페이지 및 Postman 활용한 시나리오 테스트 수행 |

---

### 🔍 문제 해결 및 특이 사항

- **Base64 vs Base64url 인코딩 차이**로 인한 서명 검증 오류 발생 → Java용 Base64url 처리 방식 재구현
- **ClientDataJson의 UTF-8 Encoding 문제** 해결 → JSON 파싱 단계별 로깅 및 Yubico 라이브러리 내부 코드 분석
- **도메인 기반 인증 제약** 우회 실험 (로컬 환경에서 인증 테스트 위한 조건 세팅)

---

### 💬 회고

비밀번호 없는 인증이라는 추상적인 개념을 실제 백엔드 로직으로 구현하면서, **FIDO2의 인증 흐름, 암호화 구조, 브라우저 클라이언트 역할**까지 폭넓게 이해할 수 있었습니다. 특히 세션 기반 인증보다 **보안성과 사용자 경험이 우수한 차세대 인증 흐름에 대한 이해**를 바탕으로, 이후 프로젝트(예: 반찬 고도화 버전, 공공서비스 인증 도입 등)에 적용 가능성을 실증할 수 있었습니다.

---
