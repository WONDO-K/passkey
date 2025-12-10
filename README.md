## ✅ Passkey 인증 시스템 실험 및 백엔드 구현

### 📌 개요

FIDO2 기반의 비밀번호 없는 인증 시스템인 **Passkey 인증 방식**을 실습 및 구현하였습니다. 이는 기존 반찬 프로젝트의 2차 인증 시스템을 발전시키기 위한 실험으로, 실제 서비스에는 도입하지 못했지만 **완성도 높은 백엔드 구현과 테스트 환경 구성**을 완료하였습니다.

---

## 👨‍💻 담당 역할

- **FIDO2/Passkey 인증 원리 학습** (PublicKeyCredential, Challenge-Response 구조 등)
- **WebAuthn 프로토콜 분석 및 백엔드 로직 구현**
- **Spring Boot 기반 Passkey 등록·인증 API 설계**
- **Base64URL 디코딩 오류 해결(RFC 4648 기반 커스텀 디코더 구현)**
- **Redis 기반 Challenge 상태 관리**
- **브라우저(WebAuthn) · 서버 간 데이터 파싱 및 검증 흐름 구축**

---

## 🛠 기술 스택

`Java 17`, `Spring Boot 3`, `Redis`, `Spring Security`,  
`WebAuthn (FIDO2)`, `Yubico Java Library`, `Base64URL`, `JWT`, `Postman`

---

## 🚀 Passkey 등록·인증 흐름 요약

| 기능 구분 | 설명 |
|----------|------|
| **1. Passkey 등록** | 브라우저(WebAuthn)가 생성한 Attestation 데이터를 서버에서 파싱 및 검증 후 DB 저장 |
| **2. Challenge 발급** | Redis에 Challenge 저장 → 응답 단계에서 비교하여 위변조 방지 |
| **3. Passkey 인증** | 클라이언트 서명(Signature) 검증 → PublicKey 기반으로 서버에서 직접 검증 |
| **4. Base64URL 처리** | WebAuthn 데이터의 URL-safe Base64를 RFC 4648 규칙으로 복원하여 충돌 해결 |
| **5. 단계별 분기 처리** | 등록/인증 과정에서 예외 상황별로 정확한 검증 흐름 유지 |

---

## 📸 Passkey 시연 화면 (Frontend ↔ Backend 실제 연동 결과)

아래 화면들은 단순 UI 데모가 아니라,  
**본 프로젝트의 Passkey 백엔드 로직(`AuthService`, `ChallengeService`, `Base64Util`)과 실제 WebAuthn 클라이언트가 연동되어 동작한 결과**입니다.

### 1) Passkey 등록 입력 화면
![Register UI](./image35.png)

### 2) Windows Hello Passkey 생성 UI  
(브라우저가 WebAuthn API를 통해 인증기(Authenticator) 호출)
![Windows Credential Selection](./image36.png)

### 3) 사용자 본인 인증(PIN/Biometrics) 단계  
![PIN Authentication](./image37.png)

### 4) 브라우저 콘솔 출력 – 서버 검증 완전 성공  
서버가 Challenge 일치 여부, AuthenticatorData, ClientDataJSON, Signature 등을 모두 검증했음을 의미합니다.
![Console Log](./image38.png)

---

## 🔍 문제 해결 및 기술적 특징

### ✔ Base64URL → ByteArray 변환 충돌 해결  
WebAuthn Credential에서 전달되는 ID, signature 등이  
URL-safe Base64(`-`, `_`, padding 제거)로 인코딩되어 있어  
Java 서버에서 디코딩이 실패하는 문제가 발생했습니다.

이를 해결하기 위해 **RFC 4648 규칙 기반 커스텀 Base64URL 디코더**를 작성하여  
패딩 복원 및 URL-safe 문자 변환 문제를 직접 해결했습니다.

### ✔ Stateless 서버 환경(JWT)에서 Passkey 상태 관리 문제 해결  
Passkey 인증은 특정 Challenge 상태를 유지해야 하므로  
JWT 기반 stateless 환경과 충돌이 발생합니다.

이를 해결하기 위해 Redis를 Challenge 저장소로 사용하여:  
- 인증 요청마다 Challenge 생성  
- Redis에 안전하게 저장  
- 클라이언트 응답의 Challenge와 비교 검증  
- 인증 성공 시 즉시 삭제하여 재사용 방지  

라는 **단일 책임 구조의 안정적인 인증 흐름**을 구축했습니다.

---

## 💬 회고

Passkey 인증을 단순 개념이 아니라 **직접 백엔드 인증 흐름까지 구현해보며**,  
WebAuthn 구조, 브라우저·OS 인증기 역할, 서명 검증 방식 등  
보안 인증 체계를 깊이 있게 이해할 수 있었습니다.

또한 기존 SMS OTP 기반 인증 대비  
**보안성·사용성 모두 우수한 차세대 인증 방식을 직접 설계하고 검증했다는 점**에서  
이후 프로젝트 확장(공공서비스 인증, 금융서비스 인증) 가능성을 확인할 수 있었습니다.
