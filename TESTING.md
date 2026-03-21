# DechoNet MCP Server — 테스트 가이드

## 1. CLI 테스트 (빌드 확인)

### 빌드

```bash
cd mcp
npm install
npm run build
```

### 서버 초기화 확인

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | node build/index.js
```

**기대 결과**: `serverInfo.name: "dechonet"`, `capabilities.tools` 포함

### 도구 목록 확인 (13개)

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n' | node build/index.js
```

**기대 결과**: 13개 도구 — dns_lookup, ssl_check, http_security, email_auth, port_scan, dns_propagation, reverse_dns, asn_lookup, whois_lookup, ip_info, email_header_analysis, subnet_calc, security_scan

### 도구 호출 테스트 (오프라인 — subnet_calc)

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}\n{"jsonrpc":"2.0","method":"notifications/initialized"}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"subnet_calc","arguments":{"cidr":"10.0.0.0/16"}}}\n' | node build/index.js
```

**기대 결과**:
```
network: 10.0.0.0
broadcast: 10.0.255.255
totalHosts: 65534
subnetMask: 255.255.0.0
```

### 도구 호출 테스트 (온라인 — dns_lookup)

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}\n{"jsonrpc":"2.0","method":"notifications/initialized"}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dns_lookup","arguments":{"domain":"example.com"}}}\n' | node build/index.js
```

**기대 결과**: `Status: OK`, A/AAAA 레코드 포함, DNSSEC 상태 표시

---

## 2. MCP Inspector 테스트

공식 MCP Inspector를 사용하면 GUI로 도구를 테스트할 수 있습니다.

```bash
npx @modelcontextprotocol/inspector node build/index.js
```

브라우저에서 Inspector가 열리면:
1. 왼쪽 사이드바에서 **Tools** 클릭
2. 13개 도구 목록 확인
3. 도구 선택 → 파라미터 입력 → 실행
4. 결과 확인

### Inspector 테스트 시나리오

| 도구 | 입력 | 확인 사항 |
|------|------|----------|
| `subnet_calc` | cidr: `192.168.1.0/24` | 254 hosts, 정상 계산 |
| `dns_lookup` | domain: `google.com` | A 레코드 존재, Status: OK |
| `ssl_check` | host: `google.com` | 인증서 유효, Grade 표시 |
| `email_auth` | domain: `gmail.com` | SPF/DMARC ON |
| `security_scan` | domain: `example.com` | Health Score 0-100 |
| `asn_lookup` | query: `AS15169` | Google 네트워크 정보 |
| `reverse_dns` | ip: `8.8.8.8` | PTR: dns.google |
| `whois_lookup` | domain: `example.com` | 등록일/만료일 |

---

## 3. Claude Desktop 테스트

### 설정

`claude_desktop_config.json`에 추가:

```json
{
  "mcpServers": {
    "dechonet": {
      "command": "node",
      "args": ["/절대경로/mcp/build/index.js"]
    }
  }
}
```

**파일 위치:**
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

### 확인 사항

1. Claude Desktop 완전 종료 후 재시작
2. 입력창 오른쪽 하단에 **MCP 도구 아이콘** (망치 모양) 표시 확인
3. 아이콘 클릭 → "dechonet" 서버 + 13개 도구 목록 표시

### 테스트 프롬프트

아래 프롬프트를 Claude Desktop에 입력하고, DechoNet 도구가 호출되는지 확인:

**기본 도구 호출:**
```
example.com의 DNS 레코드를 확인해줘
```
→ `dns_lookup` 호출 → DNS 결과 표시

**종합 진단:**
```
dechonet.com의 보안 상태를 전체 점검해줘
```
→ `security_scan` 호출 → Health Score + 등급 + 영역별 상태

**SSL 확인:**
```
google.com의 SSL 인증서가 유효한지 확인해줘
```
→ `ssl_check` 호출 → 인증서 정보 + 등급

**이메일 보안:**
```
gmail.com의 이메일 인증 설정을 점검해줘
```
→ `email_auth` 호출 → SPF/DMARC/DKIM 결과

**오프라인 도구:**
```
10.0.0.0/8 서브넷 계산해줘
```
→ `subnet_calc` 호출 → 네트워크/브로드캐스트/호스트 수

**복합 질문 (에이전트가 여러 도구 조합):**
```
example.com의 DNS 레코드를 확인하고, 그 IP의 ASN도 알려줘
```
→ `dns_lookup` → A 레코드 IP 추출 → `asn_lookup` 순차 호출

---

## 4. SSE 트랜스포트 테스트

### 서버 시작

```bash
cd mcp
npm run start:sse
```

### Health Check

```bash
curl http://localhost:3100/
```

**기대 결과**: `{"name":"dechonet-mcp","version":"1.0.0","tools":[...],"transport":"sse"}`

### SSE 연결 테스트

```bash
curl -N http://localhost:3100/sse
```

**기대 결과**: SSE 스트림 시작 (`data: ...` 형식의 이벤트)

---

## 5. 에러 시나리오 테스트

| 시나리오 | 입력 | 기대 결과 |
|----------|------|----------|
| 잘못된 도메인 | dns_lookup: `not-a-domain!!!` | `isError: true`, 에러 메시지 |
| 빈 입력 | dns_lookup: `""` | 에러 반환 (crash 아님) |
| 존재하지 않는 도메인 | ssl_check: `thisdomaindoesnotexist12345.com` | 연결 실패 에러 |
| 잘못된 CIDR | subnet_calc: `abc/99` | `isError: true`, "Invalid" |
| API 타임아웃 | security_scan (느린 도메인) | 부분 결과 반환 |

---

## 6. 체크리스트

### 릴리스 전 확인

- [ ] `npm run build` 성공
- [ ] 13개 도구 목록 확인
- [ ] subnet_calc (오프라인) 정상
- [ ] dns_lookup (온라인) 정상
- [ ] security_scan (종합) 정상
- [ ] MCP Inspector에서 전 도구 테스트
- [ ] Claude Desktop 연동 확인
- [ ] SSE 서버 시작 + health check
- [ ] 에러 입력 시 crash 없음
- [ ] 메인 프로젝트 테스트 381개 통과
