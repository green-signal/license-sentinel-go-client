package licensesentinel

import "time"

type ResultCode string

const (
	// ResultOK возвращается, когда проверка токена/подписи на стороне
	// license-sentinel выполнена успешно и ответ считается валидным.
	ResultOK ResultCode = "ok"
	// ResultConfigError возвращается, когда на стороне license-sentinel
	// есть проблема конфигурации (например, недоступен или не настроен signer).
	ResultConfigError ResultCode = "config_error"
	// ResultChallengeBuildFailed возвращается, когда license-sentinel
	// не смог сформировать challenge для текущего запроса.
	ResultChallengeBuildFailed ResultCode = "challenge_build_failed"
	// ResultSignFailed возвращается, когда license-sentinel
	// не смог подписать challenge (например, токен/ключ недоступен).
	ResultSignFailed ResultCode = "sign_failed"
	// ResultVerifyFailed возвращается, когда license-sentinel
	// не смог подтвердить корректность подписи после операции подписания.
	ResultVerifyFailed ResultCode = "verify_failed"
)

type CheckResult struct {
	OK        bool       `json:"ok"`
	Code      ResultCode `json:"code"`
	CheckedAt time.Time  `json:"checked_at"`
	Challenge string     `json:"challenge,omitempty"`
	Signature string     `json:"signature,omitempty"`
}
