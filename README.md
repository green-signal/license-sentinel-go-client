# license-sentinel-go-client

Go SDK для `license-sentinel`.

## Структура проекта

```text
.
|-- cmd/license-sentinel-http-example/  # исполняемый пример для HTTP
|-- cmd/license-sentinel-uds-example/   # исполняемый пример для UDS
|-- client.go                       # клиент (HTTP/UDS) и кэш сертификата
|-- models.go                       # модели API
|-- verify.go                       # локальная проверка подписи и сертификата
|-- client_test.go
|-- go.mod
|-- LICENSE
`-- README.md
```

## Установка

```bash
go get github.com/green-signal/license-sentinel-go-client@latest
```

## Быстрый старт

```go
package main

import (
	"context"
	"log"

	licensesentinel "github.com/green-signal/license-sentinel-go-client"
)

func main() {
	client, err := licensesentinel.New(licensesentinel.Config{
		BaseURL:  "http://127.0.0.1:8080",
		ClientID: "test-client",
	})
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.Check(context.Background(), "nonce-1")
	if err != nil {
		log.Fatal(err)
	}
	if !result.OK {
		log.Fatalf("проверка вернула неуспешный код: %s", result.Code)
	}
}
```

### Подключение через UDS

```go
client, err := licensesentinel.New(licensesentinel.Config{
    ClientID:       "test-client",
    UnixSocketPath: "/tmp/license-sentinel.sock",
})
```

## Запуск примера (HTTP)

```bash
go run ./cmd/license-sentinel-http-example \
  -base-url http://127.0.0.1:8080 \
  -client-id test-client \
  -nonce demo-nonce
```

## Запуск примера (UDS)

```bash
go run ./cmd/license-sentinel-uds-example \
  -unix-socket /tmp/license-sentinel.sock \
  -client-id test-client \
  -nonce demo-nonce
```

## Как работает проверка

- SDK получает сертификат через `/api/v1/certificate` и кэширует его.
- Ответ `/api/v1/signature/check` валидируется внутри SDK автоматически.
- Валидация включает проверку подписи challenge и проверку цепочки сертификата до встроенного CA.

## Публичный API

- `Init(ctx)` — предварительно получить и закэшировать сертификат.
- `RefreshCertificate(ctx)` — принудительно обновить сертификат.
- `Check(ctx, clientNonce)` — выполнить запрос `/signature/check` и автоматически провалидировать ответ.
- `CheckAndVerify(ctx, clientNonce)` — совместимый алиас для `Check`.
- `Config.UnixSocketPath` — включить UDS-транспорт (если задан, `BaseURL` можно не указывать).

## Лицензия

Apache License 2.0. См. [LICENSE](LICENSE).
