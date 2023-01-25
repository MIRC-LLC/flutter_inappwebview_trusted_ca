//
//  AuthChallenge.swift
//  WKWebView
//
//  Created by Gladkiy Sergey on 23.11.2022.
//

import Foundation

// MARK: AuthChallenge
typealias AuthChallengeResult = (URLSession.AuthChallengeDisposition, URLCredential?)
typealias AuthChallengeCompletion = (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
typealias AuthChallengeHandler = Handling<URLAuthenticationChallenge, AuthChallengeResult>

/// Обработчик URLAuthenticationChallenge для WKWebView в приложении
typealias AsyncAuthChallengeHandler = Handling<(URLAuthenticationChallenge, AuthChallengeCompletion), Void>

extension AsyncAuthChallengeHandler {

	/// Очередь для обработки челенджей WebView
	///
	/// WebView производит проверку на главном потоке,
	/// проверка сертификтов должна быть асинхронной для использования SecTrustEvaluate
	private static let handlerQueue = DispatchQueue(label: "WKWebView.AuthChallengeHandler")

	/**
	 Метод для установки дополнительных доверенных сертификатов в WebView через WKNavigationDelegate.

	 - Usage: В WKNavigationDelegate методе webView didReceive challenge нужно прописать
	 AsyncAuthChallengeHandler
	   .webViewAddTrusted(certificates: [*сертификаты которые необходимо добавить*])
	   .handle((challenge, completionHandler))
	 - Parameter certificates: .der рутовые сертификаты которым нужно доверять.
	 - Parameter ignoreUserCertificates: Нужно ли игнорировать сертификаты которые поставил пользователь самостоятельно.
	 */
	static func webViewAddTrusted(certificates: [Data],
								  ignoreUserCertificates: Bool = true) -> AsyncAuthChallengeHandler {
		.handle { (challenge: URLAuthenticationChallenge, completion: @escaping AuthChallengeCompletion) in
			handlerQueue.async {
				/*
				 Если не нужно игнорировать сертификаты установленные пользователем в систему,
				 то просто добавляем дополнительные сертификаты и проводим валидацию цепочки.
				 */
				guard ignoreUserCertificates else {
					let result = AuthChallengeHandler.chain(
						.setAnchor(certificates: certificates, includeSystemAnchors: true),
						.secTrustEvaluateSSL(withCustomCerts: true)
					).handle(challenge)
					completion(result.0, result.1)
					return
				}

				/*
				 SecTrustGetTrustResult в методе secTrustEvaluateSSL возвращает статус *успешной* валидации .proceed
				 по которому можно понять был ли использован кастомный рут сертификат в цепочке, но
				 не позволяет различить откуда сертификат был взят (может быть установлен програмно через
				 SecTrustSetAnchorCertificates, либо руками в настройках системы).

				 Если нужно игнорировать сертификаты установленные пользователем в систему,
				 то проверяем валидность цепочки только с системными сертификатами (без добавленных нами/пользователем)
				 и если проверка не прошла с recoverable failure, то пробуем проверить цепочку
				 только с кастомными рутовыми сертификатами без системных (SecTrustSetAnchorCertificatesOnly
				 позволяет выставить флаг для игнорирования всех сертификатов кроме тех что были переданы)
				 */

				// Пробуем валидацию без доп. сертификатов
				_ = AuthChallengeHandler.setAnchor(
					certificates: [], includeSystemAnchors: true
				).handle(challenge)

				// Проводим валидацию цепочки
				let systemCertsResult = AuthChallengeHandler.secTrustEvaluateSSL(
					// Сертификаты пользователя игнориуем
					withCustomCerts: false
				).handle(challenge)

				guard
					// Если это не NSURLAuthenticationMethodServerTrust
					systemCertsResult.0 != .performDefaultHandling,
					// Если цепочка прошла валидацию и добавление сертификата не понадобилось
					systemCertsResult.0 != .useCredential
				else {
					completion(systemCertsResult.0, systemCertsResult.1)
					return
				}

				// Добавляем наши сертификаты
				_ = AuthChallengeHandler.setAnchor(
					certificates: certificates,
					// Игнорируем сертификаты пользователя и системные
					includeSystemAnchors: false
				).handle(challenge)

				// Если валидация не прошла на этом этапе, то цепочка невалидна, либо Root недоверенный
				let customCertsResult = AuthChallengeHandler
					.secTrustEvaluateSSL(withCustomCerts: true)
					.handle(challenge)

				completion(customCertsResult.0, customCertsResult.1)
			}
		}
	}
}

extension AuthChallengeHandler {
	/// Связывание хендлеров в цепочку ответственности.
	///
	/// Управление передается следующему хендлеру если предыдущий вернул `.performDefaultHandling`.
	///
	///	- Tag: AuthChallengeHandler.chain
	static func chain(_ nonEmpty: AuthChallengeHandler, _ handlers: AuthChallengeHandler...) -> AuthChallengeHandler {
		chain(first: nonEmpty, other: handlers, passOverWhen: { $0.0 == .performDefaultHandling })
	}
}

extension AuthChallengeHandler {
	/// Установка AnchorCertificates методом [SecTrustSetAnchorCertificates]
	///
	/// После установки сертификата Handler вернет `.perfromDefaultHandling`,
	/// для кастомизации дефолтной проверки используйте
	/// [Chaining](x-source-tag://AuthChallengeHandler.chain)
	///
	/// - Parameters:
	///   - certificates: сертификаты в `.der` формате
	///   - includeSystemAnchors: true если нужно оставить системные сертификаты, иначе `SecTrustEvaluate`
	///    будет использовать только Anchor сертификаты
	static func setAnchor(certificates: [Data], includeSystemAnchors: Bool = false) -> Self {
		return .handle {
			guard let trust = serverTrust($0) else {
				return (.performDefaultHandling, nil)
			}
			SecTrustSetAnchorCertificates(
				trust, certificates.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) } as CFArray
			)
			SecTrustSetAnchorCertificatesOnly(trust, !includeSystemAnchors)
			return (.performDefaultHandling, nil)
		}
	}
}

private extension AuthChallengeHandler {
	/// Вердикт на основании валидации цепочки методом SecPolicyCreateSSL -> SecTrustEvaluate
	static func secTrustEvaluateSSL(withCustomCerts: Bool) -> AuthChallengeHandler {
		.handle {
			guard let trust = serverTrust($0) else {
				return (.performDefaultHandling, nil)
			}
			guard evaluate(trust, host: $0.protectionSpace.host, allowCustomRootCertificate: withCustomCerts) else {
				return (.cancelAuthenticationChallenge, nil)
			}
			return (.useCredential, URLCredential(trust: trust))
		}
	}

	static func serverTrust(_ authChallenge: URLAuthenticationChallenge) -> SecTrust? {
		guard authChallenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust else { return nil }
		return authChallenge.protectionSpace.serverTrust
	}

	static func evaluate(_ trust: SecTrust, host: String, allowCustomRootCertificate: Bool) -> Bool {
		let sslPolicy = SecPolicyCreateSSL(true, host as CFString)
		let status = SecTrustSetPolicies(trust, sslPolicy)
		if status != errSecSuccess {
			return false
		}

		var error: CFError?
		guard SecTrustEvaluateWithError(trust, &error) && error == nil else {
			return false
		}
		var result = SecTrustResultType.invalid
		let getTrustStatus = SecTrustGetTrustResult(trust, &result)
		guard getTrustStatus == errSecSuccess && (result == .unspecified || result == .proceed) else {
			return false
		}
		if allowCustomRootCertificate == false && result == .proceed { return false }
		return true
	}
}
