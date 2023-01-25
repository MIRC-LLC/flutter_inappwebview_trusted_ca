//
//  Config.swift
//  WKWebView
//
//  Created by Gladkiy Sergey on 23.11.2022.
//

import Foundation

/// Добавить сертификат Минцифры в папку Certificates (в папке представлен скаченный  с
/// скачать можно с https://www.gosuslugi.ru/crt
/// в папке Certificates представлен данный сертификат Минцифры
/// также можно добавитть дополнительные доверенные сертификаты

enum Config {
	static func certificates(_ subdirectory: String?) -> [Data] {
		let certificates: [Data] = Bundle.main
			.urls(
				forResourcesWithExtension: "der",
				subdirectory: subdirectory
			)?.compactMap {
				do {
					return try Data(contentsOf: $0)
				} catch let error {
					assertionFailure("Не получается загрузить сертификат: \(error)")
					return nil
				}
			} ?? []
		assert(!certificates.isEmpty, "Сертификаты не найдены")
		return certificates
	}
}
