//
//  Handling.swift
//  WKWebView
//
//  Created by Gladkiy Sergey on 23.11.2022.
//

import Foundation

///	Структура обработки событий
///
///	Организуя блоки логики в статические экземпляры структуры Handling мы добиваемся
///	максимальной переиспользуемости. Пример использования ниже в этом файле.
///
/// Использование generic параметров в структуре полезно универсальностью расширений не требующих
/// дополнительной информации из типа I или использующих протоколы этого типа
///
/// Пример:
/// ```
/// extension Handling where O == Void {
///		static var log: Handling {
///			return .init {
///				print($0)
///			}
///		}
///}
/// ```
struct Handling<I, O> {
	var handle: (I) -> O

	init(handler: @escaping (I) -> O) {
		handle = handler
	}

	static func handle(_ handler: @escaping (I) -> O) -> Handling<I, O> { .init(handler: handler) }
}


extension Handling {
	/// Связывание хендлеров в цепочку.
	///
	/// Управление передается следующему хендлеру до тех пор пока условие
	/// `passOverWhen` не вернет `false`. Если после прохождения по всем хендлерам
	/// условие `passOver` не сработает, то вернется результат исполнения первого хендлера.
	static func chain(first: Handling, other handlers: [Handling],
					  passOverWhen passOver: @escaping (O) -> Bool) -> Handling {
		.handle {
			let firstHandlerResult = first.handle($0)
			guard passOver(firstHandlerResult) else { return firstHandlerResult }

			for handler in handlers {
				let handlingResult = handler.handle($0)
				guard passOver(handlingResult) else {
					return handlingResult
				}
			}

			return firstHandlerResult
		}
	}
}
