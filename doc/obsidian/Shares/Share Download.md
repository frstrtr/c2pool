Расписано с дальнейшим размышлениям для: [[Переработка системы загрузки шар]]
__Переработано в коммите `fcc34782ef5aae68d6cd49dc04d110e2d50a2a0d`__

--------------------

У P2PNode в методе start() запускается бесконечный, асинхронный, метод (inlineCallbacks) -- download_shares().
В цикле ```while True:```
###### 1. Ожидается появляение desired с помощью конструкции: ^1
```python
desired = yield desired_var.get_when_satisfies(lambda val: len(val) != 0)
```
Где yield ожидает, пока [[Events#get_when_satisfies]] при каждом изменении desired_var, значение desired_var.value будет не пустым массивом.

###### 2. Проверяется, есть ли сейчас подключение к пирам. 
Если нет, то на 1 секунду засыпает download_shares, а потом по новой, к п.1 ([[#^1]] )

###### 3. Запрашиваются шары в сети:
```python
try:
	shares = yield peer.get_shares(
		hashes=[share_hash],
		parents=random.randrange(500),
		stops=list(set(self.node.tracker.heads) | set(self.node.tracker.get_nth_parent_hash(head, min(max(0, self.node.tracker.get_height_and_last(head)[0] - 1), 10)) for head in self.node.tracker.heads
		))[:100],
	)
except defer.TimeoutError:
	print 'Share request timed out!'
	continue
except:
	log.err(None, 'in download_shares:')
	peer.badPeerHappened(30)
	continue
```
Где происходит запрос get_shares и yield ожидает ответ, после чего исхода может быть три:
- Произойдёт таймаут
- Произойдёт какая-то ошибка во время получения и парсинга шар, из-за чего мы дисконектимся просто от пира.
- Мы получим шары, у запроса будет got_response и мы их будем обрабатывать.
###### 4. Вызывается handle_shares для полученных шар.
```python
self.handle_shares([(share, []) for share in shares], peer)
```
