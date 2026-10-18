SELECT * FROM security_events WHERE pid = 9007199254740993 AND session_id > 9007199254740993 AND to_tsvector('simple', security_events::text) @@ plainto_tsquery('simple', '9007199254740993')
