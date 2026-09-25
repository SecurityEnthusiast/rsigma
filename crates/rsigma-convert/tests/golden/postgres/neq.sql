SELECT * FROM security_events WHERE NOT "Field" = 'foo' AND ("Image" = "ParentImage") IS NOT TRUE AND "Image" IS NOT NULL
