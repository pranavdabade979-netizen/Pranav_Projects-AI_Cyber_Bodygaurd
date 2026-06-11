from database.mongo_db import log_event

log_event({
    "test": "MongoDB connected successfully"
})

print("Data inserted!")