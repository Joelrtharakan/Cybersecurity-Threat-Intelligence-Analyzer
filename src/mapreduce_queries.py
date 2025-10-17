"""
mapreduce_queries.py
Runs several aggregation jobs on cyber_intel.urls and writes outputs into collections.
Outputs:
 - counts_by_type
 - mal_domains
 - malicious_tld_counts
 - url_length_by_type
"""

from pymongo import MongoClient
import pprint

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "cyber_intel"
COLL_NAME = "urls"

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
col = db[COLL_NAME]

def mr_counts_by_type():
    pipeline = [
        {"$group": {"_id": "$type", "value": {"$sum": 1}}}
    ]
    results = list(col.aggregate(pipeline))
    # Insert into collection
    db['counts_by_type'].drop()  # Clear previous
    if results:
        db['counts_by_type'].insert_many(results)
    print("Top types:")
    for doc in db['counts_by_type'].find().sort('value', -1).limit(20):
        pprint.pprint(doc)

def mr_malicious_domains():
    pipeline = [
        {"$match": {"type": {"$ne": "benign"}}},
        {"$group": {"_id": "$domain", "value": {"$sum": 1}}}
    ]
    results = list(col.aggregate(pipeline))
    db['mal_domains'].drop()
    if results:
        db['mal_domains'].insert_many(results)
    print("Top malicious domains:")
    for doc in db['mal_domains'].find().sort('value', -1).limit(20):
        pprint.pprint(doc)

def mr_malicious_tld_counts():
    pipeline = [
        {"$match": {"type": {"$ne": "benign"}}},
        {"$group": {"_id": {"$ifNull": ["$tld", "unknown"]}, "value": {"$sum": 1}}}
    ]
    results = list(col.aggregate(pipeline))
    db['malicious_tld_counts'].drop()
    if results:
        db['malicious_tld_counts'].insert_many(results)
    for doc in db['malicious_tld_counts'].find().sort('value', -1).limit(50):
        pprint.pprint(doc)

def mr_url_length_by_type():
    pipeline = [
        {"$project": {
            "type": {"$ifNull": ["$type", "unknown"]},
            "url_length": {"$ifNull": ["$url_length", 0]}
        }},
        {"$project": {
            "type": 1,
            "bucket": {
                "$concat": [
                    {"$toString": {"$multiply": [{"$floor": {"$divide": ["$url_length", 50]}}, 50]}},
                    "-",
                    {"$toString": {"$add": [{"$multiply": [{"$floor": {"$divide": ["$url_length", 50]}}, 50]}, 49]}}
                ]
            }
        }},
        {"$group": {"_id": {"type": "$type", "bucket": "$bucket"}, "value": {"$sum": 1}}}
    ]
    results = list(col.aggregate(pipeline))
    db['url_length_by_type'].drop()
    if results:
        db['url_length_by_type'].insert_many(results)
    print("Sample url_length_by_type:")
    for doc in db['url_length_by_type'].find().limit(30):
        pprint.pprint(doc)

def main():
    mr_counts_by_type()
    mr_malicious_domains()
    mr_malicious_tld_counts()
    mr_url_length_by_type()
    print("All aggregation jobs completed.")

if __name__ == '__main__':
    main()
