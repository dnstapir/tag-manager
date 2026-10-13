# Configuration example
```toml
# Debugging for entire app, CLI flag "-debug" has the same effect
debug = true

# Interval at which periodic tasks can be executed, if needed
interval = 120

# NATS configuration
[nats]
# Debugging NATS parts only
debug = true

# URL where NATS server can be found, can also be set via env "DNSTAPIR_NATS_URL"
url = "nats://localhost:4222"

# Subject for listening to incoming events that typically drive the analyst
event_subject = "internal.events.new_qname"

# Subject prefix used when when setting observation flags for a domain
observation_subject_prefix = "internal.observations"

# Configuration for observation buckets
[[nats.observation_buckets]]
# What is the name of the NATS bucket that will contain the observations?
name = "<BUCKET NAME>"

# What is the observation we are trying to set?
observation = "<OBSERVATION NAME>"

# Time-to-live for the observations in this bucket
ttl = 10

# Should this analyst create the bucket? Observation buckets are typically pre-provisioned
create = false

# Configuration for this analysts private bucket that it can use for arbitrary data
[nats.private_bucket]
# Bucket name, ensure it's unique if there are multiple instances of this analyst
name = "private_tag-manager"

# Should this analyst create the bucket? Typically yes for private buckets
create = true

# Configuration for the "seen domains" bucket which keeps track of seen domains
# Keys in this bucket do not expire
# Should only be used by a dedicated analyst such as github.com/dnstapir/tapir-analyse-new-qname
[nats.seen_domains_bucket]
# Bucket name
name = "seen_domains"

# Should this analyst create the bucket? Most of the time, the answer is no
create = false

```
