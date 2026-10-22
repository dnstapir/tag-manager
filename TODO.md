# Overview
The `tag-manager` is responsible for tagging domains in NATS. It uses
the NATS Key-Value (KV) store functionality to do so. Upon starting up
it must make sure there is a bucket provisioned in the NATS cluster for
storing the tags.

Microanalysts who rely on `tapir-analyse-lib` can set tags directly with
the lib and do not need to go via `tag-manager`. Microanalysts should
not try to set up the tag bucket themselves, however.

`tag-manager` should provide a REST API so that tags can be set
programmatically through that, for instance from a Jupyter notebook.
Setting tags via the REST API should require authorization.

`tag-manager` should also provide a web GUI for browsing the tagged
domains. Searching and filtering based on tags and/or domain name
should be possible. It should also be possible to set tags via the web
GUI, after authorization.

There are two classes of tags, `well-defined` and `custom`.
`well-defined` tags are those that have received a code point
[here](https://github.com/dnstapir/tapir-analyse-lib/blob/main/common/tags.go).
`custom` tags are those that have not. Both kinds should be settable from
the web GUI and via the REST API. `tag-manager` is responsible for placing
them in the correct namespace, either `<prefix>.tags.well-defined` or
`<prefix>.tags.custom`.

A domain, `example.com` is tagged with `some-tag` if there exists a key
`<prefix>.tags.well-defined.some-tag.com.example` in the tag bucket.
Alternatively, for a `custom` tag the key would be something like:
`<prefix>.tags.custom.some-other-tag.com.example`.
The value behind the key can be anything, it is currently unused. The
`<prefix>` placeholder is a configuration parameter that the Core
operator can choose as they please to avoid namespace collisions with
other things that might be using the same NATS cluster.




# Example 1: Starting up
```mermaid
sequenceDiagram
    participant tag-manager
    participant NATS
    participant microanalyst

    note over tag-manager: Upon starting up, the tag manager creates a bucket
    tag-manager->>+NATS: CreateIfNotExists("my-tag-bucket")

    note over microanalyst: Microanalysts and other entities can then start tagging domains
    microanalyst->>+NATS: Put("<prefix>.tags.well-defined.some-tag.com.example")
```

# Example 2: Reading and writing
```mermaid
sequenceDiagram
    participant microanalyst
    participant NATS
    participant tag-manager
    actor Analyst

    note over microanalyst: A microanalyst sets a well-defined tag (tag needs to be registered)
    microanalyst->>+NATS: Put("<prefix>.tags.well-defined.some-tag.com.example")

    note over Analyst: A human analyst sets a custom tag through a Jupyter notebook
    Analyst->>+tag-manager: HTTP POST /domain/example.com?tag=some-other-tag
    tag-manager->>+NATS: Put("<prefix>.tags.custom.some-tag.com.example")

    note over Analyst: The analyst then wants to see all tags for a specific domain name
    Analyst->>+tag-manager: HTTP GET /domain/example.com
    
    note over tag-manager: tag-manager gathers all tags for a specific domain name
    tag-manager->>+NATS: Get("<prefix>.tags.*.*.com.example")
    tag-manager->>+Analyst: {"example.com": ["some-tag", "some-other-tag"]}
```
