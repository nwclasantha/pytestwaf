"""DNS caching module.

Python's httpx handles DNS caching internally, so this module
is a compatibility shim. The Go version used a custom DNS cache
with background refresh; in Python, httpx's connection pooling
provides equivalent functionality.
"""
