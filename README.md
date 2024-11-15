<!-- <img src="https://github.com/user-attachments/assets/35bfded5-3f21-46b5-91f7-014f5a09fac3" width=200 /> -->

<img src="https://github.com/user-attachments/assets/46a5c546-7e9b-42c7-87f4-bc8defe674e0" width=250 />


# DuckDB DHT Client Extension
This extension provides **DuckDB** instances access to mainline **DHT**.<br>

### Usage

Start a local [DHTd](https://github.com/lmangani/dhtd/releases/tag/v0.0.1) node instance

#### DHTd
DHTd serves as backend for this extension to operate across multiple DuckDB sessions

```
docker run -d --name dhtd -p 6881:6881 -v /tmp:/tmp ghcr.io/lmangani/dhtd:main
```

#### DuckDB

Query the DHTd node from DuckDB running on the same host

```sql
D SELECT dht_search('6f84758b0ddd8dc05840bf932a77935d8b5b8b93');
┌────────────────────────────────────────────────────────┐
│ dht_search('6f84758b0ddd8dc05840bf932a77935d8b5b8b93') │
│                        varchar                         │
├────────────────────────────────────────────────────────┤
│ Search started. Run dht_results() to get results       │
└────────────────────────────────────────────────────────┘

D SELECT * FROM dht_results('6f84758b0ddd8dc05840bf932a77935d8b5b8b93');
┌────────────────────────────────────────┬───────┐
│                address                 │ port  │
│                varchar                 │ int32 │
├────────────────────────────────────────┼───────┤
│ 2800:2202:4000:73b:b39f:759:2f3b:134   │ 26976 │
│ 2800:2202:4000:73b:89e3:8001:d02e:f218 │ 26976 │
│ 2800:2202:4000:73b::98bd               │ 26976 │
│ 2601:8c0:800:7626:be24:11ff:fe08:b8a3  │ 30165 │
│ 2a00:ee2:802:5942::10:0                │  7588 │
└────────────────────────────────────────┴───────┘
```

```sql
D SELECT version, node_id, uptime FROM dht_status();
┌─────────┬──────────────────────┬─────────┐
│ version │       node_id        │ uptime  │
│ varchar │       varchar        │ varchar │
├─────────┼──────────────────────┼─────────┤
│ 1.0.2   │ 552ba13e8034e1d3ec…  │ 1h1m    │
├─────────┴──────────────────────┴─────────┤
│ 1 rows              21 columns (3 shown) │
└──────────────────────────────────────────┘
```


## Vision
This experiment is part of a Proof-of-Concept to distribute queries through functions _(without modifying the query planner)_

```sql
--- Start an HTTP Socket (insecure) in the background
SELECT http_serve('0.0.0.0', 8123, ''); 

--- Announce your Socket with your hash/token to DHTd
SELECT dht_announce('somesupersecrettokennobodyknowsabout', 8123);

-- Repeat for multiple peers w/ same hash/token

--- Check for Discovered Peers by hash/token in DHTd (not self)
SELECT dht_results('somesupersecrettokennobodyknowsabout');

┌─────────────────┬───────┐
│     address     │ port  │
│     varchar     │ int32 │
├─────────────────┼───────┤
│ xxx.xx.xx.xxx   │  8123 │
│ yyy.yyy.yy.yyy  │  8123 │
├─────────────────┴───────┤
│ 2 rows        2 columns │
└─────────────────────────┘

--- Create a VIEW for your hash/token peer network
CREATE OR REPLACE VIEW backends AS
SELECT (address) as "who", ("http://" || address || ":" || port) AS "url",
FROM dht_results('somesupersecrettokennobodyknowsabout');

--- Query the Network (TODO: add authentication)
SET variable __backends = (SELECT ARRAY_AGG(url) AS urls_array FROM backends);
SELECT * FROM url_flock('SELECT ''hello'', version()', getvariable('__backends') );

┌─────────┬─────────────┐
│ 'hello' │ "version"() │
│ varchar │   varchar   │
├─────────┼─────────────┤
│ hello   │ v1.1.2      │
│ hello   │ v1.1.3      │
└─────────┴─────────────┘
```
