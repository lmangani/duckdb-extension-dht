<!-- <img src="https://github.com/user-attachments/assets/35bfded5-3f21-46b5-91f7-014f5a09fac3" width=200 /> -->

<img src="https://github.com/user-attachments/assets/46a5c546-7e9b-42c7-87f4-bc8defe674e0" width=250 />


# DuckDB DHT Client Extension
This extension provides **DuckDB** instances access to mainline **DHT**.<br>

### Usage

Start a local [DHTd](https://github.com/lmangani/dhtd/releases/tag/v0.0.1) node instance

```
dhtd --daemon --peer bttracker.debian.org:6881 --peer router.bittorrent.com:6881
```

Query the DHTd node from DuckDB on the same host

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


## Vision
```sql
LOAD http_server; LOAD chsql; LOAD dht;

--- Start an HTTP Socket (insecure)
SELECT http_serve('0.0.0.0', 8123, ''); 

--- Announce your Socket with your hash
SELECT dht_announce('somesupersecrettokennobodyknowsabout', 8123);

--- Check for Discovered Peers by hash
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

--- Create a VIEW for your results as backends
CREATE OR REPLACE VIEW backends AS
SELECT (address) as "who", ("http://" || address || ":" || port) AS "url",
FROM dht_results('somesupersecrettokennobodyknowsabout');

--- Query the Backends (TODO: authentication)
SET variable __backends = (SELECT ARRAY_AGG(url) AS urls_array FROM backends);
SELECT * FROM url_flock('SELECT ''hello'', version()', getvariable('__backends') );

┌─────────┬─────────────┐
│ 'hello' │ "version"() │
│ varchar │   varchar   │
├─────────┼─────────────┤
│ hello   │ v1.1.2      │
│ hello   │ 24.8.4.1    │
└─────────┴─────────────┘
```
