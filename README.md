[![golang](https://img.shields.io/badge/golang-1.21.1-blue?style=flat-square&logo=go)](https://go.dev)
[![python](https://img.shields.io/badge/python-3.9-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/release/python-390/)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

# Falcon

Enhancing Asynchronous BFT Consensus with Fewer Agreements and Partial Sorting.

This repository contains a **Go** implementation of the Falcon asynchronous BFT
protocol. Each `(epoch, height)` slot runs a Reliable Broadcast (RBC), an
optimistic `Prepare` phase, and — when the optimistic path fails — a binary
Asynchronous Binary Agreement (ABA) driven by a threshold shared coin. Committed
blocks are totally ordered by a commitor using ring-buffer *partial sorting*. It
uses real cryptography (ed25519 for signatures, kyber BLS threshold signatures
for the common coin), native TCP networking, and [nutsdb](https://github.com/nutsdb/nutsdb)
for storage.

## Repository layout

| Package | Responsibility |
|---|---|
| `crypto` | ed25519 signatures + kyber threshold (BLS) common coin, hashing, `SigService` |
| `network` | TCP `Sender`/`Receiver` and the gob message `Codec` |
| `store` | asynchronous key-value store over nutsdb |
| `pool` | transaction pool (synthetic load generator + batching) |
| `core` | the Falcon protocol: messages, aggregator, commitor, synchronizer, core state machine |
| `config` | committee / key / parameter file (de)serialization |
| `logger` | leveled logging |
| `node` + `main.go` | node assembly and the CLI |
| `benchmark` | Python + [Fabric](http://www.fabfile.org/) benchmarking scripts |

## Quick Start

Falcon is written in Go, but all benchmarking scripts are written in Python and
run with [Fabric](http://www.fabfile.org/). To deploy and benchmark a testbed of
4 nodes on your local machine, clone the repo and install the Python
dependencies:

```
$ git clone https://github.com/yingbin119/Falcon_go.git
$ cd Falcon/benchmark
$ pip install -r requirements.txt
```

You also need [Go](https://go.dev/dl/) (1.21+) on your `PATH` and
[tmux](https://linuxize.com/post/getting-started-with-tmux/#installing-tmux)
(which runs all nodes in the background). Finally, run a local benchmark using
Fabric:

```
$ fab local
```

When the benchmark terminates, it displays a summary of the execution similar to
the one below.

```
-----------------------------------------
 SUMMARY:
-----------------------------------------
 + CONFIG:
 Protocol: Falcon
 DDOS attack: False
 Committee size: 4 nodes
 Input rate: 2,000 tx/s
 Transaction size: 250 B
 Batch size: 200 tx/Batch
 Faults: 1 nodes
 Execution time: 10 s

 + RESULTS:
 Consensus TPS: 6,029 tx/s
 Consensus latency: 39 ms

 End-to-end TPS: 6,026 tx/s
 End-to-end latency: 46 ms
-----------------------------------------
```

You can customize the benchmark parameters (committee size, input rate, batch
size, faults, DDoS, ...) in `benchmark/fabfile.py`.

## Running a node manually

The `main.go` CLI exposes the following subcommands:

```
$ go build -o main .

# generate ed25519 key files (.node-key-i.json)
$ ./main keys --path . --nodes 4

# generate threshold-signature shares (.node-ts-key-i.json); T must be f+1
$ ./main threshold_keys --path . --N 4 --T 2

# run a single node against a committee/parameters file
$ ./main run --keys .node-key-0.json --threshold_keys .node-ts-key-0.json \
             --committee .committee.json --parameters .parameters.json \
             --store db-0 --log_out logs --log_level 15 --node_id 0

# or run a whole N-node testbed in one process (useful for a quick smoke test)
$ ./main deploy --nodes 4
```

## Aliyun Benchmarks

The following steps explain how to run benchmarks on Alibaba Cloud across
multiple data centers (WAN).

**1. Set up your Aliyun credentials**

Set up your Aliyun credentials to enable programmatic access to your account from
your local machine. First, find your `AccessKey ID` and `AccessKey Secret`, then
create a file `~/.aliyun/access.json` with the following content:

```json
{
  "AccessKey ID": "your accessKey ID",
  "AccessKey Secret": "your accessKey Secret"
}
```

**2. Add your SSH public key to your Aliyun account**

This operation is manual and needs to be repeated for each Aliyun region that you
plan to use. Ensure you set the same key name on all regions. If you don't have
an SSH key, you can create one using [ssh-keygen](https://www.ssh.com/ssh/keygen/):

```
ssh-keygen -f ~/.ssh/aliyun
```

**3. Configure the testbed**

The file [settings.json](benchmark/settings.json) (located in
[Falcon/benchmark](benchmark)) contains all the configuration parameters of the
testbed to deploy. Its content looks as follows:

```json
{
  "key": {
    "name": "Falcon",
    "path": "/root/.ssh/id_rsa",
    "accesskey": "/root/.aliyun/access.json"
  },
  "ports": {
    "consensus": 8000
  },
  "instances": {
    "type": "ecs.g9i.xlarge",
    "regions": ["us-east-1", "ap-southeast-1", "us-west-1", "eu-central-1"]
  }
}
```

**4. Create a testbed**

The Aliyun instances are orchestrated with [Fabric](http://www.fabfile.org/) from
the file [fabfile.py](benchmark/fabfile.py). The command `fab create` creates new
instances (`--nodes` per region), `fab install` installs the dependencies, and
`fab uploadexec` compiles and uploads the executable:

```
$ fab create
$ fab install
$ fab uploadexec
```

**5. Run a benchmark**

```
$ fab remote
```
