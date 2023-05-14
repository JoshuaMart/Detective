<p align="center">  
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>  
    <a href="https://github.com/JoshuaMart/Detective/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>  
    <a href="https://github.com/JoshuaMart/Detective"><img src="https://img.shields.io/badge/release-v0.0.1-informational"></a>
    <a href="https://github.com/JoshuaMart/Detective/issues" target="_blank"><img src="https://img.shields.io/github/issues/JoshuaMart/Detective?color=blue" /></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation-usages">Installation & Usage</a>
</p>

# Features

Detective provides an organized recognition in vHost rather than organizing the results by hostnames / URLS

Example output :
```json
{
  "1.1.1.1": {
    "cdn": true,
    "ports": [443],
    "vhosts": {
      "www.domain.tld": {
        "443": {
          "url": "https://www.domain.tld",
          "title": "Example Title",
          "status_code": 200,
          "technologies": ["PHP"]
        }
      }
    }
  },
  "1.1.1.2": {
    "cdn": false,
    "ports": [80,443,3306],
    "vhosts": {
      "other.domain.tld": {
        "80": {
          "url": "https://other.domain.tld",
          "title": "Example Title",
          "status_code": 200,
          "technologies": ["PHP","MySQL"]
        }
      },
      "another.domain.tld": {
        "443": {
          "host": "another.domain.tld",
          "title": "Example Title",
          "status_code": 200,
          "technologies": ["PHP","MySQL"]
        }
      }
    }
  }
}
```

Vhosts containing a URL are directly reachable in a browser, while those containing a host but no 
URL are reachable by specifying the Host header like :
```
curl -k https://1.1.1.2 -H 'Host: another.domain.tld'
```

# Installation & Usages

```bash
git clone https://github.com/JoshuaMart/Detective
cd Detective
```

You must then modify the configuration files in `./src/recon/configs`. It is then possible to use the tool either via Docker or directly

```docker
docker build . -t detective
docker run -v ./src:/detective dective -d domain.tld
```

```bash
bash install.sh
ruby src/main.rb -d domain.tld
```

```bash
Usage: detective.rb [options]
    -h, --help                       Display this screen
    -d, --domain domain              Domain to scan
    -m, --minimize                   Minimize HTTPX results
    -s, --silent                     Does not display logs messages
        --vhosts                     vHosts bruteforce
```