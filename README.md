# SSHFP resolver for Golang

[![License][License-Image]][License-Url]
[![Godoc][Godoc-Image]][Godoc-Url]
[![ReportCard][ReportCard-Image]][ReportCard-Url]
[![Build][Build-Status-Image]][Build-Status-Url]
[![Coverage][Coverage-Image]][Coverage-Url]

**NOTE: Package is functional but not production ready! It requires at least Golang 1.12 with Go modules**

The sshfp project is a Golang implementation of SSH fingerprints stored in SSHFP DNS records which can be used together
with [golang.org/x/crypto/ssh.Client](https://godoc.org/golang.org/x/crypto/ssh#Client) using a custom
[HostKeyCallback](https://godoc.org/github.com/xor-gate/sshfp#Resolver.HostKeyCallback) with modular caching. Learn more about the DNS SSHFP record type on [Wikipedia](https://en.wikipedia.org/wiki/SSHFP_record). 

At least go 1.12 is required

This package is based on the awesome Golang DNS package from [github.com/miekg/dns](https://github.com/miekg/dns).

And implements at least the following RFCs:

* https://www.ietf.org/rfc/rfc1035.txt
* https://tools.ietf.org/rfc/rfc6594.txt
* https://www.ietf.org/rfc/rfc4255.txt
* https://tools.ietf.org/html/rfc7479

# LICENSE

[MIT](LICENSE)

[License-Url]: http://opensource.org/licenses/MIT
[License-Image]: https://img.shields.io/npm/l/express.svg
[Stability-Status-Image]: http://badges.github.io/stability-badges/dist/experimental.svg
[Build-Status-Url]: http://travis-ci.org/xor-gate/sshfp
[Build-Status-Image]: https://travis-ci.org/xor-gate/sshfp.svg?branch=develop
[Godoc-Url]: https://godoc.org/github.com/xor-gate/sshfp
[Godoc-Image]: https://godoc.org/github.com/xor-gate/sshfp?status.svg
[ReportCard-Url]: http://goreportcard.com/report/xor-gate/sshfp
[ReportCard-Image]: https://goreportcard.com/badge/github.com/xor-gate/sshfp
[Coverage-Url]: https://codecov.io/gh/xor-gate/sshfp 
[Coverage-image]: https://codecov.io/gh/xor-gate/sshfp/branch/develop/graph/badge.svg 
