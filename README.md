# sshfp for golang

[![License][License-Image]][License-Url]
[![Godoc][Godoc-Image]][Godoc-Url]
[![ReportCard][ReportCard-Image]][ReportCard-Url]
[![Build][Build-Status-Image]][Build-Status-Url]
[![Coverage][Coverage-Image]][Coverage-Url]

**NOTE: Package is functional but work-in-progress**

The sshfp project is a Golang implementation of SSH fingerprints stored in SSHFP DNS records which can be used together with [golang.org/x/crypto/ssh.Client](https://godoc.org/golang.org/x/crypto/ssh#Client) using a custom [HostKeyCallback](https://godoc.org/github.com/xor-gate/sshfp#Resolver.HostKeyCallback) with optional cache. Learn more about the DNS SSHFP record type on [Wikipedia](https://en.wikipedia.org/wiki/SSHFP_record). 

At least go 1.7 is required

This package is based on the awesome Golang DNS package from [github.com/miekg/dns](https://github.com/miekg/dns).

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
[Build-Status-Image]: https://travis-ci.org/xor-gate/sshfp.svg?branch=master
[Godoc-Url]: https://godoc.org/github.com/xor-gate/sshfp
[Godoc-Image]: https://godoc.org/github.com/xor-gate/sshfp?status.svg
[ReportCard-Url]: http://goreportcard.com/report/xor-gate/sshfp
[ReportCard-Image]: https://goreportcard.com/badge/github.com/xor-gate/sshfp
[Coverage-Url]: https://coveralls.io/r/xor-gate/sshfp?branch=master
[Coverage-image]: https://img.shields.io/coveralls/xor-gate/sshfp.svg
