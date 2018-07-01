# sshfp for golang

**NOTE: Package is functional but work-in-progress**

The sshfp project is a Golang implementation of SSH fingerprints stored in SSHFP DNS records which can be used together with [golang.org/x/crypto/ssh.Client](https://godoc.org/golang.org/x/crypto/ssh#Client) using a custom [HostKeyCallback](https://godoc.org/github.com/xor-gate/sshfp#Resolver.HostKeyCallback) with optional cache. Learn more about the DNS SSHFP record type on [Wikipedia](https://en.wikipedia.org/wiki/SSHFP_record). 

This package is based on the awesome Golang DNS package from [github.com/miekg/dns](https://github.com/miekg/dns).

# LICENSE

[MIT](LICENSE)
