package main

import (
	"fmt"

	"github.com/xor-gate/sshfp"
)

func main() {
	mc := sshfp.NewMemoryCache()
	res := sshfp.NewResolver(sshfp.WithCache(mc))
	ssh := NewSSHClient(res.HostKeyCallback)
	ssh.SetPrivateKeyFromFile("/home/jjacobs/.ssh/id_ecdsa")
	err := ssh.Connect("jerry", "shulgin.xor-gate.org:6222")
	err = ssh.Connect("jerry", "shulgin.xor-gate.org:6222")
	fmt.Println(err)
}
