package main

import (
	"os"
	"log"
	"github.com/xor-gate/sshfp"
	"gopkg.in/src-d/go-git.v4"
	gitssh "gopkg.in/src-d/go-git.v4/plumbing/transport/ssh"
)

func main() {
	auth, err := gitssh.NewPublicKeysFromFile("xor-gate", "/home/jjacobs/.ssh/id_rsa", "")
	if err != nil {
		log.Fatal(err)
	}

	mc, err := sshfp.NewMemoryCache()
	if err != nil {
		log.Fatal(err)
	}

	hkcb, err := sshfp.NewResolver(sshfp.WithCache(mc), sshfp.WithDNSClientConfigFromFile("/etc/resolv.conf"))
	if err != nil {
		log.Fatal(err)
	}

	auth.HostKeyCallbackHelper.HostKeyCallback = hkcb.HostKeyCallback

	r, err := git.PlainClone("sshfp-git-example", false, &git.CloneOptions{
		Auth:     auth,
		URL:      "git@github.com:xor-gate/sshfp.git",
		Progress: os.Stdout,
	})
	if err != nil {
		log.Fatal(err)
	}

	ref, err := r.Head()
	if err != nil {
		log.Fatal(err)
	}

	commit, err := r.CommitObject(ref.Hash())
	if err != nil {
		log.Fatal(err)
	}

	log.Println(commit)
}
